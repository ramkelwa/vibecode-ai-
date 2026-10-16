"""Module 9: API endpoint discovery (static only).

Analyzes retrieved JavaScript for:
- fetch() calls and their methods
- XMLHttpRequest (open(method, url))
- axios / ky / superagent style calls (axios.get/post/..., axios({method, url}))
- WebSocket constructor calls
- API base URL constants and request-like URL strings

Per endpoint: normalized URL/path, method (or UNKNOWN), discovery source,
line, same-origin classification, confidence, dynamic-construction flag.
Results are deduplicated. Nothing is probed, enumerated, or authenticated.
Missing methods are reported as UNKNOWN, never invented.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.scanners.context import ScanContext
from app.scanners.schema import FindingData

MODULE = "api_discovery"

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

# fetch("url") / fetch('url', {method: "POST"})
_FETCH = re.compile(r"\bfetch\s*\(\s*[\"'`]([^\"'`]+)[\"'`]\s*(?:,\s*\{([^}]*)\})?", re.S)
# xhr.open("GET", "url")
_XHR_OPEN = re.compile(r"\.open\s*\(\s*[\"']([A-Za-z]+)[\"']\s*,\s*[\"'`]([^\"'`]+)[\"'`]")
# axios.get("url") / axios.post("url", ...)
_AXIOS_SHORT = re.compile(r"\baxios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]", re.I)
# axios({ method: "POST", url: "..." })
_AXIOS_OBJ = re.compile(r"\baxios\s*\(\s*\{([^}]*)\}", re.S)
# new WebSocket("url")
_WEBSOCKET = re.compile(r"\bnew\s+WebSocket\s*\(\s*[\"'`]([^\"'`]+)[\"'`]")
# base URL constants: const API_BASE = "https://api.example.com"
_BASE_URL = re.compile(r"(?i)\b(?:api[_-]?base[_-]?url|base[_-]?url|api[_-]?url|apiurl)\b\s*[:=]\s*[\"']([^\"']+)[\"']")
# request-like path strings starting with /api/ or /v1/ etc.
_PATH_STR = re.compile(r"[\"'`](/(?:api|v\d+|rest|graphql)[A-Za-z0-9_\-/.{}]*)[\"'`]")

_DYNAMIC = re.compile(r"[\"'`]\s*\+|\$\{|\.concat\(|\$\{.*\}", re.S)


def _line_of(source: str, pos: int) -> int:
    return source.count("\n", 0, pos) + 1


def _classify(url: str, doc_origin: str) -> str:
    p = urlparse(url)
    if p.netloc:
        origin = f"{p.scheme or 'https'}://{p.netloc}"
        return "same-origin" if origin == doc_origin else "cross-origin"
    return "same-origin"  # relative path


def _normalize(url: str) -> str:
    return url.strip()


def _extract_method(cfg: str) -> Optional[str]:
    m = re.search(r"method\s*:\s*[\"']([A-Za-z]+)[\"']", cfg or "", re.I)
    return m.group(1).upper() if m else None


def discover_endpoints_in_source(source: str, asset_url: str, doc_origin: str) -> List[Dict[str, Any]]:
    """Extract endpoint records from one JS source. Deduplicates."""
    found: List[Dict[str, Any]] = []
    seen: set = set()

    def add(url: str, method: Optional[str], src: str, pos: int, confidence: str, call_context: str = "") -> None:
        url = _normalize(url)
        if not url or url.startswith("data:") or url.startswith("blob:"):
            return
        # A URL is dynamically constructed if the captured string itself contains
        # template/concat markers OR concatenation directly follows the string
        # literal in the source (e.g. fetch('/api/u/' + id)).
        look_ahead = source[pos : pos + len(url) + 60]
        dynamic = bool(_DYNAMIC.search(url)) or bool(_DYNAMIC.search(look_ahead))
        method_u = (method or "UNKNOWN").upper()
        # Dedupe by URL: if this URL was seen with UNKNOWN and we now have a
        # specific method (or vice versa), keep one record, preferring the
        # specific method and the highest-confidence source. Methods are never
        # invented - only merged from actual call sites.
        existing = next((e for e in found if e["url"] == url), None)
        if existing is not None:
            conf_rank = {"low": 0, "uncertain": 1, "firm": 2}
            if existing["method"] == "UNKNOWN" and method_u != "UNKNOWN":
                existing["method"] = method_u
                existing["source"] = src
            if conf_rank[confidence] > conf_rank[existing["confidence"]]:
                existing["confidence"] = confidence
                existing["source"] = src
            existing["dynamically_constructed"] = existing["dynamically_constructed"] or dynamic
            return
        seen.add((url, method_u))
        found.append(
            {
                "url": url,
                "method": (method or "UNKNOWN").upper(),
                "source": src,
                "source_asset": asset_url,
                "line": _line_of(source, pos),
                "same_origin": _classify(url, doc_origin) == "same-origin",
                "confidence": confidence,
                "dynamically_constructed": dynamic,
                # When dynamic, the captured string is only a prefix of the real URL.
                "partial": dynamic,
            }
        )

    for m in _FETCH.finditer(source):
        method = _extract_method(m.group(2))
        conf = "firm" if method else "uncertain"
        add(m.group(1), method, "fetch", m.start(), conf, call_context=m.group(0))

    for m in _XHR_OPEN.finditer(source):
        method = m.group(1).upper()
        if method in HTTP_METHODS:
            add(m.group(2), method, "xmlhttprequest", m.start(), "firm")

    for m in _AXIOS_SHORT.finditer(source):
        add(m.group(2), m.group(1).upper(), "axios", m.start(), "firm")

    for m in _AXIOS_OBJ.finditer(source):
        method = _extract_method(m.group(1))
        url_m = re.search(r"url\s*:\s*[\"'`]([^\"'`]+)[\"'`]", m.group(1))
        if url_m:
            add(url_m.group(1), method, "axios", m.start(), "firm" if method else "uncertain")

    for m in _WEBSOCKET.finditer(source):
        add(m.group(1), "WS", "websocket", m.start(), "firm")

    for m in _BASE_URL.finditer(source):
        add(m.group(1), "UNKNOWN", "base_url_constant", m.start(), "uncertain")

    seen_urls = {e["url"] for e in found}
    for m in _PATH_STR.finditer(source):
        # Skip generic path strings already captured by a specific call pattern
        # under any method - they are the same observation, not new endpoints.
        if _normalize(m.group(1)) in seen_urls:
            continue
        add(m.group(1), "UNKNOWN", "url_string", m.start(), "low")

    return found


async def analyze_api_endpoints(ctx: ScanContext) -> list[FindingData]:
    """Build the API endpoint inventory from all retrieved JS sources."""
    endpoints: List[Dict[str, Any]] = []
    doc_url: str = ctx.artifacts.get("document_url") or ctx.target_url
    doc_origin = f"{urlparse(doc_url).scheme}://{urlparse(doc_url).netloc}"

    inventory: Dict[str, Any] = ctx.artifacts.get("js_assets")
    if inventory is None:
        from app.scanners.js_discovery import discover_assets

        inventory = await discover_assets(ctx)

    for asset in inventory.get("external", []):
        content = asset.get("content")
        if content:
            endpoints.extend(discover_endpoints_in_source(content, asset["url"], doc_origin))

    # Inline scripts from the document.
    doc_result: Dict[str, Any] = await ctx.fetch(ctx.target_url)
    if doc_result["ok"]:
        import re as _re

        for sm in _re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", doc_result["body"], _re.S | _re.I):
            if sm.group(1).strip():
                endpoints.extend(
                    discover_endpoints_in_source(sm.group(1), doc_result["url"], doc_origin)
                )

    ctx.artifacts["api_endpoints"] = endpoints
    return []  # inventory module: no findings unless a phase-4 policy says otherwise
