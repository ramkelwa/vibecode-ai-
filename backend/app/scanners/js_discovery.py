"""Module 7: JavaScript asset discovery.

Finds inline and external scripts in the retrieved document, then fetches
external scripts under strict limits, recording origin, status, content type,
size, and SHA-256 digest for each asset that was actually retrieved.

Safety properties:
- reuses ScanContext networking (scope validation, rate limits, budget,
  redirect re-validation, pinned-IP transport)
- hard cap on assets fetched per scan and bytes per asset
- source maps are NOT fetched unless explicitly enabled via settings
- failures are recorded per asset; nothing is fabricated
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List
from urllib.parse import urlparse

from app.core.config import settings
from app.scanners.context import ScanContext
from app.scanners.html_analysis import parse_html
from app.scanners.schema import FindingData

MODULE = "js_discovery"

MAX_ASSETS_PER_SCAN = 30
MAX_ASSET_BYTES = 1 * 1024 * 1024  # 1 MiB per script asset


async def discover_assets(ctx: ScanContext) -> Dict[str, Any]:
    """Discover script assets from the document and fetch external ones."""
    doc_url: str = ctx.artifacts.get("document_url") or ctx.target_url
    html_result: Dict[str, Any] = await ctx.fetch(ctx.target_url)

    inventory: Dict[str, Any] = {"inline": [], "external": [], "errors": {}}
    ctx.artifacts["js_assets"] = inventory

    if not html_result["ok"]:
        inventory["errors"]["document"] = html_result["error"] or f"status {html_result['status']}"
        return inventory

    parsed = parse_html(html_result["url"], html_result["body"])
    asset_urls: List[str] = []
    seen: set[str] = set()

    for script in parsed.get("scripts", []):
        if script.get("inline"):
            inventory["inline"].append({"length": script.get("inline_length", 0)})
        else:
            src = script.get("src")
            if src and src not in seen:
                seen.add(src)
                asset_urls.append(src)

    # Fetch external scripts, bounded and scope-checked (ctx.fetch enforces scope).
    fetched = 0
    for url in asset_urls:
        if fetched >= MAX_ASSETS_PER_SCAN:
            inventory["errors"]["asset_limit"] = (
                f"stopped after {MAX_ASSETS_PER_SCAN} assets; {len(asset_urls) - fetched} not fetched"
            )
            break
        entry: Dict[str, Any] = {
            "url": url,
            "origin": urlparse(url).netloc,
            "same_origin": urlparse(url).netloc == urlparse(doc_url).netloc,
        }
        result = await ctx.fetch(url)
        if result["ok"]:
            body = result["body"][:MAX_ASSET_BYTES]
            entry.update(
                {
                    "status": result["status"],
                    "content_type": result["headers"].get("content-type"),
                    "size": len(body.encode("utf-8", errors="replace")),
                    "sha256": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
                    "content": body,
                }
            )
            fetched += 1
        else:
            entry["error"] = result["error"] or f"status {result['status']}"
            inventory["errors"][url] = entry["error"]
        inventory["external"].append(entry)

    # Source maps: never fetched automatically.
    inventory["source_maps_fetched"] = False
    if not settings.SCAN_ALLOW_PRIVATE_TARGETS:
        pass  # scope already enforced by ctx.fetch for every asset

    return inventory


async def analyze_js_assets(ctx: ScanContext) -> list[FindingData]:
    """Asset discovery produces an inventory; findings are contextual only."""
    await discover_assets(ctx)
    return []
