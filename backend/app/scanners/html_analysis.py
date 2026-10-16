"""Module 6: HTML analysis.

What it can detect (only from the actually retrieved document):
- page title, metadata, links, scripts, and resource URLs (relative URLs
  resolved against the correct document URL)
- forms: method, action URL, input types, password-field presence
- external form actions (observations requiring review, not verdicts)

What it deliberately does NOT do:
- submit forms or execute JavaScript
- declare "missing CSRF protection" from the absence of an obvious token
  (a hidden token can be named anything; absence of evidence is not evidence)

Malformed HTML, unusual encodings, and oversized pages are handled by
BeautifulSoup's lenient parser and the response size cap in ScanContext.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from app.scanners.context import ScanContext
from app.scanners.schema import FindingData

MODULE = "html_analysis"

MAX_HTML_BYTES = 2 * 1024 * 1024  # align with response cap


def _absolute(document_url: str, ref: str) -> Optional[str]:
    if not ref:
        return None
    try:
        return urljoin(document_url, ref)
    except ValueError:
        return None


def parse_html(document_url: str, html: str) -> Dict[str, Any]:
    """Parse HTML into a structured summary. Raises nothing for malformed HTML."""
    soup = BeautifulSoup(html, "html.parser")  # lenient with malformed input
    out: Dict[str, Any] = {
        "title": None,
        "meta": [],
        "links": [],
        "scripts": [],
        "resources": [],
        "forms": [],
        "has_password_field": False,
        "parse_error": None,
    }
    try:
        title_tag = soup.find("title")
        out["title"] = title_tag.get_text(strip=True) if title_tag else None

        for meta in soup.find_all("meta")[:100]:
            entry = {k: v for k, v in meta.attrs.items() if isinstance(v, str)}
            if entry:
                out["meta"].append(entry)

        for a in soup.find_all("a", href=True)[:500]:
            href = a.get("href", "")
            abs_url = _absolute(document_url, href)
            if abs_url:
                out["links"].append({"href": abs_url, "text": a.get_text(strip=True)[:200]})

        for script in soup.find_all("script")[:500]:
            entry: Dict[str, Any] = {"inline": not script.get("src")}
            src = script.get("src")
            if src:
                entry["src"] = _absolute(document_url, src)
            if script.get("type"):
                entry["type"] = script.get("type")
            code = script.string or script.get_text()
            if code:
                entry["inline_length"] = len(code)
            out["scripts"].append(entry)

        for res in soup.find_all(["link", "img"])[:500]:
            ref = res.get("href") or res.get("src")
            if ref:
                abs_url = _absolute(document_url, ref)
                if abs_url:
                    out["resources"].append({"tag": res.name, "url": abs_url})

        for form in soup.find_all("form")[:100]:
            action = form.get("action", "")
            method = (form.get("method") or "GET").upper()
            inputs: List[Dict[str, Any]] = []
            has_password = False
            for inp in form.find_all("input")[:200]:
                itype = (inp.get("type") or "text").lower()
                if itype == "password":
                    has_password = True
                inputs.append({"type": itype, "name": inp.get("name")})
            action_abs = _absolute(document_url, action) if action else document_url
            out["forms"].append(
                {
                    "method": method,
                    "action": action_abs,
                    "action_external": (
                        urlparse(action_abs).netloc != urlparse(document_url).netloc
                        if action_abs
                        else False
                    ),
                    "input_count": len(inputs),
                    "input_types": sorted({i["type"] for i in inputs}),
                    "has_password_field": has_password,
                }
            )
            if has_password:
                out["has_password_field"] = True
    except Exception as exc:  # malformed HTML must not crash the scan
        out["parse_error"] = type(exc).__name__
    return out


async def analyze_html(ctx: ScanContext) -> list[FindingData]:
    """Fetch the target document and extract the real HTML structure."""
    findings: list[FindingData] = []
    result: Dict[str, Any] = await ctx.fetch(ctx.target_url)

    if not result["ok"]:
        ctx.artifacts["html_analysis"] = {"error": result["error"] or f"status {result['status']}"}
        return findings

    parsed = parse_html(result["url"], result["body"][:MAX_HTML_BYTES])
    html_artifact: Dict[str, Any] = parsed
    if isinstance(parsed, dict) and isinstance(result.get("headers"), dict):
        html_artifact["response_headers"] = {
            k: v for k, v in result["headers"].items() if isinstance(k, str) and isinstance(v, str)
        }
    ctx.artifacts["html_analysis"] = html_artifact
    ctx.artifacts["document_url"] = result["url"]

    for form in parsed.get("forms", []):
        if form.get("action_external"):
            findings.append(
                FindingData(
                    title="Form posts to an external origin",
                    description="A form on this page submits data to a different origin than the page itself. Verify this is intentional (e.g. an SSO or payment provider).",
                    category=MODULE,
                    severity="info",
                    confidence="certain",
                    affected_asset=result["url"],
                    evidence={
                        "form_action": form["action"],
                        "form_method": form["method"],
                    },
                    source_module=MODULE,
                    cwe="CWE-200",
                    impact="User-submitted data leaves the site's origin; a compromised external endpoint would receive it.",
                    remediation="Confirm the external action URL is an expected integration and served over HTTPS.",
                    verification_status="potential",
                )
            )
    return findings
