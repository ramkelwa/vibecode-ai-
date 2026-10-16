"""Module 8: JavaScript static analysis.

Conservative pattern-based analysis of retrieved JavaScript (never executed):
- candidate credentials/token-like strings (values REDACTED in all output)
- dangerous API usage: eval(), new Function(), innerHTML, outerHTML,
  document.write(), dynamic script insertion, debugger statements
- insecure http:// resource references inside scripts

Limits (documented false-positive considerations):
- a match is NOT proof of a vulnerability; each finding is contextual
- public API identifiers, placeholder strings ('YOUR_API_KEY'), and ordinary
  configuration are filtered where recognizable
- no AST parser is bundled; regex precision is limited and stated per finding
- discovered values are never validated against external services
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from app.scanners.context import ScanContext
from app.scanners.schema import FindingData

MODULE = "js_analysis"

_REDACTED = "***REDACTED***"

# Candidate secret assignments. Capture groups: 1 = key name, 2 = value.
_SECRET_PATTERNS = [
    re.compile(r"(?i)\b(api[_-]?key|api[_-]?secret|secret|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*[\"']([A-Za-z0-9_\-\.]{16,})[\"']"),
    re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*[\"'](\S{6,})[\"']"),
    re.compile(r"\b(sk_live_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b"),  # JWT
]

# Values that are clearly placeholders, not real secrets.
_PLACEHOLDER_VALUES = {"your_api_key", "your_api_key_here", "changeme", "change_me", "xxx", "test", "dummy", "example", "insert_api_key", "todo"}

# Dangerous APIs with risk context.
_DANGEROUS_APIS = [
    (re.compile(r"\beval\s*\("), "eval() executes arbitrary strings as code"),
    (re.compile(r"new\s+Function\s*\("), "new Function() compiles strings into executable functions"),
    (re.compile(r"\.innerHTML\s*="), "innerHTML assignment can inject untrusted markup"),
    (re.compile(r"\.outerHTML\s*="), "outerHTML assignment can inject untrusted markup"),
    (re.compile(r"document\.write\s*\("), "document.write() injects markup during parsing"),
    (re.compile(r"(?i)document\.createElement\s*\(\s*[\"']script[\"']"), "dynamic script element creation"),
    (re.compile(r"\bdebugger\b"), "debugger statement left in production code"),
]

_HTTP_URL = re.compile(r"[\"']http://[^\"'\s]{4,}[\"']")


def _redact_value(value: str) -> str:
    if len(value) <= 4:
        return _REDACTED
    return value[:2] + _REDACTED + value[-1:]


def _is_placeholder(value: str) -> bool:
    return value.lower() in _PLACEHOLDER_VALUES or set(value.lower()) <= {"x", "*", "."}


def analyze_js_source(source: str, asset_url: str) -> List[FindingData]:
    """Analyze one JS source string. Returns redacted, contextual findings."""
    findings: List[FindingData] = []

    for pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(source):
            value = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
            if _is_placeholder(value):
                continue  # public configuration / placeholder, not a secret
            line_no = source.count("\n", 0, m.start()) + 1
            key = m.group(1) if m.lastindex and m.lastindex >= 2 else "embedded credential"
            findings.append(
                FindingData(
                    title=f"Candidate hardcoded secret ({key})",
                    description=f"A token-like string assigned to '{key}' was found in JavaScript. This is a candidate only - the value has been redacted and was not validated against any service.",
                    category=MODULE,
                    severity="high",
                    confidence="uncertain",
                    affected_asset=asset_url,
                    evidence={
                        "line": line_no,
                        "key": key,
                        "value": _redact_value(value),
                        "redacted": True,
                        "context": "pattern match in static JS; manual verification required",
                    },
                    source_module=MODULE,
                    cwe="CWE-798",
                    impact="If genuine, embedded credentials expose whatever the key grants, to anyone who can load this script.",
                    remediation="Rotate the credential if genuine; move secrets server-side; never ship keys in client bundles.",
                    verification_status="potential",
                )
            )

    for pattern, why in _DANGEROUS_APIS:
        count = len(pattern.findall(source))
        if count:
            line_match = pattern.search(source)
            line_no = source.count("\n", 0, line_match.start()) + 1 if line_match else 0
            findings.append(
                FindingData(
                    title=f"Dangerous API usage: {why.split(' ', 2)[0]}",
                    description=f"{why}. Observed {count} time(s). This is contextual - the actual risk depends on whether untrusted input reaches it.",
                    category=MODULE,
                    severity="info",
                    confidence="certain",
                    affected_asset=asset_url,
                    evidence={"line": line_no, "occurrences": count, "api": pattern.pattern},
                    source_module=MODULE,
                    cwe="CWE-95",
                    impact="These APIs become vulnerabilities when untrusted data flows into them; usage alone is not exploitation.",
                    remediation="Review whether untrusted input can reach these calls; prefer safe DOM APIs and avoid eval.",
                    verification_status="potential",
                )
            )

    for m in _HTTP_URL.finditer(source):
        url = m.group(0).strip("\"'")
        if any(url.startswith(p) for p in ("http://localhost", "http://127.0.0.1", "http://schema.", "http://www.w3.org/", "http://ns.adobe.")):
            continue  # namespaces/local references are not network calls
        line_no = source.count("\n", 0, m.start()) + 1
        findings.append(
            FindingData(
                title="Insecure http:// reference in JavaScript",
                description="A script references an http:// URL. If this is fetched at runtime, the request is unencrypted.",
                category=MODULE,
                severity="low",
                confidence="uncertain",
                affected_asset=asset_url,
                evidence={"line": line_no, "url": url, "note": "static reference; may be a namespace or comment"},
                source_module=MODULE,
                cwe="CWE-319",
                impact="Unencrypted requests can be read or modified on the network path.",
                remediation="Use https:// for all runtime-fetched resources.",
                verification_status="potential",
            )
        )

    return findings


async def analyze_js(ctx: ScanContext) -> list[FindingData]:
    """Run static analysis over all fetched script assets."""
    findings: List[FindingData] = []
    inventory: Dict[str, Any] = ctx.artifacts.get("js_assets")
    if inventory is None:
        from app.scanners.js_discovery import discover_assets

        inventory = await discover_assets(ctx)

    ctx.artifacts["js_analysis"] = {"assets_analyzed": 0}
    for asset in inventory.get("external", []):
        content = asset.get("content")
        if not content:
            continue  # never fabricate analysis for unretrieved assets
        ctx.artifacts["js_analysis"]["assets_analyzed"] += 1
        findings.extend(analyze_js_source(content, asset["url"]))

    # Inline scripts come from the document itself.
    doc_result: Dict[str, Any] = await ctx.fetch(ctx.target_url)
    if doc_result["ok"]:
        from app.scanners.html_analysis import parse_html

        parsed = parse_html(doc_result["url"], doc_result["body"])
        for script in parsed.get("scripts", []):
            if script.get("inline") and doc_result["body"]:
                import re as _re

                for sm in _re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", doc_result["body"], _re.S | _re.I):
                    code = sm.group(1)
                    if code.strip():
                        ctx.artifacts["js_analysis"]["assets_analyzed"] += 1
                        findings.extend(analyze_js_source(code, doc_result["url"]))

    return findings
