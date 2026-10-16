"""Module 4: HTTP security headers analysis.

What it can detect (only from headers actually present/absent in the response):
- missing or weak Content-Security-Policy
- missing X-Content-Type-Options, Referrer-Policy, X-Frame-Options / frame-ancestors
- permissive CORS (Access-Control-Allow-Origin: * with credentials)
- missing Strict-Transport-Security on HTTPS responses
- informational: Server / X-Powered-By version disclosure

What it cannot detect:
- whether a CSP is bypassable (no policy evaluation), clickjacking feasibility
  against specific pages, or header behavior across all routes (single-response
  observation only).
"""

from __future__ import annotations

from typing import Any, Dict

from app.scanners.context import ScanContext
from app.scanners.schema import FindingData

MODULE = "http_headers"


async def analyze_headers(ctx: ScanContext) -> list[FindingData]:
    """Fetch the target once (no redirect following) and inspect real headers."""
    findings: list[FindingData] = []
    result: Dict[str, Any] = await ctx.fetch(ctx.target_url)

    if not result["ok"]:
        ctx.artifacts["http_headers"] = {"error": result["error"] or f"status {result['status']}"}
        return findings

    headers: Dict[str, str] = result["headers"]
    ctx.artifacts["http_headers"] = {"observed": headers, "status": result["status"]}
    asset = result["url"]

    def has(name: str) -> bool:
        return name in headers and bool(headers[name].strip())

    # --- CSP -------------------------------------------------------------
    if not has("content-security-policy"):
        findings.append(
            FindingData(
                title="Missing Content-Security-Policy",
                description="The response contains no Content-Security-Policy header, so the browser has no restriction on script or resource origins.",
                category=MODULE,
                severity="medium",
                confidence="certain",
                affected_asset=asset,
                evidence={"header": "content-security-policy", "observed": None},
                source_module=MODULE,
                cwe="CWE-693",
                impact="Injected script content faces fewer browser-side restrictions.",
                remediation="Add a CSP, starting in report-only mode: Content-Security-Policy-Report-Only.",
                verification_status="potential",
            )
        )
    elif "unsafe-inline" in headers["content-security-policy"]:
        findings.append(
            FindingData(
                title="CSP allows 'unsafe-inline'",
                description="The delivered CSP includes 'unsafe-inline', which negates much of the policy's protection against injected scripts.",
                category=MODULE,
                severity="low",
                confidence="certain",
                affected_asset=asset,
                evidence={"header": "content-security-policy", "value": headers["content-security-policy"]},
                source_module=MODULE,
                cwe="CWE-79",
                impact="Inline script injection is not blocked by the policy.",
                remediation="Use nonces or hashes instead of 'unsafe-inline'.",
                verification_status="potential",
            )
        )

    # --- X-Content-Type-Options ------------------------------------------
    if not has("x-content-type-options"):
        findings.append(
            FindingData(
                title="Missing X-Content-Type-Options header",
                description="The response does not include X-Content-Type-Options: nosniff.",
                category=MODULE,
                severity="low",
                confidence="certain",
                affected_asset=asset,
                evidence={"header": "x-content-type-options", "observed": None},
                source_module=MODULE,
                cwe="CWE-430",
                impact="Browsers may MIME-sniff responses and interpret them as executable content.",
                remediation="Send 'X-Content-Type-Options: nosniff' on all responses.",
                verification_status="potential",
            )
        )

    # --- Referrer-Policy ---------------------------------------------------
    if not has("referrer-policy"):
        findings.append(
            FindingData(
                title="Missing Referrer-Policy header",
                description="The response does not include a Referrer-Policy header.",
                category=MODULE,
                severity="info",
                confidence="certain",
                affected_asset=asset,
                evidence={"header": "referrer-policy", "observed": None},
                source_module=MODULE,
                cwe="CWE-200",
                impact="Full URLs (including query strings) may leak to third parties via the Referer header.",
                remediation="Send 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
                verification_status="potential",
            )
        )

    # --- Framing -----------------------------------------------------------
    csp = headers.get("content-security-policy", "")
    if not has("x-frame-options") and "frame-ancestors" not in csp:
        findings.append(
            FindingData(
                title="No framing protection (X-Frame-Options / CSP frame-ancestors)",
                description="Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
                category=MODULE,
                severity="low",
                confidence="certain",
                affected_asset=asset,
                evidence={"x-frame-options": headers.get("x-frame-options"), "csp_frame_ancestors": None},
                source_module=MODULE,
                cwe="CWE-1021",
                impact="The page may be embedded by third-party sites, enabling clickjacking-style UI redress.",
                remediation="Add 'X-Frame-Options: DENY' or a CSP frame-ancestors directive.",
                verification_status="potential",
            )
        )

    # --- HSTS on HTTPS ------------------------------------------------------
    if asset.startswith("https://") and not has("strict-transport-security"):
        findings.append(
            FindingData(
                title="Missing Strict-Transport-Security (HSTS)",
                description="An HTTPS response was observed without a Strict-Transport-Security header.",
                category=MODULE,
                severity="low",
                confidence="certain",
                affected_asset=asset,
                evidence={"header": "strict-transport-security", "observed": None},
                source_module=MODULE,
                cwe="CWE-319",
                impact="Users may be downgraded to HTTP on first visit or after typing the bare hostname.",
                remediation="Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' after validating all subdomains support HTTPS.",
                verification_status="potential",
            )
        )

    # --- Permissive CORS ------------------------------------------------------
    acao = headers.get("access-control-allow-origin")
    if acao == "*" and headers.get("access-control-allow-credentials", "").lower() == "true":
        findings.append(
            FindingData(
                title="CORS allows any origin with credentials",
                description="The response combines Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
                category=MODULE,
                severity="medium",
                confidence="certain",
                affected_asset=asset,
                evidence={
                    "access-control-allow-origin": acao,
                    "access-control-allow-credentials": headers.get("access-control-allow-credentials"),
                },
                source_module=MODULE,
                cwe="CWE-942",
                impact="Browsers reject this combination, but permissive CORS configurations frequently indicate copy-paste misconfiguration; reflected origins would expose credentialed responses.",
                remediation="Reflect an explicit allowlist of origins instead of '*'.",
                verification_status="potential",
            )
        )

    # --- Permissions-Policy (observation only when absent) ----------------
    if not has("permissions-policy"):
        findings.append(
            FindingData(
                title="Missing Permissions-Policy header",
                description="The response does not include a Permissions-Policy header, so browser feature access (camera, geolocation, etc.) is governed by defaults rather than explicit policy.",
                category=MODULE,
                severity="info",
                confidence="certain",
                affected_asset=asset,
                evidence={"header": "permissions-policy", "observed": None},
                source_module=MODULE,
                cwe="CWE-693",
                impact="Browser features are available to embedded content by default; this is a hardening observation, not a vulnerability.",
                remediation="Send a Permissions-Policy restricting features the site does not use.",
                verification_status="informational",
            )
        )

    # --- Version disclosure (informational) ------------------------------------
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server or powered:
        findings.append(
            FindingData(
                title="Server software version disclosed",
                description="The response reveals server/framework details.",
                category=MODULE,
                severity="info",
                confidence="certain",
                affected_asset=asset,
                evidence={"server": server or None, "x-powered-by": powered or None},
                source_module=MODULE,
                cwe="CWE-200",
                impact="Disclosed versions help attackers match known exploits; this alone is not a vulnerability.",
                remediation="Remove or genericize Server / X-Powered-By headers.",
                verification_status="informational",
            )
        )
    return findings
