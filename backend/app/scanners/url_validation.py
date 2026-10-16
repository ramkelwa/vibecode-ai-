"""Module 1: URL validation and redirect-chain analysis.

What it can detect (from real observation only):
- non-http(s) schemes, missing hostnames
- embedded credentials in the URL (user:pass@host)
- invalid/out-of-range ports and unusual non-default ports
- cross-origin redirects (scheme/host/port changes along the chain)
- redirects into prohibited IP ranges (validated per hop)
- redirect chains exceeding the configured limit, and redirect loops

What it cannot detect:
- open redirects that require attacker-controlled parameters (no active probing)
- client-side (JavaScript) redirects - that is the JS module's job
"""

from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlparse

from app.scanners.context import MAX_REDIRECTS, ScanContext
from app.scanners.schema import FindingData

MODULE = "url_validation"

DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(url: str) -> tuple[str, str, str]:
    p = urlparse(url)
    return (p.scheme.lower(), (p.hostname or "").lower(), str(p.port or ""))


def validate_url(url: str) -> list[FindingData]:
    """Pure URL validation (no network). Returns findings for structural issues."""
    findings: list[FindingData] = []
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        findings.append(
            FindingData(
                title="URL uses a non-HTTP(S) scheme",
                description=f"The target URL uses the '{parsed.scheme}' scheme. Only http/https can be assessed.",
                category=MODULE,
                severity="info",
                confidence="certain",
                affected_asset=url,
                evidence={"observed_scheme": parsed.scheme},
                source_module=MODULE,
                cwe="CWE-20",
                impact="Scanner cannot assess this target over unsupported schemes.",
                remediation="Provide an http(s) URL.",
                verification_status="informational",
            )
        )
    if not parsed.hostname:
        findings.append(
            FindingData(
                title="URL has no hostname",
                description="The target URL does not contain a hostname, so it cannot be resolved or validated.",
                category=MODULE,
                severity="info",
                confidence="certain",
                affected_asset=url,
                evidence={"netloc": parsed.netloc},
                source_module=MODULE,
                impact="No assessment possible.",
                remediation="Provide a fully qualified URL including the host.",
                verification_status="informational",
            )
        )
    if parsed.username or parsed.password:
        findings.append(
            FindingData(
                title="URL contains embedded credentials",
                description="The URL embeds a username/password (user:pass@host), which leaks credentials in logs, Referer headers, and browser history.",
                category=MODULE,
                severity="medium",
                confidence="certain",
                affected_asset=url,
                evidence={"has_username": bool(parsed.username), "has_password": bool(parsed.password)},
                source_module=MODULE,
                cwe="CWE-522",
                impact="Credentials are exposed in clear text wherever the URL appears.",
                remediation="Remove credentials from URLs; use authentication headers or session handling.",
                verification_status="confirmed",
            )
        )
    # urlparse itself raises ValueError for out-of-range ports - handle it.
    try:
        port = parsed.port
    except ValueError:
        port = -1
    if port is not None and not (0 < port <= 65535):
        findings.append(
            FindingData(
                title="URL contains an invalid port",
                description=f"The URL specifies an invalid port ({port}), which is outside the valid range 1-65535.",
                category=MODULE,
                severity="info",
                confidence="certain",
                affected_asset=url,
                evidence={"port": None},
                source_module=MODULE,
                impact="Requests to this URL cannot be completed.",
                remediation="Use a valid TCP port.",
                verification_status="informational",
            )
        )
    return findings


async def analyze_redirects(ctx: ScanContext) -> list[FindingData]:
    """Follow redirects (within limits) and report what is actually observed."""
    findings: list[FindingData] = []
    result: Dict[str, Any] = await ctx.fetch(ctx.target_url, follow_redirects=True)

    if result["error"] == "too_many_redirects":
        findings.append(
            FindingData(
                title="Redirect chain exceeds the safe limit",
                description=f"More than {MAX_REDIRECTS} redirects were followed; the chain was stopped.",
                category=MODULE,
                severity="low",
                confidence="certain",
                affected_asset=ctx.target_url,
                evidence={"redirects": result["redirects"], "limit": MAX_REDIRECTS},
                source_module=MODULE,
                cwe="CWE-601",
                impact="Excessive redirects slow requests and can hide the true destination.",
                remediation="Reduce redirect chains to at most one hop.",
                verification_status="confirmed",
            )
        )
        ctx.artifacts["final_url"] = None
        return findings

    if result["error"]:
        # A plain network failure is a limitation, not a vulnerability: it is
        # recorded as an artifact, not a finding. But some error classes ARE
        # security-relevant observations and must never disappear silently:
        # - destination_not_allowed while following redirects: the scanner's
        #   SSRF/scope guard refused a hop; that refusal proves a redirect
        #   went to a prohibited destination.
        # - redirect_loop: the site redirects in a cycle.
        ctx.artifacts["redirect_error"] = result["error"]
        redirects_seen = result.get("redirects") or []
        if isinstance(result["error"], str) and result["error"].startswith("destination_not_allowed"):
            findings.append(
                FindingData(
                    title="Redirect to a prohibited destination (refused)",
                    description=(
                        "A redirect hop resolved to a destination the scanner's "
                        "scope policy forbids (private/internal address or "
                        "unsupported scheme), so the request was refused. This "
                        "is evidence of the redirect's direction, not of the "
                        "destination's behavior."
                    ),
                    category=MODULE,
                    severity="medium" if redirects_seen else "low",
                    confidence="certain",
                    affected_asset=ctx.target_url,
                    evidence={
                        "error": result["error"],
                        "hops_followed": len(redirects_seen),
                        "redirects": redirects_seen,
                    },
                    source_module=MODULE,
                    cwe="CWE-601",
                    impact="Redirects into prohibited ranges enable internal-service funneling when the parameter is user-controlled.",
                    remediation="Restrict redirects to intended, validated destinations.",
                    verification_status="confirmed" if redirects_seen else "potential",
                )
            )
        elif result["error"] == "redirect_loop":
            findings.append(
                FindingData(
                    title="Redirect loop detected",
                    description="The chained redirects cycled back to an already-visited URL and were stopped.",
                    category=MODULE,
                    severity="low",
                    confidence="certain",
                    affected_asset=ctx.target_url,
                    evidence={"chain": redirects_seen},
                    source_module=MODULE,
                    impact="Cycling redirects waste client and crawler resources and can hide the real target.",
                    remediation="Remove the circular redirect rule.",
                    verification_status="confirmed",
                )
            )
        return findings

    chain = result["redirects"]
    final_url = result["url"]
    ctx.artifacts["final_url"] = final_url
    ctx.artifacts["redirect_chain"] = chain

    if chain:
        # Cross-origin hops are reported from observed evidence only.
        for hop in chain:
            if _origin(hop["from"]) != _origin(hop["to"]):
                findings.append(
                    FindingData(
                        title="Redirect to a different origin",
                        description="The redirect chain leaves the original origin. This is common (e.g. http->https) but must be reviewed.",
                        category=MODULE,
                        severity="info",
                        confidence="certain",
                        affected_asset=hop["from"],
                        evidence={"from": hop["from"], "to": hop["to"], "chain": chain},
                        source_module=MODULE,
                        cwe="CWE-601",
                        impact="Cross-origin redirects can be abused in phishing or open-redirect scenarios if they reflect user input.",
                        remediation="Verify the redirect is intentional and does not forward arbitrary user-supplied URLs.",
                        verification_status="potential",
                    )
                )
    return findings
