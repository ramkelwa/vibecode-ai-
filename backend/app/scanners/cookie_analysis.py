"""Module 5: Cookie security attribute analysis.

What it can detect (only from Set-Cookie headers actually returned):
- cookies without Secure
- cookies without HttpOnly
- cookies without SameSite
- cookies with an explicit overly-broad Domain attribute
- session-name cookies (PHPSESSID, JSESSIONID, ...) lacking attributes

What it cannot detect:
- cookie values' entropy, session fixation (requires active session tests),
  or cookies set by JavaScript (document.cookie is invisible here).
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.scanners.context import ScanContext
from app.scanners.schema import FindingData

MODULE = "cookie_analysis"

SESSION_COOKIE_NAMES = {"phpsessid", "jsessionid", "asp.net_sessionid", "sessionid", "connect.sid", "laravel_session"}


def _parse_set_cookie(raw: str) -> Dict[str, Any]:
    parts = [p.strip() for p in raw.split(";")]
    name_value = parts[0] if parts else ""
    name, _, value = name_value.partition("=")
    attrs: Dict[str, str] = {}
    for part in parts[1:]:
        key, _, val = part.partition("=")
        attrs[key.strip().lower()] = val.strip()
    return {"name": name.strip(), "value": value.strip(), "attrs": attrs}


async def analyze_cookies(ctx: ScanContext) -> list[FindingData]:
    """Fetch the target and inspect real Set-Cookie headers."""
    findings: list[FindingData] = []
    result: Dict[str, Any] = await ctx.fetch(ctx.target_url)

    if not result["ok"]:
        ctx.artifacts["cookies"] = {"error": result["error"] or f"status {result['status']}"}
        return findings

    headers = result["headers"]
    # httpx merges repeated headers with ", " - keep both representations.
    raw_cookies: List[str] = []
    get_list = headers.get("set-cookie")
    if get_list:
        # httpx returns the raw joined value; split conservatively on Set-Cookie boundaries.
        raw_cookies = [c.strip() for c in get_list.split(", ") if "=" in c]

    parsed = [_parse_set_cookie(c) for c in raw_cookies]
    ctx.artifacts["cookies"] = {"observed": [c["name"] for c in parsed]}

    for cookie in parsed:
        name = cookie["name"]
        attrs = cookie["attrs"]
        evidence = {
            "cookie_name": name,
            "attributes_observed": {k: v or True for k, v in attrs.items()},
            "set_cookie_header_redacted": True,
        }
        is_session = name.lower() in SESSION_COOKIE_NAMES

        # NOTE: boolean flags parse to "" - check membership, not truthiness.
        if "secure" not in attrs:
            findings.append(
                FindingData(
                    title=f"Cookie '{name}' lacks the Secure attribute",
                    description="The cookie was set without the Secure flag, so the browser will also send it over plain HTTP.",
                    category=MODULE,
                    severity="medium" if is_session else "low",
                    confidence="certain",
                    affected_asset=result["url"],
                    evidence=evidence,
                    source_module=MODULE,
                    cwe="CWE-614",
                    impact="The cookie can be captured on network paths that downgrade to HTTP.",
                    remediation="Add the Secure attribute when setting this cookie.",
                    verification_status="confirmed",
                )
            )
        if "httponly" not in attrs and is_session:
            findings.append(
                FindingData(
                    title=f"Session cookie '{name}' lacks HttpOnly",
                    description="A session-identified cookie was set without HttpOnly, so client-side scripts can read it.",
                    category=MODULE,
                    severity="medium",
                    confidence="certain",
                    affected_asset=result["url"],
                    evidence=evidence,
                    source_module=MODULE,
                    cwe="CWE-1004",
                    impact="Any XSS can exfiltrate the session token.",
                    remediation="Set HttpOnly on session cookies.",
                    verification_status="confirmed",
                )
            )
        if not attrs.get("samesite") and is_session:
            findings.append(
                FindingData(
                    title=f"Session cookie '{name}' has no SameSite attribute",
                    description="The session cookie was set without a SameSite attribute; modern browsers default to Lax but explicit control is preferred.",
                    category=MODULE,
                    severity="low",
                    confidence="certain",
                    affected_asset=result["url"],
                    evidence=evidence,
                    source_module=MODULE,
                    cwe="CWE-1275",
                    impact="Cross-site requests may carry the cookie depending on browser defaults.",
                    remediation="Set 'SameSite=Lax' (or 'Strict') on session cookies.",
                    verification_status="confirmed",
                )
            )
        domain = attrs.get("domain", "")
        if domain and not domain.lstrip(".").endswith(_registrable_suffix_hint(result["url"])):
            findings.append(
                FindingData(
                    title=f"Cookie '{name}' scoped to an unrelated Domain",
                    description="The cookie's Domain attribute does not match the site that set it.",
                    category=MODULE,
                    severity="low",
                    confidence="uncertain",
                    affected_asset=result["url"],
                    evidence=evidence,
                    source_module=MODULE,
                    cwe="CWE-565",
                    impact="An overly broad or mismatched Domain widens who receives the cookie.",
                    remediation="Scope cookies to the most specific host/domain needed.",
                    verification_status="potential",
                )
            )
        # Session cookies without explicit expiry (session cookies) are normal;
        # only flag long-lived non-session cookies lacking Secure above.
        expires = attrs.get("expires", "")
        max_age = attrs.get("max-age", "")
        if expires:
            evidence["has_expires"] = True
        if max_age:
            evidence["has_max_age"] = True
            try:
                if int(max_age) > 31536000:  # > 1 year
                    findings.append(
                        FindingData(
                            title=f"Cookie '{name}' has an excessive Max-Age (> 1 year)",
                            description="The cookie persists for more than one year, extending the window in which it can be replayed if captured.",
                            category=MODULE,
                            severity="info",
                            confidence="certain",
                            affected_asset=result["url"],
                            evidence=evidence,
                            source_module=MODULE,
                            cwe="CWE-539",
                            impact="Long-lived cookies increase the impact of any future capture.",
                            remediation="Limit cookie lifetime to the minimum practical duration.",
                            verification_status="informational",
                        )
                    )
            except ValueError:
                evidence["max_age_unparseable"] = True
    return findings


def _registrable_suffix_hint(url: str) -> str:
    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    parts = host.split(".")
    # Crude hint: last two labels ('example.com'). Only used as a mismatch signal.
    return ".".join(parts[-2:]) if len(parts) >= 2 else host
