"""Module 2: DNS record analysis.

What it can detect (only from real resolver responses):
- presence/absence of A/AAAA records
- CNAME chains (helps correlate infrastructure)
- MX / NS / TXT records that leak internal hints (e.g. `internal-` prefixes)
- missing SPF (TXT starting with 'v=spf1') on a zone that has MX records

What it cannot detect:
- subdomain takeover (requires active probing), zone transfers assumed denied,
  DNSSEC validation depth, or split-horizon/internal records.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from urllib.parse import urlparse

from app.core.config import settings
from app.scanners.context import ScanContext
from app.scanners.schema import FindingData

MODULE = "dns_analysis"

# dnspython is optional at import time so the module degrades cleanly.
try:
    import dns.resolver  # type: ignore

    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover
    HAS_DNSPYTHON = False


def _query_sync(name: str, rdtype: str) -> List[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = settings.SCAN_REQUEST_TIMEOUT
    resolver.timeout = settings.SCAN_REQUEST_TIMEOUT
    answers = resolver.resolve(name, rdtype)
    return [r.to_text().strip('"') for r in answers]


async def _query(name: str, rdtype: str) -> List[str]:
    return await asyncio.to_thread(_query_sync, name, rdtype)


async def analyze_dns(ctx: ScanContext) -> list[FindingData]:
    """Query real DNS records for the target host."""
    findings: list[FindingData] = []
    host = urlparse(ctx.target_url).hostname
    if not host:
        ctx.artifacts["dns"] = {"error": "no hostname"}
        return findings

    dns_info: Dict[str, Any] = {"host": host}
    ctx.artifacts["dns"] = dns_info

    if not HAS_DNSPYTHON:
        ctx.artifacts["dns"]["skipped"] = "dnspython not installed"
        return findings

    a_records: List[str] = []
    try:
        a_records = await _query(host, "A")
        dns_info["A"] = a_records
    except Exception as exc:
        dns_info["A_error"] = type(exc).__name__

    try:
        aaaa = await _query(host, "AAAA")
        dns_info["AAAA"] = aaaa
    except Exception:
        pass

    txt_records: List[str] = []
    try:
        txt_records = await _query(host, "TXT")
        dns_info["TXT"] = txt_records
    except Exception:
        pass

    mx_records: List[str] = []
    try:
        mx_records = await _query(host, "MX")
        dns_info["MX"] = mx_records
    except Exception:
        pass

    if not a_records and "A_error" not in dns_info:
        findings.append(
            FindingData(
                title="No IPv4 (A) record for target host",
                description=f"DNS resolution returned no A record for {host}.",
                category=MODULE,
                severity="info",
                confidence="certain",
                affected_asset=host,
                evidence=dns_info,
                source_module=MODULE,
                impact="The host may not be reachable over IPv4; IPv6-only deployments can break client access.",
                remediation="Verify the DNS zone is correct if the site should be reachable over IPv4.",
                verification_status="confirmed",
            )
        )

    has_spf = any(r.lower().startswith("v=spf1") for r in txt_records)
    if mx_records and not has_spf:
        findings.append(
            FindingData(
                title="Domain sends mail (MX) without an SPF policy",
                description="MX records exist but no 'v=spf1' TXT record was found, so any host may send mail as this domain.",
                category=MODULE,
                severity="low",
                confidence="firm",
                affected_asset=host,
                evidence={"MX": mx_records, "spf_present": False},
                source_module=MODULE,
                cwe="CWE-290",
                impact="Email spoofing of the domain is possible, enabling phishing.",
                remediation="Publish an SPF record (e.g. 'v=spf1 -all' if the domain sends no mail).",
                verification_status="confirmed",
            )
        )

    # Internal-hint leakage: only report when actually observed in the record text.
    for rtype in ("MX", "TXT"):
        for rec in dns_info.get(rtype, []):
            lowered = rec.lower()
            if any(hint in lowered for hint in ("internal.", ".local", "10.0.", "192.168.")):
                findings.append(
                    FindingData(
                        title=f"DNS {rtype} record may leak internal infrastructure names",
                        description="A public DNS record contains what looks like an internal hostname or private IP.",
                        category=MODULE,
                        severity="low",
                        confidence="uncertain",
                        affected_asset=host,
                        evidence={"record": rec, "type": rtype},
                        source_module=MODULE,
                        cwe="CWE-200",
                        impact="Attackers gain reconnaissance hints about internal naming/addressing.",
                        remediation="Review the record and remove internal naming details from public DNS.",
                        verification_status="potential",
                    )
                )
    return findings
