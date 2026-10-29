"""Strict URL validation for VirusTotal submissions (third-party threat intel).

This module is deliberately stricter than the scan-target policy in
``app.core.ratelimit``: VirusTotal submissions are made to a *third-party
service*, so internal, private, and non-routable URLs must NEVER be submitted,
regardless of ``SCAN_ALLOW_PRIVATE_TARGETS`` (which only governs VibeShield's
own scanner).

Safety properties:
- only http/https schemes with a hostname
- no embedded usernames/passwords in the URL
- no control characters / whitespace; bounded URL length
- valid explicit ports only
- hostname structure validated; literal-IP hosts checked directly
- the hostname is resolved (best effort) and EVERY resolved IPv4/IPv6 address
  must be globally routable — loopback, private, link-local, CGNAT, reserved,
  multicast, unspecified and other non-global addresses are rejected, which
  also covers cloud metadata endpoints such as 169.254.169.254

Note: this backend never fetches the submitted target itself — it only sends
the URL *string* to VirusTotal's API — so DNS-rebinding TOCTOU on a direct
fetch does not apply. Resolution validation still guards against users
submitting internal hostnames that resolve behind the firewall.

Important distinction (VirusTotal API note): where the implementation needs an
existing URL report it uses the documented base64 (urlsafe, unpadded)
URL-ID encoding and `GET /urls/{url_id}`. No direct request is ever made to
the submitted destination server.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from app.core.config import settings
from app.core.ratelimit import resolve_host


class UrlNotAllowed(ValueError):
    """Raised when a submitted URL fails the strict VirusTotal policy."""


# Hostname structure: dot-separated labels of letters/digits/hyphens (IDN must
# be sent as punycode/style ASCII here; raw non-ASCII hosts are rejected).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)

# Control characters, whitespace, and other characters that must never appear
_RAW_FORBIDDEN = re.compile(r"[\x00-\x20\x7f-\x9f]")


def _check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Reject any address that is not unambiguously globally routable."""
    # is_global is False for loopback, private, link-local, reserved, CGNAT
    # (100.64.0.0/10), documentation ranges, multicast, and unspecified — the
    # set of ranges we must never send to a third party.
    not_global_reasons = []
    if ip.is_loopback:
        not_global_reasons.append("loopback")
    if ip.is_private:
        not_global_reasons.append("private")
    if ip.is_link_local:
        not_global_reasons.append("link-local")
    if ip.is_reserved:
        not_global_reasons.append("reserved")
    if ip.is_multicast:
        not_global_reasons.append("multicast")
    if ip.is_unspecified:
        not_global_reasons.append("unspecified")
    if not ip.is_global:
        not_global_reasons.append("not globally routable (possible internal/metadata address)")
    if not_global_reasons:
        raise UrlNotAllowed(
            "URL host resolves to a non-public address ("
            + ", ".join(not_global_reasons)
            + "); internal/cloud-metadata destinations must not be submitted"
        )


def _validate_literal_ip(host: str) -> None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return
    _check_ip(ip)


def validate_virustotal_url(raw_url: str) -> Tuple[str, str]:
    """Validate a user-supplied URL for VirusTotal submission.

    Returns ``(parsed_url, hostname)`` on success; raises :class:`UrlNotAllowed`
    with a safe, user-presentable reason otherwise. Never includes credentials
    or the full URL in error messages.
    """
    url = (raw_url or "").strip()
    if not url:
        raise UrlNotAllowed("URL is empty")
    if len(url) > settings.VIRUSTOTAL_MAX_URL_LENGTH:
        raise UrlNotAllowed(
            f"URL exceeds the maximum length of {settings.VIRUSTOTAL_MAX_URL_LENGTH} characters"
        )
    if _RAW_FORBIDDEN.search(url):
        raise UrlNotAllowed("URL contains control characters or whitespace")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UrlNotAllowed("URL must use the http:// or https:// scheme")
    if parsed.username or parsed.password:
        raise UrlNotAllowed("URLs containing embedded usernames or passwords are not allowed")
    if parsed.fragment:
        # Fragments are never sent to any server; submitting them is a leak risk.
        raise UrlNotAllowed("URL fragments (#...) are not allowed")
    host = parsed.hostname  # lower-cased; None when absent
    if not host:
        raise UrlNotAllowed("URL has no hostname")
    try:
        host = host.rstrip(".")
    except Exception:  # pragma: no cover - hostname is always str here
        raise UrlNotAllowed("URL has a malformed hostname") from None
    if not host:
        raise UrlNotAllowed("URL has no hostname")

    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise UrlNotAllowed("Local/internal hostnames must not be submitted")

    # Port (explicit) must be numeric and in range. urlparse raises ValueError
    # for out-of-range ports when accessed, so capture defensively.
    port: Optional[int]
    try:
        port = parsed.port
    except ValueError:
        raise UrlNotAllowed("URL has an invalid port") from None
    if port is not None and not (1 <= port <= 65535):
        raise UrlNotAllowed("URL has an invalid port")

    # Literal IP (v4/v6) — validate directly. NB: "example.com" style hosts are
    # handled by the DNS path below.
    if ":" in host or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        _validate_literal_ip(host)
        return parsed, host

    if not _HOSTNAME_RE.match(host):
        raise UrlNotAllowed("URL hostname is malformed")

    # Resolve and validate every returned address (A + AAAA). If resolution
    # fails the URL cannot be verified as public — be conservative and reject.
    ips = resolve_host(host)
    if not ips:
        raise UrlNotAllowed(
            "URL hostname could not be resolved; refusing to submit unverifiable destinations"
        )
    for ip in ips:
        _check_ip(ip)
    return parsed, host
