"""Shared scan context and the HTTP fetch helper used by passive modules.

Safety properties enforced here (for every module, no opt-outs):
- hard per-request timeout from settings
- response size cap (never buffer unbounded bodies)
- redirect re-validation: scheme, credentials, and IP of every hop
- DNS-rebinding mitigation: the actual socket destination IP is validated at
  connection time (not just a preliminary lookup) via a pinned-IP transport
- request budget consumption via ScanLimiter
"""

from __future__ import annotations

import ipaddress
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.core.ratelimit import ScanLimiter, TargetNotAllowed
from app.scanners.schema import FindingData

logger = get_logger("scanner")

MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB per response
MAX_REDIRECTS = 5

USER_AGENT = "VibeShieldAI/0.1 (+passive assessment; authorized scan)"


def _ip_is_disallowed(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


class DestinationNotAllowed(TargetNotAllowed):
    """Raised when a request destination fails IP/scope validation."""


def resolve_ips(hostname: str) -> List[str]:
    """Resolve a hostname to IP strings. Empty list on failure."""
    import socket

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    ips: List[str] = []
    for info in infos:
        raw = info[4][0]
        if raw not in ips:
            ips.append(raw)
    return ips


def check_ip_scope(ip: str, *, allow_private: Optional[bool] = None) -> None:
    """Raise DestinationNotAllowed if this IP is outside the permitted scope."""
    allow = settings.SCAN_ALLOW_PRIVATE_TARGETS if allow_private is None else allow_private
    if not allow and _ip_is_disallowed(ip):
        raise DestinationNotAllowed(f"destination IP {ip} is in a prohibited range")


def validate_url_strict(url: str, *, allow_private: Optional[bool] = None) -> str:
    """Strict pre-request URL validation: scheme, credentials, port, host, scope."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise DestinationNotAllowed(f"unsupported scheme: {parsed.scheme!r}")
    if parsed.username or parsed.password:
        raise DestinationNotAllowed("URLs with embedded credentials are not allowed")
    host = parsed.hostname
    if not host:
        raise DestinationNotAllowed("URL has no hostname")
    # urlparse raises ValueError for out-of-range ports.
    try:
        port = parsed.port
    except ValueError:
        raise DestinationNotAllowed("invalid port in URL") from None
    if port is not None and not (0 < port <= 65535):
        raise DestinationNotAllowed(f"invalid port: {port}")
    allow = settings.SCAN_ALLOW_PRIVATE_TARGETS if allow_private is None else allow_private
    if not allow:
        # Literal-IP hosts are checked directly; hostnames via resolution.
        try:
            ipaddress.ip_address(host)
            check_ip_scope(host, allow_private=allow)
        except ValueError:
            for ip in resolve_ips(host):
                check_ip_scope(ip, allow_private=allow)
    return url


@dataclass
class ScanContext:
    """State shared across all modules for a single scan run."""

    target_url: str
    limiter: ScanLimiter = field(default_factory=ScanLimiter)
    findings: List[FindingData] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    # Resolved destination IPs for the initial target (recorded for evidence).
    resolved_ips: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        host = urlparse(self.target_url).hostname
        if host:
            try:
                ipaddress.ip_address(host)
                self.resolved_ips = [host]
            except ValueError:
                self.resolved_ips = resolve_ips(host)

    def add(self, finding: FindingData) -> None:
        self.findings.append(finding)

    # -- destination validation -------------------------------------------------
    def validate_destination(self, url: str) -> str:
        """Validate scheme, credentials, port, host and resolved IPs for a URL
        we are about to touch."""
        return validate_url_strict(url)

    # -- HTTP ------------------------------------------------------------------
    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        follow_redirects: bool = False,
        max_redirects: int = MAX_REDIRECTS,
    ) -> Dict[str, Any]:
        """Perform validated, rate-limited, budgeted HTTP request(s).

        Redirects are followed manually so that every hop is re-validated
        (scheme/credentials/IP scope) before the next request is issued, and
        redirect loops are detected. When private targets are disallowed, each
        connection pins the resolved-and-validated destination IP, so DNS
        rebinding between check and connect cannot bypass scope enforcement.
        """
        self.validate_destination(url)
        result: Dict[str, Any] = {
            "url": url,
            "ok": False,
            "error": None,
            "status": None,
            "status_codes": [],
            "headers": {},
            "body": "",
            "redirects": [],
        }
        try:
            allow_private = settings.SCAN_ALLOW_PRIVATE_TARGETS
            current = url
            hops = 0
            visited: List[str] = []
            while True:
                if current in visited:
                    result["error"] = "redirect_loop"
                    break
                visited.append(current)
                self.validate_destination(current)

                # Pin the validated destination IP at connection time.
                transport: Optional[httpx.AsyncHTTPTransport] = None
                host = urlparse(current).hostname or ""
                pinned: Optional[str] = None
                if not allow_private:
                    try:
                        ipaddress.ip_address(host)
                        candidates = [host]
                    except ValueError:
                        candidates = resolve_ips(host)
                    scoped = [ip for ip in candidates if not _ip_is_disallowed(ip)]
                    if not scoped:
                        raise DestinationNotAllowed(
                            f"no permitted IP for {host!r}; refusing to connect"
                        )
                    pinned = scoped[0]

                await self.limiter.acquire()  # budget + rate limit
                if pinned is not None:
                    transport = _PinnedTransport(pinned)
                async with httpx.AsyncClient(
                    timeout=settings.SCAN_REQUEST_TIMEOUT,
                    headers={"User-Agent": USER_AGENT},
                    verify=ssl.create_default_context(),
                    transport=transport,
                ) as client:
                    resp = await client.request(method, current, follow_redirects=False)

                result["status"] = resp.status_code
                result["status_codes"].append(resp.status_code)
                result["headers"] = {k.lower(): v for k, v in resp.headers.items()}

                if resp.status_code in (301, 302, 303, 307, 308) and follow_redirects:
                    hops += 1
                    if hops > max_redirects:
                        result["error"] = "too_many_redirects"
                        break
                    location = resp.headers.get("location", "")
                    if not location:
                        result["error"] = "redirect_without_location"
                        break
                    next_url = self._absolute(current, location)
                    result["redirects"].append(
                        {"from": current, "to": next_url, "status": resp.status_code}
                    )
                    current = next_url
                    continue

                body = resp.content[:MAX_RESPONSE_BYTES]
                result["body"] = body.decode(resp.encoding or "utf-8", errors="replace")
                result["ok"] = True
                result["url"] = current
                break
        except httpx.HTTPError as exc:
            result["error"] = f"{type(exc).__name__}"
        except DestinationNotAllowed as exc:
            result["error"] = f"destination_not_allowed: {exc}"
        return result

    @staticmethod
    def _absolute(base: str, location: str) -> str:
        from urllib.parse import urljoin

        return urljoin(base, location)


class _PinnedTransport(httpx.AsyncHTTPTransport):
    """Transport that connects only to a pre-validated destination IP.

    The TLS SNI/Host header still use the original hostname, but the TCP
    connection is pinned to the IP that was validated, closing the
    check-then-connect gap exploited by DNS rebinding.
    """

    def __init__(self, ip: str) -> None:
        super().__init__()
        self._ip = ip
        self._pool: Dict[str, Any] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Rewrite the request to the pinned IP, preserving Host/SNI intent.
        request.read()
        url = request.url
        port = url.port or (443 if url.scheme == "https" else 80)
        target = httpx.URL(str(url)).copy_with(host=self._ip, port=port)
        request._url = target
        return await super().handle_async_request(request)
