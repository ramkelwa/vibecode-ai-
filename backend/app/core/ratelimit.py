"""Rate limiting, request budgeting, and target-safety guards for scanning.

These controls are the backbone of the "authorized, non-destructive, controlled"
scanning requirement: every outbound request goes through a token bucket and a
hard per-scan budget, and targets are validated against an allow policy.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from app.core.config import settings


class RequestBudgetExceeded(RuntimeError):
    """Raised when a scan exceeds its hard cap on outbound requests."""


class TargetNotAllowed(ValueError):
    """Raised when a target is disallowed by the safety policy."""


@dataclass
class TokenBucket:
    """Simple async token-bucket rate limiter (per-target)."""

    rate: float  # tokens per second
    capacity: Optional[float] = None
    _tokens: float = field(init=False)
    _last: float = field(init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    def __post_init__(self) -> None:
        self.capacity = self.capacity or max(1.0, self.rate)
        self._tokens = self.capacity
        self._last = time.monotonic()

    async def acquire(self, tokens: float = 1.0) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                await asyncio.sleep(deficit / self.rate)


class RequestBudget:
    """Hard cap on the number of outbound requests for a single scan."""

    def __init__(self, limit: Optional[int] = None) -> None:
        self.limit = limit or settings.SCAN_MAX_REQUESTS_PER_TARGET
        self.used = 0

    def consume(self, n: int = 1) -> None:
        self.used += n
        if self.used > self.limit:
            raise RequestBudgetExceeded(
                f"Scan exceeded request budget of {self.limit} outbound requests"
            )

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


def resolve_host(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a hostname to IP addresses (best-effort)."""
    ips = []
    try:
        for info in socket.getaddrinfo(hostname, None):
            raw = info[4][0]
            try:
                ips.append(ipaddress.ip_address(raw))
            except ValueError:
                continue
    except socket.gaierror:
        return []
    return ips


def is_private_target(url: str) -> bool:
    host = urlparse(url).hostname
    if not host:
        return True
    if host in ("localhost", "testserver"):
        return True
    for ip in resolve_host(host):
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    return False


def validate_target(url: str) -> str:
    """Validate and normalize a scan target URL.

    Enforces http/https scheme and, unless private targets are explicitly
    allowed (lab/local/staging use), rejects internal address ranges to prevent
    the platform from being pointed at infrastructure the tester does not own.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise TargetNotAllowed(f"Unsupported scheme '{parsed.scheme}'; only http/https are allowed")
    if not parsed.hostname:
        raise TargetNotAllowed("Target URL has no hostname")

    if not settings.SCAN_ALLOW_PRIVATE_TARGETS and is_private_target(url):
        raise TargetNotAllowed(
            "Target resolves to a private/internal address and private scanning is disabled"
        )
    return url


class ScanLimiter:
    """Bundles the rate limiter and request budget used for one scan."""

    def __init__(self, rate: Optional[float] = None, budget: Optional[int] = None) -> None:
        self.bucket = TokenBucket(rate or settings.SCAN_REQUESTS_PER_SECOND)
        self.budget = RequestBudget(budget)

    async def acquire(self) -> None:
        self.budget.consume(1)
        await self.bucket.acquire(1)
