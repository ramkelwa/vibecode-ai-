"""Tests for http_headers and cookie_analysis modules using a controlled
local server (Starlette TestClient-style transport inside httpx)."""

from __future__ import annotations

from typing import Dict, Tuple

import httpx
import pytest

from app.scanners.context import ScanContext


def make_context(url: str) -> ScanContext:
    return ScanContext(target_url=url)


class _StubTransport(httpx.AsyncBaseTransport):
    """Controlled test server: returns canned responses for specific URLs."""

    def __init__(self, routes: Dict[str, Tuple[int, Dict[str, str], bytes]]) -> None:
        self.routes = routes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        key = str(request.url)
        if key in self.routes:
            status, headers, body = self.routes[key]
            return httpx.Response(status, headers=headers, content=body)
        return httpx.Response(404, content=b"not found")


def patch_fetch(monkeypatch: pytest.MonkeyPatch, routes: Dict[str, Tuple[int, Dict[str, str], bytes]]) -> None:
    """Make ctx.fetch use the stub transport instead of the network."""

    async def fake_fetch(self, url, *, method="GET", follow_redirects=False, max_redirects=5):
        self.validate_destination(url)
        result = {
            "url": url, "ok": False, "error": None, "status": None,
            "headers": {}, "body": "", "redirects": [],
        }
        if url in routes:
            status, headers, body = routes[url]
            result.update(
                ok=True, status=status,
                headers={k.lower(): v for k, v in headers.items()},
                body=body.decode("utf-8", errors="replace"),
            )
        else:
            result["error"] = "connection_error"
        return result

    monkeypatch.setattr(ScanContext, "fetch", fake_fetch)


SECURE_RESPONSE = (200, {
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=63072000",
    "Permissions-Policy": "camera=(), geolocation=()",
}, b"<html>ok</html>")


@pytest.mark.asyncio
async def test_secure_headers_produce_no_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://example.test/"
    patch_fetch(monkeypatch, {url: SECURE_RESPONSE})
    from app.scanners import http_headers

    ctx = make_context(url)
    findings = await http_headers.analyze_headers(ctx)
    assert findings == []


@pytest.mark.asyncio
async def test_missing_permissions_policy_is_an_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://example.test/"
    patch_fetch(monkeypatch, {url: (200, {}, b"hi")})
    from app.scanners import http_headers

    ctx = make_context(url)
    findings = await http_headers.analyze_headers(ctx)
    pp = [f for f in findings if f.title == "Missing Permissions-Policy header"]
    assert len(pp) == 1
    assert pp[0].severity == "info"
    assert pp[0].verification_status == "informational"


@pytest.mark.asyncio
async def test_missing_headers_are_reported_individually(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://example.test/"
    patch_fetch(monkeypatch, {url: (200, {"Server": "nginx/1.24.0"}, b"hi")})
    from app.scanners import http_headers

    ctx = make_context(url)
    findings = await http_headers.analyze_headers(ctx)
    titles = {f.title for f in findings}
    assert "Missing Content-Security-Policy" in titles
    assert "Missing X-Content-Type-Options header" in titles
    assert "Missing Referrer-Policy header" in titles
    assert "Missing Strict-Transport-Security (HSTS)" in titles
    assert "Missing Permissions-Policy header" in titles
    # evidence must reference the real observed header set
    csp = next(f for f in findings if f.title == "Missing Content-Security-Policy")
    assert csp.evidence == {"header": "content-security-policy", "observed": None}
    assert all(f.source_module == "http_headers" for f in findings)


@pytest.mark.asyncio
async def test_fetch_failure_is_not_a_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://unreachable.test/"
    patch_fetch(monkeypatch, {})  # no routes -> connection error
    from app.scanners import http_headers

    ctx = make_context(url)
    findings = await http_headers.analyze_headers(ctx)
    assert findings == []
    assert ctx.artifacts["http_headers"]["error"] == "connection_error"


# ---------------------------------------------------------------------------
# Cookie analysis
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_insecure_session_cookie_is_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://example.test/login"
    patch_fetch(monkeypatch, {url: (200, {
        "Set-Cookie": "PHPSESSID=REDACTED-VALUE; Path=/",
    }, b"ok")})
    from app.scanners import cookie_analysis

    ctx = make_context(url)
    findings = await cookie_analysis.analyze_cookies(ctx)
    titles = [f.title for f in findings]
    assert any("lacks the Secure attribute" in t for t in titles)
    assert any("lacks HttpOnly" in t for t in titles)
    assert any("no SameSite attribute" in t for t in titles)
    # cookie values must never appear in evidence
    for f in findings:
        assert "REDACTED-VALUE" not in str(f.evidence)


@pytest.mark.asyncio
async def test_well_formed_session_cookie_produces_no_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://example.test/login"
    patch_fetch(monkeypatch, {url: (200, {
        "Set-Cookie": "sessionid=REDACTED; Path=/; Secure; HttpOnly; SameSite=Lax",
    }, b"ok")})
    from app.scanners import cookie_analysis

    ctx = make_context(url)
    findings = await cookie_analysis.analyze_cookies(ctx)
    assert findings == []
