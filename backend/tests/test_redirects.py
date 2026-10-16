"""Redirect analysis tests using httpx MockTransport (controlled redirects)."""

from __future__ import annotations

import httpx
import pytest

from app.scanners import url_validation
from app.scanners.context import ScanContext


def transport_with_redirects(chains: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        target = str(request.url)
        if target in chains:
            return httpx.Response(
                302, headers={"Location": chains[target]}, content=b""
            )
        return httpx.Response(200, content=b"final destination")

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_cross_origin_redirect_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://start.test/redirect"
    chains = {url: "https://other.test/landing"}

    def make_fetch(monkeypatch):
        real_async_client = httpx.AsyncClient

        def client_factory(*a, **kw):
            kw.pop("transport", None)
            return real_async_client(*a, transport=transport_with_redirects(chains), **kw)

        monkeypatch.setattr("app.scanners.context.httpx.AsyncClient", client_factory)

    make_fetch(monkeypatch)
    ctx = ScanContext(target_url=url)
    findings = await url_validation.analyze_redirects(ctx)
    cross = [f for f in findings if f.title == "Redirect to a different origin"]
    assert len(cross) == 1
    assert cross[0].evidence["from"] == url
    assert cross[0].verification_status == "potential"
    assert ctx.artifacts["final_url"] == "https://other.test/landing"


@pytest.mark.asyncio
async def test_same_origin_redirect_is_not_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://start.test/a"
    chains = {url: "https://start.test/b"}

    real_async_client = httpx.AsyncClient

    def client_factory(*a, **kw):
        kw.pop("transport", None)
        return real_async_client(*a, transport=transport_with_redirects(chains), **kw)

    monkeypatch.setattr("app.scanners.context.httpx.AsyncClient", client_factory)
    ctx = ScanContext(target_url=url)
    findings = await url_validation.analyze_redirects(ctx)
    assert findings == []
    assert ctx.artifacts["final_url"] == "https://start.test/b"
