"""Phase 2 tests: strict URL validation, scope enforcement, redirect safety,
DNS failure handling, TLS failure classification, and concurrency control."""

from __future__ import annotations

import httpx
import pytest

from app.scanners import url_validation
from app.scanners.context import (
    DestinationNotAllowed,
    ScanContext,
    check_ip_scope,
    validate_url_strict,
)

# --- Strict URL validation ---------------------------------------------------

@pytest.mark.parametrize("url,reason", [
    ("ftp://example.com", "scheme"),
    ("https://user:pass@example.com/", "credentials"),
    ("https://example.com:99999/", "port"),
    ("https:///no-host", "hostname"),
])
def test_validate_url_strict_rejects(url: str, reason: str) -> None:
    with pytest.raises(DestinationNotAllowed):
        validate_url_strict(url, allow_private=True)


def test_validate_url_strict_allows_normal_url() -> None:
    assert validate_url_strict("https://example.com/", allow_private=True) == "https://example.com/"


def test_check_ip_scope_blocks_private_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.core.config.settings.SCAN_ALLOW_PRIVATE_TARGETS", False)
    with pytest.raises(DestinationNotAllowed):
        check_ip_scope("127.0.0.1", allow_private=False)
    with pytest.raises(DestinationNotAllowed):
        check_ip_scope("169.254.169.254", allow_private=False)  # cloud metadata
    with pytest.raises(DestinationNotAllowed):
        check_ip_scope("10.1.2.3", allow_private=False)
    check_ip_scope("93.184.216.34", allow_private=False)  # public: OK


def test_embedded_credentials_reported_as_finding() -> None:
    findings = url_validation.validate_url("https://admin:secret@example.com/")
    titles = [f.title for f in findings]
    assert "URL contains embedded credentials" in titles
    f = next(f for f in findings if "credentials" in f.title)
    # value itself must not leak into evidence
    assert "secret" not in str(f.evidence)


def test_invalid_port_reported() -> None:
    findings = url_validation.validate_url("https://example.com:70000/")
    assert any("invalid port" in f.title.lower() for f in findings)


# --- Redirect safety -----------------------------------------------------------

def _transport(chains: dict[str, str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        target = str(request.url)
        if target in chains:
            return httpx.Response(302, headers={"Location": chains[target]})
        return httpx.Response(200, content=b"done")

    return httpx.MockTransport(handler)


def _patch_client(monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport) -> None:
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw.pop("transport", None)
        return real(*a, transport=transport, **kw)

    monkeypatch.setattr("app.scanners.context.httpx.AsyncClient", factory)


@pytest.mark.asyncio
async def test_redirect_loop_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    chains = {
        "https://loop.test/a": "https://loop.test/b",
        "https://loop.test/b": "https://loop.test/a",
    }
    _patch_client(monkeypatch, _transport(chains))
    ctx = ScanContext(target_url="https://loop.test/a")
    result = await ctx.fetch(ctx.target_url, follow_redirects=True)
    assert result["error"] == "redirect_loop"
    assert len(result["redirects"]) <= 2


@pytest.mark.asyncio
async def test_redirect_chain_records_status_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    chains = {"https://chain.test/x": "https://chain.test/y"}
    _patch_client(monkeypatch, _transport(chains))
    ctx = ScanContext(target_url="https://chain.test/x")
    result = await ctx.fetch(ctx.target_url, follow_redirects=True)
    assert result["ok"] is True
    assert result["status_codes"] == [302, 200]
    assert result["redirects"][0]["status"] == 302
    assert result["url"] == "https://chain.test/y"


@pytest.mark.asyncio
async def test_redirect_to_private_ip_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    chains = {"https://evil.test/start": "http://127.0.0.1:8080/admin"}
    _patch_client(monkeypatch, _transport(chains))
    monkeypatch.setattr("app.core.config.settings.SCAN_ALLOW_PRIVATE_TARGETS", False)
    # Controlled fixture: evil.test resolves to a public IP for the first hop.
    monkeypatch.setattr("app.scanners.context.resolve_ips", lambda host: ["93.184.216.34"])
    ctx = ScanContext(target_url="https://evil.test/start")
    result = await ctx.fetch(ctx.target_url, follow_redirects=True)
    assert result["error"] is not None
    assert "destination_not_allowed" in result["error"]
    # and the chain up to the block is preserved
    assert result["redirects"][0]["to"] == "http://127.0.0.1:8080/admin"


# --- DNS failures --------------------------------------------------------------

@pytest.mark.asyncio
async def test_dns_nxdomain_is_recorded_not_fabricated(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.scanners import dns_analysis

    class _NX:
        pass

    def raise_nx(name: str, rdtype: str) -> list:
        import dns.exception

        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns_analysis, "HAS_DNSPYTHON", True)
    monkeypatch.setattr(dns_analysis, "_query", raise_nx)
    ctx = ScanContext(target_url="https://nonexistent.invalid/")
    findings = await dns_analysis.analyze_dns(ctx)
    assert ctx.artifacts["dns"]["A_error"] == "NXDOMAIN"
    # NXDOMAIN must not produce a fake "no A record" confirmation
    assert all("No IPv4" not in f.title for f in findings)


# --- TLS failure classification -------------------------------------------------

@pytest.mark.asyncio
async def test_tls_connection_failure_is_not_a_cert_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.scanners import tls_analysis

    def fail(*a, **kw):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(tls_analysis, "_probe_sync", fail)
    ctx = ScanContext(target_url="https://closed.test/")
    findings = await tls_analysis.analyze_tls(ctx)
    assert findings == []  # limitation, not a vulnerability
    assert ctx.artifacts["tls"]["error_class"] == "connection_failure"


# --- Concurrency control ---------------------------------------------------------

@pytest.mark.asyncio
async def test_semaphore_limits_concurrent_scans() -> None:
    from app.scanners import orchestrator

    orchestrator._semaphores.clear()
    sem = orchestrator._get_semaphore(2)
    assert orchestrator._get_semaphore(2) is sem  # cached per key
    assert sem._value == 2
    default = orchestrator._get_semaphore()
    assert default is not sem  # default key is the configured max concurrency


@pytest.mark.asyncio
async def test_scan_id_bound_to_finding_rows() -> None:
    from app.scanners.schema import FindingData

    f = FindingData(
        title="t", description="", category="c", severity="low",
        confidence="firm", affected_asset="a", source_module="m",
    )
    assert f.scan_id is None
    f2 = f.with_scan("abc123")
    assert f2.scan_id == "abc123"
    assert f2.to_dict()["scan_id"] == "abc123"
