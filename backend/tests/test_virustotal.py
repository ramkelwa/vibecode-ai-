"""VirusTotal integration tests — fully mocked at the HTTP boundary.

No live VirusTotal API calls are ever made; the httpx.AsyncClient.request
method is monkeypatched so tests run offline and deterministically
(pytest-asyncio auto mode handles async test functions).
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional

import httpx
import pytest

from app.core import url_guard
from app.core.config import settings
from app.core.url_guard import UrlNotAllowed, validate_virustotal_url
from app.services import virustotal as vt

FAKE_KEY = "test-virustotal-key-9999"


# --- Fake httpx transport ----------------------------------------------------

class FakeResponse:
    def __init__(self, status_code: int, body: Any = None, headers: Optional[Dict[str, str]] = None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}

    def json(self) -> Any:
        if isinstance(self._body, Exception):
            raise self._body
        if isinstance(self._body, (bytes, str)):
            import json as jsonlib

            return jsonlib.loads(self._body)  # raises on malformed JSON path
        return self._body


class FakeHttp:
    """Records calls and returns scripted responses."""

    def __init__(self) -> None:
        self.calls: list[Dict[str, Any]] = []
        self.script: list[Any] = []

    def queue(self, *responses: Any) -> None:
        self.script.extend(responses)

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(
            {"method": method, "url": url, "headers": kwargs.get("headers"), "data": kwargs.get("data")}
        )
        if not self.script:
            raise AssertionError("unexpected extra HTTP call in test")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = self

        class FakeClient:
            async def __aenter__(self) -> "FakeClient":
                return self

            async def __aexit__(self, *args: Any) -> None:
                return None

            async def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
                return fake.request(method, url, **kwargs)

        monkeypatch.setattr(vt, "_create_client", lambda: FakeClient())


@pytest.fixture()
def fake_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", FAKE_KEY)


@pytest.fixture(autouse=True)
def clean_guard():
    vt.submission_guard._window.clear()
    vt.submission_guard._dedup.clear()
    yield
    vt.submission_guard._window.clear()
    vt.submission_guard._dedup.clear()


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


def _mock_dns(monkeypatch: pytest.MonkeyPatch, ip: str = "93.184.216.34") -> None:
    monkeypatch.setattr(url_guard, "resolve_host", lambda host: [ipaddress.ip_address(ip)])


def _submission_body(analysis_id: str = "abc123") -> Dict[str, Any]:
    return {"data": {"id": analysis_id, "type": "analysis", "attributes": {"status": "queued"}}}


# --- URL validation ----------------------------------------------------------


def test_valid_http_and_https_urls() -> None:
    assert validate_virustotal_url("http://example.com/path")[0].scheme == "http"
    parsed, host = validate_virustotal_url("https://example.com")
    assert host == "example.com"


def test_unsupported_scheme_rejected() -> None:
    with pytest.raises(UrlNotAllowed):
        validate_virustotal_url("ftp://example.com/file")
    with pytest.raises(UrlNotAllowed):
        validate_virustotal_url("javascript:alert(1)")


def test_malformed_and_missing_hostname_rejected() -> None:
    with pytest.raises(UrlNotAllowed):
        validate_virustotal_url("https:///no-host")
    with pytest.raises(UrlNotAllowed):
        validate_virustotal_url("https://bad_host.example.com")
    with pytest.raises(UrlNotAllowed):
        validate_virustotal_url("not a url at all")


def test_embedded_credentials_rejected() -> None:
    with pytest.raises(UrlNotAllowed):
        validate_virustotal_url("https://user:pass@example.com")


def test_control_characters_and_fragments_rejected() -> None:
    with pytest.raises(UrlNotAllowed):
        validate_virustotal_url("https://example.com/\x01")
    with pytest.raises(UrlNotAllowed):
        validate_virustotal_url("https://example.com/x#frag")


def test_invalid_port_rejected() -> None:
    with pytest.raises(UrlNotAllowed):
        validate_virustotal_url("https://example.com:9999999/")


def test_loopback_private_metadata_literals_rejected() -> None:
    urls = [
        "http://127.0.0.1/",
        "http://10.1.2.3/",
        "http://172.16.0.5/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/",
        "http://192.0.2.10/",
        "http://198.51.100.5/",
        "http://224.0.0.1/",
        "http://[::1]/",
        "http://[fd00::1]/",
        "http://[fe80::1]/",
        "http://localhost/",
        "http://myserver.local/",
    ]
    for url in urls:
        with pytest.raises(UrlNotAllowed):
            validate_virustotal_url(url)


def test_dns_resolution_failure_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_guard, "resolve_host", lambda host: [])
    with pytest.raises(UrlNotAllowed, match="could not be resolved"):
        validate_virustotal_url("https://unresolvable.invalid/")


def test_dns_resolution_guard_hostname_resolving_private_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_guard, "resolve_host", lambda host: [ipaddress.ip_address("10.9.9.9")])
    with pytest.raises(UrlNotAllowed):
        validate_virustotal_url("https://example.com/")


def test_upper_length_limit_rejected() -> None:
    with pytest.raises(UrlNotAllowed):
        validate_virustotal_url("https://example.com/" + "a" * 3000)


# --- Service-level behavior (mocked HTTP) ------------------------------------


async def test_submit_success_uses_api_key_header(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(200, _submission_body("hexid123")))
    fake.install(monkeypatch)

    result = await vt.submit_url_for_analysis("https://example.com/")
    assert result.status == "queued"
    assert result.analysis_id == "hexid123"
    sent = fake.calls[0]
    assert sent["headers"]["x-apikey"] == FAKE_KEY
    assert sent["method"] == "POST"
    assert sent["data"]["url"] == "https://example.com/"


async def test_missing_api_key_raises_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "")
    with pytest.raises(vt.VirusTotalNotConfigured):
        await vt.submit_url_for_analysis("https://example.com/")


@pytest.mark.parametrize("status", [401, 403])
async def test_auth_rejection_mapped(monkeypatch: pytest.MonkeyPatch, fake_key, status: int) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(status, {"error": {"message": "denied"}}))
    fake.install(monkeypatch)
    with pytest.raises(vt.VirusTotalUpstreamError):
        await vt.get_analysis("abc")


async def test_analysis_404_mapped(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(404, {}))
    fake.install(monkeypatch)
    with pytest.raises(vt.VirusTotalNotFoundError):
        await vt.get_analysis("gone")


async def test_analysis_429_respects_retry_after(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(429, {}, headers={"Retry-After": "17"}))
    fake.install(monkeypatch)
    with pytest.raises(vt.VirusTotalRateLimited) as excinfo:
        await vt.get_analysis("abc")
    assert excinfo.value.retry_after == 17.0


async def test_analysis_5xx_single_bounded_retry(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(500), FakeResponse(500))
    fake.install(monkeypatch)
    with pytest.raises(vt.VirusTotalUpstreamError):
        await vt.get_analysis("abc")
    assert len(fake.calls) == 2  # exactly one retry for read-only calls


async def test_submission_5xx_is_never_retried(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(500))
    fake.install(monkeypatch)
    with pytest.raises(vt.VirusTotalUpstreamError):
        await vt.submit_url_for_analysis("https://a.example/")
    assert len(fake.calls) == 1  # no auto-retry: avoids duplicate submissions


async def test_network_timeout_mapped(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(httpx.ConnectTimeout("boom"), httpx.ConnectTimeout("boom"))
    fake.install(monkeypatch)
    with pytest.raises(vt.VirusTotalUpstreamError):
        await vt.get_analysis("abc")


async def test_malformed_upstream_json_mapped(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(200, "not-json{"))
    fake.install(monkeypatch)
    with pytest.raises(vt.VirusTotalBadUpstreamResponse):
        await vt.get_analysis("abc")


async def test_unexpected_structure_mapped(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(200, {"unexpected": "shape"}))
    fake.install(monkeypatch)
    with pytest.raises(vt.VirusTotalBadUpstreamResponse):
        await vt.get_analysis("abc")


async def test_completed_analysis_statistics_normalized(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(
        FakeResponse(
            200,
            {
                "data": {
                    "id": "hexid123",
                    "type": "analysis",
                    "attributes": {
                        "status": "completed",
                        "stats": {
                            "harmless": 80,
                            "malicious": 2,
                            "suspicious": 1,
                            "undetected": 60,
                            "timeout": 0,
                        },
                    },
                    "meta": {"url_info": {"id": "b64urlid"}},
                }
            },
        )
    )
    fake.install(monkeypatch)
    result = await vt.get_analysis("hexid123")
    assert result.status == "completed"
    assert result.stats.malicious == 2
    assert result.engines_reporting == 143  # 80+2+1+60, only when all buckets present
    assert result.report_url == "https://www.virustotal.com/gui/url/b64urlid"


async def test_partial_stats_not_fabricated(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(
        FakeResponse(
            200,
            {
                "data": {
                    "id": "hex",
                    "type": "analysis",
                    "attributes": {
                        "status": "completed",
                        "stats": {"malicious": 1},  # missing buckets stay unknown
                    },
                }
            },
        )
    )
    fake.install(monkeypatch)
    result = await vt.get_analysis("hex")
    assert result.stats.malicious == 1
    assert result.stats.harmless is None
    assert result.engines_reporting is None


async def test_report_success(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(
        FakeResponse(
            200,
            {
                "data": {
                    "type": "url",
                    "id": "-url-id-",
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 90,
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 70,
                            "timeout": 1,
                        },
                        "last_analysis_date": 1700000000,
                    },
                }
            },
        )
    )
    fake.install(monkeypatch)
    result = await vt.get_url_report("https://example.com/")
    assert result.status == "completed"
    assert result.last_analysis_date is not None
    assert result.stats.malicious == 0
    assert result.engines_reporting == 160  # sum of primary buckets only (timeout excluded)
    assert fake.calls[0]["url"].endswith("/urls/" + vt.url_instance_identifier("https://example.com/"))


async def test_report_404_is_not_found(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(404, {}))
    fake.install(monkeypatch)
    with pytest.raises(vt.VirusTotalNotFoundError):
        await vt.get_url_report("https://example.com/")


async def test_dedup_reuses_recent_submission(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(200, _submission_body("first-id")))
    fake.install(monkeypatch)
    r1 = await vt.submit_url_for_analysis("https://example.com/")
    r2 = await vt.submit_url_for_analysis("https://example.com/")
    assert r1.analysis_id == "first-id"
    assert r2.analysis_id == "first-id"  # deduplicated, no second HTTP call
    assert len(fake.calls) == 1


async def test_app_side_rate_limit(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    monkeypatch.setattr(settings, "VIRUSTOTAL_MAX_SUBMITS_PER_MINUTE", 1)
    fake = FakeHttp()
    fake.queue(FakeResponse(200, _submission_body("id1")))
    fake.install(monkeypatch)
    await vt.submit_url_for_analysis("https://a.example/")
    with pytest.raises(vt.VirusTotalRateLimited):
        await vt.submit_url_for_analysis("https://b.example/")


async def test_failed_submission_releases_rate_slot(monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(500), FakeResponse(200, _submission_body("id2")))
    fake.install(monkeypatch)
    with pytest.raises(vt.VirusTotalUpstreamError):
        await vt.submit_url_for_analysis("https://a.example/")
    r = await vt.submit_url_for_analysis("https://b.example/")
    assert r.analysis_id == "id2"


# --- API route behavior ------------------------------------------------------


def test_route_scan_unconfigured_returns_503(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "")
    resp = client.post("/api/virustotal/scan", json={"url": "https://example.com/"})
    assert resp.status_code == 503
    assert "not configured" in resp.json()["detail"].lower()


def test_route_scan_success_and_key_never_exposed(
    client, monkeypatch: pytest.MonkeyPatch, fake_key
) -> None:
    """Route-level integration: the real route handler invokes the real
    service, which is stubbed at the isolated ``app.services.virustotal.httpx.AsyncClient``
    path (same isolation pattern the rest of the suite uses).
    """
    _mock_dns(monkeypatch)
    sent: list[Dict[str, Any]] = []

    async def request(self_client, method, url, **kwargs):
        sent.append({"headers": kwargs.get("headers"), "url": url})
        return FakeResponse(200, _submission_body("hexid123"))

    monkeypatch.setattr(
        "app.services.virustotal.httpx.AsyncClient.request", request
    )
    resp = client.post("/api/virustotal/scan", json={"url": "https://example.com/"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "queued"
    assert resp.json()["analysis_id"] == "hexid123"
    # The API key never reaches any HTTP response body.
    assert FAKE_KEY not in resp.text
    # ...and the outbound request did carry it, server-side only.
    assert sent and sent[0]["headers"]["x-apikey"] == FAKE_KEY


def test_route_scan_rejects_internal_url(client, monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    resp = client.post("/api/virustotal/scan", json={"url": "http://intranet.corp.local/admin"})
    assert resp.status_code == 400
    assert "internal" in resp.json()["detail"].lower()


def test_route_analysis_status_success(client, monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(
        FakeResponse(
            200,
            {"data": {"id": "hexid123", "type": "analysis", "attributes": {"status": "queued"}}},
        )
    )
    fake.install(monkeypatch)
    resp = client.get("/api/virustotal/analysis/hexid123")
    assert resp.status_code == 200
    assert resp.json()["status"] == "queued"
    assert FAKE_KEY not in resp.text


def test_route_analysis_invalid_id_400(client, fake_key) -> None:
    resp = client.get("/api/virustotal/analysis/" + "x" * 100)
    assert resp.status_code == 400


def test_route_analysis_404(client, monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(404, {}))
    fake.install(monkeypatch)
    resp = client.get("/api/virustotal/analysis/missing-id")
    assert resp.status_code == 404


def test_route_rate_limit_returns_429_with_retry_after(client, monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    fake = FakeHttp()
    fake.queue(FakeResponse(429, {}, headers={"Retry-After": "42"}))
    fake.install(monkeypatch)
    resp = client.get("/api/virustotal/analysis/abc")
    assert resp.status_code == 429
    assert resp.headers.get("retry-after") == "42"


def test_route_report_success_and_not_found(client, monkeypatch: pytest.MonkeyPatch, fake_key) -> None:
    _mock_dns(monkeypatch)
    fake = FakeHttp()
    fake.queue(
        FakeResponse(
            200,
            {
                "data": {
                    "type": "url",
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 90,
                            "malicious": 0,
                            "suspicious": 0,
                            "undetected": 70,
                            "timeout": 1,
                        },
                        "last_analysis_date": 1700000000,
                    },
                }
            },
        ),
        FakeResponse(404, {}),
    )
    fake.install(monkeypatch)
    ok = client.get("/api/virustotal/report", params={"url": "https://example.com/"})
    assert ok.status_code == 200
    assert ok.json()["stats"]["malicious"] == 0
    assert FAKE_KEY not in ok.text
    assert vt.url_instance_identifier("https://example.com/") in ok.json()["report_url"]
    missing = client.get("/api/virustotal/report", params={"url": "https://example.org/"})
    assert missing.status_code == 200
    assert missing.json()["status"] == "not_found"


def test_url_id_encoding_matches_official_spec() -> None:
    assert vt.url_instance_identifier("https://www.virustotal.com/") == (
        "aHR0cHM6Ly93d3cudmlydXN0b3RhbC5jb20v"
    )
