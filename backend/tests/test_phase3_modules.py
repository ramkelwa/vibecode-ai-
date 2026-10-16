"""Phase 3 tests: HTML analysis, JS discovery/static analysis, API endpoint
discovery. All inputs are controlled fixtures - no live sites."""

from __future__ import annotations

from typing import Dict, Tuple

import pytest

from app.scanners import api_discovery, html_analysis, js_analysis
from app.scanners.context import ScanContext
from app.scanners.js_discovery import discover_assets

DOC_URL = "https://target.test/page"


# --- A: HTML analysis --------------------------------------------------------

MALFORMED_HTML = "<html><head><title>Broken</title><form action='/login'><input type='password'></form>"


def test_malformed_html_parses_without_exception() -> None:
    parsed = html_analysis.parse_html(DOC_URL, MALFORMED_HTML)
    assert parsed["title"] == "Broken"
    assert len(parsed["forms"]) == 1
    assert parsed["has_password_field"] is True
    assert parsed["parse_error"] is None


def test_relative_urls_resolved_against_document() -> None:
    html = "<a href='/about'>About</a><script src='/static/app.js'></script><img src='img/logo.png'>"
    parsed = html_analysis.parse_html(DOC_URL, html)
    assert parsed["links"][0]["href"] == "https://target.test/about"
    assert parsed["scripts"][0]["src"] == "https://target.test/static/app.js"
    assert parsed["resources"][0]["url"] == "https://target.test/img/logo.png"


def test_absolute_urls_kept() -> None:
    html = "<a href='https://other.test/x'>x</a>"
    parsed = html_analysis.parse_html(DOC_URL, html)
    assert parsed["links"][0]["href"] == "https://other.test/x"


def test_external_form_action_is_observation() -> None:
    html = "<form action='https://payment.example.com/checkout' method='post'></form>"
    parsed = html_analysis.parse_html(DOC_URL, html)
    assert parsed["forms"][0]["action_external"] is True


def test_form_metadata_recorded() -> None:
    html = "<form method='POST' action='/submit'><input type='text' name='a'><input type='password'></form>"
    parsed = html_analysis.parse_html(DOC_URL, html)
    form = parsed["forms"][0]
    assert form["method"] == "POST"
    assert form["action"] == "https://target.test/submit"
    assert form["input_types"] == ["password", "text"]
    assert form["has_password_field"] is True


def test_no_csrf_claim_from_missing_token() -> None:
    parsed = html_analysis.parse_html(DOC_URL, "<form action='/login'></form>")
    # The module must not assert CSRF absence - check no such finding text exists.
    assert "csrf" not in str(parsed).lower()


# --- B: JS discovery -----------------------------------------------------------

def _patch_fetch_chain(monkeypatch: pytest.MonkeyPatch, pages: Dict[str, Tuple[int, Dict[str, str], str]]) -> None:
    async def fake_fetch(self, url, *, method="GET", follow_redirects=False, max_redirects=5):
        if url in pages:
            status, headers, body = pages[url]
            return {"url": url, "ok": True, "error": None, "status": status,
                    "headers": {k.lower(): v for k, v in headers.items()},
                    "body": body, "redirects": []}
        return {"url": url, "ok": False, "error": "connection_error", "status": None,
                "headers": {}, "body": "", "redirects": []}

    monkeypatch.setattr(ScanContext, "fetch", fake_fetch)


@pytest.mark.asyncio
async def test_asset_discovery_dedupes_and_digests(monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib

    html = ("<script src='/a.js'></script><script src='/a.js'></script>"
            "<script>var inline = 1;</script>")
    js = "console.log('hello')"
    _patch_fetch_chain(monkeypatch, {
        DOC_URL: (200, {}, html),
        "https://target.test/a.js": (200, {"Content-Type": "application/javascript"}, js),
    })
    ctx = ScanContext(target_url=DOC_URL)
    inv = await discover_assets(ctx)
    assert len(inv["external"]) == 1  # deduped
    assert inv["external"][0]["sha256"] == hashlib.sha256(js.encode()).hexdigest()
    assert inv["external"][0]["same_origin"] is True
    assert len(inv["inline"]) == 1
    assert inv["source_maps_fetched"] is False


@pytest.mark.asyncio
async def test_unreachable_asset_recorded_not_fabricated(monkeypatch: pytest.MonkeyPatch) -> None:
    html = "<script src='/missing.js'></script>"
    _patch_fetch_chain(monkeypatch, {DOC_URL: (200, {}, html)})
    ctx = ScanContext(target_url=DOC_URL)
    inv = await discover_assets(ctx)
    assert inv["external"][0].get("error") == "connection_error"
    assert "sha256" not in inv["external"][0]
    assert inv["errors"]["https://target.test/missing.js"] == "connection_error"


# --- C: JS static analysis -------------------------------------------------------

def test_real_secret_detected_and_redacted() -> None:
    src = "var config = { apiKey: 'AKIAIOSFODNN7EXAMPLE123x' };"
    findings = js_analysis.analyze_js_source(src, "https://t.test/x.js")
    secret = next(f for f in findings if "secret" in f.title.lower())
    assert secret.severity == "high"
    ev = str(secret.evidence)
    assert "AKIAIOSFODNN7EXAMPLE123x" not in ev  # value redacted
    assert secret.evidence["redacted"] is True


def test_placeholder_keys_are_false_positive_filtered() -> None:
    src = "const config = { api_key: 'YOUR_API_KEY_HERE' };"
    findings = js_analysis.analyze_js_source(src, "https://t.test/x.js")
    assert not any("secret" in f.title.lower() for f in findings)


def test_dangerous_apis_are_contextual_observations() -> None:
    src = "eval(userInput); document.write('<b>x</b>'); el.innerHTML = data;"
    findings = js_analysis.analyze_js_source(src, "https://t.test/x.js")
    dangerous = [f for f in findings if "Dangerous API usage" in f.title]
    assert len(dangerous) >= 3
    assert all(f.severity == "info" for f in dangerous)
    assert all(f.verification_status == "potential" for f in dangerous)
    assert all("contextual" in f.description.lower() for f in dangerous)


def test_jwt_detected_as_candidate() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    src = f"var token = '{jwt}';"
    findings = js_analysis.analyze_js_source(src, "https://t.test/x.js")
    assert any("secret" in f.title.lower() for f in findings)


def test_insecure_http_url_flagged_namespaces_skipped() -> None:
    src = "fetch('http://api.target.test/data'); var NS = 'http://www.w3.org/2000/svg';"
    findings = js_analysis.findings if hasattr(js_analysis, "findings") else js_analysis.analyze_js_source(src, "https://t.test/x.js")
    http_f = [f for f in findings if "http://" in str(f.evidence)]
    assert len(http_f) == 1
    assert "api.target.test" in str(http_f[0].evidence)


# --- D: API endpoint discovery -----------------------------------------------------

def test_fetch_get_and_post_discovered() -> None:
    src = "fetch('/api/users'); fetch('/api/items', {method: 'POST'});"
    eps = api_discovery.discover_endpoints_in_source(src, "https://t.test/a.js", "https://t.test")
    by_url = {e["url"]: e for e in eps}
    assert by_url["/api/users"]["method"] == "UNKNOWN"
    assert by_url["/api/users"]["confidence"] == "uncertain"
    assert by_url["/api/items"]["method"] == "POST"
    assert by_url["/api/items"]["confidence"] == "firm"


def test_xhr_and_axios_discovered() -> None:
    src = ("xhr.open('GET', '/api/status');"
           "axios.post('/api/login', data);"
           "axios({method: 'PUT', url: '/api/update'});")
    eps = api_discovery.discover_endpoints_in_source(src, "https://t.test/a.js", "https://t.test")
    m = {(e["url"], e["method"], e["source"]) for e in eps}
    assert ("/api/status", "GET", "xmlhttprequest") in m
    assert ("/api/login", "POST", "axios") in m
    assert ("/api/update", "PUT", "axios") in m


def test_websocket_and_base_url_discovered() -> None:
    src = "new WebSocket('wss://ws.target.test/socket'); const API_BASE_URL = 'https://api.target.test';"
    eps = api_discovery.discover_endpoints_in_source(src, "https://t.test/a.js", "https://t.test")
    ws = next(e for e in eps if e["source"] == "websocket")
    assert ws["method"] == "WS"
    assert ws["same_origin"] is False
    base = next(e for e in eps if e["source"] == "base_url_constant")
    assert base["confidence"] == "uncertain"


def test_dynamic_construction_flagged() -> None:
    src = "fetch('/api/users/' + userId);"
    eps = api_discovery.discover_endpoints_in_source(src, "https://t.test/a.js", "https://t.test")
    assert eps[0]["dynamically_constructed"] is True


def test_endpoints_deduplicated() -> None:
    src = "fetch('/api/users'); fetch('/api/users'); axios.get('/api/users');"
    eps = api_discovery.discover_endpoints_in_source(src, "https://t.test/a.js", "https://t.test")
    urls = [e["url"] for e in eps]
    assert len(urls) == len(set(urls))
    assert len(urls) == 1  # same URL+method(UNKNOWN) dedupes


def test_cross_origin_classified() -> None:
    src = "fetch('https://cdn.other.test/api/data');"
    eps = api_discovery.discover_endpoints_in_source(src, "https://t.test/a.js", "https://t.test")
    assert eps[0]["same_origin"] is False
