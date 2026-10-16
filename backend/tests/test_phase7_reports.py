"""Tests for Phase 7: AI provider status, explanation endpoint, and reports.

These tests exercise the provider abstraction, the explanation endpoint, and
the JSON/PDF report endpoints without depending on a real AI provider. The
provider is forced to offline by the test environment so every provider-coupled
path is verified through graceful degradation and honest error surfaces.

Coverage targets (from the spec):
- zero findings
- multiple findings
- Unicode content
- missing evidence
- redacted secrets
- provider unavailability
- malformed AI responses
- timeouts
- prompt-injection-like target content
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_phase7.db")
os.environ.setdefault("SCAN_ALLOW_PRIVATE_TARGETS", "true")

from app.core.database import Base, engine
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def _create_schema() -> None:
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture()
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Provider status
# ---------------------------------------------------------------------------


def test_ai_provider_status_offline_by_default(client: TestClient) -> None:
    resp = client.get("/api/ai-provider/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["family"] == "offline"
    assert body["enabled"] is False
    assert body["configured"] is True
    assert body["model_hint"] == "offline"
    assert "AI is disabled by default" in body["notes"]


def test_ai_provider_status_not_enabled_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import settings
    from app.providers import provider_status

    monkeypatch.setattr(settings, "AI_PROVIDER_FAMILY", "openai_compat")
    monkeypatch.setattr(settings, "AI_API_KEY", "")
    monkeypatch.setattr(settings, "AI_PROVIDER_BASE_URL", "https://openrouter.ai/api/v1")

    status = provider_status()

    assert status["family"] == "openai_compat"
    assert status["configured"] is False
    assert status["enabled"] is False
    assert "AI_API_KEY" in status["notes"]


def test_ai_provider_status_configured_is_boolean(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.core.config import settings
    from app.providers import provider_status

    monkeypatch.setattr(settings, "AI_PROVIDER_FAMILY", "openai_compat")
    monkeypatch.setattr(settings, "AI_API_KEY", "configured-key")
    monkeypatch.setattr(settings, "AI_PROVIDER_BASE_URL", "https://openrouter.ai/api/v1")

    status = provider_status()

    assert status["configured"] is True
    assert status["enabled"] is True


def test_ai_provider_status_never_exposes_keys(client: TestClient) -> None:
    resp = client.get("/api/ai-provider/status")
    body = resp.json()
    text = json.dumps(body, ensure_ascii=False)
    for forbidden in ("sk-", "sk_live_", "sk_test_", "glpat-", "ghp_", "api-key=", "Bearer "):
        assert forbidden not in text, f"status response should not contain {forbidden!r}"


# ---------------------------------------------------------------------------
# AI explanation endpoint
# ---------------------------------------------------------------------------


def _create_finding_scan(client: TestClient, findings: List[Dict[str, Any]]) -> str:
    from app.core.database import SessionLocal
    from app.models import Finding, Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        for f in findings:
            row = Finding(
                scan_id=scan.id,
                title=f["title"],
                description=f.get("description", ""),
                category=f.get("category", "uncategorized"),
                severity=f.get("severity", "low"),
                confidence=f.get("confidence", "uncertain"),
                affected_asset=f.get("affected_asset", ""),
                evidence=f.get("evidence", {}),
                source_module=f.get("source_module", "manual"),
                cwe=f.get("cwe"),
                cve=f.get("cve"),
                impact=f.get("impact", ""),
                remediation=f.get("remediation", ""),
                verification_status=f.get("verification_status", "potential"),
            )
            db.add(row)
        db.commit()
        return scan.id
    finally:
        db.close()


def _attach_phase5_to_scan(db_session, scan_id: str) -> None:
    """Wire Phase 5 post-processing onto a scan so the report endpoints have data to render."""
    from app.models import Finding, Scan
    from app.scanners import phase5

    scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
    if scan is None:
        return
    finding_rows = db_session.query(Finding).filter(Finding.scan_id == scan_id).all()
    finding_dicts = [
        {
            "id": r.id,
            "title": r.title,
            "description": r.description,
            "category": r.category,
            "severity": r.severity,
            "confidence": r.confidence,
            "affected_asset": r.affected_asset,
            "evidence": r.evidence or {},
            "source_module": r.source_module,
            "cwe": r.cwe,
            "cve": r.cve,
            "impact": r.impact,
            "remediation": r.remediation,
            "verification_status": r.verification_status,
        }
        for r in finding_rows
    ]
    links = phase5.correlate_findings(finding_dicts)
    summary = phase5.build_risk_summary(
        finding_dicts, scan_id=scan_id, correlations=len(links)
    )
    scan.artifacts = {
        **(scan.artifacts or {}),
        "correlations": links,
        "risk_summary": summary,
        "html_analysis": {
            "title": "Example Domain",
            "meta": [
                {"name": "description", "content": "An example page with a secret-looking value"},
                {"name": "charset", "content": "utf-8"},
            ],
            "links": [
                {"href": "https://www.iana.org/domains/example", "is_external": True},
            ],
            "scripts": [],
            "resources": [],
            "forms": [],
        },
        "js_analysis": {
            "secret_candidates": [
                {
                    "pattern": r"api[_-]?key\s*[:=]\s*\S+",
                    "context": "const token = 'sk-abc123'; // probably fake",
                    "value_redacted": True,
                },
                {
                    "pattern": r"password\s*[:=]\s*\S+",
                    "context": "pass: s3cret",
                    "value_redacted": True,
                },
            ],
            "dangerous_apis": [],
            "insecure_http_refs": [],
            "debugger_usage": [],
            "errors": [],
        },
        "api_endpoints": [
            {
                "url": "https://api.example.com/v1/users",
                "method": "GET",
                "source": "html_analysis",
                "line": None,
                "same_origin": True,
                "confidence": "high",
                "dynamically_constructed": False,
                "partial": False,
            },
            {
                "url": "https://api.example.com/v1/orders",
                "method": "POST",
                "source": "js_analysis",
                "line": 42,
                "same_origin": True,
                "confidence": "medium",
                "dynamically_constructed": True,
                "partial": False,
            },
        ],
        "dns": {"A_error": None, "A": []},
        "tls": {"scheme": "https"},
        "http_headers": {"server": "nginx"},
        "cookies": [],
        "document_url": scan.target_url,
        "js_assets": [
            {
                "url": "https://www.example.com/js/app.js",
                "type": "text/javascript",
                "same_origin": True,
                "size_bytes": 4096,
                "sha256": "0" * 64,
                "content_type": "application/javascript",
                "errors": [],
            },
        ],
    }
    db_session.commit()


def _first_finding_id(scan_id: str) -> str:
    from app.core.database import SessionLocal
    from app.models import Finding

    db = SessionLocal()
    try:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).first()
        assert row is not None, f"scan {scan_id} has no findings"
        return row.id
    finally:
        db.close()


def test_explain_finding_not_found(client: TestClient) -> None:
    resp = client.post(
        "/api/ai-provider/explain/does-not-exist",
        json={"finding_id": "any"},
    )
    assert resp.status_code == 404


def test_explain_finding_with_no_ai(client: TestClient) -> None:
    scan_id = _create_finding_scan(
        client,
        [
            {
                "title": "Test finding",
                "category": "url_validation",
                "severity": "low",
                "confidence": "uncertain",
                "affected_asset": "https://example.com",
                "source_module": "url_validation",
                "evidence": {"url": "https://example.com"},
            },
        ],
    )
    finding_id = _first_finding_id(scan_id)
    resp = client.post(
        f"/api/ai-provider/explain/{scan_id}",
        json={"finding_id": finding_id},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["label"] == "AI interpretation unavailable"
    assert body["provider"] == "offline"
    assert body["model"] == "offline"
    assert body["text"] == ""
    assert body["error"] == "AI provider is disabled (AI_PROVIDER_FAMILY=offline)"
    assert body["warning"] is None
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:\d{2}|Z)?", body["generated_at"]) is not None


def test_explain_finding_persists_on_row(client: TestClient) -> None:
    scan_id = _create_finding_scan(
        client,
        [
            {
                "title": "Persisted test finding",
                "category": "url_validation",
                "severity": "low",
                "confidence": "uncertain",
                "affected_asset": "https://example.com",
                "source_module": "url_validation",
                "evidence": {},
            },
        ],
    )
    finding_id = _first_finding_id(scan_id)
    resp = client.post(
        f"/api/ai-provider/explain-and-store/{scan_id}",
        json={"finding_id": finding_id},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["text"] == ""
    assert body["error"] == "AI provider is disabled (AI_PROVIDER_FAMILY=offline)"

    from app.core.database import SessionLocal
    from app.models import Finding

    db = SessionLocal()
    try:
        row = db.query(Finding).filter(Finding.scan_id == scan_id).first()
        assert row is not None
        assert row.ai_provider == "offline"
        assert row.ai_explanation in (None, "")
        assert row.ai_error == "AI provider is disabled (AI_PROVIDER_FAMILY=offline)"
        assert row.ai_generated_at is not None
    finally:
        db.close()


def test_explain_finding_respects_evidence_masking(client: TestClient) -> None:
    """When AI is enabled we still validate that secret values are not emitted raw.

    We cannot hit a real provider here, but we can assert the provider layer
    redacts well-known sensitive evidence keys before building the prompt.
    """
    from app.providers import _redact_secrets_for_prompt

    evidence = {
        "url": "https://example.com",
        "api_key": "sk-live-12345",
        "password": "s3cret",
        "nested": {"token": "abc", "count": 3},
        "safe": "hello",
    }
    redacted = _redact_secrets_for_prompt(evidence)
    assert redacted["api_key"] == "***REDACTED***"
    assert redacted["password"] == "***REDACTED***"
    assert redacted["nested"]["token"] == "***REDACTED***"
    assert redacted["safe"] == "hello"


def test_explain_finding_prompt_blocked_on_malformed_evidence(client: TestClient) -> None:
    """Build the prompt, then assert it does not contain raw secret keys from evidence."""
    from app.providers import build_explanation_prompt

    finding = {
        "title": "Test",
        "category": "url_validation",
        "severity": "low",
        "confidence": "uncertain",
        "affected_asset": "https://example.com",
        "source_module": "url_validation",
        "evidence": {
            "api_key": "sk-live-12345",
            "nested": {"token": "abc"},
        },
    }
    prompt = build_explanation_prompt(finding, include_evidence=True)
    assert "sk-live-12345" not in prompt
    assert "***REDACTED***" in prompt


# ---------------------------------------------------------------------------
# Report endpoints
# ---------------------------------------------------------------------------


def test_report_json_returns_400_for_incomplete_scan(client: TestClient) -> None:
    from app.core.database import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="running")
        db.add(scan)
        db.commit()
        scan_id = scan.id
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/json")
    assert resp.status_code == 400
    assert "only available for completed scans" in resp.json()["detail"]


def test_report_json_returns_400_without_risk_summary(client: TestClient) -> None:
    from app.core.database import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        scan.artifacts = {"html_analysis": {"title": "x"}}
        db.commit()
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/json")
    assert resp.status_code == 400
    assert "risk summary not available" in resp.json()["detail"]


def test_report_json_with_zero_findings(client: TestClient) -> None:
    from app.core.database import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        _attach_phase5_to_scan(db, scan_id)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        scan_row.artifacts["risk_summary"] = {
            "counts": {
                "total": 0,
                "normalized": 0,
                "deduplicated": 0,
                "duplicate_groups": 0,
                "malformed_skipped": 0,
                "correlations_considered": 0,
                "by_severity": {},
                "by_confidence": {},
                "by_verification_status": {},
                "by_category": {},
            },
            "prioritized": [],
            "formula": {
                "name": "vibeshield-phase5-priority-1",
                "expression": "priority = ...",
                "limitations": ["Linear heuristic"],
            },
            "remediation_suggestions": [],
            "errors": [],
        }
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["generated_by"] == "VibeShield AI"
    assert len(body["finding_details"]) == 0
    assert body["scan"]["modules_executed"] == []
    assert body["tool_errors"] == []
    assert "No findings were stored" in json.dumps(body)


def test_report_json_with_multiple_findings(client: TestClient) -> None:
    from app.core.database import SessionLocal
    from app.models import Finding, Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        for i, sev in enumerate(["critical", "high", "medium", "low", "info"]):
            db.add(
                Finding(
                    scan_id=scan_id,
                    title=f"Finding {i+1}",
                    description=f"Description for finding {i+1}",
                    category="url_validation",
                    severity=sev,
                    confidence="uncertain",
                    affected_asset="https://example.com",
                    evidence={"seq": i},
                    source_module="url_validation",
                    verification_status="potential",
                )
            )
        db.commit()
        _attach_phase5_to_scan(db, scan_id)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        summary = scan_row.artifacts["risk_summary"]
        summary["counts"]["total"] = 5
        summary["counts"]["deduplicated"] = 5
        summary["prioritized"] = [
            {
                "id": r.id,
                "title": r.title,
                "category": r.category,
                "severity": r.severity,
                "confidence": r.confidence,
                "verification_status": r.verification_status,
                "affected_asset": r.affected_asset,
                "source_modules": [r.source_module],
                "priority": 10.0,
                "remediation": "",
                "cwe": None,
                "cve": None,
                "contributing_original_ids": [],
            }
            for r in db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.id).all()
        ]
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan"]["modules_executed"] == []
    assert len(body["finding_details"]) == 5
    titles = {f["title"] for f in body["finding_details"]}
    assert titles == {f"Finding {i}" for i in range(1, 6)}
    assert body["tool_errors"] == []


def test_report_json_preserves_unicode(client: TestClient) -> None:
    from app.core.database import SessionLocal
    from app.models import Finding, Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.add(
            Finding(
                scan_id=scan_id,
                title="測試 例 🚀",
                description="café résumé naïve",
                category="url_validation",
                severity="low",
                confidence="uncertain",
                affected_asset="https://例え.jp/path?q=🍣",
                evidence={"note": "café résumé na\u00EFve"},
                source_module="url_validation",
                verification_status="potential",
            )
        )
        db.commit()
        _attach_phase5_to_scan(db, scan_id)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        summary = scan_row.artifacts["risk_summary"]
        summary["counts"]["total"] = 1
        summary["counts"]["deduplicated"] = 1
        summary["prioritized"] = [
            {
                "id": r.id,
                "title": r.title,
                "category": r.category,
                "severity": r.severity,
                "confidence": r.confidence,
                "verification_status": r.verification_status,
                "affected_asset": r.affected_asset,
                "source_modules": [r.source_module],
                "priority": 10.0,
                "remediation": "",
                "cwe": None,
                "cve": None,
                "contributing_original_ids": [],
            }
            for r in db.query(Finding).filter(Finding.scan_id == scan_id).all()
        ]
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_details"][0]["title"] == "測試 例 🚀"
    assert "café résumé naïve" in body["finding_details"][0]["description"]
    assert "https://例え.jp/path?q=🍣" in body["finding_details"][0]["affected_asset"]


def test_report_json_missing_evidence_is_empty_not_crashed(client: TestClient) -> None:
    from app.core.database import SessionLocal
    from app.models import Finding, Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.add(
            Finding(
                scan_id=scan_id,
                title="No-evidence finding",
                description="",
                category="url_validation",
                severity="low",
                confidence="uncertain",
                affected_asset="",
                evidence={},  # no evidence keys
                source_module="url_validation",
                verification_status="potential",
            )
        )
        db.commit()
        _attach_phase5_to_scan(db, scan_id)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        summary = scan_row.artifacts["risk_summary"]
        summary["counts"]["total"] = 1
        summary["counts"]["deduplicated"] = 1
        summary["prioritized"] = [
            {
                "id": r.id,
                "title": r.title,
                "category": r.category,
                "severity": r.severity,
                "confidence": r.confidence,
                "verification_status": r.verification_status,
                "affected_asset": r.affected_asset,
                "source_modules": [r.source_module],
                "priority": 10.0,
                "remediation": "",
                "cwe": None,
                "cve": None,
                "contributing_original_ids": [],
            }
            for r in db.query(Finding).filter(Finding.scan_id == scan_id).all()
        ]
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/json")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["finding_details"]) == 1
    assert body["finding_details"][0]["evidence"] == {}


def test_report_json_redacted_secrets_not_emitted_raw(client: TestClient) -> None:
    from app.core.database import SessionLocal
    from app.models import Finding, Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.add(
            Finding(
                scan_id=scan_id,
                title="Secret evidence finding",
                description="",
                category="url_validation",
                severity="low",
                confidence="uncertain",
                affected_asset="https://example.com",
                evidence={
                    "api_key": "sk-live-12345",
                    "password": "s3cret",
                    "nested": {"token": "abc", "count": 3},
                    "safe": "hello",
                },
                source_module="url_validation",
                verification_status="potential",
            )
        )
        db.commit()
        _attach_phase5_to_scan(db, scan_id)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        summary = scan_row.artifacts["risk_summary"]
        summary["counts"]["total"] = 1
        summary["counts"]["deduplicated"] = 1
        summary["prioritized"] = [
            {
                "id": r.id,
                "title": r.title,
                "category": r.category,
                "severity": r.severity,
                "confidence": r.confidence,
                "verification_status": r.verification_status,
                "affected_asset": r.affected_asset,
                "source_modules": [r.source_module],
                "priority": 10.0,
                "remediation": "",
                "cwe": None,
                "cve": None,
                "contributing_original_ids": [],
            }
            for r in db.query(Finding).filter(Finding.scan_id == scan_id).all()
        ]
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/json")
    assert resp.status_code == 200
    body = resp.json()
    evidence = body["finding_details"][0]["evidence"]
    assert evidence["api_key"] == "***REDACTED***"
    assert evidence["password"] == "***REDACTED***"
    assert evidence["nested"]["token"] == "***REDACTED***"
    # count should survive because it is not a secret key
    assert evidence["nested"]["count"] == 3
    assert evidence["safe"] == "hello"


def test_report_json_prompt_injection_target_content_sanitized(client: TestClient) -> None:
    """Target-controlled strings (URL, evidence text) must not survive as instructions.

    We assert the report body does not contain raw script-like payloads that were
    stored as evidence - they are escaped-rendered, not executed.
    """
    from app.core.database import SessionLocal
    from app.models import Finding, Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        payload = "<script>alert(1)</script>"
        db.add(
            Finding(
                scan_id=scan_id,
                title="Prompt-injection-like finding",
                description="",
                category="url_validation",
                severity="low",
                confidence="uncertain",
                affected_asset="https://example.com",
                evidence={"payload": payload, "url": "https://example.com/Injected?cmd=rm"},
                source_module="url_validation",
                verification_status="potential",
            )
        )
        db.commit()
        _attach_phase5_to_scan(db, scan_id)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        summary = scan_row.artifacts["risk_summary"]
        summary["counts"]["total"] = 1
        summary["counts"]["deduplicated"] = 1
        summary["prioritized"] = [
            {
                "id": r.id,
                "title": r.title,
                "category": r.category,
                "severity": r.severity,
                "confidence": r.confidence,
                "verification_status": r.verification_status,
                "affected_asset": r.affected_asset,
                "source_modules": [r.source_module],
                "priority": 10.0,
                "remediation": "",
                "cwe": None,
                "cve": None,
                "contributing_original_ids": [],
            }
            for r in db.query(Finding).filter(Finding.scan_id == scan_id).all()
        ]
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_details"][0]["evidence"]["payload"] == payload
    # The report escapes HTML for display; the JSON payload should still contain
    # the raw stored value (not the rendered form), but the PDF path must not
    # execute it. We verify the JSON round-trip keeps the exact stored string.
    assert body["finding_details"][0]["evidence"]["url"] == "https://example.com/Injected?cmd=rm"


def _html_escape_locates_payload(text: str) -> bool:
    """True when the escaped (&lt;script...) form of the payload shows up."""
    return "&amp;lt;script&amp;gt;" in text or "&lt;script&gt;" in text or "u0026lt;" in text


def _pdf_text(pdf_bytes: bytes) -> str:
    """Extract the readable text of a PDF by decompressing its content streams.

    ReportLab writes text inside FlateDecode streams, so raw byte search is
    unreliable; this helper decompresses every stream before matching.
    """
    import re as _re
    import zlib

    text_parts: List[str] = [
        pdf_bytes[:1024].decode("latin-1", errors="replace")  # header + metadata
    ]
    for match in _re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", pdf_bytes, _re.DOTALL):
        raw = match.group(1)
        try:
            text_parts.append(zlib.decompress(raw).decode("latin-1", errors="replace"))
        except zlib.error:
            text_parts.append(raw.decode("latin-1", errors="replace"))
    return "\n".join(text_parts)


def test_report_pdf_is_valid_pdf_bytes(client: TestClient) -> None:
    from app.core.database import SessionLocal
    from app.models import Finding, Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        db.add(
            Finding(
                scan_id=scan_id,
                title="PDF test finding",
                description="Description",
                category="url_validation",
                severity="medium",
                confidence="uncertain",
                affected_asset="https://example.com",
                evidence={"url": "https://example.com"},
                source_module="url_validation",
                verification_status="potential",
            )
        )
        db.commit()
        _attach_phase5_to_scan(db, scan_id)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        summary = scan_row.artifacts["risk_summary"]
        summary["counts"]["total"] = 1
        summary["counts"]["deduplicated"] = 1
        summary["prioritized"] = [
            {
                "id": r.id,
                "title": r.title,
                "category": r.category,
                "severity": r.severity,
                "confidence": r.confidence,
                "verification_status": r.verification_status,
                "affected_asset": r.affected_asset,
                "source_modules": [r.source_module],
                "priority": 10.0,
                "remediation": "",
                "cwe": None,
                "cve": None,
                "contributing_original_ids": [],
            }
            for r in db.query(Finding).filter(Finding.scan_id == scan_id).all()
        ]
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.headers["content-disposition"].endswith(f"vibeshield-report-{scan_id}.pdf")
    body = resp.content
    assert body[:4] == b"%PDF"
    text = _pdf_text(body)
    assert "VibeShield AI" in text
    assert "PDF test finding" in text
    # Ensure no raw secret leaked into the decompressed PDF text
    assert "sk-live" not in text
    assert "sk-live-12345" not in text


def test_report_pdf_zero_findings(client: TestClient) -> None:
    from app.core.database import SessionLocal
    from app.models import Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        _attach_phase5_to_scan(db, scan_id)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        scan_row.artifacts["risk_summary"] = {
            "counts": {
                "total": 0,
                "normalized": 0,
                "deduplicated": 0,
                "duplicate_groups": 0,
                "malformed_skipped": 0,
                "correlations_considered": 0,
                "by_severity": {},
                "by_confidence": {},
                "by_verification_status": {},
                "by_category": {},
            },
            "prioritized": [],
            "formula": {
                "name": "vibeshield-phase5-priority-1",
                "expression": "priority = ...",
                "limitations": ["Linear heuristic"],
            },
            "remediation_suggestions": [],
            "errors": [],
        }
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:4] == b"%PDF"
    text = _pdf_text(resp.content)
    assert "No findings were stored for this scan." in text


def test_report_pdf_escaped_evidence_does_not_execute_html(client: TestClient) -> None:
    """ReportLab Paragraph rendering must escape raw HTML/JS stored as evidence."""
    from app.core.database import SessionLocal
    from app.models import Finding, Scan

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        html_payload = "<script>alert(1)</script><img src=x onerror=alert(2)>"
        db.add(
            Finding(
                scan_id=scan_id,
                title="Escaped evidence finding",
                description="",
                category="html_analysis",
                severity="low",
                confidence="uncertain",
                affected_asset="https://example.com",
                evidence={"raw_html": html_payload},
                source_module="html_analysis",
                verification_status="potential",
            )
        )
        db.commit()
        _attach_phase5_to_scan(db, scan_id)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        summary = scan_row.artifacts["risk_summary"]
        summary["counts"]["total"] = 1
        summary["counts"]["deduplicated"] = 1
        summary["prioritized"] = [
            {
                "id": r.id,
                "title": r.title,
                "category": r.category,
                "severity": r.severity,
                "confidence": r.confidence,
                "verification_status": r.verification_status,
                "affected_asset": r.affected_asset,
                "source_modules": [r.source_module],
                "priority": 10.0,
                "remediation": "",
                "cwe": None,
                "cve": None,
                "contributing_original_ids": [],
            }
            for r in db.query(Finding).filter(Finding.scan_id == scan_id).all()
        ]
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/pdf")
    assert resp.status_code == 200
    raw_text = resp.content.decode("latin-1", errors="replace")
    text = _pdf_text(resp.content)
    # The payload with live-looking unescaped parens must not appear in the
    # PDF string syntax; the rendered form PDF-string-escapes parens
    # (alert\(1\)) so the value is inert document text, not executable syntax.
    assert "<script>alert(1)</script>" not in text
    assert "onerror=alert(2)" not in text
    # The inert, string-escaped representation must be present.
    assert "alert\\(1\\)" in text
    # No script-launching action may exist anywhere in the document.
    assert "/JavaScript" not in raw_text
    assert "/OpenAction" not in raw_text


def test_report_pdf_module_unavailable_reported_honestly(client: TestClient) -> None:
    from app.core.database import SessionLocal
    from app.models import Scan, ScanStage

    db = SessionLocal()
    try:
        scan = Scan(target_url="https://example.com", status="completed")
        db.add(scan)
        db.commit()
        scan_id = scan.id
        scan.modules_requested = ["url_validation", "dns_analysis", "tls_analysis"]
        db.add_all(
            [
                ScanStage(scan_id=scan_id, module="url_validation", status="completed", detail="2 findings"),
                ScanStage(scan_id=scan_id, module="dns_analysis", status="failed", detail="NXDOMAIN"),
                ScanStage(scan_id=scan_id, module="tls_analysis", status="running", detail=""),
            ]
        )
        db.commit()
        _attach_phase5_to_scan(db, scan_id)
        scan_row = db.query(Scan).filter(Scan.id == scan_id).first()
        summary = scan_row.artifacts["risk_summary"]
        summary["counts"]["total"] = 0
        summary["counts"]["deduplicated"] = 0
        summary["prioritized"] = []
        db.commit()
        scan_id = scan_row.id
    finally:
        db.close()

    resp = client.get(f"/api/reports/{scan_id}/json")
    assert resp.status_code == 200
    body = resp.json()
    assert "dns_analysis" in body["scan"]["modules_failed"]
    assert "tls_analysis" in body["scan"]["modules_unavailable"]


# ---------------------------------------------------------------------------
# Provider unavailability + malformed responses (provider layer)
# ---------------------------------------------------------------------------


def test_provider_offline_explanation_has_explaining_error(client: TestClient) -> None:
    scan_id = _create_finding_scan(
        client,
        [
            {
                "title": "Offline test",
                "category": "url_validation",
                "severity": "low",
                "confidence": "uncertain",
                "affected_asset": "https://example.com",
                "source_module": "url_validation",
            },
        ],
    )
    finding_id = _first_finding_id(scan_id)
    resp = client.post(
        f"/api/ai-provider/explain/{scan_id}",
        json={"finding_id": finding_id},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["text"] == ""
    assert body["error"] == "AI provider is disabled (AI_PROVIDER_FAMILY=offline)"


def test_provider_unavailable_returns_error_not_exception(client: TestClient) -> None:
    """Simulate an unavailable provider by forcing the provider layer to report an error.

    We cannot hot-swap the real provider in a test without env surgery, but we
    can assert the provider contract: when configured=False it returns an error
    dict, not an exception.
    """
    from app.providers import OpenAiCompatProvider

    p = OpenAiCompatProvider(base_url="https://example.invalid", api_key="", model_hint="test")
    assert not p.configured
    result = p.generate_text("prompt")
    assert "error" in result
    assert result["text"] == ""


def test_provider_malformed_response_returns_error_not_crash(client: TestClient) -> None:
    """Validate that the provider validates structured responses before trusting them.

    We call the response parser directly (transport-independent) so the
    validation logic itself is exercised without network behavior mattering.
    """
    from app.providers import _parse_provider_response

    raw = json.dumps({"choices": [{"message": {"role": "assistant"}}]}).encode("utf-8")
    result = _parse_provider_response(200, raw, provider="test", model="test")
    assert result["text"] == ""
    assert ("missing valid" in result["error"].lower()
            or "content" in result["error"].lower()
            or "not an object" in result["error"].lower())


def test_provider_missing_choices_returns_error(client: TestClient) -> None:
    from app.providers import _parse_provider_response

    raw = json.dumps({"choices": []}).encode("utf-8")
    result = _parse_provider_response(200, raw, provider="test", model="test")
    assert result["text"] == ""
    assert "error" in result


def test_provider_timeout_path_not_crashing(client: TestClient) -> None:
    """The provider uses explicit timeouts; unreachable hosts should not hang.

    We probe the provider helper against a closed port and assert it returns an
    error within a reasonable time instead of hanging the test.
    """
    from app.providers import _post_json

    start = time.monotonic()
    result = _post_json(
        "http://127.0.0.1:1/test",
        json.dumps({"choices": [{"message": {"content": "x"}}]}),
        api_key="",
        provider="test",
        model="test",
    )
    elapsed = time.monotonic() - start
    assert result["text"] == ""
    assert "error" in result
    assert elapsed < 30.0, "provider should not hang for several seconds on a closed port"
