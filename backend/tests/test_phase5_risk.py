"""Phase 5 engine tests: normalization, dedup, correlation, risk summary.

Plus regression tests for the Phase 4 project-scan API path (the production
endpoint previously referenced an unimported launcher) and the artifacts
endpoint exposure of project/Phase 5 sections.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from app.scanners.phase5 import (
    FORMULA_NAME,
    build_risk_summary,
    correlate_findings,
    deduplicate_findings,
    finding_priority,
    normalize_all,
    normalize_asset,
    normalize_category,
    normalize_confidence,
    normalize_severity,
)

# --- helpers -----------------------------------------------------------------

def _finding(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "title": "Missing Content-Security-Policy header",
        "description": "no CSP observed",
        "category": "http_headers",
        "severity": "medium",
        "confidence": "firm",
        "affected_asset": "https://e.com/",
        "source_module": "http_headers",
        "verification_status": "potential",
        "evidence": {"observed": True},
    }
    base.update(overrides)
    return base


# --- normalization -----------------------------------------------------------


class TestSeverityAndCategoryNormalization:
    def test_synonym_labels_map_to_platform_scale(self) -> None:
        assert normalize_severity("moderate") == ("medium", "moderate")
        assert normalize_severity("informational") == ("info", "informational")
        assert normalize_severity("High") == ("high", "High")
        assert normalize_confidence("confirmed") == ("certain", "confirmed")
        assert normalize_category("headers") == ("http_headers", "headers", True)
        assert normalize_category("deps") == ("dependency_audit", "deps", True)

    def test_missing_or_unspecified_severity_marks_unknown_not_invented(self) -> None:
        assert normalize_severity(None) == ("unknown", "")
        assert normalize_severity("") == ("unknown", "")
        assert normalize_severity("unspecified") == ("unknown", "unspecified")
        assert normalize_severity("weird-label") == ("unknown", "weird-label")
        assert normalize_confidence("") == ("unknown", "")

    def test_unknown_category_preserved_with_recognition_flag(self) -> None:
        category, original, recognized = normalize_category("vendor-thing")
        assert category == "vendor-thing"
        assert original == "vendor-thing"
        assert recognized is False

    def test_asset_url_canonicalized_without_losing_path_query_context(self) -> None:
        n = normalize_asset("HTTPS://Example.COM:443/path/?signed=AbC#frag")
        assert n["asset"] == "https://example.com/path/?signed=AbC"
        assert n["original"] == "HTTPS://Example.COM:443/path/?signed=AbC#frag"
        assert n["changed"] is True
        # path/query case preserved (signed values can be case-sensitive)
        assert normalize_asset("https://h.tld/A?K=V")["asset"] == "https://h.tld/A?K=V"
        # non-default ports survive
        assert normalize_asset("https://h.tld:8443/")["asset"] == "https://h.tld:8443/"

    def test_malformed_findings_become_errors_not_crashes(self) -> None:
        normalized, errors = normalize_all([{}, "not a dict", {"title": ""}, _finding()])
        assert len(normalized) == 1
        assert len(errors) == 3
        assert all("reason" in e for e in errors)


# --- deduplication -----------------------------------------------------------


class TestDeduplication:
    def test_duplicate_from_two_modules_keeps_all_sources(self) -> None:
        norm, _ = normalize_all([
            _finding(source_module="http_headers"),
            _finding(source_module="zap_dynamic", affected_asset="HTTPS://E.COM:443"),
        ])
        dup = deduplicate_findings(norm)
        assert dup["inputs"] == 2
        assert dup["duplicate_groups"] == 1
        assert len(dup["findings"]) == 1
        merged = dup["findings"][0]
        assert set(merged["source_modules"]) == {"http_headers", "zap_dynamic"}

    def test_same_title_different_asset_not_merged(self) -> None:
        norm, _ = normalize_all([
            _finding(affected_asset="https://a.tld/"),
            _finding(affected_asset="https://b.tld/"),
        ])
        dup = deduplicate_findings(norm)
        assert dup["duplicate_groups"] == 0
        assert len(dup["findings"]) == 2

    def test_same_title_different_category_not_merged(self) -> None:
        norm, _ = normalize_all([
            _finding(category="http_headers", source_module="http_headers"),
            _finding(category="zs_headers", source_module="zs_headers"),
        ])
        dup = deduplicate_findings(norm)
        assert len(dup["findings"]) == 2

    def test_conflicting_severity_uses_most_severe_and_preserves_labels(self) -> None:
        norm, _ = normalize_all([
            _finding(severity="medium", severity_raw_out=None, source_module="http_headers", verification_status="potential"),
            _finding(severity="high", source_module="zap_dynamic", verification_status="unverified"),
        ])
        dup = deduplicate_findings(norm)
        merged = dup["findings"][0]
        assert merged["severity"] == "high"
        labels = merged["evidence"]["observed_severity_labels"]
        assert sorted(str(x) for x in labels) == ["high", "medium"]
        # Weak claim is never upgraded: merged record keeps weakest status.
        assert merged["verification_status"] == "unverified"

    def test_output_is_deterministic(self) -> None:
        findings = [_finding(i=str(i)) for i in range(5)]
        findings[2], findings[4] = findings[4], findings[2]
        norm, _ = normalize_all(findings)
        a = json.dumps(deduplicate_findings(norm))
        norm2, _ = normalize_all(list(reversed(findings)))
        b = json.dumps(deduplicate_findings(norm2))
        # same multiset in different input order -> same merged output
        assert a == b


# --- correlation -------------------------------------------------------------


def _correlation_fixture() -> List[Dict[str, Any]]:
    return [
        {
            "title": "Plain HTTP instead of HTTPS",
            "description": "",
            "category": "tls_analysis",
            "severity": "medium",
            "confidence": "certain",
            "affected_asset": "https://e.com/",
            "evidence": {"scheme": "http"},
            "source_module": "tls_analysis",
            "verification_status": "potential",
        },
        {
            "title": "Insecure http:// reference in JavaScript",
            "description": "",
            "category": "js_analysis",
            "severity": "low",
            "confidence": "uncertain",
            "affected_asset": "https://e.com/app.js",
            "evidence": {"url": "http://img.host/img.png"},
            "source_module": "js_analysis",
            "verification_status": "unverified",
        },
        {
            "title": "Candidate hardcoded secret (api_key)",
            "description": "",
            "category": "js_analysis",
            "severity": "high",
            "confidence": "uncertain",
            "affected_asset": "https://e.com/app.js",
            "evidence": {"redacted": True},
            "source_module": "js_analysis",
            "verification_status": "potential",
        },
        {
            "title": "API endpoint reference /api/v1",
            "description": "",
            "category": "api_discovery",
            "severity": "info",
            "confidence": "firm",
            "affected_asset": "https://e.com/app.js",
            "evidence": {},
            "source_module": "api_discovery",
            "verification_status": "informational",
        },
    ]


class TestCorrelation:
    def test_transport_rule_links_with_reason(self) -> None:
        links = correlate_findings(_correlation_fixture())
        rule = [l for l in links if l["relation"] == "insecure_transport_resource"]
        assert len(rule) == 1
        assert "http:// URL" in rule[0]["reason"]
        assert "same host" in rule[0]["reason"] or "same-host" in rule[0]["reason"].lower()

    def test_same_asset_secret_and_endpoint_rule(self) -> None:
        links = correlate_findings(_correlation_fixture())
        rule = [l for l in links if l["relation"] == "secret_and_endpoint_same_asset"]
        assert len(rule) == 1
        assert "same script asset" in rule[0]["reason"]
        assert "does not confirm any leak" in rule[0]["reason"]
        # secret asset and endpoint asset share the asset key
        assert rule[0]["finding_title"].startswith("Candidate hardcoded secret")

    def test_correlation_never_upgrades_evidence(self) -> None:
        fixture = _correlation_fixture()
        before = {f["title"]: (f["severity"], f["confidence"], f["verification_status"]) for f in fixture}
        correlate_findings(fixture)
        after = {f["title"]: (f["severity"], f["confidence"], f["verification_status"]) for f in fixture}
        assert before == after

    def test_correlations_deterministic(self) -> None:
        links = correlate_findings(_correlation_fixture())
        again = correlate_findings(_correlation_fixture())
        assert json.dumps(links) == json.dumps(again)


# --- risk summary ------------------------------------------------------------


class TestRiskSummary:
    def test_counts_and_formula_documented_in_summary(self) -> None:
        fixture = _correlation_fixture() + [_finding()]
        summary = build_risk_summary(fixture, scan_id="s1", correlations=1)
        assert summary["formula"]["name"] == FORMULA_NAME
        assert summary["formula"]["expression"]
        assert summary["formula"]["limitations"]
        counts = summary["counts"]
        # 4 correlation fixture entries + 1 CSP finding; none malformed
        assert counts["total"] == 5
        assert counts["malformed_skipped"] == 0
        assert counts["by_severity"]["medium"] == 2  # tls finding + CSP finding
        assert counts["by_confidence"]["uncertain"] == 2
        assert counts["deduplicated"] == counts["normalized"]
        assert len(summary["prioritized"]) <= 10

    def test_no_cvss_or_score_invented(self) -> None:
        summary = build_risk_summary(_correlation_fixture())
        # No numeric exploitability score fields appear on prioritized items;
        # severity/confidence remain scalars from the scanners.
        for f in summary["prioritized"]:
            assert not any("cvss" in k for k in f.keys())
            assert 0 <= f["priority"] <= 100

    def test_priority_ordering_severity_first(self) -> None:
        findings = [
            _finding(title="low item", severity="low"),
            _finding(title="crit item", severity="critical", confidence="certain"),
            _finding(title="high item", severity="high"),
        ]
        norm, _ = normalize_all(findings)
        summary = build_risk_summary(norm)
        titles = [f["title"] for f in summary["prioritized"]]
        assert titles.index("crit item") < titles.index("high item")
        assert titles.index("high item") < titles.index("low item")
        assert finding_priority(summary["prioritized"][0]) >= finding_priority(summary["prioritized"][-1])

    def test_unknown_severity_findings_ranked_with_unknown_marks(self) -> None:
        findings = [_finding(severity="", confidence="")]
        norm, _ = normalize_all(findings)
        dup = deduplicate_findings(norm)
        assert dup["findings"][0]["severity"] == "unknown"
        summary = build_risk_summary(norm)
        assert summary["counts"]["by_severity"].get("unknown") == 1

    def test_summary_stable_for_stored_results(self) -> None:
        fixture = _correlation_fixture()
        a = json.dumps(build_risk_summary(fixture, scan_id="s", correlations=0))
        b = json.dumps(build_risk_summary(list(reversed(fixture)), scan_id="s", correlations=0))
        assert a == b

    def test_remediation_suggestions_prioritized_and_unique(self) -> None:
        fixture = _correlation_fixture() + [
            _finding(title="x", remediation="Rotate the credential if genuine; move secrets server-side."),
        ]
        summary = build_risk_summary(fixture, scan_id="s")
        seens = summary["remediation_suggestions"]
        assert "Rotate the credential if genuine; move secrets server-side." in seens
        assert len(seens) == len(set(seens))


# --- API layer ---------------------------------------------------------------


class TestPhase5Api:
    @pytest.fixture()
    def seeded_scan_id(self) -> str:
        from app.core.database import SessionLocal
        from app.models import Finding, Scan

        db = SessionLocal()
        try:
            scan = Scan(target_url="https://seeded.tld/", status="completed", modules_requested=[])
            db.add(scan)
            db.commit()
            for d in _correlation_fixture() + [_finding()]:
                db.add(Finding(scan_id=scan.id, **{
                    k: d.get(k) for k in (
                        "title", "description", "category", "severity", "confidence",
                        "affected_asset", "source_module", "impact",
                    )
                }, evidence=d.get("evidence", {}), remediation=d.get("remediation", ""),
                   verification_status=d.get("verification_status", "potential")))
            db.commit()
            return scan.id
        finally:
            db.close()

    def test_risk_summary_endpoint(self, client, seeded_scan_id) -> None:
        resp = client.get(f"/api/scans/{seeded_scan_id}/risk-summary")
        assert resp.status_code == 200
        body = resp.json()
        assert body["scan_id"] == seeded_scan_id
        assert body["counts"]["total"] == 5
        assert body["formula"]["name"] == FORMULA_NAME
        assert any(f["priority"] >= (body["prioritized"][-1] or {}).get("priority", 0)
                   for f in body["prioritized"])

    def test_correlations_endpoint_has_reasons(self, client, seeded_scan_id) -> None:
        resp = client.get(f"/api/scans/{seeded_scan_id}/correlations")
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == len(body["links"])
        for link in body["links"]:
            assert link["reason"]
        rules = {l["relation"] for l in body["links"]}
        assert "insecure_transport_resource" in rules

    def test_unknown_scan_404(self, client) -> None:
        assert client.get("/api/scans/nope/risk-summary").status_code == 404
        assert client.get("/api/scans/nope/correlations").status_code == 404


class TestPhase4ProjectScanApi:
    def test_project_scan_created_through_endpoint(self, client) -> None:
        from types import SimpleNamespace

        from app.tools.pathguard import PathNotAuthorized  # noqa: F401  (guards import path)

        project_dir = str(Path(__file__).resolve().parent)  # a real existing dir
        launched: List[Any] = []

        def fake_launch(scan_id: str, resolved_dir: str, modules: Any) -> None:
            launched.append((scan_id, resolved_dir))

        # One mock settings object shared by app.core.config and tooling, so
        # pathguard resolves against the same authorized root.
        fake_settings = SimpleNamespace(
            AUTHORIZED_PROJECT_ROOTS=project_dir,
            authorized_project_roots=[project_dir],
        )
        with patch("app.core.config.settings", fake_settings), patch(
            "app.tools.pathguard.settings", fake_settings,
        ), patch("app.api.scans.launch_project_scan", fake_launch):
            resp = client.post(
                "/api/scans/project",
                json={"project_dir": project_dir, "confirm_authorized": True},
            )
        assert resp.status_code == 201, resp.text
        assert resp.json()["scan"]["status"] in ("pending", "running")
        assert len(launched) == 1

    def test_project_scan_requires_configuration(self, client) -> None:
        from app.core.config import settings

        with patch.object(type(settings), "AUTHORIZED_PROJECT_ROOTS", "", create=True):
            resp = client.post(
                "/api/scans/project",
                json={"project_dir": "C:/nope", "confirm_authorized": True},
            )
        assert resp.status_code == 400

    def test_artifacts_endpoint_exposes_phase4_and_phase5_sections(self, client) -> None:
        from app.core.database import SessionLocal
        from app.models import Scan

        db = SessionLocal()
        try:
            scan = Scan(
                target_url="C:/proj", status="completed", modules_requested=[],
                artifacts={
                    "dependency_audit": {"root": "C:/proj", "manifests": [], "tool_runs": []},
                    "source_analysis": {"errors": []},
                    "correlations": [{"id": "l1", "relation": "r", "finding": "a", "related_to": "b",
                                      "finding_title": "a", "related_title": "b", "reason": "why"}],
                },
            )
            db.add(scan)
            db.commit()
            scan_id = scan.id
        finally:
            db.close()
        resp = client.get(f"/api/scans/{scan_id}/artifacts")
        assert resp.status_code == 200
        body = resp.json()
        assert body["dependency_audit"]["root"] == "C:/proj"
        assert body["source_analysis"] == {"errors": []}
        assert body["correlations"][0]["reason"] == "why"
