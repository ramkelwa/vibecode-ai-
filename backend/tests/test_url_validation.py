"""Tests for the URL validation module (pure, no network)."""

from __future__ import annotations

import pytest

from app.scanners import url_validation


def test_valid_https_url_produces_no_findings() -> None:
    findings = url_validation.validate_url("https://example.com/page")
    assert findings == []


def test_non_http_scheme_is_reported() -> None:
    findings = url_validation.validate_url("ftp://example.com/file")
    assert len(findings) == 1
    assert findings[0].title == "URL uses a non-HTTP(S) scheme"
    assert findings[0].verification_status == "informational"


def test_missing_hostname_is_reported() -> None:
    findings = url_validation.validate_url("https:///path-only")
    assert any(f.title == "URL has no hostname" for f in findings)


def test_finding_schema_rejects_invalid_severity() -> None:
    from app.scanners.schema import FindingData

    with pytest.raises(ValueError, match="invalid severity"):
        FindingData(
            title="x", description="", category="c", severity="banana",
            confidence="firm", affected_asset="a", source_module="m",
        )


def test_finding_id_is_deterministic() -> None:
    a = url_validation.validate_url("ftp://x")
    b = url_validation.validate_url("ftp://x")
    assert a[0].id == b[0].id
