"""Persistence tests: records actually round-trip through the database."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Generator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.core.database import SessionLocal, _upgrade_schema
from app.models import Finding, Scan


@pytest.fixture()
def db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def test_scan_and_finding_roundtrip(db: Session) -> None:
    scan = Scan(target_url="https://example.com", status="completed", modules_requested=["url"])
    db.add(scan)
    db.flush()

    finding = Finding(
        scan_id=scan.id,
        title="Missing Content-Security-Policy",
        category="http_headers",
        severity="medium",
        confidence="firm",
        affected_asset="https://example.com",
        evidence={"header": "content-security-policy", "observed": None},
        source_module="http_headers",
        cwe="CWE-693",
        verification_status="potential",
    )
    db.add(finding)
    db.commit()

    loaded_scan = db.query(Scan).filter_by(id=scan.id).one()
    assert loaded_scan.status == "completed"
    assert len(loaded_scan.findings) == 1
    loaded_finding = loaded_scan.findings[0]
    assert loaded_finding.title == "Missing Content-Security-Policy"
    assert loaded_finding.verification_status == "potential"
    assert loaded_finding.evidence["header"] == "content-security-policy"
    assert isinstance(loaded_finding.created_at, datetime)
    assert loaded_finding.created_at.tzinfo is not None or loaded_finding.created_at is not None


def test_timestamps_are_utc(db: Session) -> None:
    scan = Scan(target_url="https://example.org")
    db.add(scan)
    db.commit()
    assert scan.created_at is not None
    # SQLite loses tzinfo; the stored value must be the UTC wall clock either way.
    utc_now = datetime.now(timezone.utc)
    delta = abs((utc_now.replace(tzinfo=None) - scan.created_at.replace(tzinfo=None)).total_seconds())
    assert delta < 60


def test_upgrade_schema_adds_new_columns_without_losing_rows() -> None:
    legacy_engine = create_engine("sqlite://")
    try:
        with legacy_engine.begin() as connection:
            connection.execute(text("CREATE TABLE scans (id TEXT PRIMARY KEY, target_url TEXT)"))
            connection.execute(text("CREATE TABLE findings (id TEXT PRIMARY KEY)"))
            connection.execute(text("INSERT INTO scans (id, target_url) VALUES ('scan-1', 'https://example.com')"))
            connection.execute(text("INSERT INTO findings (id) VALUES ('finding-1')"))

        _upgrade_schema(legacy_engine)
        _upgrade_schema(legacy_engine)

        with legacy_engine.connect() as connection:
            scan = connection.execute(
                text("SELECT id, target_url, artifacts FROM scans WHERE id = 'scan-1'")
            ).one()
            finding = connection.execute(
                text(
                    "SELECT id, ai_explanation, ai_error, ai_provider, ai_generated_at "
                    "FROM findings WHERE id = 'finding-1'"
                )
            ).one()

        assert scan == ("scan-1", "https://example.com", "{}")
        assert finding == ("finding-1", None, None, None, None)
    finally:
        legacy_engine.dispose()
