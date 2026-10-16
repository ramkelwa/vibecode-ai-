"""Tests for the /api/health endpoint.

Covers: healthy database, database-unavailable behavior (API must stay up and
truthfully report DB-dependent features as unavailable).
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi.testclient import TestClient

from app.api import health as health_module


def test_health_ok_with_database(client: TestClient) -> None:
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body: Dict[str, Any] = resp.json()
    assert body["status"] == "ok"
    assert body["database"]["state"] == "ok"
    assert body["features"]["scans"] is True


def test_health_reports_db_unavailable_without_crashing(client: TestClient) -> None:
    # Simulate a real database outage by patching the probe to raise.
    original = health_module.engine

    class _BrokenEngine:
        def connect(self) -> Any:
            raise RuntimeError("connection refused")

    health_module.engine = _BrokenEngine()  # type: ignore[assignment]
    try:
        resp = client.get("/api/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"  # API itself is up
        assert body["database"]["state"] == "unavailable"
        assert body["features"]["scans"] is False
        assert body["features"]["findings"] is False
    finally:
        health_module.engine = original
