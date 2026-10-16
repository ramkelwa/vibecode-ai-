"""Tests for the /api/scans endpoints (real DB, real background pipeline)."""

from __future__ import annotations

import time
from typing import Any, Dict

from fastapi.testclient import TestClient


def wait_for_scan(client: TestClient, scan_id: str, timeout: float = 30.0) -> Dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = client.get(f"/api/scans/{scan_id}")
        body = resp.json()
        if body["scan"]["status"] in ("completed", "failed", "cancelled"):
            return body
        time.sleep(0.2)
    raise TimeoutError(f"scan {scan_id} did not finish in {timeout}s")


def test_create_scan_requires_authorization_confirmation(client: TestClient) -> None:
    resp = client.post("/api/scans", json={"target_url": "https://example.com", "confirm_authorized": False})
    assert resp.status_code == 422  # pydantic validation


def test_create_scan_rejects_bad_scheme(client: TestClient) -> None:
    resp = client.post("/api/scans", json={"target_url": "gopher://example.com", "confirm_authorized": True})
    assert resp.status_code == 422


def test_create_scan_unknown_module_rejected(client: TestClient) -> None:
    resp = client.post(
        "/api/scans",
        json={
            "target_url": "https://example.com",
            "confirm_authorized": True,
            "modules": ["not_a_module"],
        },
    )
    assert resp.status_code == 400
    assert "unknown modules" in resp.json()["detail"]


def test_create_scan_and_get_status_with_real_stages(client: TestClient) -> None:
    resp = client.post(
        "/api/scans",
        json={"target_url": "https://example.com", "confirm_authorized": True,
              "modules": ["url_validation"]},
    )
    assert resp.status_code == 201
    scan_id = resp.json()["scan"]["id"]
    assert resp.json()["scan"]["status"] in ("pending", "running", "completed")

    body = wait_for_scan(client, scan_id)
    assert body["scan"]["status"] == "completed"
    stages = {s["module"]: s["status"] for s in body["stages"]}
    assert stages["url_validation"] == "completed"
    # unrequested modules must be recorded as skipped, not silently dropped
    assert stages["http_headers"] == "skipped"
    # example.com over the network may or may not be reachable; findings list
    # must exist either way and never contain fabricated entries
    assert isinstance(body["findings"], list)


def test_get_unknown_scan_returns_404(client: TestClient) -> None:
    resp = client.get("/api/scans/does-not-exist")
    assert resp.status_code == 404


def test_list_scans_includes_created_scan(client: TestClient) -> None:
    resp = client.post(
        "/api/scans",
        json={"target_url": "https://example.org", "confirm_authorized": True,
              "modules": ["url_validation"]},
    )
    scan_id = resp.json()["scan"]["id"]
    listing = client.get("/api/scans").json()["scans"]
    assert any(s["id"] == scan_id for s in listing)
