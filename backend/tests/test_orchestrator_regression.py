"""Regression tests for the Phase 8 orchestrator defect.

Defect: the scan pipeline executed async modules with ``asyncio.run`` while a
loop was already running in the pipeline thread. Every async module stage
therefore failed with RuntimeError in real scan runs (unit tests passed only
because they called the analyzers directly). The fix runs coroutine modules on
a fresh loop in a helper thread when a loop is already running.

These tests drive the REAL orchestrator (launch_scan path) rather than calling
analyzers directly, so a regression in stage execution is caught.
"""

from __future__ import annotations

import time
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient


def _wait_scan(client: TestClient, scan_id: str, timeout: float = 30.0) -> Dict[str, Any]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/api/scans/{scan_id}").json()
        if body["scan"]["status"] in ("completed", "failed", "cancelled"):
            return body
        time.sleep(0.2)
    raise TimeoutError(f"scan {scan_id} did not finish")


def test_async_module_stage_completes_in_real_scan_run(client: TestClient) -> None:
    """Regression: async modules (http_headers) must complete, not fail.

    The endpoint targets a closed loopback port so the fetch fails softly and
    the module records an honest result; the assertion is that the STAGE
    itself completes instead of failing with RuntimeError (the Phase 8
    orchestrator defect).
    """
    resp = client.post(
        "/api/scans",
        json={
            "target_url": "http://127.0.0.1:1/closed-port",
            "confirm_authorized": True,
            "modules": ["http_headers", "cookie_analysis", "html_analysis"],
        },
    )
    assert resp.status_code == 201
    scan_id = resp.json()["scan"]["id"]
    body = _wait_scan(client, scan_id)
    assert body["scan"]["status"] == "completed"
    stages = {s["module"]: s for s in body["stages"]}
    for module in ("http_headers", "cookie_analysis", "html_analysis"):
        assert stages[module]["status"] == "completed", (
            f"{module} stage regressed: {stages[module]['status']} "
            f"({stages[module].get('detail')})"
        )


def test_sync_module_stage_completes_in_real_scan_run(client: TestClient) -> None:
    """The sync path (url_validation) keeps working alongside the fix."""
    resp = client.post(
        "/api/scans",
        json={
            "target_url": "https://example.com",
            "confirm_authorized": True,
            "modules": ["url_validation"],
        },
    )
    assert resp.status_code == 201
    scan_id = resp.json()["scan"]["id"]
    body = _wait_scan(client, scan_id)
    stages = {s["module"]: s["status"] for s in body["stages"]}
    assert stages["url_validation"] == "completed"
