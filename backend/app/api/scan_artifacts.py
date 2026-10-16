"""Scan artifacts API: exposes real inventories produced by Phase 3 modules.

Artifacts are persisted as JSON on the Scan row when the pipeline finishes
(single source of truth; no fabricated values when a module failed - the
artifact for a failed module is simply absent or carries its error).
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Scan

router = APIRouter(prefix="/scans", tags=["scan-artifacts"])


@router.get("/{scan_id}/artifacts")
def get_artifacts(scan_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    artifacts: Dict[str, Any] = scan.artifacts or {}
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "html": artifacts.get("html_analysis"),
        "document_url": artifacts.get("document_url"),
        "js_assets": artifacts.get("js_assets"),
        "js_analysis": artifacts.get("js_analysis"),
        "api_endpoints": artifacts.get("api_endpoints"),
        "dns": artifacts.get("dns"),
        "tls": artifacts.get("tls"),
        "http_headers": artifacts.get("http_headers"),
        "cookies": artifacts.get("cookies"),
        # Phase 4 project-scan inventories (present only when the scan ran
        # the corresponding project modules).
        "dependency_audit": artifacts.get("dependency_audit"),
        "source_analysis": artifacts.get("source_analysis"),
        "zap_dynamic": artifacts.get("zap_dynamic"),
        # Phase 5 post-processing results persisted at completion.
        "correlations": artifacts.get("correlations"),
        "risk_summary": artifacts.get("risk_summary"),
    }
