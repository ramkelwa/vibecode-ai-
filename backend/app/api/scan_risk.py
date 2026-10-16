"""Phase 5 risk API: deterministic normalization summary + correlation links.

Every value served here is computed from already-stored scan findings by the
Phase 5 engine (app/scanners/phase5.py). Nothing is hardcoded on the dashboard,
nothing is re-scanned, and no LLM is involved anywhere in this path.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models import Finding, Scan
from app.scanners import phase5

router = APIRouter(prefix="/scans", tags=["phase5-risk"])


def findings_to_dicts(db: Session, scan_id: str) -> list[Dict[str, Any]]:
    """Serialize stored Finding rows into the engine's input shape."""
    rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return [
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
        for r in rows
    ]


def _get_scan_or_404(db: Session, scan_id: str) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


@router.get("/{scan_id}/risk-summary")
def get_risk_summary(scan_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Deterministic risk summary computed from the scan's stored findings."""
    scan = _get_scan_or_404(db, scan_id)
    findings = findings_to_dicts(db, scan_id)
    correlations = correlate_links(db, scan_id)
    return phase5.build_risk_summary(
        findings, scan_id=scan.id, correlations=len(correlations)
    )


@router.get("/{scan_id}/correlations")
def get_correlations(scan_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Correlation links between related findings, each with its reason."""
    scan = _get_scan_or_404(db, scan_id)
    links = correlate_links(db, scan_id)
    return {
        "scan_id": scan.id,
        "links": links,
        "count": len(links),
        "note": (
            "Links add review context only; severity, confidence and "
            "verification status are never upgraded by correlation."
        ),
    }


def correlate_links(db: Session, scan_id: str) -> list[Dict[str, Any]]:
    """Compute (deterministically) the correlation links for one scan.

    Computing live from the stored findings keeps old and new scans served by
    the same function - the same links are also persisted on the scan's
    artifacts at completion time, so the stored copy and any request-time
    computation agree by construction.
    """
    findings = findings_to_dicts(db, scan_id)
    return phase5.correlate_findings(findings)
