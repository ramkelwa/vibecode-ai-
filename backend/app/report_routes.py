"""Report download endpoints (Phase 7).

Two formats are provided for completed scans:
- /api/reports/{scan_id}/json — a curated JSON document
- /api/reports/{scan_id}/pdf — a ReportLab PDF rendered from the same curated data

Both are built strictly from stored scan artifacts and findings. When a section
has no source data, the report says so. Redaction of sensitive values is applied
consistently with the scanner's redaction rules. Provider keys are never included.

The report endpoints depend on stored Phase 5 results (risk_summary,
correlations) and the scan's artifact map. When those are absent (scan not
finished, or Phase 5 post-processing skipped), the endpoints return a 400 with
an honest explanation rather than fabricating data.
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.scan_risk import _get_scan_or_404
from app.core.database import get_db
from app.models import Finding, Scan
from app.report import (
    build_report_payload,
    default_limitations,
    default_methodology,
    render_json_report,
    render_pdf_report,
)

router = APIRouter()


@router.get("/{scan_id}/json")
def report_json(
    scan_id: str,
    *,
    db: Session = Depends(get_db),
) -> Response:
    scan = _get_scan_or_404(db, scan_id)
    if scan.status not in ("completed",):
        raise HTTPException(
            status_code=400,
            detail=(
                f"report is only available for completed scans; this scan is {scan.status}"
            ),
        )

    artifacts = scan.artifacts or {}
    risk_summary = artifacts.get("risk_summary")
    if not isinstance(risk_summary, dict):
        raise HTTPException(
            status_code=400,
            detail="scan risk summary not available; run a scan first or check Phase 5 post-processing",
        )
    correlations = artifacts.get("correlations")
    if not isinstance(correlations, list):
        correlations = []

    # Reconstruct curated finding details from the stored rows.
    finding_rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    finding_details = [
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

    # Heuristic: which modules failed / were unavailable, derived from stages.
    stages = scan.stages or []
    stage_by_module = {s.module: s for s in stages}
    requested = set(scan.modules_requested or [])
    executed = [m for m, s in stage_by_module.items() if s.status == "completed"]
    failed = [m for m, s in stage_by_module.items() if s.status == "failed"]
    skipped = [m for m, s in stage_by_module.items() if s.status == "skipped"]
    unavailable = _guess_unavailable(requested, executed, failed, skipped, artifacts)

    tool_errors: List[str] = []
    for s in stages:
        if s.status == "failed" and s.detail:
            tool_errors.append(f"module {s.module}: {s.detail}")
    if scan.error:
        tool_errors.append(f"scan: {scan.error}")

    payload = build_report_payload(
        scan_id=scan.id,
        target=scan.target_url,
        authorized_scope=_authorized_scope_for_scan(scan),
        scan_status=scan.status,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        modules_requested=scan.modules_requested or [],
        modules_executed=executed,
        modules_available_but_skipped=skipped,
        modules_failed=failed,
        modules_unavailable=unavailable,
        methodology=default_methodology(),
        limitations=default_limitations(),
        summary_counts=risk_summary.get("counts", {}),
        prioritized_findings=risk_summary.get("prioritized", []),
        remediation_suggestions=risk_summary.get("remediation_suggestions", []),
        correlation_links=correlations,
        risk_formula=risk_summary.get("formula", {}),
        inventory=artifacts,
        finding_details=finding_details,
        tool_errors=tool_errors,
    )

    body = render_json_report(payload)
    return Response(
        content=body,
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename=vibeshield-report-{scan.id}.json",
        },
    )


@router.get("/{scan_id}/pdf")
def report_pdf(
    scan_id: str,
    *,
    db: Session = Depends(get_db),
) -> Response:
    scan = _get_scan_or_404(db, scan_id)
    if scan.status not in ("completed",):
        raise HTTPException(
            status_code=400,
            detail=(
                f"report is only available for completed scans; this scan is {scan.status}"
            ),
        )

    artifacts = scan.artifacts or {}
    risk_summary = artifacts.get("risk_summary")
    if not isinstance(risk_summary, dict):
        raise HTTPException(
            status_code=400,
            detail="scan risk summary not available; run a scan first or check Phase 5 post-processing",
        )
    correlations = artifacts.get("correlations")
    if not isinstance(correlations, list):
        correlations = []

    finding_rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    finding_details = [
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

    stages = scan.stages or []
    stage_by_module = {s.module: s for s in stages}
    requested = set(scan.modules_requested or [])
    executed = [m for m, s in stage_by_module.items() if s.status == "completed"]
    failed = [m for m, s in stage_by_module.items() if s.status == "failed"]
    skipped = [m for m, s in stage_by_module.items() if s.status == "skipped"]
    unavailable = _guess_unavailable(requested, executed, failed, skipped, artifacts)

    tool_errors: List[str] = []
    for s in stages:
        if s.status == "failed" and s.detail:
            tool_errors.append(f"module {s.module}: {s.detail}")
    if scan.error:
        tool_errors.append(f"scan: {scan.error}")

    payload = build_report_payload(
        scan_id=scan.id,
        target=scan.target_url,
        authorized_scope=_authorized_scope_for_scan(scan),
        scan_status=scan.status,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        modules_requested=scan.modules_requested or [],
        modules_executed=executed,
        modules_available_but_skipped=skipped,
        modules_failed=failed,
        modules_unavailable=unavailable,
        methodology=default_methodology(),
        limitations=default_limitations(),
        summary_counts=risk_summary.get("counts", {}),
        prioritized_findings=risk_summary.get("prioritized", []),
        remediation_suggestions=risk_summary.get("remediation_suggestions", []),
        correlation_links=correlations,
        risk_formula=risk_summary.get("formula", {}),
        inventory=artifacts,
        finding_details=finding_details,
        tool_errors=tool_errors,
    )

    body = render_pdf_report(payload)
    return Response(
        content=body,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=vibeshield-report-{scan.id}.pdf",
        },
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _guess_unavailable(
    requested: set,
    executed: List[str],
    failed: List[str],
    skipped: List[str],
    artifacts: Dict[str, Any],
) -> List[str]:
    """Best-effort guess of which requested modules were unavailable.

    We only flag a requested module as unavailable when there is no completed
    stage for it, no failed stage for it, and no artifact for it. This is a
    heuristic; when in doubt we under-report rather than invent.
    """
    unavailable: List[str] = []
    requested_all = requested.copy()
    for m in sorted(requested_all):
        if m in executed or m in failed or m in skipped:
            continue
        if artifacts and m in artifacts and artifacts[m] is not None:
            continue
        unavailable.append(m)
    return unavailable


def _authorized_scope_for_scan(scan: Scan) -> str:
    """Reconstruct an authorized-scope note from the scan row.

    We do not store an explicit authorization note on the scan in this schema;
    the authorization check is enforced at scan creation time. When a project
    scan is used, the target_url is the authorized directory path; otherwise it
    is the target URL. We return an honest description, never an invented note.
    """
    if scan.target_url.startswith(("http://", "https://")):
        return f"target URL authorized for scanning: {scan.target_url}"
    return f"authorized project directory: {scan.target_url}"
