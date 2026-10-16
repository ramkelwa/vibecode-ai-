"""Scan management API: create scans, read status, list results.

Safety: every target is validated against the safety policy before a scan is
accepted, and scans only run passively in Phase 1 (GET requests at limited rate).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.ratelimit import TargetNotAllowed, validate_target
from app.models import Finding, Scan, ScanStage
from app.scanners.orchestrator import (
    cancel_scan,
    launch_project_scan,
    launch_scan,
)

router = APIRouter(prefix="/scans", tags=["scans"])

ALLOWED_MODULES = {
    "url_validation",
    "dns_analysis",
    "tls_analysis",
    "http_headers",
    "cookie_analysis",
    "html_analysis",
    "js_discovery",
    "js_analysis",
    "api_discovery",
    # Phase 4 project scan modules require a project_dir and
    # AUTHORIZED_PROJECT_ROOTS; they are requested via the
    # POST /api/scans/project endpoint, not via modules on a website scan.
    "dependency_audit",
    "source_analysis",
    "zap_dynamic",
}


class ScanCreate(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)
    modules: Optional[List[str]] = None
    confirm_authorized: bool = Field(description="Must be true: confirms you are authorized to test this target")

    @field_validator("target_url")
    @classmethod
    def _normalize(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        return v

    @field_validator("confirm_authorized")
    @classmethod
    def _must_confirm(cls, v: bool) -> bool:
        if not v:
            raise ValueError("you must confirm you are authorized to test this target")
        return v


class ProjectScanCreate(BaseModel):
    """Create a Phase 4 project scan over an authorized local source directory."""
    project_dir: str = Field(
        min_length=1, max_length=2048,
        description="Absolute path to an authorized project directory.",
    )
    modules: Optional[List[str]] = None
    confirm_authorized: bool = Field(
        description=(
            "Must be true: confirms you are authorized to test the target URL "
            "associated with this project (required even for static project scans)."
        ),
    )

    @field_validator("project_dir")
    @classmethod
    def _normalize_dir(cls, v: str) -> str:
        return v.strip()

    @field_validator("confirm_authorized")
    @classmethod
    def _must_confirm(cls, v: bool) -> bool:
        if not v:
            raise ValueError("you must confirm you are authorized to test this target")
        return v


class ScanOut(BaseModel):
    id: str
    target_url: str
    status: str
    modules_requested: List[str]
    error: Optional[str]
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    @classmethod
    def from_row(cls, scan: Scan) -> "ScanOut":
        return cls(
            id=scan.id,
            target_url=scan.target_url,
            status=scan.status,
            modules_requested=scan.modules_requested or [],
            error=scan.error,
            created_at=scan.created_at.isoformat(),
            started_at=scan.started_at.isoformat() if scan.started_at else None,
            finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
        )


@router.post("", status_code=201)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> Dict[str, Any]:
    # Structural validation happens first (cheap, no network).
    try:
        validate_target(payload.target_url)
    except TargetNotAllowed as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    modules = payload.modules
    if modules is not None:
        unknown = set(modules) - ALLOWED_MODULES
        if unknown:
            raise HTTPException(status_code=400, detail=f"unknown modules: {sorted(unknown)}")
        if not modules:
            raise HTTPException(status_code=400, detail="modules list cannot be empty")

    scan = Scan(
        target_url=payload.target_url,
        status="pending",
        modules_requested=modules if modules is not None else sorted(ALLOWED_MODULES),
    )
    db.add(scan)
    db.commit()

    launch_scan(scan.id, scan.target_url, scan.modules_requested)
    return {"scan": ScanOut.from_row(scan).model_dump()}


@router.get("")
def list_scans(db: Session = Depends(get_db)) -> Dict[str, Any]:
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(100).all()
    return {"scans": [ScanOut.from_row(s).model_dump() for s in scans]}


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    stages = db.query(ScanStage).filter(ScanStage.scan_id == scan_id).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return {
        "scan": ScanOut.from_row(scan).model_dump(),
        "stages": [
            {
                "module": s.module,
                "status": s.status,
                "detail": s.detail,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            }
            for s in stages
        ],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "affected_asset": f.affected_asset,
                "evidence": f.evidence,
                "source_module": f.source_module,
                "cwe": f.cwe,
                "impact": f.impact,
                "remediation": f.remediation,
                "verification_status": f.verification_status,
            }
            for f in findings
        ],
    }


@router.post("/{scan_id}/cancel")
def cancel(scan_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if scan.status not in ("pending", "running"):
        raise HTTPException(status_code=409, detail=f"scan already {scan.status}")
    cancelled = cancel_scan(scan_id)
    if cancelled:
        scan.status = "cancelled"
        db.commit()
    return {"cancelled": cancelled, "status": scan.status}


@router.post("/project", status_code=201)
def create_project_scan(payload: ProjectScanCreate, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Create a Phase 4 project scan (dependency audit / source analysis).

    This operates on an authorized local source directory, not a website target.
    PROJECT_SCAN_CREATE keeps the same authorization confirmation requirement as
    website scans because the project scanner's documentation states that the
    target URL authorization context must be confirmed even for static project
    scans - the confirm_authorized field is retained for that reason.
    """
    from app.core.config import settings
    from app.tools.pathguard import PathNotAuthorized, resolve_authorized_dir

    if not settings.AUTHORIZED_PROJECT_ROOTS.strip():
        raise HTTPException(
            status_code=400,
            detail=(
                "project scanning is not configured: set AUTHORIZED_PROJECT_ROOTS "
                "to one or more absolute directories the user is authorized to scan"
            ),
        )

    modules = payload.modules
    allowed_project_modules = {"dependency_audit", "source_analysis"}
    zap_allowed = {"zap_dynamic"}
    if modules is not None:
        unknown = set(modules) - (allowed_project_modules | zap_allowed)
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=(f"unknown project modules: {sorted(unknown)}"),
            )
        if not modules:
            raise HTTPException(status_code=400, detail="modules list cannot be empty")
    else:
        modules = sorted(allowed_project_modules)

    try:
        resolved = resolve_authorized_dir(payload.project_dir)
    except PathNotAuthorized as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan = Scan(
        target_url=payload.project_dir,
        status="pending",
        modules_requested=modules,
    )
    db.add(scan)
    db.commit()

    launch_project_scan(scan.id, str(resolved), scan.modules_requested)
    return {"scan": ScanOut.from_row(scan).model_dump()}
