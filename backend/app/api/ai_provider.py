"""AI provider status + optional evidence-grounded explanation API (Phase 7).

Safety properties:
- all provider keys come from environment variables only
- no provider key is ever returned to the browser
- AI-generated text is returned separately from raw scanner evidence
- the AI response is labeled with its provider and model so the UI can
  distinguish it from scanner output
- failures are graceful: an unavailable/malformed/timeout provider returns an
  error detail and an empty explanation, never crashes the API
- the core application stays functional when AI is disabled (provider family
  "offline" returns an empty explanation with an explanatory error)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.scan_risk import _get_scan_or_404
from app.core.database import get_db
from app.core.logging import get_logger
from app.models import Finding
from app.providers import AiProvider, build_provider, provider_status
from app.scanners import phase5

logger = get_logger("api.ai")

router = APIRouter(prefix="/ai-provider", tags=["ai-provider"])


class AiProviderStatusOut(BaseModel):
    family: str
    configured: bool
    model_hint: str
    enabled: bool
    notes: str


@router.get("/status", response_model=AiProviderStatusOut)
def ai_provider_status_endpoint() -> Dict[str, Any]:
    return provider_status()


class ExplainFindingRequest(BaseModel):
    finding_id: str = Field(min_length=1, max_length=128)
    correlation_ids: Optional[List[str]] = Field(
        default=None,
        description="Optional correlation link ids to include as review context.",
    )
    include_evidence: bool = Field(
        default=True,
        description="Whether to include stored redacted evidence in the prompt.",
    )
    include_remediation: bool = Field(
        default=True,
        description="Whether to include stored remediation text in the prompt.",
    )


class AiExplanationOut(BaseModel):
    finding_id: str
    provider: str
    model: str
    text: str
    error: Optional[str] = None
    warning: Optional[str] = None
    generated_at: str
    label: str = "AI-generated interpretation"


@router.post("/explain/{scan_id}", response_model=AiExplanationOut)
def explain_finding(
    scan_id: str,
    payload: ExplainFindingRequest,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    scan = _get_scan_or_404(db, scan_id)
    finding = db.query(Finding).filter(Finding.scan_id == scan_id, Finding.id == payload.finding_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found in this scan")

    correlation_links = []
    if payload.correlation_ids:
        from app.scanners import phase5
        all_links = phase5.correlate_findings([_finding_to_dict(f) for f in scan.findings])
        id_set = set(payload.correlation_ids)
        correlation_links = [l for l in all_links if l.get("id") in id_set]
        if len(correlation_links) != len(id_set):
            missing = id_set - {l.get("id") for l in correlation_links}
            if missing:
                logger.info("correlation ids not present in scan %s: %s", scan_id, sorted(missing))

    provider: AiProvider = build_provider()
    result = provider.explain_finding(
        _finding_to_dict(finding),
        correlation_links=correlation_links if correlation_links else None,
    )

    text = result.get("text") or ""
    if not isinstance(text, str):
        text = str(text)

    error = result.get("error")
    if error is not None and not isinstance(error, str):
        error = str(error)

    return {
        "finding_id": finding.id,
        "provider": result.get("provider") or provider.family or "offline",
        "model": result.get("model") or provider.model_hint or "offline",
        "text": text,
        "error": error,
        "warning": result.get("warning"),
        "generated_at": _now_iso(),
        "label": "AI-generated interpretation" if text else "AI interpretation unavailable",
    }


@router.post("/explain-and-store/{scan_id}", response_model=AiExplanationOut)
def explain_finding_and_store(
    scan_id: str,
    payload: ExplainFindingRequest,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Generate an AI explanation and persist it on the finding row.

    This is the optional, explicit action the UI can surface — it keeps the
    AI text attached to the finding so it survives reloads and is clearly
    attributable to a provider + model + timestamp.
    """
    scan = _get_scan_or_404(db, scan_id)
    finding = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id, Finding.id == payload.finding_id)
        .first()
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found in this scan")

    correlation_links = []
    if payload.correlation_ids:
        all_links = phase5.correlate_findings([_finding_to_dict(f) for f in scan.findings])
        id_set = set(payload.correlation_ids)
        correlation_links = [l for l in all_links if l.get("id") in id_set]

    provider: AiProvider = build_provider()
    result = provider.explain_finding(
        _finding_to_dict(finding),
        correlation_links=correlation_links or None,
    )

    text = result.get("text") or ""
    if not isinstance(text, str):
        text = str(text)

    finding.ai_explanation = text if text else None
    finding.ai_error = result.get("error")
    finding.ai_provider = result.get("provider") or provider.family or "offline"
    finding.ai_generated_at = _now_dt()
    db.commit()

    return {
        "finding_id": finding.id,
        "provider": result.get("provider") or provider.family or "offline",
        "model": result.get("model") or provider.model_hint or "offline",
        "text": text,
        "error": result.get("error"),
        "warning": result.get("warning"),
        "generated_at": finding.ai_generated_at.isoformat(),
        "label": "AI-generated interpretation" if text else "AI interpretation unavailable",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    return {
        "id": f.id,
        "title": f.title,
        "description": f.description,
        "category": f.category,
        "severity": f.severity,
        "confidence": f.confidence,
        "affected_asset": f.affected_asset,
        "evidence": f.evidence or {},
        "source_module": f.source_module,
        "cwe": f.cwe,
        "cve": f.cve,
        "impact": f.impact,
        "remediation": f.remediation,
        "verification_status": f.verification_status,
    }


def _now_dt():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_dt().isoformat()
