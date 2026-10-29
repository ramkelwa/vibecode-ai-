"""VirusTotal threat-intelligence endpoints (third-party data source).

These endpoints are deliberately SEPARATE from VibeShield's own scanning API:
VirusTotal results are third-party threat intelligence and are never persisted
as, presented as, or mixed with VibeShield scan findings.

Safety properties:
- every submitted URL passes the strict third-party URL guard (scheme, no
  credentials, public addresses only) before anything leaves the process
- a missing VIRUSTOTAL_API_KEY yields a clear 503 "not configured" response —
  the application keeps running without this feature
- upstream failures are mapped to consistent, safe error responses; raw
  upstream bodies/headers are never forwarded
- rate limits return HTTP 429 with ``Retry-After`` where known
- the API key is only ever used server-side inside the service module
"""

from __future__ import annotations

import asyncio
import hashlib
import re

from fastapi import APIRouter, File, HTTPException, Query, Response, UploadFile
from pydantic import BaseModel, Field, field_validator

from app.core.logging import get_logger
from app.core.url_guard import UrlNotAllowed, validate_virustotal_url
from app.services import virustotal as vt

logger = get_logger("api.virustotal")

router = APIRouter(prefix="/virustotal", tags=["virustotal"])
MAX_FILE_SIZE_BYTES = 32 * 1024 * 1024
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


class VirusTotalScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


@router.post("/scan")
async def submit_scan(payload: VirusTotalScanRequest) -> dict:
    """Submit a URL to VirusTotal for analysis (explicit user action).

    Submission is asynchronous upstream: the returned ``status`` is ``queued``
    and the client should poll ``GET /api/virustotal/analysis/{analysis_id}``.
    """
    if not vt.is_configured():
        raise HTTPException(
            status_code=503,
            detail="VirusTotal is not configured on this server (missing API key).",
        )
    # URL validation includes a blocking DNS lookup — run off the event loop.
    try:
        await asyncio.to_thread(validate_virustotal_url, payload.url)
    except UrlNotAllowed as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        # Dedup + rate limiting + submission happen inside the service.
        data = await vt.submit_url_for_analysis(payload.url)
    except vt.VirusTotalRateLimited as exc:
        return _rate_limited(exc)
    except vt.VirusTotalNotConfigured:
        raise HTTPException(status_code=503, detail="VirusTotal is not configured on this server (missing API key).")
    except vt.VirusTotalUpstreamError as exc:
        raise HTTPException(status_code=502, detail=_safe_detail(exc)) from exc
    except vt.VirusTotalBadUpstreamResponse as exc:
        raise HTTPException(status_code=502, detail=_safe_detail(exc)) from exc

    return _serialize(data)


@router.get("/analysis/{analysis_id}")
async def get_analysis(analysis_id: str) -> dict:
    """Poll the status of a previously submitted VirusTotal analysis."""
    if not vt.is_configured():
        raise HTTPException(
            status_code=503,
            detail="VirusTotal is not configured on this server (missing API key).",
        )
    try:
        data = await vt.get_analysis(analysis_id)
    except vt.VirusTotalBadUpstreamResponse as exc:
        # Covers strictly-invalid ids supplied by the client as well.
        raise HTTPException(status_code=400, detail=_safe_detail(exc)) from exc
    except vt.VirusTotalNotFoundError:
        raise HTTPException(status_code=404, detail="Analysis not found on VirusTotal.")
    except vt.VirusTotalRateLimited as exc:
        return _rate_limited(exc)
    except vt.VirusTotalUpstreamError as exc:
        raise HTTPException(status_code=502, detail=_safe_detail(exc)) from exc
    return _serialize(data)


@router.get("/report")
async def get_report(url: str = Query(min_length=1, max_length=2048)) -> dict:
    """Look up an existing VirusTotal URL report (no new submission)."""
    url = url.strip()
    if not vt.is_configured():
        raise HTTPException(
            status_code=503,
            detail="VirusTotal is not configured on this server (missing API key).",
        )
    try:
        await asyncio.to_thread(validate_virustotal_url, url)
    except UrlNotAllowed as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        data = await vt.get_url_report(url)
    except vt.VirusTotalNotFoundError:
        return _serialize(
            vt.VirustotalResult(
                status="not_found",
                url=url,
                message="VirusTotal has no existing report for this URL. Submit a new scan to request one.",
            )
        )
    except vt.VirusTotalRateLimited as exc:
        return _rate_limited(exc)
    except vt.VirusTotalUpstreamError as exc:
        raise HTTPException(status_code=502, detail=_safe_detail(exc)) from exc
    except vt.VirusTotalBadUpstreamResponse as exc:
        raise HTTPException(status_code=502, detail=_safe_detail(exc)) from exc
    return _serialize(data)


@router.get("/file-report/{sha256}")
async def get_file_report(sha256: str) -> dict:
    """Look up a public file report by SHA-256; file content is not uploaded."""
    if not _SHA256_RE.fullmatch(sha256):
        raise HTTPException(status_code=400, detail="A valid SHA-256 hash is required.")
    if not vt.is_configured():
        raise HTTPException(
            status_code=503,
            detail="VirusTotal is not configured on this server (missing API key).",
        )
    digest = sha256.lower()
    try:
        data = await vt.get_file_report(digest)
    except vt.VirusTotalNotFoundError:
        return _serialize(
            vt.VirustotalResult(
                status="not_found",
                object_type="file",
                sha256=digest,
                report_url=vt.gui_file_report_url(digest),
                message="VirusTotal has no existing report for this file. Submit it to request an analysis.",
            )
        )
    except vt.VirusTotalRateLimited as exc:
        return _rate_limited(exc)
    except vt.VirusTotalUpstreamError as exc:
        raise HTTPException(status_code=502, detail=_safe_detail(exc)) from exc
    except vt.VirusTotalBadUpstreamResponse as exc:
        raise HTTPException(status_code=502, detail=_safe_detail(exc)) from exc
    return _serialize(data)


@router.post("/files/scan")
async def submit_file_scan(file: UploadFile = File(...)) -> dict:
    """Submit a file to VirusTotal after the user explicitly confirms sharing."""
    if not vt.is_configured():
        raise HTTPException(
            status_code=503,
            detail="VirusTotal is not configured on this server (missing API key).",
        )
    filename = (file.filename or "").replace("\\", "/").rsplit("/", 1)[-1].strip()
    if (
        not filename
        or len(filename) > 255
        or any(ord(char) < 32 or ord(char) == 127 for char in filename)
    ):
        raise HTTPException(status_code=400, detail="The uploaded file needs a valid filename.")
    if file.size is not None and file.size > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="VirusTotal file submissions are limited to 32 MiB.")
    content = await file.read(MAX_FILE_SIZE_BYTES + 1)
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="VirusTotal file submissions are limited to 32 MiB.")
    digest = hashlib.sha256(content).hexdigest()
    try:
        data = await vt.submit_file_for_analysis(filename, content, digest)
    except vt.VirusTotalRateLimited as exc:
        return _rate_limited(exc)
    except vt.VirusTotalNotConfigured:
        raise HTTPException(status_code=503, detail="VirusTotal is not configured on this server (missing API key).")
    except vt.VirusTotalUpstreamError as exc:
        raise HTTPException(status_code=502, detail=_safe_detail(exc)) from exc
    except vt.VirusTotalBadUpstreamResponse as exc:
        raise HTTPException(status_code=502, detail=_safe_detail(exc)) from exc
    finally:
        await file.close()
    return _serialize(data)


def _serialize(data: vt.VirustotalResult) -> dict:
    out = data.model_dump()
    # Provide a friendly top-level message for the UI.
    out.setdefault("message", None)
    return out


def _rate_limited(exc: vt.VirusTotalRateLimited) -> Response:
    headers = {}
    if exc.retry_after:
        headers["Retry-After"] = str(int(exc.retry_after))
    return Response(
        status_code=429,
        media_type="application/json",
        headers=headers,
        content=(
            '{"detail": "VirusTotal rate limit reached. Please wait before trying again."}'
        ),
    )


def _safe_detail(exc: vt.VirusTotalUpstreamError | vt.VirusTotalBadUpstreamResponse) -> str:
    """Return a safe, non-embarassment description — never raw upstream data."""
    return str(exc)
