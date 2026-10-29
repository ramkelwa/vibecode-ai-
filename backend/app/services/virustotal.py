"""VirusTotal API v3 service — third-party threat intelligence.

This service is a thin, defensive client over the official VirusTotal API v3:

- auth via the ``x-apikey`` header, read only from the backend environment
  (``VIRUSTOTAL_API_KEY``); the key is never logged or returned
- explicit connect/total timeouts on every request
- no automatic retry for URL *submissions* (POST) — an automatic retry could
  enqueue duplicate analyses and burn API quota; bounded single retry only for
  read-only GETs on transient 5xx/network errors, honoring ``Retry-After``
- upstream status categories (401/403, 404, 429, 5xx, network, malformed body)
  are mapped to safe typed exceptions — raw upstream bodies are never proxied
  to the frontend
- results are *normalized*: only documented attributes are read, optional
  statistics stay optional (missing data is never turned into a zero), and
  ``last_analysis_stats`` counts are never confused with VibeShield findings

Official endpoints used (VirusTotal API v3 documentation):
- POST /urls                  submit a URL for analysis (URL form-encoded)
- POST /files                 submit a user-confirmed file for analysis (multipart)
- GET  /analyses/{id}         retrieve a submitted analysis
- GET  /urls/{url_id}         retrieve an existing URL report
- GET  /files/{sha256}        retrieve an existing file report by SHA-256
  where url_id is the URL base64 (urlsafe, unpadded) encoded per official docs.

Assumption about account permissions: a standard VirusTotal API key can submit
URLs, read analyses, and read public URL reports. Premium-only capabilities
(private scanning, higher quotas) are NOT assumed anywhere below.

Architecture note: like ``app.scanners.context`` this client creates a fresh
``httpx.AsyncClient`` per request and closes it deterministically — cheap here
because VirusTotal calls are rare and rate-limited deliberately.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import time
from typing import Any, Dict, Optional, Tuple

import httpx
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("services.virustotal")

# Category mapping for normalizing upstream status strings.
_ANALYSIS_COMPLETE = {"completed"}
_ANALYSIS_QUEUED = {"queued"}
_ANALYSIS_STARTED = {"started"}


class VirusTotalNotConfigured(RuntimeError):
    """VIRUSTOTAL_API_KEY is not set — feature is unavailable, app stays up."""


class VirusTotalRateLimited(RuntimeError):
    """Application-side or upstream quota exhausted."""

    def __init__(self, retry_after: Optional[float] = None) -> None:
        super().__init__("VirusTotal rate limit reached")
        self.retry_after = retry_after


class VirusTotalUpstreamError(RuntimeError):
    """Upstream responded with an unexpected/non-retryable error."""

    def __init__(self, status: int, category: str) -> None:
        super().__init__(f"VirusTotal request failed ({category})")
        self.status = status
        self.category = category


class VirusTotalNotFoundError(LookupError):
    """VirusTotal has no report/analysis for the requested object."""


class VirusTotalBadUpstreamResponse(RuntimeError):
    """Malformed or structurally unexpected upstream response."""


# --- Normalized response models (typed backend contract) ---------------------


class VirustotalStats(BaseModel):
    """Engine vote counts. Every field optional — missing data stays unknown."""

    malicious: Optional[int] = Field(None, ge=0)
    suspicious: Optional[int] = Field(None, ge=0)
    harmless: Optional[int] = Field(None, ge=0)
    undetected: Optional[int] = Field(None, ge=0)
    timeout: Optional[int] = Field(None, ge=0)


class VirustotalEngineResult(BaseModel):
    engine: str
    category: str
    result: Optional[str] = None
    method: Optional[str] = None
    engine_update: Optional[str] = None


class VirustotalResult(BaseModel):
    """Normalized VirusTotal result, clearly attributed to the third party."""

    source: str = "virustotal"
    status: str  # queued | pending | completed | failed
    object_type: str = "url"
    analysis_id: Optional[str] = None
    url: Optional[str] = None  # as safe to echo back to the requesting user
    sha256: Optional[str] = None
    last_analysis_date: Optional[str] = None  # ISO 8601
    stats: Optional[VirustotalStats] = None
    engine_results: list[VirustotalEngineResult] = Field(default_factory=list)
    # Total engines that actually reported. Only computed when the primary
    # vote buckets are all present; never fabricated from partial data.
    engines_reporting: Optional[int] = None
    report_url: Optional[str] = None
    message: Optional[str] = None


def is_configured() -> bool:
    return bool(settings.VIRUSTOTAL_API_KEY.strip())


def url_instance_identifier(url: str) -> str:
    """Official URL-ID encoding: base64url of the exact URL, padding stripped."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def gui_report_url(url: str) -> str:
    """Official gui link for a URL report (id per documentation)."""
    return f"https://www.virustotal.com/gui/url/{url_instance_identifier(url)}"


# --- Application-side abuse controls ----------------------------------------

class _SubmissionGuard:
    """In-process submission rate limit + short-lived dedup cache.

    NOTE: counts are per-process (per worker). Multi-worker deployments get a
    multiplied budget; this is documented in the README as a limitation. The
    absolute protection is that submissions are always explicit user actions.
    The dedup key is a SHA-256 of the URL — sensitive URLs are never cached in
    plaintext.
    """

    def __init__(self) -> None:
        self._window: list[float] = []
        self._dedup: Dict[str, tuple[float, str]] = {}
        self._ttl = 900.0  # 15 minutes

    def check_and_record(self, url: str) -> Optional[str]:
        """Register a submission attempt; returns a prior analysis_id when the
        same URL was submitted within the TTL window (dedup hit)."""
        now = time.monotonic()
        key = hashlib.sha256(url.encode()).hexdigest()
        self._evict_dedup(now)
        hit = self._dedup.get(key)
        if hit and now - hit[0] < self._ttl:
            return hit[1]
        limit = max(1, settings.VIRUSTOTAL_MAX_SUBMITS_PER_MINUTE)
        self._window[:] = [t for t in self._window if now - t < 60.0]
        if len(self._window) >= limit:
            raise VirusTotalRateLimited()
        self._window.append(now)
        return None

    def remember(self, url: str, analysis_id: str) -> None:
        key = hashlib.sha256(url.encode()).hexdigest()
        self._evict_dedup(time.monotonic())
        self._dedup[key] = (time.monotonic(), analysis_id)

    def release_last(self) -> None:
        """Return the most recently consumed rate-limit slot (submission failed
        before VirusTotal accepted it, so the slot was not actually used)."""
        if self._window:
            self._window.pop()

    def _evict_dedup(self, now: float) -> None:
        expired = [k for k, (ts, _) in self._dedup.items() if now - ts >= self._ttl]
        for k in expired:
            self._dedup.pop(k, None)


submission_guard = _SubmissionGuard()
_submission_lock = asyncio.Lock()


# --- HTTP plumbing -----------------------------------------------------------


def _headers() -> Dict[str, str]:
    return {"x-apikey": settings.VIRUSTOTAL_API_KEY, "accept": "application/json"}


def _timeout() -> httpx.Timeout:
    total = float(settings.VIRUSTOTAL_TIMEOUT)
    return httpx.Timeout(connect=min(10.0, total), read=total, write=total, pool=min(10.0, total))


def _create_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=_timeout())


def _map_http_error(status: int, retry_after: Optional[str]) -> Exception:
    if status in (401, 403):
        return VirusTotalUpstreamError(status, "authentication/authorization rejected by VirusTotal")
    if status == 404:
        return VirusTotalNotFoundError("no such object on VirusTotal")
    if status == 429:
        seconds: Optional[float] = None
        if retry_after:
            try:
                seconds = max(0.0, float(retry_after))
            except ValueError:
                seconds = None
        return VirusTotalRateLimited(seconds)
    if 500 <= status <= 599:
        return VirusTotalUpstreamError(status, "VirusTotal service error")
    return VirusTotalUpstreamError(status, "unexpected response from VirusTotal")


async def _request(
    method: str,
    path: str,
    *,
    allow_retry: bool,
    data: Optional[Dict[str, str]] = None,
    files: Optional[Dict[str, Tuple[str, bytes, str]]] = None,
) -> httpx.Response:
    """Perform one API call with safe error mapping and bounded retry (GET only)."""
    if not is_configured():
        raise VirusTotalNotConfigured()
    url = f"{settings.VIRUSTOTAL_BASE_URL.rstrip('/')}{path}"
    attempts = 2 if allow_retry else 1
    last_error: Optional[Exception] = None
    for attempt in range(attempts):
        try:
            async with _create_client() as client:
                request_kwargs: Dict[str, Any] = {"headers": _headers()}
                if data is not None:
                    request_kwargs["data"] = data
                if files is not None:
                    request_kwargs["files"] = files
                resp = await client.request(method, url, **request_kwargs)
            if 200 <= resp.status_code < 300:
                return resp
            retry_after = resp.headers.get(
                "retry-after", resp.headers.get("Retry-After")
            )
            error = _map_http_error(resp.status_code, retry_after)
            # Retry only transient upstream faults (5xx) on read-only calls;
            # auth/4xx retries would just waste the caller's quota.
            retryable = isinstance(error, VirusTotalUpstreamError) and 500 <= error.status <= 599
            if retryable and allow_retry and attempt == 0:
                last_error = error
                await asyncio.sleep(1.0)
                continue
            raise error
        except (VirusTotalRateLimited, VirusTotalNotFoundError, VirusTotalUpstreamError):
            raise
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            # Timeout / connection failure: category only — never the URL.
            if allow_retry and attempt == 0:
                last_error = VirusTotalUpstreamError(0, "network timeout or connection failure")
                await asyncio.sleep(1.0)
                continue
            raise VirusTotalUpstreamError(0, "network timeout or connection failure") from exc
    raise last_error or VirusTotalUpstreamError(0, "request failed")


def _parse_json(resp: httpx.Response) -> Any:
    """Parse an upstream JSON body; malformed bodies get a safe category."""
    try:
        return resp.json()
    except Exception:
        raise VirusTotalBadUpstreamResponse("malformed response from VirusTotal") from None


def _require_shape(body: Any) -> Dict[str, Any]:
    if not isinstance(body, dict):
        raise VirusTotalBadUpstreamResponse("unexpected response structure from VirusTotal")
    data = body.get("data")
    if not isinstance(data, dict):
        raise VirusTotalBadUpstreamResponse("unexpected response structure from VirusTotal")
    return data


def _normalize_stats(raw: Any) -> Optional[tuple[VirustotalStats, Optional[int]]]:
    if not isinstance(raw, dict):
        return None

    def opt_int(key: str) -> Optional[int]:
        v = raw.get(key)
        return v if isinstance(v, int) and v >= 0 else None

    stats = VirustotalStats(
        malicious=opt_int("malicious"),
        suspicious=opt_int("suspicious"),
        harmless=opt_int("harmless"),
        undetected=opt_int("undetected"),
        timeout=opt_int("timeout"),
    )
    primary = (stats.malicious, stats.suspicious, stats.harmless, stats.undetected)
    total = sum(primary) if all(x is not None for x in primary) else None
    return stats, total


def _normalize_engine_results(raw: Any) -> list[VirustotalEngineResult]:
    if not isinstance(raw, dict):
        return []
    normalized: list[VirustotalEngineResult] = []
    for engine, value in sorted(raw.items(), key=lambda item: str(item[0]).casefold()):
        if not isinstance(engine, str) or not isinstance(value, dict):
            continue
        category = value.get("category")
        if not isinstance(category, str):
            continue

        def safe_text(key: str, limit: int = 300) -> Optional[str]:
            item = value.get(key)
            return item[:limit] if isinstance(item, str) else None

        normalized.append(
            VirustotalEngineResult(
                engine=engine[:100],
                category=category[:40],
                result=safe_text("result"),
                method=safe_text("method", 100),
                engine_update=safe_text("engine_update", 40),
            )
        )
        if len(normalized) >= 200:
            break
    return normalized


def _epoch_to_iso(value: Any) -> Optional[str]:
    if isinstance(value, (int, float)) and value > 0:
        from datetime import datetime, timezone

        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    return None


# --- Public service operations -----------------------------------------------


async def submit_url_for_analysis(url: str) -> VirustotalResult:
    """POST /urls — queue a *new* analysis. Synchronous policy: callers must
    have validated the URL with ``url_guard`` already; dedup + rate limit apply
    here because both depend on the exact URL string."""
    async with _submission_lock:
        existing = submission_guard.check_and_record(url)
        if existing:
            return VirustotalResult(
                status="queued",
                analysis_id=existing,
                url=url,
                message="A recent submission for this URL was reused (deduplicated); analysis may already be queued.",
            )
        try:
            resp = await _request("POST", "/urls", allow_retry=False, data={"url": url})
            body: Any = _parse_json(resp)
        except Exception:
            submission_guard.release_last()
            raise
        data = _require_shape(body)
        analysis_id = data.get("id")
        if not isinstance(analysis_id, str) or not analysis_id:
            raise VirusTotalBadUpstreamResponse("unexpected response structure from VirusTotal")
        submission_guard.remember(url, analysis_id)
        return VirustotalResult(
            status="queued",
            analysis_id=analysis_id,
            url=url,
            report_url=gui_report_url(url),
            message="URL submitted successfully for analysis.",
        )


async def get_analysis(analysis_id: str) -> VirustotalResult:
    """GET /analyses/{id} — status + stats of a previously submitted analysis."""
    # Strict id format: VirusTotal analysis ids are hex-like tokens <= 64 chars.
    stripped = analysis_id.strip()
    if not stripped or len(stripped) > 64 or not all(c.isalnum() or c in "-_" for c in stripped):
        raise VirusTotalBadUpstreamResponse("invalid analysis id format")
    try:
        resp = await _request(
            "GET", f"/analyses/{stripped}", allow_retry=True
        )
        body: Any = _parse_json(resp)
    except VirusTotalNotFoundError:
        raise
    data = _require_shape(body)
    attrs = data.get("attributes")
    if not isinstance(attrs, dict):
        raise VirusTotalBadUpstreamResponse("unexpected response structure from VirusTotal")
    raw_status = str(attrs.get("status", ""))
    if raw_status in _ANALYSIS_COMPLETE:
        status = "completed"
    elif raw_status in _ANALYSIS_QUEUED or raw_status in _ANALYSIS_STARTED:
        status = "queued"
    elif raw_status == "failed":
        status = "failed"
    elif raw_status == "":
        raise VirusTotalBadUpstreamResponse("unexpected response structure from VirusTotal")
    else:
        status = "pending"

    normalized: Optional[tuple[VirustotalStats, Optional[int]]] = None
    stats_raw = attrs.get("stats") if isinstance(attrs.get("stats"), dict) else attrs.get("last_analysis_stats")
    if status == "completed":
        normalized = _normalize_stats(stats_raw)
    engine_results = _normalize_engine_results(
        attrs.get("results") if isinstance(attrs.get("results"), dict)
        else attrs.get("last_analysis_results")
    )
    result = VirustotalResult(
        status=status,
        analysis_id=stripped,
        last_analysis_date=None,
        stats=normalized[0] if normalized and status == "completed" else None,
        engine_results=engine_results if status == "completed" else [],
        engines_reporting=normalized[1] if normalized and status == "completed" else None,
    )
    meta = data.get("meta")
    if isinstance(meta, dict):
        file_info = meta.get("file_info")
        if isinstance(file_info, dict) and isinstance(file_info.get("sha256"), str):
            try:
                digest = _validate_sha256(file_info["sha256"])
            except VirusTotalBadUpstreamResponse:
                digest = ""
            if digest:
                result.object_type = "file"
                result.sha256 = digest
                result.report_url = gui_file_report_url(digest)
        url_info = meta.get("url_info")
        if (
            result.object_type == "url"
            and isinstance(url_info, dict)
            and isinstance(url_info.get("id"), str)
        ):
            result.report_url = f"https://www.virustotal.com/gui/url/{url_info['id']}"
    return result


async def get_url_report(url: str) -> VirustotalResult:
    """GET /urls/{url_id} — read an existing public report (no new submission)."""
    url_id = url_instance_identifier(url)
    try:
        resp = await _request("GET", f"/urls/{url_id}", allow_retry=True)
        body: Any = _parse_json(resp)
    except VirusTotalNotFoundError as exc:
        raise VirusTotalNotFoundError("VirusTotal has no existing report for this URL") from exc
    data = _require_shape(body)
    attrs = data.get("attributes")
    if not isinstance(attrs, dict):
        raise VirusTotalBadUpstreamResponse("unexpected response structure from VirusTotal")
    normalized = _normalize_stats(attrs.get("last_analysis_stats"))
    engine_results = _normalize_engine_results(attrs.get("last_analysis_results"))
    result = VirustotalResult(
        status="completed",
        url=url,
        last_analysis_date=_epoch_to_iso(attrs.get("last_analysis_date")),
        stats=normalized[0] if normalized else None,
        engine_results=engine_results,
        engines_reporting=normalized[1] if normalized else None,
        report_url=gui_report_url(url),
    )
    return result


def _validate_sha256(sha256: str) -> str:
    value = sha256.strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", value):
        raise VirusTotalBadUpstreamResponse("invalid SHA-256 hash")
    return value


def gui_file_report_url(sha256: str) -> str:
    return f"https://www.virustotal.com/gui/file/{_validate_sha256(sha256)}"


async def get_file_report(sha256: str) -> VirustotalResult:
    """GET /files/{sha256} — look up an existing public file report."""
    digest = _validate_sha256(sha256)
    resp = await _request("GET", f"/files/{digest}", allow_retry=True)
    data = _require_shape(_parse_json(resp))
    attrs = data.get("attributes")
    if not isinstance(attrs, dict):
        raise VirusTotalBadUpstreamResponse("unexpected response structure from VirusTotal")
    normalized = _normalize_stats(attrs.get("last_analysis_stats"))
    return VirustotalResult(
        status="completed",
        object_type="file",
        sha256=digest,
        last_analysis_date=_epoch_to_iso(attrs.get("last_analysis_date")),
        stats=normalized[0] if normalized else None,
        engine_results=_normalize_engine_results(attrs.get("last_analysis_results")),
        engines_reporting=normalized[1] if normalized else None,
        report_url=gui_file_report_url(digest),
    )


async def submit_file_for_analysis(
    filename: str, content: bytes, sha256: str
) -> VirustotalResult:
    """POST /files — submit a file only after explicit user consent."""
    digest = _validate_sha256(sha256)
    if hashlib.sha256(content).hexdigest() != digest:
        raise VirusTotalBadUpstreamResponse("file hash does not match uploaded content")
    identifier = f"file:{digest}"
    async with _submission_lock:
        existing = submission_guard.check_and_record(identifier)
        if existing:
            return VirustotalResult(
                status="queued",
                object_type="file",
                analysis_id=existing,
                sha256=digest,
                report_url=gui_file_report_url(digest),
                message="A recent submission for this file was reused (deduplicated); analysis may already be queued.",
            )
        try:
            resp = await _request(
                "POST",
                "/files",
                allow_retry=False,
                files={"file": (filename, content, "application/octet-stream")},
            )
            body = _parse_json(resp)
        except Exception:
            submission_guard.release_last()
            raise
        data = _require_shape(body)
        analysis_id = data.get("id")
        if not isinstance(analysis_id, str) or not analysis_id:
            raise VirusTotalBadUpstreamResponse("unexpected response structure from VirusTotal")
        submission_guard.remember(identifier, analysis_id)
        return VirustotalResult(
            status="queued",
            object_type="file",
            analysis_id=analysis_id,
            sha256=digest,
            report_url=gui_file_report_url(digest),
            message="File submitted successfully for analysis.",
        )
