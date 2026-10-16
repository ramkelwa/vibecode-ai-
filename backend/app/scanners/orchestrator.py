"""Scan orchestrator: runs the passive modules for one scan.

Guarantees:
- each module runs independently; a module crash fails only that module's stage
- stage records (running/completed/failed/skipped) are persisted as ScanStage rows
- findings are only ever produced from module output - nothing is invented here
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.models import Finding, Scan, ScanStage
from app.scanners.context import ScanContext
from app.scanners.schema import FindingData

logger = get_logger("orchestrator")

# Global concurrency control: at most SCAN_MAX_CONCURRENCY scans run at once.
# Fair, cross-loop-safe (created lazily per running loop in run_scan).
_semaphores: Dict[int, asyncio.Semaphore] = {}


def _get_semaphore(value: Optional[int] = None) -> asyncio.Semaphore:
    key = value or settings.SCAN_MAX_CONCURRENCY
    sem = _semaphores.get(key)
    if sem is None:
        sem = asyncio.Semaphore(key)
        _semaphores[key] = sem
    return sem

# Ordered pipeline of passive website scanning modules (Phases 1-3).
# js_discovery runs before js_analysis/api_discovery so their inventories exist.
MODULE_PIPELINE = [
    ("url_validation", "app.scanners.url_validation"),
    ("dns_analysis", "app.scanners.dns_analysis"),
    ("tls_analysis", "app.scanners.tls_analysis"),
    ("http_headers", "app.scanners.http_headers"),
    ("cookie_analysis", "app.scanners.cookie_analysis"),
    ("html_analysis", "app.scanners.html_analysis"),
    ("js_discovery", "app.scanners.js_discovery"),
    ("js_analysis", "app.scanners.js_analysis"),
    ("api_discovery", "app.scanners.api_discovery"),
]

# Phase 4: dependency audit + static source analysis for an authorized local
# project directory. These are separate from website scanning: they receive a
# project base path, not a target URL. They run only when explicitly requested
# and when a project directory is supplied.
PROJECT_MODULE_PIPELINE = [
    ("dependency_audit", "app.scanners.phase4", "analyze_project_dependencies"),
    ("source_analysis", "app.scanners.phase4", "analyze_project_source"),
]

# Module entry-point names (resolved dynamically; explicit mapping for clarity).
_MODULE_ANALYZERS = {
    "url_validation": "analyze_redirects",
    "dns_analysis": "analyze_dns",
    "tls_analysis": "analyze_tls",
    "http_headers": "analyze_headers",
    "cookie_analysis": "analyze_cookies",
    "html_analysis": "analyze_html",
    "js_discovery": "analyze_js_assets",
    "js_analysis": "analyze_js",
    "api_discovery": "analyze_api_endpoints",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _finding_rows_to_dicts(rows) -> List[Dict[str, Any]]:
    """Serialize stored Finding rows into the Phase 5 engine's input shape."""
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


def _attach_phase5_results(db: Session, scan_id: str, scan: Scan) -> None:
    """Persist Phase 5 correlations and risk summary onto the scan's artifacts.

    Both are computed deterministically from the findings that were just
    written for this scan; recomputing them from the same rows anywhere else
    (API endpoints) yields identical values, so the stored copy and live
    computation agree by construction.
    """
    from app.scanners import phase5

    try:
        rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        finding_dicts = _finding_rows_to_dicts(rows)
        links = phase5.correlate_findings(finding_dicts)
        summary = phase5.build_risk_summary(
            finding_dicts, scan_id=scan_id, correlations=len(links)
        )
        scan.artifacts = {
            **(scan.artifacts or {}),
            "correlations": links,
            "risk_summary": summary,
        }
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("phase 5 post-processing failed for scan %s: %s", scan_id, exc)


async def run_scan(scan_id: str, target_url: str, modules: Optional[List[str]] = None) -> None:
    """Execute the passive website pipeline for a persisted scan and write real results."""
    async with _get_semaphore():
        await _run_scan_locked(scan_id, target_url, modules)


async def _run_scan_locked(
    scan_id: str, target_url: str, modules: Optional[List[str]] = None
) -> None:
    db: Session = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s not found; aborting pipeline", scan_id)
            return
        scan.status = "running"
        scan.started_at = _now()
        requested = set(modules or [name for name, _ in MODULE_PIPELINE])
        db.commit()

        ctx = ScanContext(target_url=target_url)

        for module_name, module_path in MODULE_PIPELINE:
            if module_name not in requested:
                stage = ScanStage(scan_id=scan_id, module=module_name, status="skipped",
                                  detail="not requested")
                db.add(stage)
                db.commit()
                continue

            _run_module(db, scan_id, module_name, module_path, ctx)

        scan.findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()  # refresh
        # Persist real artifacts (inventories) - never fabricated content.
        scan.artifacts = ctx.artifacts
        _attach_phase5_results(db, scan_id, scan)
        scan.status = "completed"
        scan.finished_at = _now()
        db.commit()
        logger.info("scan %s completed with %d findings", scan_id, len(ctx.findings))
    except Exception as exc:
        # Phase 8: an unexpected exception used to leave the row in "running"
        # forever (the async wrapper had no error capture). Fail the scan
        # honestly so the UI can show what happened.
        logger.exception("scan %s crashed: %s", scan_id, exc)
        try:
            db.rollback()
            stale = db.get(Scan, scan_id)
            if stale is not None:
                stale.status = "failed"
                stale.error = f"pipeline error: {type(exc).__name__}: {exc}"[:2000]
                stale.finished_at = _now()
                db.commit()
        except Exception:  # pragma: no cover - double failure
            logger.exception("could not persist failure state for scan %s", scan_id)
    finally:
        db.close()


def _run_coro(coro: Any, timeout: Optional[float] = None) -> Any:
    """Run an async module coroutine without nesting event loops.

    The scan pipeline may itself execute inside a running event loop (async
    path) or on a plain thread (sync path). ``asyncio.run`` only works in the
    second case; in the first case it raises RuntimeError and every async
    module stage failed in real scans. When a loop is already running we run
    the coroutine on a fresh loop in a helper thread so the module's own code
    stays unchanged.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)  # type: ignore[arg-type]
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=1, thread_name_prefix="vibeshield-module-coro"
    ) as ex:
        fut = ex.submit(asyncio.run, coro)
        return fut.result(timeout=timeout)


def _run_module(
    db: Session, scan_id: str, module_name: str, module_path: str, ctx: ScanContext
) -> None:
    stage = ScanStage(scan_id=scan_id, module=module_name, status="running", started_at=_now())
    db.add(stage)
    db.commit()
    try:
        mod = __import__(module_path, fromlist=["analyze"])
        if module_name == "url_validation":
            findings = validate_url_entry(ctx)
        else:
            analyzer_name = _MODULE_ANALYZERS[module_name]
            analyze = getattr(mod, analyzer_name)
            findings = _run_coro(analyze(ctx), timeout=settings.SCAN_TOTAL_TIMEOUT)
        for f in findings:
            db.add(_to_row(scan_id, f))
        stage.status = "completed"
        stage.detail = f"{len(findings)} finding(s)"
    except Exception as exc:
        # Real error capture: stage fails honestly, other modules continue.
        stage.status = "failed"
        stage.detail = f"{type(exc).__name__}"
        logger.warning("module %s failed: %s", module_name, exc)
    stage.finished_at = _now()
    db.commit()


def validate_url_entry(ctx: ScanContext) -> List[FindingData]:
    """The full url_validation entry point used by real scans.

    Merges the static URL checks with the module's own redirect-chain analysis.
    Phase 8 regression: the pipeline previously ran only the static checks and
    silently skipped analyze_redirects, so redirect chains, loops, and
    refused redirects were never observed in real scan runs.
    """
    from app.scanners import url_validation

    findings: List[FindingData] = list(url_validation.validate_url(ctx.target_url))
    findings.extend(_run_coro(url_validation.analyze_redirects(ctx), timeout=settings.SCAN_TOTAL_TIMEOUT))
    return findings


def _to_row(scan_id: str, f: FindingData) -> Finding:
    d = f.to_dict()
    return Finding(
        scan_id=scan_id,
        title=d["title"],
        description=d["description"],
        category=d["category"],
        severity=d["severity"],
        confidence=d["confidence"],
        affected_asset=d["affected_asset"],
        evidence=d["evidence"],
        source_module=d["source_module"],
        cwe=f.cwe,
        cve=f.cve,
        impact=d["impact"],
        remediation=d["remediation"],
        verification_status=d["verification_status"],
    )


def _to_row_from_dict(scan_id: str, d: Dict[str, Any]) -> Finding:
    return Finding(
        scan_id=scan_id,
        title=d["title"],
        description=d["description"],
        category=d["category"],
        severity=d.get("severity", "low"),
        confidence=d.get("confidence", "low"),
        affected_asset=d.get("affected_asset", ""),
        evidence=d.get("evidence", {}),
        source_module=d.get("source_module", ""),
        cwe=d.get("cwe"),
        cve=d.get("cve"),
        impact=d.get("impact", ""),
        remediation=d.get("remediation", ""),
        verification_status=d.get("verification_status", "potential"),
    )


# --- Background execution -----------------------------------------------------
# Phase 1 uses a single asyncio task per scan (FastAPI's event loop). This keeps
# scans asynchronous without introducing Redis/Celery before it is warranted.

_tasks: Dict[str, Any] = {}


def launch_scan(scan_id: str, target_url: str, modules: Optional[List[str]] = None) -> None:
    """Start the passive website scan as a background job and record it for status."""
    coro = run_scan(scan_id, target_url, modules)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # Called from a sync context (endpoint worker thread): run the coroutine
        # on a dedicated background thread with its own loop.
        import threading

        def _runner() -> None:
            try:
                asyncio.run(coro)
            except asyncio.CancelledError:
                pass  # cancelled by the user; the cancel endpoint state stands
            except Exception:
                # Phase 8: an unlogged background crash made failures invisible
                # (scan rows stuck in running). Log it and record the failure.
                import uuid

                logger.exception("background scan thread crashed (scan %s)", scan_id)

        thread = threading.Thread(target=_runner, name=f"scan-{scan_id}", daemon=True)
        thread.start()
        _tasks[scan_id] = thread
        return
    task = loop.create_task(coro)
    _tasks[scan_id] = task


def launch_project_scan(
    scan_id: str, project_dir: str, modules: Optional[List[str]] = None
) -> None:
    """Start a Phase 4 project (dependency / source) scan as a background job."""
    coro = run_project_scan(scan_id, project_dir, modules)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        import threading

        def _runner() -> None:
            try:
                asyncio.run(coro)
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("background project scan thread crashed (scan %s)", scan_id)

        thread = threading.Thread(target=_runner, name=f"proj-scan-{scan_id}", daemon=True)
        thread.start()
        _tasks[scan_id] = thread
        return
    task = loop.create_task(coro)
    _tasks[scan_id] = task


def cancel_scan(scan_id: str) -> bool:
    job = _tasks.get(scan_id)
    if isinstance(job, asyncio.Task):
        if not job.done():
            job.cancel()
            return True
        return False
    # Thread-based jobs have no safe kill semantics; report not-cancelled.
    return False


# --- Project (Phase 4) scan pipeline -----------------------------------------------


async def run_project_scan(scan_id: str, project_dir: str, modules: Optional[List[str]] = None) -> None:
    """Run the Phase 4 dependency-audit / source-analysis pipeline for one project scan.

    This is separate from website scanning: it operates on an authorized project
    directory (scheme/source) rather than a target URL (website asset flow).
    """
    async with _get_semaphore():
        await _run_project_scan_locked(scan_id, project_dir, modules)


async def _run_project_scan_locked(
    scan_id: str, project_dir: str, modules: Optional[List[str]] = None
) -> None:
    db: Session = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            logger.error("Project scan %s not found; aborting pipeline", scan_id)
            return
        try:
            await _run_project_scan_body(db, scan, scan_id, project_dir, modules)
        except Exception as exc:
            # Phase 8 regression fix: an unexpected post-stage exception used to
            # leave the scan row stuck in "running" forever (the background
            # thread swallowed it). Record the failure honestly instead.
            logger.exception("project scan %s crashed: %s", scan_id, exc)
            db.rollback()
            stale = db.get(Scan, scan_id)
            if stale is not None:
                stale.status = "failed"
                stale.error = f"pipeline error: {type(exc).__name__}: {exc}"[:2000]
                stale.finished_at = _now()
                db.commit()
    finally:
        db.close()


async def _run_project_scan_body(
    db: Session, scan: Scan, scan_id: str, project_dir: str,
    modules: Optional[List[str]] = None,
) -> None:
    scan.status = "running"
    scan.started_at = _now()
    requested = set(modules or [name for name, _ in PROJECT_MODULE_PIPELINE])
    db.commit()

    ctx = ScanContext(target_url="")  # phase4 does not use target_url
    ctx.findings = []
    ctx.artifacts = {}

    for module_name, module_path, analyzer_name in PROJECT_MODULE_PIPELINE:
        if module_name not in requested:
            stage = ScanStage(scan_id=scan_id, module=module_name, status="skipped",
                              detail="not requested")
            db.add(stage)
            db.commit()
            continue

        stage = ScanStage(scan_id=scan_id, module=module_name, status="running",
                          started_at=_now())
        db.add(stage)
        db.commit()

        try:
            args = {"ctx": ctx, "project_dir": project_dir}
            mod = __import__(module_path, fromlist=[analyzer_name])
            analyze = getattr(mod, analyzer_name)
            findings = await analyze(**args)  # type: ignore[misc]
            for f in findings:
                db.add(_to_row(scan_id, f))
            ctx.findings.extend(findings)
            # FindingData dataclasses are not JSON serializable; persist the
            # plain dicts or the final commit crashes and the scan row is
            # left stuck in "running" (Phase 8 defect).
            if module_name == "dependency_audit":
                from app.scanners import phase4
                ctx.artifacts[module_name] = phase4.artifacts_for_orchestrator(None, project_dir)
            else:
                ctx.artifacts[module_name] = (
                    [f.to_dict() for f in findings]  # FindingData objects
                    if findings and hasattr(findings[0], "to_dict")
                    else findings  # already plain dicts
                )
            stage.status = "completed"
            stage.detail = f"{len(findings)} finding(s)"
        except Exception as exc:
            stage.status = "failed"
            stage.detail = f"{type(exc).__name__}"
            logger.warning("project module %s failed: %s", module_name, exc)
        stage.finished_at = _now()
        db.commit()

    try:
        scan.findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        scan.artifacts = ctx.artifacts
        _attach_phase5_results(db, scan_id, scan)
        scan.status = "completed"
        scan.finished_at = _now()
        db.commit()
        logger.info("project scan %s completed with %d findings", scan_id, len(ctx.findings))
    finally:
        db.close()
