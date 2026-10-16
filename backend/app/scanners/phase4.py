"""Phase 4 scanning modules: dependency audit + source code analysis.

Entry points called by the orchestrator:
- ``audit_dependencies(ctx, project_dir)`` — manifest parsing + npm/pip audits
- ``analyze_source(ctx, project_dir)`` — semgrep static analysis

Salient contracts (see tools/ docstrings for details):
- nothing is executed from the target project; tool invocations use argument
  lists with ``shell=False`` and hard timeouts
- missing tools, malformed output, and failed advisory lookups are all
  representable as distinct AuditOutcome status values
- dependency audit findings are clearly labeled as dependency-ecosystem issues
  and never presented as exploitable website vulnerabilities (finding category
  is "dependency_audit", description calls out scope explicitly)
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.logging import get_logger
from app.scanners.context import ScanContext
from app.scanners.schema import FindingData
from app.tools import auditors
from app.tools.manifests import (
    DependencyEntry,
    ManifestParseResult,
    discover_manifests,
    parse_manifest_file,
)
from app.tools.pathguard import resolve_authorized_dir
from app.tools.semgrep_scan import MODULE as SOURCE_MODULE
from app.tools.semgrep_scan import run_semgrep
from app.tools.zap_scan import MODULE as ZAP_MODULE
from app.tools.zap_scan import safe_scan, zap_enabled, zap_status

logger = get_logger("phase4")

MODULE_DEPS = "dependency_audit"
MODULE_SRC = "source_analysis"

# Severity mapping for advisories from tools that report severity directly.
# Advisory severity stays tool-reported; confidence stays 'firm'; verification
# status stays 'unverified' (tool verdicts are pending review by definition).
_TOOL_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium",
                  "moderate": "medium", "low": "low", "info": "info"}


class Phase4Error(RuntimeError):
    """Raised only for orchestration-level errors the caller must see."""


# --- shared helpers -------------------------------------------------------------


def _dedupe_findings(items: List[FindingData]) -> List[FindingData]:
    seen: set = set()
    out: List[FindingData] = []
    for f in items:
        # Dedup identity: module + asset + title + cve/advisory id.
        key = (
            f.source_module,
            f.affected_asset,
            f.title,
            (f.evidence or {}).get("advisory_id", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _advisory_findings(advisories, *, project_dir: str, tool_name: str) -> List[FindingData]:
    """Convert Advisory records into FindingData with explicit provenance.

    Severity stays tool-reported (mapped to the platform scale); confidence is
    'firm' (tool output observed); verification_status 'unverified' — a
    dependency advisory is not a confirmed exploitable web vulnerability
    (requirement #5), so the category and description make the scoping
    explicit.
    """
    findings: List[FindingData] = []
    for a in advisories:
        sev = _TOOL_SEVERITY.get(a.severity.lower() if isinstance(a.severity, str) else "", "low")
        if not a.advisory_id:
            # Advisory without an id is still recorded, but flagged clearly
            # rather than fabricated.
            title = a.title or f"Unidentified advisory for {a.package}"
        else:
            title = f"{a.advisory_id}: {a.title or a.package}"
        affected = f"{a.package}@{a.vulnerable_range or 'unversioned' } ({a.ecosystem})"
        findings.append(
            FindingData(
                title=title[:500],
                description=(
                    f"{a.ecosystem} dependency '{a.package}' has a reported advisory from {tool_name}. "
                    "This is a dependency-ecosystem finding (source-code supply chain); it is NOT "
                    "evidence of an exploitable website vulnerability by itself."
                ),
                category=MODULE_DEPS,
                severity=sev,
                confidence="firm",
                affected_asset=affected,
                evidence={
                    "tool": tool_name,
                    "package": a.package,
                    "ecosystem": a.ecosystem,
                    "advisory_id": a.advisory_id,
                    "vulnerable_range": a.vulnerable_range,
                    "advisory_url": a.url,
                    "reported_severity_raw": a.severity,
                    "title": a.title,
                    "source_file": project_dir,
                },
                source_module=MODULE_DEPS,
                cwe=None,
                cve=None,
                impact=(f"{a.ecosystem} dependency risk; NOT automatically a website exploit"),
                remediation=a.remediation or "review upstream advisory and upgrade",
                verification_status="potential",
            )
        )
    return findings


# --- dependency audit entry point --------------------------------------------------


def audit_dependencies(project_dir: Path) -> Dict[str, Any]:
    """Run the full dependency-audit workflow for one authorized project.

    Returns a dict with ``findings`` (FindingData dicts), ``artifacts``
    (parsed manifest inventories + tool outcomes), and ``status``. Never
    raises for tool-affecting issues; a ``Phase4Error`` is raised only if the
    path is not authorized.
    """
    root = resolve_authorized_dir(str(project_dir))

    started = time.monotonic()
    manifests = discover_manifests(root)
    parsed: List[ManifestParseResult] = [parse_manifest_file(p) for p in manifests]

    artifacts: Dict[str, Any] = {
        "root": str(root),
        "manifests": [
            {
                "path": r.file_path,
                "ecosystem": r.ecosystem,
                "dependency_count": len(r.dependencies),
                "errors": r.errors,
                "unsupported": r.unsupported,
                "dependencies": [
                    {
                        "name": d.name,
                        "version": d.version,
                        "pinned": d.pinned,
                        "from_lockfile": d.from_lockfile,
                    }
                    for d in r.dependencies[:500]  # bound artifact payload
                ],
            }
            for r in parsed
        ],
        "tool_runs": [],
    }

    all_findings: List[FindingData] = []

    # --- npm audit (only when node manifests present) ---
    has_node = any(r.ecosystem == "npm" for r in parsed)
    if has_node:
        outcome = auditors.run_npm_audit(root)
        tool_record: Dict[str, Any] = {
            "tool": outcome.tool_name,
            "version": outcome.tool_version,
            "status": outcome.status,
            "exit_code": outcome.exit_code,
            "duration_seconds": outcome.duration_seconds,
            "advisory_count": len(outcome.advisories),
            "errors": outcome.errors[:20],
        }
        if outcome.advisories:
            tool_record["advisories"] = [
                {
                    "package": a.package,
                    "advisory_id": a.advisory_id,
                    "title": a.title,
                    "severity": a.severity,
                    "vulnerable_range": a.vulnerable_range,
                    "fixed_version": a.fixed_version,
                    "remediation": a.remediation,
                    "url": a.url,
                    "source_tool": a.source_tool,
                }
                for a in outcome.advisories
            ]
        artifacts["tool_runs"].append(tool_record)
        if outcome.ok:
            all_findings.extend(
                _advisory_findings(outcome.advisories, project_dir=str(root), tool_name="npm-audit")
            )
        elif outcome.status == "tool_missing":
            all_findings.append(_tool_gap_finding("npm-audit", str(root), "npm-audit binary not installed"))
        elif outcome.status in ("tool_failed", "timeout", "unparsed_output"):
            all_findings.append(
                _tool_gap_finding("npm-audit", str(root), "; ".join(outcome.errors)[:500])
            )
    else:
        artifacts["tool_runs"].append({
            "tool": "npm-audit", "status": "not_applicable",
            "detail": "no node manifests found",
        })

    # --- pip-audit ---
    python_deps: List[DependencyEntry] = [
        d for r in parsed if r.ecosystem == "pypi" for d in r.dependencies
    ]
    if python_deps:
        pinned = [d for d in python_deps if d.pinned and d.version]
        unpinned_count = len(python_deps) - len(pinned)
        if not pinned:
            artifacts["tool_runs"].append({
                "tool": "pip-audit", "status": "unpinned",
                "detail": f"{unpinned_count} python dependency declarations, none pinned; audit skipped (no invented versions)",
            })
            all_findings.append(
                FindingData(
                    title="python dependencies are not pinned; pip-audit skipped",
                    description=(
                        "pip-audit requires pinned versions. Manifest declarations are not pinned, "
                        "and the auditor never invents versions, so no audit ran."
                    ),
                    category=MODULE_DEPS,
                    severity="info",
                    confidence="certain",
                    affected_asset=str(root),
                    evidence={"tool": "pip-audit", "unpinned_count": unpinned_count},
                    source_module=MODULE_DEPS,
                    impact="supply-chain risk cannot be assessed without pinned versions",
                    remediation="pin requirements (e.g. pip freeze > requirements.txt) and re-run",
                    verification_status="informational",
                )
            )
        else:
            reqs = auditors.write_tmp_requirements(pinned)
            try:
                outcome = auditors.run_pip_audit(reqs, root)
                artifacts["tool_runs"].append({
                    "tool": outcome.tool_name,
                    "version": outcome.tool_version,
                    "status": outcome.status,
                    "exit_code": outcome.exit_code,
                    "duration_seconds": outcome.duration_seconds,
                    "advisory_count": len(outcome.advisories),
                    "audited_pinned_packages": len(pinned),
                    "unpinned_count": unpinned_count,
                    "errors": outcome.errors[:20],
                })
                if outcome.advisories:
                    tool_record["advisories"] = [
                        {
                            "package": a.package,
                            "advisory_id": a.advisory_id,
                            "title": a.title,
                            "severity": a.severity,
                            "vulnerable_range": a.vulnerable_range,
                            "fixed_version": a.fixed_version,
                            "remediation": a.remediation,
                            "url": a.url,
                            "source_tool": a.source_tool,
                        }
                        for a in outcome.advisories
                    ]
                if outcome.ok:
                    all_findings.extend(
                        _advisory_findings(outcome.advisories, project_dir=str(root), tool_name="pip-audit")
                    )
                elif outcome.status == "tool_missing":
                    all_findings.append(_tool_gap_finding("pip-audit", str(root), "pip-audit binary not installed"))
                elif outcome.status in ("tool_failed", "timeout", "unparsed_output"):
                    all_findings.append(
                        _tool_gap_finding("pip-audit", str(root), "; ".join(outcome.errors)[:500])
                    )
            finally:
                import contextlib
                with contextlib.suppress(OSError):
                    reqs.unlink()
    else:
        artifacts["tool_runs"].append({
            "tool": "pip-audit", "status": "not_applicable",
            "detail": "no python manifests found",
        })

    findings_out = _dedupe_findings(all_findings)
    artifacts["duration_seconds"] = round(time.monotonic() - started, 2)
    return {
        "module": MODULE_DEPS,
        "status": "completed",
        "findings": [f.to_dict() for f in findings_out],
        "artifacts": artifacts,
    }


def _finalize_tool_artifacts_for_orchestrator(outcome: Dict[str, Any]) -> Dict[str, Any]:
    """Rebuild the Phase 4 dependency artifacts shape the orchestrator persists.

    Phase 8 regression: the orchestrator persisted a flat list for
    dependency_audit instead of the full artifacts dict, so the frontend/API
    artifact endpoint could not locate manifests/tool_runs. This keeps the
    artifact shape stable and re-derives advisories into the tool_runs records
    only when they were recorded there by audit_dependencies.
    """
    artifacts = outcome.get("artifacts", {})
    if not isinstance(artifacts, dict):
        return {}
    # Re-attach advisories into tool_runs entries that carried them.
    tool_runs = artifacts.get("tool_runs") or []
    if isinstance(tool_runs, list):
        rebuilt: List[Dict[str, Any]] = []
        for tr in tool_runs:
            rec = dict(tr)
            if rec.get("tool") in ("npm-audit", "pip-audit") and rec.get("status") == "completed":
                if "advisories" not in rec:
                    rec["advisories"] = []
            rebuilt.append(rec)
        artifacts = {**artifacts, "tool_runs": rebuilt}
    return artifacts


def _tool_gap_finding(tool: str, root: str, reason: str) -> FindingData:
    """A finding explaining why an audit produced no advisory data.

    This distinguishes a vulnerable-dependency NULL result (grep: no advidories)
    from a tool that could not run — required by the spec’s "never invent CVEs"
    and "distinguish unavailable advisory DB" requirements.
    """
    if "not installed" in reason or "missing" in reason:
        sev, stat = "info", "informational"
    elif "timeout" in reason or "failed" in reason or "could not be parsed" in reason:
        sev, stat = "low", "unverified"
    else:
        sev, stat = "info", "informational"
    return FindingData(
        title=f"{tool} did not produce advisory data",
        description=(
            f"{tool} could not be used to audit this project ({reason}). "
            "No advisories were invented; treat this as an audit coverage gap, "
            "not as a clean result."
        ),
        category=MODULE_DEPS,
        severity=sev,
        confidence="certain",
        affected_asset=root,
        evidence={"tool": tool, "reason": reason[:500]},
        source_module=MODULE_DEPS,
        impact="incomplete dependency-advisory coverage for this scan",
        remediation=f"install/fix {tool} and re-run the scan",
        verification_status=stat,
    )


# --- source analysis entry point ----------------------------------------------------


def analyze_source(project_dir: Path) -> Dict[str, Any]:
    """Run static source analysis (semgrep) on an authorized project directory."""
    result = run_semgrep(project_dir)
    findings: List[FindingData] = []
    for rec in result.get("findings", []):
        # run_semgrep already produced FindingData dicts via to_dict(); keep them.
        dr = dict(rec)
        findings.append(FindingData(
            title=dr["title"],
            description=dr["description"],
            category=SOURCE_MODULE,
            severity=dr["severity"],
            confidence=dr["confidence"],
            affected_asset=dr["affected_asset"],
            evidence=dr.get("evidence", {}),
            source_module=SOURCE_MODULE,
            cwe=dr.get("cwe"),
            cve=dr.get("cve"),
            impact=dr.get("impact", ""),
            remediation=dr.get("remediation", ""),
            verification_status=dr.get("verification_status", "unverified"),
        ))
    deduped = _dedupe_findings(findings)
    return {
        "module": SOURCE_MODULE,
        "status": result.get("status", "tool_failed"),
        "findings": [f.to_dict() for f in deduped],
        "artifacts": {
            "tool": "semgrep",
            "scanned_file_count": result.get("scanned_file_count", 0),
            "tool_version": result.get("tool_version"),
            "errors": result.get("errors", []),
            "duration_seconds": result.get("duration_seconds", 0.0),
            "root": result.get("root"),
        },
    }


# --- optional dynamic scan (ZAP) -----------------------------------------------------


def run_dynamic_scan_if_configured(target_url: str, authorized_target_url: str) -> Dict[str, Any]:
    """Optional ZAP dynamic scan - disabled unless explicitly configured."""
    if not zap_enabled():
        status = zap_status()
        return {
            "module": ZAP_MODULE,
            "status": "disabled",
            "reason": status.get("reason", "zap api url not configured"),
            "findings": [],
            "artifacts": {"module": ZAP_MODULE, "enabled": False},
        }
    result = safe_scan(target_url, authorized_target_url)
    findings: List[FindingData] = []
    for alert in result.get("alerts", []):
        risk = str(alert.get("risk", "")).lower()
        sev = {"informational": "info", "low": "low", "medium": "medium",
               "high": "high"}.get(risk, "low")
        findings.append(FindingData(
            title=f"ZAP: {alert.get('name', 'alert')} ({alert.get('plugin_id')})",
            description=str(alert.get("description", ""))[:1500],
            category=ZAP_MODULE,
            severity=sev,
            confidence="firm",
            affected_asset=str(alert.get("url", ""))[:2000],
            evidence={
                "tool": "zap",
                "plugin_id": alert.get("plugin_id"),
                "alert_ref": alert.get("alert_ref"),
                "evidence_redacted": alert.get("evidence_redacted"),
                "cwe_id": alert.get("cwe_id"),
            },
            source_module=ZAP_MODULE,
            impact="tool-reported dynamic scan result pending review",
            remediation=str(alert.get("solution", ""))[:1000],
            verification_status="unverified",
        ))
    return {
        "module": ZAP_MODULE,
        "status": result.get("status", "completed"),
        "findings": [f.to_dict() for f in _dedupe_findings(findings)],
        "artifacts": {"module": ZAP_MODULE, "enabled": True,
                      "duration_seconds": result.get("duration_seconds", 0.0)},
        "errors": result.get("errors", []),
    }


# --- orchestrator-facing async wrappers ---------------------------------------------


async def analyze_project_dependencies(ctx: Optional[ScanContext], project_dir: str) -> List[FindingData]:
    """Async entry point for the orchestrator (Phase 4 module 10)."""
    outcome = audit_dependencies(Path(project_dir))
    ctx_artifacts = _finalize_tool_artifacts_for_orchestrator(outcome)
    if ctx is not None:
        ctx.artifacts[MODULE_DEPS] = ctx_artifacts
    return [FindingData(
        title=f["title"],
        description=f["description"],
        category=f["category"],
        severity=f["severity"],
        confidence=f["confidence"],
        affected_asset=f["affected_asset"],
        evidence=f.get("evidence", {}),
        source_module=f["source_module"],
        cwe=f.get("cwe"),
        cve=f.get("cve"),
        impact=f.get("impact", ""),
        remediation=f.get("remediation", ""),
        verification_status=f.get("verification_status", "potential"),
    ) for f in outcome.get("findings", [])]


def artifacts_for_orchestrator(ctx: Optional[ScanContext], project_dir: str) -> Dict[str, Any]:
    """Build the Phase 4 dependency artifacts dict the orchestrator persists.

    Kept separate from analyze_project_dependencies so the E2E harness and the
    orchestrator can both independently verify the persisted artifact shape.
    """
    outcome = audit_dependencies(Path(project_dir))
    return _finalize_tool_artifacts_for_orchestrator(outcome)


async def analyze_project_source(ctx: Optional[ScanContext], project_dir: str) -> List[FindingData]:
    """Async entry point for the orchestrator (Phase 4 module 11)."""
    outcome = analyze_source(Path(project_dir))
    if ctx is not None:
        ctx.artifacts[SOURCE_MODULE] = outcome.get("artifacts", {})
    return [FindingData(
        title=f["title"],
        description=f["description"],
        category=f["category"],
        severity=f["severity"],
        confidence=f["confidence"],
        affected_asset=f["affected_asset"],
        evidence=f.get("evidence", {}),
        source_module=f["source_module"],
        cwe=f.get("cwe"),
        cve=f.get("cve"),
        impact=f.get("impact", ""),
        remediation=f.get("remediation", ""),
        verification_status=f.get("verification_status", "unverified"),
    ) for f in outcome.get("findings", [])]
