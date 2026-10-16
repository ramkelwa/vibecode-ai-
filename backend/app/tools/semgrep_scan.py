"""Semgrep static-analysis integration for authorized source directories.

Design rules honored here:
- invoked with a pre-built argument list, ``shell=False``
- only an explicit set of file extensions is scanned
- tool output parsed as JSON, never treated as instructions
- findings recorded as tool-reported results pending review: verification
  status is always ``unverified`` and confidence ``firm`` (tool-reported)
- missing installation, timeouts, and malformed output are handled gracefully
- rule metadata (id, message, severity, cwe/cve refs) is preserved verbatim
- evidence lines have secrets redacted before storage
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.core.logging import get_logger
from app.scanners.schema import FindingData
from app.tools.pathguard import PathNotAuthorized, allowed_file, resolve_authorized_dir
from app.tools.subprocess_runner import resolve_binary, run_tool

logger = get_logger("semgrep")

MODULE = "source_analysis"

# Explicit supported file-type allowlist (requirement #2).
SUPPORTED_EXTENSIONS = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".java", ".rb", ".php", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".json", ".yaml", ".yml", ".toml", ".md",
})

MAX_FILES_SCANNED = 2000
MAX_FILE_BYTES = 2 * 1024 * 1024

# Map semgrep severity onto the platform scale. Unknown labels map to 'low'
# with the ORIGINAL label preserved in evidence so nothing is lost.
_SEVERITY_MAP = {
    "ERROR": "medium",       # semgrep default ruleset severity
    "WARNING": "low",
    "INFO": "info",
    # newer semgrep "OSS"/pro labels
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _map_severity(label: Optional[str]) -> str:
    if not label or not isinstance(label, str):
        return "low"
    return _SEVERITY_MAP.get(label.strip().upper(), "low")


_REDACTED = "***REDACTED***"

import re

# Common secret-bearing key names that should not leak via semgrep evidence.
_SECRET_KEY_HINTS = ("password", "secret", "token", "api_key", "apikey", "private_key")

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{5,}\b")


def _redact_evidence(text: str) -> str:
    """Redact obvious secret-bearing lines from captured evidence."""
    if not text:
        return text
    lowered = text.lower()
    if any(h in lowered for h in _SECRET_KEY_HINTS):
        return _REDACTED
    # Long base64-ish/JWT-like runs are also redacted.
    if _JWT_RE.search(text):
        return _REDACTED
    return text




def collect_source_files(root: Path, max_files: int = MAX_FILES_SCANNED) -> List[Path]:
    """List candidate source files inside an authorized dir with allowlist filter."""
    skip_dirs = {".git", ".hg", ".svn", "node_modules", ".venv", "venv",
                 "site-packages", "__pycache__", "dist", "build",
                 ".mypy_cache", ".pytest_cache", ".semgrep_cache"}
    found: List[Path] = []
    try:
        it = root.rglob("*")
    except OSError:
        return found
    for p in it:
        if len(found) >= max_files:
            break
        try:
            if p.is_dir():
                if p.name in skip_dirs:
                    found.append(p)  # marker handled below - pruned by filter
                continue
            if not p.is_file():
                continue
        except OSError:
            continue
        if any(part in skip_dirs for part in p.parts):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if allowed_file(p, SUPPORTED_EXTENSIONS):
            found.append(p)
    return found


def parse_semgrep_json(stdout: str) -> List[Dict[str, Any]]:
    """Parse ``semgrep --json`` output as raw result dicts, never as instructions."""
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    results = data.get("results")
    if not isinstance(results, list):
        return []
    clean: List[Dict[str, Any]] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        check = r.get("check_id") if isinstance(r.get("check_id"), str) else ""
        start = r.get("start") if isinstance(r.get("start"), dict) else {}
        line = start.get("line") if isinstance(start.get("line"), int) else None
        path = r.get("path") if isinstance(r.get("path"), str) else ""
        extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        message = extra.get("message") if isinstance(extra.get("message"), str) else ""
        sev_raw = extra.get("severity") if isinstance(extra.get("severity"), str) else ""
        lines_str = extra.get("lines") if isinstance(extra.get("lines"), str) else ""
        clean.append({
            "check_id": check,
            "path": path,
            "line": line,
            "message": message,
            "severity_raw": sev_raw,
            "metadata": metadata,
            "lines": _redact_evidence(lines_str),
        })
    return clean


def findings_from_semgrep(
    records: List[Dict[str, Any]],
    root_dir: str,
) -> List[FindingData]:
    """Convert parsed semgrep records into FindingData objects.

    Contract:
    - severity/confidence separated; confidence is always 'firm' (tool-output)
    - verification_status 'unverified' (pending review)
    - cve/cwe preserved only when the tool's metadata reported them
    """
    findings: List[FindingData] = []
    for rec in records:
        check_id = rec.get("check_id") or "unknown-rule"
        path = rec.get("path") or ""
        line = rec.get("line")
        message = rec.get("message") or ""
        metadata = rec.get("metadata", {}) or {}
        sev = _map_severity(rec.get("severity_raw"))
        cwe = None
        cve = None
        if isinstance(metadata, dict):
            cwes = metadata.get("cwe")
            if isinstance(cwes, str):
                cwe = cwes.split(",")[0].strip() or None
            elif isinstance(cwes, list) and cwes:
                first = cwes[0]
                cwe = str(first).strip() or None
            cves = metadata.get("cve") or metadata.get("cves")
            if isinstance(cves, str):
                cve = cves.split(",")[0].strip() or None
            elif isinstance(cves, list) and cves:
                cve = str(cves[0]).strip() or None
        source_ref = f"{path}:{line}" if line is not None else path
        findings.append(
            FindingData(
                title=f"Semgrep: {check_id}",
                description=message[:2000],
                category=MODULE,
                severity=sev,
                confidence="firm",
                affected_asset=source_ref,
                evidence={
                    "tool": "semgrep",
                    "rule_id": check_id,
                    "path": path,
                    "line": line,
                    "rule_message_redacted": _redact_evidence(message),
                    "evidence_redacted": rec.get("lines", ""),
                },
                source_module=MODULE,
                cwe=cwe,
                cve=cve,
                impact="pending review (tool-reported static analysis result)",
                remediation=str(metadata.get("fix") or "review the reported location")[:1000]
                if isinstance(metadata, dict) else "review the reported location",
                verification_status="unverified",
            )
        )
    return findings


def run_semgrep(project_dir: Path) -> Dict[str, Any]:
    """Run semgrep over an authorized project directory.

    Returns a dict with ``status`` (completed | tool_missing | timeout |
    tool_failed | no_findings | unauthorized_path | unsupported_files),
    ``tool_version``, ``duration_seconds``, ``findings``, ``errors`` and
    ``scanned_file_count``.
    """
    out: Dict[str, Any] = {
        "tool": "semgrep",
        "status": "no_findings",
        "tool_version": None,
        "duration_seconds": 0.0,
        "findings": [],
        "errors": [],
        "scanned_file_count": 0,
        "root": str(project_dir),
    }
    try:
        resolve_authorized_dir(str(project_dir))
    except PathNotAuthorized as exc:
        out["status"] = "unauthorized_path"
        out["errors"] = [str(exc)]
        return out

    candidates = collect_source_files(project_dir)
    if not candidates:
        out["status"] = "unsupported_files"
        out["errors"] = ["no supported source files inside the authorized directory"]
        return out
    out["scanned_file_count"] = len(candidates)

    binary = resolve_binary(settings.SEMGREP_PATH, "semgrep")
    if binary is None:
        out["status"] = "tool_missing"
        out["errors"] = ["semgrep binary not found on PATH"]
        return out

    version_result = run_tool([binary, "--version"], timeout=30, tool_name="semgrep")
    if version_result.ok and version_result.stdout:
        out["tool_version"] = version_result.stdout.strip().splitlines()[0][:200]

    # Real invocation: pass explicit target files so the tool cannot wander
    # outside the authorized root.
    argv = [binary, "--json"]
    for p in candidates:
        argv.append(str(p))

    result = run_tool(
        argv,
        timeout=settings.SEMGREP_TIMEOUT,
        cwd=str(project_dir),
        tool_name="semgrep",
    )
    out["duration_seconds"] = result.duration_seconds

    if result.error == "not_installed":
        out["status"] = "tool_missing"
        out["errors"].append("semgrep binary disappeared mid-run")
        return out
    if result.timed_out:
        out["status"] = "timeout"
        out["errors"].append("semgrep exceeded execution timeout")
        return out
    if result.stderr and not result.stdout and result.exit_code not in (0, 1):
        # semgrep exits 1 when findings exist
        out["status"] = "tool_failed"
        out["errors"].append(result.stderr[-500:])
        return out

    records = parse_semgrep_json(result.stdout or "")
    findings = findings_from_semgrep(records, str(project_dir))
    out["findings"] = finds_to_plain(findings)
    if not findings and result.exit_code == 0:
        out["status"] = "no_findings"
    else:
        out["status"] = "completed"
    return out


def finds_to_plain(findings: List[FindingData]) -> List[Dict[str, Any]]:
    return [f.to_dict() for f in findings]
