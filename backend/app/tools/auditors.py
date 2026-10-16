"""npm audit and pip-audit runners producing structured advisory findings.

Design rules honored here:
- subprocess invoked with a pre-built argument list, ``shell=False``
- tool output is treated as untrusted data, never as instructions: it is parsed
  as JSON or skipped entirely on malformed input
- advisory database failures and ausent tools are distinguished from "no
  findings": a caller can always tell WHY an audit produced nothing
- advisory identifiers, package names, versions, ranges, and remediations are
  recorded only as observed tool output - nothing is invented
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from app.core.config import settings
from app.tools.subprocess_runner import (
    ToolResult,
    binary_version,
    resolve_binary,
    run_tool,
)

logger_name = "auditors"

# Hard time bounds per tool invocation (seconds).
NPM_AUDIT_TIMEOUT = 120
PIP_AUDIT_TIMEOUT = 180

NPM_AUDIT_CONFIG_PATH = "NPM_AUDIT_PATH"
PIP_AUDIT_CONFIG = "PIP_AUDIT_PATH"


@dataclass
class Advisory:
    """One advisory as reported by an audit tool. Nothing here is synthesized."""

    package: str
    ecosystem: str
    advisory_id: str          # e.g. CVE-... / GHSA-... / PYSEC-... (as reported)
    title: str
    severity: str             # tool-reported; mapped conservatively
    fixed_version: Optional[str]  # only when the tool reported a fix version
    vulnerable_range: str = ""
    remediation: str = ""
    url: str = ""
    source_tool: str = ""
    # Where the severity label came from: "tool" when the advisory source
    # reported it, otherwise a documented platform default (never presented
    # as tool-reported data).
    severity_source: str = "tool"


@dataclass
class AuditOutcome:
    """Outcome of one audit run with explicit status semantics."""

    tool_name: str
    tool_version: Optional[str]
    status: str  # completed | no_findings | tool_missing | tool_failed | timeout | unparsed_output
    advisories: List[Advisory] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    exit_code: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.status in ("completed", "no_findings")


# --- npm audit ------------------------------------------------------------------


def _npm_severity(raw: Optional[str]) -> str:
    """Map npm severity labels onto the platform scale, conservatively.

    Unknown labels do not raise: they map to 'low' so that a finding is still
    recorded with the original label preserved in evidence.
    """
    mapping = {
        "critical": "critical",
        "high": "high",
        "moderate": "medium",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    if not raw or not isinstance(raw, str):
        return "low"
    return mapping.get(raw.strip().lower(), "low")


def parse_npm_audit_json(stdout: str) -> List[Advisory]:
    """Parse ``npm audit --json`` payload (v8+ shape with ``vulnerabilities``).

    Malformed JSON yields an empty list; the caller distinguishes that case by
    the ``status`` it assigns based on the raw text.
    """
    advisories: List[Advisory] = []
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return advisories
    if not isinstance(data, dict):
        return advisories

    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, dict):
        return advisories

    meta = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    _ = meta  # reserved: record totals in evidence upstream if needed

    for name, v in vulns.items():
        if not isinstance(v, dict):
            continue
        advisory_list = v.get("via")
        if not isinstance(advisory_list, list):
            continue
        pkg_advisories: List[Advisory] = []
        for via in advisory_list:
            if not isinstance(via, dict):
                continue  # strings are indirect dependency hints, not advisories
            url = via.get("url") if isinstance(via.get("url"), str) else ""
            # The advisory id comes only from the advisory URL. npm's numeric
            # "source" is an internal registry id, not a CVE/GHSA identifier -
            # an id is never fabricated from it (spec: never invent CVEs).
            advisory_id = url.rsplit("/", 1)[-1] if url else ""
            title = via.get("title") if isinstance(via.get("title"), str) else ""
            severity_raw = via.get("severity") if isinstance(via.get("severity"), str) else ""
            range_str = ""
            rng = via.get("range")
            if isinstance(rng, str):
                range_str = rng
            fix_list = via.get("fixAvailable")
            fixed_version: Optional[str] = None
            fix_text = ""
            if isinstance(fix_list, dict):
                fixed_version = fix_list.get("version") if isinstance(fix_list.get("version"), str) else None
                fv = fix_list.get("name")
                if isinstance(fv, str):
                    fix_text = f"update {fv}"
                    if fixed_version:
                        fix_text += f" to {fixed_version}"
            elif isinstance(fix_list, bool) and fix_list:
                fix_text = "update available"
            pkg_advisories.append(
                Advisory(
                    package=str(name),
                    ecosystem="npm",
                    advisory_id=advisory_id,
                    title=title,
                    severity=_npm_severity(severity_raw),
                    fixed_version=fixed_version,
                    vulnerable_range=range_str,
                    remediation=fix_text or ("upgrade the package" if fixed_version else "review upstream advisory"),
                    url=url,
                    source_tool="npm-audit",
                )
            )
        # v["via"] mixed entries: strings mean "depends on X which is affected"
        for via in advisory_list:
            if isinstance(via, str):
                pkg_advisories.append(
                    Advisory(
                        package=str(name),
                        ecosystem="npm",
                        advisory_id="",                    title=f"indirect dependency affected via {via}",
                    severity="info",
                    fixed_version=None,
                    vulnerable_range="",
                    remediation=f"upgrade {via}",
                    source_tool="npm-audit",
                )
            )

        # Extend per-package, inside the loop: an empty vulnerabilities map
        # must still parse cleanly (previously an UnboundLocalError), and each
        # package's advisories must be kept, not only the last one's.
        advisories.extend(pkg_advisories)

    return advisories


def run_npm_audit(project_dir: Path) -> AuditOutcome:
    """Run ``npm audit --json`` against a supplied project directory.

    Requires a package-lock.json. Never installs anything: ``--registry``
    defaults to the shared public one; no lifecycle scripts are executed
    because we never run ``npm install``.
    """
    lockfile = project_dir / "package-lock.json"
    if not lockfile.is_file():
        # Not a clean result: the audit could not run at all. "skipped" lets
        # callers record an audit coverage gap instead of a false all-clear.
        return AuditOutcome(
            tool_name="npm-audit",
            tool_version=None,
            status="skipped",
            errors=["no package-lock.json in the authorized project directory"],
        )

    binary = resolve_binary(settings.NPM_COMMAND, "npm")
    if binary is None:
        return AuditOutcome(tool_name="npm-audit", tool_version=None, status="tool_missing")

    version = binary_version([binary, "--version"])
    argv = [
        binary,
        "audit",
        "--json",
        "--package-lock-only",
        "--no-fund",
        "--no-audit-fund",
    ]
    result = run_tool(argv, timeout=NPM_AUDIT_TIMEOUT, cwd=str(project_dir), version=version, tool_name="npm-audit")
    return _finalize(result, parser=parse_npm_audit_json, tool_name="npm-audit",
                     tool_version=version, required=True)


def _finalize(
    result: ToolResult,
    *,
    parser,
    tool_name: str,
    tool_version: Optional[str],
    required: bool,
) -> AuditOutcome:
    """Turn a ToolResult into an AuditOutcome with explicit status semantics."""
    outcome = AuditOutcome(
        tool_name=tool_name,
        tool_version=tool_version,
        status="no_findings",
        duration_seconds=result.duration_seconds,
        exit_code=result.exit_code,
    )
    if result.error == "not_installed":
        outcome.status = "tool_missing"
        outcome.errors.append("tool binary not found on PATH")
        return outcome
    if result.timed_out:
        outcome.status = "timeout"
        outcome.errors.append(f"{tool_name} exceeded execution timeout")
        return outcome
    if result.error and result.error != "exit_non_zero":
        outcome.status = "tool_failed"
        outcome.errors.append(result.error)
        outcome.errors.append(result.stderr[-500:])
        return outcome

    stdout = result.stdout or ""
    if not stdout.strip():
        if result.ok:
            outcome.status = "no_findings"
        else:
            outcome.status = "tool_failed"
            outcome.errors.append("tool produced no stdout")
            outcome.errors.append(result.stderr[-500:])
        return outcome

    parsed = parser(stdout)
    if not parsed and not result.ok:
        outcome.status = "tool_failed"
        outcome.errors.append("exit non-zero and output could not be parsed")
        outcome.errors.append(result.stderr[-500:])
        return outcome
    if not parsed:
        # Exit zero but no advisories parsed. Distinguish a genuinely clean
        # audit (valid JSON payload) from unparseable output: an unparsed
        # payload must never be presented as a clean result.
        try:
            json.loads(stdout)
        except (json.JSONDecodeError, ValueError):
            outcome.status = "unparsed_output"
            outcome.errors.append("tool output could not be parsed as JSON")
            outcome.errors.append(stdout[:300])
        else:
            outcome.status = "no_findings"
        return outcome

    outcome.status = "completed"
    outcome.advisories = parsed
    return outcome


# --- pip-audit ---------------------------------------------------------------------


def _pip_severity(raw: Optional[str]) -> str:
    if not raw or not isinstance(raw, str):
        return "low"
    label = raw.strip().lower()
    mapping = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium",
               "low": "low", "info": "info", "none": "info"}
    return mapping.get(label, "low")


def parse_pip_audit_json(stdout: str) -> List[Advisory]:
    """Parse ``pip-audit --format=json`` output (list of dependency/vuln blocks)."""
    advisories: List[Advisory] = []
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return advisories
    if not isinstance(data, list):
        return advisories
    for entry in data:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or entry.get("name") or ""
        fixed_vers = entry.get("fixed_versions")
        vulns = entry.get("vulns")
        if not isinstance(vulns, list) or not vulns:
            if isinstance(fixed_vers, list) and fixed_vers:
                # pip-audit reports fixed_versions even without vulns in some
                # modes - do not invent an advisory for that.
                continue
            continue
        for v in vulns:
            if not isinstance(v, dict):
                continue
            advisory_id = ""
            for key in ("id", "aliases"):
                val = v.get(key)
                if isinstance(val, str) and val:
                    advisory_id = val
                    break
                if isinstance(val, list) and val:
                    # aliases: prefer a CVE/PYSEC style id present in the list
                    for alias in val:
                        if isinstance(alias, str) and alias:
                            advisory_id = alias
                            break
                    if advisory_id:
                        break
            fixes = v.get("fix_versions")
            fixed_version: Optional[str] = None
            if isinstance(fixes, list) and fixes and isinstance(fixes[0], str):
                fixed_version = fixes[0]
            description = v.get("description") if isinstance(v.get("description"), str) else ""
            title = description.splitlines()[0][:160] if description else advisory_id
            advisories.append(
                Advisory(
                    package=str(package),
                    ecosystem="pypi",
                    advisory_id=advisory_id,
                    title=title,
                    # pip-audit does not report severity. A neutral default is
                    # recorded and labeled as such in severity_source - a
                    # severity is never presented as tool-reported data.
                    severity="medium",
                    severity_source="platform_default (pip-audit reports no severity)",
                    fixed_version=fixed_version,
                    vulnerable_range=f"< {fixed_version}" if fixed_version else "",
                    # The advisory id is part of the remediation trail so that
                    # every upgrade suggestion is traceable to its advisory.
                    remediation=(
                        f"upgrade {package} to {fixed_version} ({advisory_id})"
                        if fixed_version
                        else (f"upgrade {package} ({advisory_id})" if advisory_id else "upgrade the package")
                    ),
                    url=v.get("link") if isinstance(v.get("link"), str) else "",
                    source_tool="pip-audit",
                )
            )
    return advisories


def run_pip_audit(requirements_file: Path, project_dir: Path) -> AuditOutcome:
    """Run pip-audit against a pinned requirements file for an authorized project."""
    binary = resolve_binary(settings.PIP_AUDIT_COMMAND, "pip-audit")
    if binary is None:
        return AuditOutcome(tool_name="pip-audit", tool_version=None, status="tool_missing")

    version = binary_version([binary, "--version"])
    # -r file + --format json + --no-deps style invocation. We deliberately do
    # NOT use ``--no-deps``: transitive pinning comes from auditors' own
    # resolution, and pip-audit never installs anything when given -r files.
    argv = [binary, "--format", "json", "--disable-pip", "-r", str(requirements_file)]
    result = run_tool(argv, timeout=PIP_AUDIT_TIMEOUT, cwd=str(project_dir), version=version, tool_name="pip-audit")
    return _finalize(result, parser=parse_pip_audit_json, tool_name="pip-audit",
                     tool_version=version, required=True)


def write_tmp_requirements(dep_entries, *, marker: str = "") -> Path:
    """Write a temporary requirements file with only pinned entries.

    pip-audit requires concrete versions; unpinned entries CANNOT be audited
    and are recorded upstream as ``unpinned`` - not fabricated.
    """
    lines = []
    for d in dep_entries:
        if d.ecosystem == "pypi" and d.pinned and d.version:
            lines.append(f"{d.name}=={d.version}")
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="vibeshield-audit-", delete=False
    )
    handle.write("\n".join(lines))
    handle.close()
    return Path(handle.name)
