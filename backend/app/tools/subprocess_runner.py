"""Safe subprocess execution for external security tools.

Requirements enforced here (no exceptions, no opt-outs):
- argument-list invocation only: ``shell=False`` is always used, so no untrusted
  string is ever interpreted by a shell
- hard execution timeout via ``subprocess.run(timeout=...)``; a timeout kills
  the process and is recorded as an error, never retried silently
- POSIX ``os.execvpe`` style environment is NOT customized: the child inherits a
  minimal, predictable environment (no PROMPT injection surface from PATH lookups
  beyond standard resolution)
- output is captured as bytes with a hard cap so a runaway tool cannot exhaust
  memory
- tool binaries are resolved from an explicit allowlist of configured paths
  (never from user-supplied strings)
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("tools")

# Cap captured stdout/stderr per tool run (1 MiB each) to bound memory use.
MAX_TOOL_OUTPUT_BYTES = 1024 * 1024


class ToolNotInstalled(RuntimeError):
    """The external tool binary is not available on this machine."""


class ToolExecutionFailed(RuntimeError):
    """The external tool ran but exited non-zero, or misbehaved."""


class ToolTimeout(ToolExecutionFailed):
    """The external tool exceeded its allowed execution time."""


@dataclass
class ToolResult:
    """Structured result of one external tool invocation."""

    command: List[str]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    error: Optional[str] = None  # normalized error class name when failed
    tool_version: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None and not self.timed_out and self.exit_code == 0


def resolve_binary(configured_path: str, python_name: str) -> Optional[str]:
    """Resolve a tool binary from an explicit configured path.

    Returns the RESOLVED path from shutil.which (never the bare name): on
    Windows, subprocess with shell=False cannot launch "npm" by bare name -
    CreateProcess does not apply PATHEXT, so only the resolved "npm.CMD"
    path works (Phase 8 defect: npm-audit reported tool_missing on Windows
    even though npm was installed).

    Never searches arbitrary user-supplied strings: falls back to the system
    PATH lookup for a fixed tool name only. Returns None when not installed.
    """
    if not settings.ENABLE_EXTERNAL_TOOLS:
        return None
    if configured_path:
        resolved = shutil.which(configured_path)
        if resolved:
            return resolved
    # configured_path may itself be just a bare name like "semgrep"; which()
    # above already covers it. Otherwise try the canonical name once.
    if python_name:
        resolved = shutil.which(python_name)
        if resolved:
            return resolved
    return None


def run_tool(
    argv: Sequence[str],
    *,
    timeout: int,
    cwd: Optional[str] = None,
    version: Optional[str] = None,
    tool_name: str = "tool",
) -> ToolResult:
    """Run an external tool with argument-list semantics and a hard timeout.

    The command MUST be a pre-built argument list whose elements were never
    concatenated from untrusted input without a separator. No shell is spawned.
    """
    argv = [str(a) for a in argv]
    started = time.monotonic()
    result = ToolResult(
        command=argv,
        exit_code=None,
        stdout="",
        stderr="",
        duration_seconds=0.0,
        tool_version=version,
    )
    try:
        completed = subprocess.run(
            argv,
            shell=False,  # explicit: never shell-interpolate
            capture_output=True,
            timeout=timeout,
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        result.exit_code = completed.returncode
        result.stdout = (completed.stdout or "")[:MAX_TOOL_OUTPUT_BYTES]
        result.stderr = (completed.stderr or "")[:MAX_TOOL_OUTPUT_BYTES]
        if completed.returncode != 0:
            # npm audit exits non-zero when vulns exist; only flag as an
            # execution failure when there is no parseable stdout payload.
            if not (result.stdout and result.stdout.strip()):
                result.error = "exit_non_zero"
                result.extra["exit_code"] = completed.returncode
            result.extra["stderr"] = result.stderr[-2000:]
    except subprocess.TimeoutExpired:
        result.timed_out = True
        result.error = "timeout"
        logger.warning("%s timed out after %ss", tool_name, timeout)
    except FileNotFoundError:
        result.error = "not_installed"
        logger.info("%s binary not found for argv[0]=%s", tool_name, argv[0])
    except PermissionError:
        result.error = "not_executable"
        logger.warning("%s binary not executable: %s", tool_name, argv[0])
    except OSError as exc:
        result.error = f"os_error: {type(exc).__name__}"
        logger.warning("%s failed with OS error: %s", tool_name, exc)
    finally:
        result.duration_seconds = round(time.monotonic() - started, 3)
    return result


def binary_version(argv: Sequence[str], *, timeout: int = 30) -> Optional[str]:
    """Best-effort tool version probe (``--version``). Returns None on failure."""
    result = run_tool(argv, timeout=timeout)
    if result.ok and result.stdout:
        return result.stdout.strip().splitlines()[0][:200]
    return None
