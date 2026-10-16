"""Authorized project-directory access control for Phase 4.

An external-tool scan may touch files ONLY inside a directory that was either
(1) explicitly configured as an authorized root, or (2) explicitly supplied in
the request body as an absolute directory under such a root (or directly
configured). Symlinks that escape the authorized root are rejected.

Nothing here trusts repository CONTENT: even when file reads are allowed, file
bytes are parsed as data and never as instructions to follow.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from app.core.config import settings


class PathNotAuthorized(ValueError):
    """Raised when a path is outside every authorized project root."""

    def __init__(self, message: str) -> None:  # pragma: no cover - trivial
        try:
            super().__init__(message)
        except TypeError:  # Path.__init__ signature varies
            ValueError.__init__(self, message)


def authorized_roots() -> List[Path]:
    roots = [Path(p).resolve() for p in settings.authorized_project_roots]
    return roots


def resolve_authorized_dir(raw: str) -> Path:
    """Resolve a user-supplied directory string against authorized roots.

    Rules:
    - absolute paths must exist, be a directory, and stay inside a configured
      authorized root after symlink resolution
    - relative paths are resolved against each configured root in turn
    - symlink escape (dir inside root pointing outside) is rejected
    """
    roots = authorized_roots()
    if not roots:
        raise PathNotAuthorized(
            "no authorized project directories are configured "
            "(AUTHORIZED_PROJECT_ROOTS); Phase 4 scanning is disabled"
        )
    candidate = Path(raw).expanduser()
    errors: List[str] = []
    for root in roots:
        if candidate.is_absolute():
            resolved = _safe_resolve(candidate)
            if resolved is None:
                errors.append(f"unresolvable path: {raw}")
                continue
        else:
            resolved = _safe_resolve(root / candidate)
            if resolved is None:
                errors.append(f"unresolvable path under {root}: {raw}")
                continue
        try:
            resolved.relative_to(root)
        except ValueError:
            errors.append(f"{raw} is not inside authorized root {root}")
            continue
        if not resolved.is_dir():
            errors.append(f"{raw} is not a directory")
            continue
        return resolved
    raise PathNotAuthorized("; ".join(errors) or f"path not authorized: {raw}")


def _safe_resolve(p: Path) -> Optional[Path]:
    """Resolve without raising; returns None when the path cannot be resolved."""
    try:
        return p.resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def resolve_authorized_file(raw: str) -> Path:
    """Same contract as resolve_authorized_dir, but for a single file."""
    p = Path(raw).expanduser()
    roots = authorized_roots()
    if not roots:
        raise PathNotAuthorized(
            "no authorized project directories configured (AUTHORIZED_PROJECT_ROOTS)"
        )
    resolved: Optional[Path] = None
    chosen_root: Optional[Path] = None
    if p.is_absolute():
        resolved = _safe_resolve(p)
        for root in roots:
            if resolved is not None and _contained(resolved, root):
                chosen_root = root
                break
    else:
        for root in roots:
            candidate = _safe_resolve(root / p)
            if candidate is not None and _contained(candidate, root):
                resolved = candidate
                chosen_root = root
                break
    if resolved is None or chosen_root is None:
        raise PathNotAuthorized(f"path not authorized: {raw}")
    if not resolved.is_file():
        raise PathNotAuthorized(f"not a file: {raw}")
    return resolved


def _contained(child: Path, root: Path) -> bool:
    try:
        child.relative_to(root)
        return True
    except ValueError:
        return False


def allowed_file(path: Path, allowed_extensions: frozenset) -> bool:
    """An explicit allowlist of file types for static analysis (requirement)."""
    return path.suffix.lower() in allowed_extensions
