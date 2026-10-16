"""Manifest and lockfile parsers for dependency auditing.

Supported formats:
- Node.js: package.json (dependencies/devDependencies), package-lock.json,
  npm-shrinkwrap.json, pnpm-lock.yaml (importers section only)
- Python: requirements.txt (incl. inline comments, extras, environment
  markers), pyproject.toml (PEP 621 [project] dependencies and
  poetry [tool.poetry.dependencies])

Contract honored by every parser:
- never invent a version: an unpinned requirement is recorded with an empty
  version string and flagged ``pinned=False``; audit tooling that requires a
  concrete version will report it as ``unpinned`` rather than guessing
- malformed input never raises: parsing failures are recorded in an ``errors``
  list so callers can distinguish "no dependencies" from "could not parse"
- nothing is executed and no network is touched here
- unknown file types are reported explicitly rather than parsed loosely
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger_name = "manifests"

# Maximum manifest size accepted (10 MiB) - manifests are text metadata files.
MAX_MANIFEST_BYTES = 10 * 1024 * 1024

# Explicit set of supported manifest/lockfile basenames.
NODE_MANIFESTS = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml"}
PYTHON_MANIFESTS = {"requirements.txt", "pyproject.toml"}
SUPPORTED_MANIFESTS = NODE_MANIFESTS | PYTHON_MANIFESTS


@dataclass
class DependencyEntry:
    """One resolved or declared dependency extracted from a manifest."""

    name: str
    ecosystem: str  # "npm" | "pypi"
    version: str = ""
    pinned: bool = False
    source_file: str = ""
    # Lockfile-derived resolutions are authoritative; manifest declares only.
    from_lockfile: bool = False


@dataclass
class ManifestParseResult:
    """Result of parsing one manifest file."""

    file_path: str
    ecosystem: str
    dependencies: List[DependencyEntry] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    # True when the file matched a supported name but could not be parsed.
    unsupported: bool = False
    # Non-fatal coverage-gap notes (skipped flag/URL lines). Unlike ``errors``
    # they record skipped input lines without failing the whole parse.
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and not self.unsupported


# --- helpers -----------------------------------------------------------------


def _norm_npm_name(name: str) -> str:
    name = name.strip()
    if name.startswith(("npm:",)):  # alias form "npm:<pkg>@<ver>"
        name = name.split(":", 1)[1]
    # scoped names (@x/y) keep their slash; strip trailing URL fragments.
    if "://" in name:
        name = name.rsplit("/", 1)[-1]
    return name


def _norm_pypi_name(name: str) -> str:
    # PEP 503 normalization: lowercase, runs of -_. -> single -
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _read_text(path: Path) -> Optional[str]:
    try:
        raw = path.read_bytes()[:MAX_MANIFEST_BYTES]
        return raw.decode("utf-8", errors="replace")
    except OSError:
        return None
    # note: caller records errors


def read_manifest(path: Path) -> Optional[str]:
    return _read_text(path)


# --- package.json ------------------------------------------------------------


def parse_package_json(text: str) -> ManifestParseResult:
    deps: List[DependencyEntry] = []
    errors: List[str] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return ManifestParseResult("package.json", "npm", errors=[f"invalid JSON: {exc.msg}"])
    if not isinstance(data, dict):
        return ManifestParseResult("package.json", "npm", errors=["top-level value is not an object"])

    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            if not isinstance(name, str) or not name.strip():
                continue
            spec_str = spec if isinstance(spec, str) else ""
            version = ""
            pinned = spec_str.startswith(("=", "")) and not any(c in spec_str for c in "><^~*|/ \t")
            if pinned and spec_str:
                version = spec_str.lstrip("=").strip()
            deps.append(
                DependencyEntry(
                    name=_norm_npm_name(name),
                    ecosystem="npm",
                    version=version,
                    pinned=bool(version),
                    source_file="package.json",
                )
            )
    return ManifestParseResult("package.json", "npm", dependencies=deps, errors=errors)


def parse_npm_lockfile(text: str, basename: str = "package-lock.json") -> ManifestParseResult:
    """Parse lockVersion 1/2/3 ``packages``/``dependencies`` trees.

    Records only real package entries; meta entries like the project root
    (empty key or without name) are skipped.
    """
    deps: List[DependencyEntry] = []
    errors: List[str] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return ManifestParseResult(basename, "npm", errors=[f"invalid JSON: {exc.msg}"])
    if not isinstance(data, dict):
        return ManifestParseResult(basename, "npm", errors=["top-level value is not an object"])

    packages = data.get("packages")
    if isinstance(packages, dict):
        seen: Dict[str, bool] = {}
        for key, info in packages.items():
            if not isinstance(info, dict):
                continue
            name = info.get("name")
            version = info.get("version")
            if not version or not isinstance(version, str):
                continue
            if not isinstance(name, str) or not name:
                # lockfile v2 entries are keyed "node_modules/<pkg>[/...]" and
                # usually carry no explicit name; derive it from the key.
                # A missing key (the root "" entry) yields no name and is
                # skipped below, never guessed.
                if not isinstance(key, str) or not key or "node_modules/" not in key:
                    continue
                name = key.rsplit("node_modules/", 1)[-1]
            if not name:
                continue
            if name in seen:
                continue
            seen[name] = True
            deps.append(
                DependencyEntry(
                    name=_norm_npm_name(name),
                    ecosystem="npm",
                    version=version,
                    pinned=True,
                    from_lockfile=True,
                    source_file=basename,
                )
            )
        return ManifestParseResult(basename, "npm", dependencies=deps, errors=errors)

    legacy = data.get("dependencies")
    if isinstance(legacy, dict):
        def _walk(node: Dict, out: List[DependencyEntry], depth: int) -> None:
            if depth > 20:
                return  # bound recursion on pathological trees
            for name, info in node.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version")
                if isinstance(version, str) and version:
                    out.append(
                        DependencyEntry(
                            name=_norm_npm_name(name),
                            ecosystem="npm",
                            version=version,
                            pinned=True,
                            from_lockfile=True,
                            source_file=basename,
                        )
                    )
                if isinstance(info.get("dependencies"), dict):
                    _walk(info["dependencies"], out, depth + 1)

        # Legacy v1 trees nest transitive deps under each entry's own
        # "dependencies" dict; shrinkwrap and package-lock.json walk alike.
        _walk(legacy, deps, 0)
        return ManifestParseResult(basename, "npm", dependencies=deps, errors=errors)

    return ManifestParseResult(basename, "npm", dependencies=deps, errors=["no recognized lockfile section"])


def parse_pnpm_lockfile(text: str, basename: str = "pnpm-lock.yaml") -> ManifestParseResult:
    """Minimal, dependency-free pnpm-lock v6+ reader.

    Parses the ``packages:`` section entries of the form quoted specifiers.
    Falls back to ``importers`` only for metadata; resolution lives in
    ``packages``. Not a YAML parser: deliberately line-based to avoid pulling
    in PyYAML, tolerating enough of pnpm's flat structure for auditing.
    """
    deps: List[DependencyEntry] = []
    errors: List[str] = []
    # Heuristic: after a line exactly "packages:" (possibly with comments
    # above), each 4-space-indented line of the form 'name@version:' or
    # '/name@ver(_hash):' holds a resolution. We capture name + version.
    in_packages = False
    entry_re = re.compile(r"^\s+'?(?P<spec>[^'\s]+?)'?:?\s*$")
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.strip() in ("packages:", "snapshots:"):
            in_packages = True
            continue
        if in_packages:
            if line and not line[0].isspace() and line.strip() != "":
                in_packages = False
                continue
            m = entry_re.match(line)
            if not m:
                continue
            spec = m.group("spec")
            # Key shapes handled: "name@version[:...]", "name@ver(peers)",
            # pnpm v6-style "/name@version/node_modules/name". Peel the
            # peer-suffix and trailing node_modules path first, then find the
            # version after the last '@' (scoped names keep their own '@').
            spec = spec.split("(", 1)[0]
            spec = spec.split("/node_modules/", 1)[0]
            spec = spec.lstrip("/")
            if " " in spec or "@" not in spec:
                continue
            name, _, version = spec.rpartition("@")
            name = name.strip()
            version = version.split("/", 1)[0].strip()
            if not name or not version:
                continue
            if name in {d.name for d in deps}:
                continue
            deps.append(
                DependencyEntry(
                    name=_norm_npm_name(name),
                    ecosystem="npm",
                    version=version,
                    pinned=True,
                    from_lockfile=True,
                    source_file=basename,
                )
            )
    if not deps:
        errors.append("no packages section recognized")
    return ManifestParseResult(basename, "npm", dependencies=deps, errors=errors)


# --- requirements.txt --------------------------------------------------------


_REQ_SPEC = re.compile(
    r"^\s*"
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]*\])?"  # extras - ignored for identity
    r"\s*(?P<op>===|==|~=|!=|<=|>=|<|>|@)?\s*"
    r"(?P<version>[^\s;,]*)"
    r"(?:\s*;\s*(?P<marker>.*))?\s*$"
)


def parse_requirements_txt(text: str, basename: str = "requirements.txt") -> ManifestParseResult:
    deps: List[DependencyEntry] = []
    errors: List[str] = []
    warnings: List[str] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()  # strip inline comments
        if not line or line.startswith(("-", ".")):  # flags, -r, -e, relative paths
            if line.startswith(("-r", "--requirement")) or line.startswith("-c"):
                warnings.append(f"line {lineno}: nested requirement file ref not followed")
            continue
        if line.startswith("http"):
            warnings.append(f"line {lineno}: direct URL reference ignored")
            continue
        m = _REQ_SPEC.match(line)
        if not m:
            if line:  # non-empty and unparsed
                errors.append(f"line {lineno}: unparsed requirement line")
            continue
        name = _norm_pypi_name(m.group("name"))
        op = m.group("op") or ""
        version = m.group("version") or ""
        marker = m.group("marker") or ""
        if "python_version" in marker or "sys_platform" in marker:
            # Keep record but mark unpinned - conditionally installed.
            deps.append(
                DependencyEntry(
                    name=name,
                    ecosystem="pypi",
                    version="",
                    pinned=False,
                    source_file=basename,
                )
            )
            continue
        if op in ("==", "===") and version:
            deps.append(
                DependencyEntry(
                    name=name,
                    ecosystem="pypi",
                    version=version.strip(),
                    pinned=True,
                    source_file=basename,
                )
            )
        else:
            # ~=, >=, <, @, plain name: no single installed version can be
            # trusted - record declaration only.
            deps.append(
                DependencyEntry(
                    name=name,
                    ecosystem="pypi",
                    version="",
                    pinned=False,
                    source_file=basename,
                )
            )
    return ManifestParseResult(basename, "pypi", dependencies=deps, errors=errors, warnings=warnings)


# --- pyproject.toml ----------------------------------------------------------


def parse_pyproject_toml(text: str, basename: str = "pyproject.toml") -> ManifestParseResult:
    deps: List[DependencyEntry] = []
    errors: List[str] = []
    try:
        import tomllib
    except ImportError:  # pragma: no cover - py3.11+ always present
        return ManifestParseResult(basename, "pypi", errors=["tomllib unavailable"])

    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError) as exc:
        return ManifestParseResult(basename, "pypi", errors=[f"invalid TOML: {exc}"])

    project = data.get("project") if isinstance(data, dict) else None
    declared: List[str] = []
    if isinstance(project, dict):
        raw = project.get("dependencies")
        if isinstance(raw, list):
            declared.extend(r for r in raw if isinstance(r, str))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    declared.extend(r for r in group if isinstance(r, str))

    # Poetry: [tool.poetry.dependencies] is a table (name = spec)
    poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data, dict) else {}
    poetry_deps = poetry.get("dependencies") if isinstance(poetry, dict) else None
    if isinstance(poetry_deps, dict):
        for name, spec in poetry_deps.items():
            version = ""
            pinned = False
            # Poetry semantics: a bare exact version spec ("2.0.1", also
            # {version = "1.0.0"}) pins that exact release; a constraint
            # specifier (^, ~, >, <, *, ranges) leaves the resolved version
            # open and is recorded as unpinned, never guessed.
            if isinstance(spec, str):
                pinned = bool(spec.strip()) and not any(c in spec for c in "><^~*=")
                version = spec.strip() if pinned else ""
            elif isinstance(spec, dict):
                v = spec.get("version")
                if isinstance(v, str) and v.strip():
                    pinned = not any(c in v for c in "><^~*=")
                    version = v.strip() if pinned else ""
            if not name or not isinstance(name, str):
                continue
            deps.append(
                DependencyEntry(
                    name=_norm_pypi_name(name),
                    ecosystem="pypi",
                    version=version,
                    pinned=pinned,
                    source_file=basename,
                )
            )

    # Parse the PEP 621 declared strings with the requirements parser for
    # consistent spec handling, then add to poetry records.
    if declared:
        text_block = "\n".join(declared)
        sub = parse_requirements_txt(text_block, basename=basename)
        dep_map = {d.name: d for d in deps}
        for d in sub.dependencies:
            if d.name in dep_map:
                continue
            d.source_file = basename
            deps.append(d)
        for err in sub.errors:
            errors.append(err)

    # Drop "python" pseudo-dependency often present in poetry tables.
    deps = [d for d in deps if d.name != "python"]
    return ManifestParseResult(basename, "pypi", dependencies=deps, errors=errors)


# --- dispatcher ----------------------------------------------------------------


def parse_manifest_file(path: Path) -> ManifestParseResult:
    """Parse one manifest file, dispatching on its basename.

    Unknown basenames produce an ``unsupported`` result; I/O errors produce a
    recorded error. Never raises.
    """
    basename = path.name
    if basename not in SUPPORTED_MANIFESTS:
        return ManifestParseResult(str(path), "unknown", unsupported=True,
                                   errors=[f"unsupported manifest name: {basename}"])
    text = read_manifest(path)
    if text is None:
        return ManifestParseResult(str(path), "unknown", errors=["file could not be read"])
    if basename == "package.json":
        res = parse_package_json(text)
        res.file_path = str(path)
        return res
    if basename in ("package-lock.json", "npm-shrinkwrap.json"):
        res = parse_npm_lockfile(text, basename)
        res.file_path = str(path)
        return res
    if basename == "pnpm-lock.yaml":
        res = parse_pnpm_lockfile(text, basename)
        res.file_path = str(path)
        return res
    if basename == "requirements.txt":
        res = parse_requirements_txt(text, basename)
        res.file_path = str(path)
        return res
    if basename == "pyproject.toml":
        res = parse_pyproject_toml(text, basename)
        res.file_path = str(path)
        return res
    return ManifestParseResult(str(path), "unknown", errors=["unhandled"], unsupported=True)


def discover_manifests(root: Path, max_depth: int = 3, max_files: int = 50) -> List[Path]:
    """Find supported manifests under an authorized root directory.

    Depth-bounded and count-bounded so a huge tree cannot stall a scan.
    Transparently skips node_modules, .venv, site-packages, and vcs dirs.
    """
    skip = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "site-packages",
            "__pycache__", "dist", ".tox", ".mypy_cache", ".pytest_cache"}
    found: List[Path] = []
    root = root.resolve()
    if not root.is_dir():
        return found
    try:
        root.iterdir()
    except OSError:
        return found

    def _walk(dirpath: Path, depth: int) -> None:
        if depth > max_depth or len(found) >= max_files:
            return
        try:
            children = sorted(dirpath.iterdir())
        except OSError:
            return
        for child in children:
            if child.name in skip or child.name.endswith(".dist-info"):
                continue
            if child.is_dir():
                _walk(child, depth + 1)
            elif child.name in SUPPORTED_MANIFESTS:
                found.append(child)
                if len(found) >= max_files:
                    return

    _walk(root, 0)
    return sorted(found)
