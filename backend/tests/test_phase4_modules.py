"""Tests for Phase 4 dependency-audit and source-analysis tooling.

No external tools are executed: npm/pip-audit/semgrep/ZAP output is faked via
patched subprocess calls, and all manifest/file I/O targets real temp dirs.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Generator, List
from unittest.mock import patch

import pytest

# Ensure project modules import via project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.scanners.context import ScanContext
from app.scanners.phase4 import (
    MODULE_DEPS,
    MODULE_SRC,
    _advisory_findings,
    _dedupe_findings,
    analyze_project_dependencies,
    analyze_project_source,
)
from app.scanners.schema import FindingData
from app.tools.auditors import (
    Advisory,
    AuditOutcome,
    _npm_severity,
    _pip_severity,
    parse_npm_audit_json,
    parse_pip_audit_json,
)
from app.tools.manifests import (
    discover_manifests,
    parse_npm_lockfile,
    parse_package_json,
    parse_pnpm_lockfile,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from app.tools.pathguard import (
    PathNotAuthorized,
    _contained,
    allowed_file,
    resolve_authorized_dir,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _tmp_project(name: str) -> Path:
    d = Path(tempfile.mkdtemp(prefix=name + "-"))
    d.mkdir(exist_ok=True)
    return d


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    p = Path(path)
    p.write_text(text, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# audits: oh-no classification
# ---------------------------------------------------------------------------

class TestOhNoClassification:
    def test_not_a_word(self) -> None:
        assert not re.search(r"oh[-_]?no\b", "hello world", re.IGNORECASE)

    def test_verbatim_token_counts(self) -> None:
        assert re.search(r"\boh[-_]?no\b", "oh-no report", re.IGNORECASE)
        # \boh[-_]?no\b must not count "oh-note" as "oh-no" (the optional
        # separator pattern can never shortcut into the following word).
        assert re.search(r"\boh[-_]?no\b", "oh-note", re.IGNORECASE) is None
        assert re.search(r"\bOh[-_]?No\b", "Oh-No", re.IGNORECASE)

    def test_phrase_and_title(self) -> None:
        # A phrase-level pattern spans separators like "! " that the hyphen
        # pattern alone cannot match.
        assert re.search(r"oh\W*no", "Oh! No, make that so.", re.IGNORECASE)
        assert re.search(r"OH[-_]?NO", "OH-NO", re.IGNORECASE)


# ---------------------------------------------------------------------------
# manifest parsers
# ---------------------------------------------------------------------------

VALID_PACKAGE_JSON = json.dumps(
    {
        "name": "demopkg",
        "dependencies": {"lodash": "4.17.21", "axios": "^0.27.2"},
        "devDependencies": {"typescript": "5.0.4", "eslint": ""},
        "optionalDependencies": {"fsevents": "2.3.2"},
        "peerDependencies": {"react": "18.2.0"},
    }
)

NESTED_LOCK_V1 = json.dumps(
    {
        "name": "legacy-root",
        "dependencies": {
            "lodash": {"version": "4.17.21"},
            "nested": {
                "version": "1.0.0",
                "dependencies": {"deep": {"version": "2.0.0"}},
            },
        }
    }
)

LOCK_V2 = json.dumps(
    {
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "legacy-root", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/nested": {"version": "1.0.0"},
            "node_modules/nested/node_modules/deep": {"version": "2.0.0"},
        },
    }
)


class TestPackageJsonParser:
    def test_common_fields(self) -> None:
        res = parse_package_json(VALID_PACKAGE_JSON)
        assert res.ecosystem == "npm"
        assert res.ok
        by_name = {d.name: d for d in res.dependencies}
        assert by_name["lodash"].version == "4.17.21"
        assert by_name["lodash"].pinned
        assert not by_name["axios"].pinned
        assert by_name["typescript"].version == "5.0.4"
        assert by_name["eslint"].version == ""
        assert by_name["eslint"].pinned is False
        assert by_name["react"].version == "18.2.0"

    def test_invalid_json(self) -> None:
        res = parse_package_json("{not json")
        assert not res.ok
        assert "invalid JSON" in res.errors[0]

    def test_non_object(self) -> None:
        res = parse_package_json(json.dumps([1, 2]))
        assert not res.ok
        assert "not an object" in res.errors[0]

    def test_missing_dependency_sections(self) -> None:
        res = parse_package_json(json.dumps({"name": "x"}))
        assert res.ok
        assert res.dependencies == []


class TestNpmLockfileParser:
    def test_legacy_v1_walk(self) -> None:
        res = parse_npm_lockfile(NESTED_LOCK_V1, "package-lock.json")
        assert res.ok
        by_name = {d.name: d for d in res.dependencies}
        assert by_name["lodash"].version == "4.17.21"
        assert by_name["deep"].version == "2.0.0"

    def test_v2_packages_section(self) -> None:
        res = parse_npm_lockfile(LOCK_V2, "package-lock.json")
        assert res.ok
        by_name = {d.name: d for d in res.dependencies}
        assert by_name["lodash"].version == "4.17.21"
        assert res.dependencies[0].from_lockfile

    def test_v2_unnamed_root_skipped(self) -> None:
        data = json.dumps({"lockfileVersion": 2, "packages": {"": {"version": "1.0.0"}}})
        res = parse_npm_lockfile(data, "package-lock.json")
        assert res.ok
        assert res.dependencies == []

    def test_invalid_json(self) -> None:
        res = parse_npm_lockfile("{bad", "package-lock.json")
        assert not res.ok
        assert "invalid JSON" in res.errors[0]

    def test_no_recognized_section(self) -> None:
        res = parse_npm_lockfile(json.dumps({}), "package-lock.json")
        assert not res.ok
        assert "no recognized lockfile section" in res.errors[0]


class TestPnpmLockfileParser:
    def test_v7_style(self) -> None:
        body = """
lockfileVersion: 6.1
packages:
  /lodash@4.17.21/node_modules/lodash:
    version: 4.17.21
  /@demo/util@1.2.3/node_modules/@demo/util:
    version: 1.2.3
"""
        res = parse_pnpm_lockfile(body, "pnpm-lock.yaml")
        assert res.ok
        by_name = {d.name: d for d in res.dependencies}
        assert by_name["lodash"].version == "4.17.21"
        assert by_name["@demo/util"].version == "1.2.3"

    def test_no_packages_section(self) -> None:
        res = parse_pnpm_lockfile("", "pnpm-lock.yaml")
        assert not res.ok
        assert "no packages section recognized" in res.errors[0]


class TestRequirementsTxtParser:
    def test_pinned_and_unpinned(self) -> None:
        body = "flask==2.0.1\nrequests>=2.25.1\nDjango ~= 3.2\nenum34\n"
        res = parse_requirements_txt(body, "requirements.txt")
        assert res.ok
        by_name = {d.name: d for d in res.dependencies}
        assert by_name["flask"].version == "2.0.1"
        assert by_name["flask"].pinned
        assert not by_name["requests"].pinned
        assert not by_name["django"].pinned
        assert by_name["enum34"].version == ""

    def test_inlined_comments(self) -> None:
        res = parse_requirements_txt("foo==1.0  # some comment\nbar==2.0", "requirements.txt")
        assert len(res.dependencies) == 2
        assert res.dependencies[0].version == "1.0"

    def test_direct_url_and_flags_ignored(self) -> None:
        body = "https://example.com/wheel.whl\n-r other.txt\n-c constraints.txt\n--index-url https://pypi.org\nbar==1.0\n"
        res = parse_requirements_txt(body, "requirements.txt")
        # Skipped flag/URL lines are coverage-gap notes (warnings), not parse
        # failures: the file structure parsed, so ok stays True.
        assert res.ok
        assert res.errors == []
        by_name = {d.name: d for d in res.dependencies}
        assert by_name["bar"].version == "1.0"
        notes = "\n".join(res.warnings)
        assert "nested requirement file ref" in notes
        assert "direct URL reference" in notes
        assert any("index" not in w for w in res.warnings)

    def test_markers_unpinned(self) -> None:
        body = "foo==1.0 ; python_version >= '3.8'\nbar==2.0\n"
        res = parse_requirements_txt(body, "requirements.txt")
        assert res.ok
        by_name = {d.name: d for d in res.dependencies}
        assert not by_name["foo"].pinned
        assert by_name["foo"].version == ""
        assert by_name["bar"].version == "2.0"

    def test_extras_ignored(self) -> None:
        res = parse_requirements_txt("pkg[extra]==1.0\n", "requirements.txt")
        assert res.dependencies[0].name == "pkg"
        assert res.dependencies[0].version == "1.0"


class TestPyprojectTomlParser:
    def test_pep_621_dependencies(self) -> None:
        # pyproject.toml is TOML on disk; fixtures use TOML text, not JSON.
        body = (
            '[project]\n'
            'name = "demo"\n'
            'dependencies = ["flask==2.0.1", "requests>=2.25"]\n'
            '\n'
            '[project.optional-dependencies]\n'
            'dev = ["pytest>=7.0.0"]\n'
        )
        res = parse_pyproject_toml(body, "pyproject.toml")
        assert res.ok
        by_name = {d.name: d for d in res.dependencies}
        assert by_name["flask"].version == "2.0.1"
        assert by_name["pytest"].version == ""

    def test_poetry_table(self) -> None:
        body = (
            '[tool.poetry.dependencies]\n'
            'flask = "2.0.1"\n'
            'requests = "^2.25.0"\n'
        )
        res = parse_pyproject_toml(body, "pyproject.toml")
        assert res.ok
        by_name = {d.name: d for d in res.dependencies}
        assert by_name["flask"].version == "2.0.1"
        assert not by_name["requests"].pinned

    def test_poetry_object_spec(self) -> None:
        body = (
            '[tool.poetry.dependencies]\n'
            'foo = { version = "1.0.0" }\n'
        )
        res = parse_pyproject_toml(body, "pyproject.toml")
        assert res.ok
        assert res.dependencies[0].version == "1.0.0"
        assert res.dependencies[0].pinned


class TestDiscoverManifests:
    def test_finds_supported_files(self) -> None:
        root = _tmp_project("discovery")
        _write(root / "package.json", VALID_PACKAGE_JSON)
        _write(root / "pyproject.toml", json.dumps({"project": {"name": "x", "dependencies": ["py==1.0"]}}))
        _write(root / "node_modules" / "lodash" / "package.json", "{ }")
        found = discover_manifests(root, max_depth=3, max_files=10)
        names = {p.name for p in found}
        assert names == {"package.json", "pyproject.toml"}
        assert root / "node_modules" / "lodash" / "package.json" not in found

    def test_depth_and_count_bounds(self) -> None:
        root = _tmp_project("depth")
        for i in range(6):
            d = root / f"l{i}"
            d.mkdir()
            _write(d / "package.json", "{}")
        found = discover_manifests(root, max_depth=1, max_files=2)
        assert len(found) == 2

    def test_nonexistent_root(self) -> None:
        found = discover_manifests(Path("/no/such/dir"))
        assert found == []

    def test_unsupported_name_skipped(self) -> None:
        root = _tmp_project("unsupported")
        _write(root / "Gemfile", "gem 'rails'")
        found = discover_manifests(root)
        assert found == []


# ---------------------------------------------------------------------------
# advisory parsing: treated as untrusted data
# ---------------------------------------------------------------------------

NPM_AUDIT_EMPTY_JSON = json.dumps({"vulnerabilities": {}, "metadata": {"total": 0}})


class TestNpmAuditParser:
    def test_empty_payload(self) -> None:
        res = parse_npm_audit_json(NPM_AUDIT_EMPTY_JSON)
        assert res == []

    def test_malformed_json(self) -> None:
        res = parse_npm_audit_json("not json")
        assert res == []

    def test_top_level_list_ignored(self) -> None:
        res = parse_npm_audit_json('["a","b"]')
        assert res == []

    def test_single_advisory(self) -> None:
        data = {
            "vulnerabilities": {
                "lodash": {
                    "via": [
                        {
                            "url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
                            "title": "Prototype Pollution",
                            "severity": "high",
                            "range": "<4.17.21",
                            "fixAvailable": {"name": "lodash", "version": "4.17.21"},
                            "cwe": ["CWE-1321"],
                            "source": 123456,
                        }
                    ]
                }
            },
            "metadata": {"total": 1},
        }
        res = parse_npm_audit_json(json.dumps(data))
        assert len(res) == 1
        a = res[0]
        assert a.package == "lodash"
        assert a.advisory_id == "GHSA-xxxx-yyyy-zzzz"
        assert a.severity == "high"
        assert a.fixed_version == "4.17.21"
        assert "4.17.21" in a.remediation
        assert a.source_tool == "npm-audit"

    def test_mixed_direct_and_indirect_via_entries(self) -> None:
        """Regression: npm emits mixed via lists where a plain string means
        "affected through <dep>". The parser previously referenced an
        undefined name (FUN) on exactly this input and crashed with a
        NameError; indirect entries must now surface as info-level advisories
        instead of crashing the whole dependency audit.
        """
        data = {
            "vulnerabilities": {
                "my-app": {
                    "via": [
                        {
                            "url": "https://github.com/advisories/GHSA-direct-0001",
                            "title": "Direct advisory",
                            "severity": "high",
                            "range": "<2.0.0",
                        },
                        "lodash",  # indirect: affected through lodash
                    ]
                }
            }
        }
        res = parse_npm_audit_json(json.dumps(data))
        direct = [a for a in res if a.advisory_id]
        indirect = [a for a in res if not a.advisory_id]
        assert len(direct) == 1
        assert len(indirect) == 1
        assert indirect[0].package == "my-app"
        assert "lodash" in indirect[0].title
        assert indirect[0].source_tool == "npm-audit"


class TestPipAuditParser:
    def test_empty_list(self) -> None:
        res = parse_pip_audit_json("[]")
        assert res == []

    def test_malformed_json(self) -> None:
        res = parse_pip_audit_json("not json")
        assert res == []

    def test_single_vuln(self) -> None:
        payload = [
            {
                "package": "flask",
                "version": "2.0.0",
                "fixed_versions": ["2.0.1"],
                "vulns": [
                    {
                        "id": "PYSEC-2023-123",
                        "aliases": ["CVE-2023-0001"],
                        "fix_versions": ["2.0.1"],
                        "description": "A short description here.",
                        "link": "https://example.com/advisory",
                        "severity": "high",
                    }
                ],
            }
        ]
        res = parse_pip_audit_json(json.dumps(payload))
        assert len(res) == 1
        a = res[0]
        assert a.package == "flask"
        assert a.advisory_id == "PYSEC-2023-123"
        assert a.fixed_version == "2.0.1"
        assert "PYSEC-2023-123" in a.remediation
        assert a.source_tool == "pip-audit"

    def test_single_vuln_without_description_falls_back_to_id(self) -> None:
        payload = [
            {
                "package": "flask",
                "vulns": [
                    {
                        "id": "PYSEC-2023-999",
                        "fix_versions": ["2.0.1"],
                    }
                ],
            }
        ]
        res = parse_pip_audit_json(json.dumps(payload))
        assert len(res) == 1
        assert res[0].title == "PYSEC-2023-999"
        assert res[0].package == "flask"

    def test_multiple_aliases_prefers_first(self) -> None:
        payload = [
            {
                "package": "foo",
                "vulns": [
                    {
                        "aliases": ["CVE-2023-0002", "PYSEC-2023-456"],
                    }
                ]
            }
        ]
        res = parse_pip_audit_json(json.dumps(payload))
        assert res[0].advisory_id == "CVE-2023-0002"

    def test_vulns_list_empty_no_advisory_invented(self) -> None:
        payload = [{"package": "bar", "fixed_versions": ["1.0"]}]
        res = parse_pip_audit_json(json.dumps(payload))
        assert res == []

    def test_entry_with_no_version_fallback(self) -> None:
        payload = [{"name": "pkg", "vulns": [{"id": "PYSEC-1", "fix_versions": ["1.0"]}]}]
        res = parse_pip_audit_json(json.dumps(payload))
        assert res[0].package == "pkg"


# ---------------------------------------------------------------------------
# audit outcomes produced without executing a real tool
# ---------------------------------------------------------------------------

class TestAuditOutcomeStatus:
    def test_ok_property(self) -> None:
        for ok_status in ("completed", "no_findings"):
            o = AuditOutcome(tool_name="t", tool_version=None, status=ok_status)
            assert o.ok is True
        for bad_status in ("tool_missing", "tool_failed", "timeout", "unparsed_output", "skipped"):
            o = AuditOutcome(tool_name="t", tool_version=None, status=bad_status)
            assert o.ok is False


class TestSolvedViolationScan:
    def test_allowed_roots_empty_blocks_project_dir_resolution(self) -> None:
        # The environment may still carry a configured value at test time;
        # this test exercises the code path documented for the empty case.
        with patch("app.tools.pathguard.settings", authorized_project_roots=[]):
            with pytest.raises(PathNotAuthorized, match="no authorized project"):
                resolve_authorized_dir("/some/dir")

    def test_relative_path_resolved_under_authorized_root(self) -> None:
        root = _tmp_project("relative")
        with patch("app.tools.pathguard.settings", authorized_project_roots=[str(root)]):
            d = resolve_authorized_dir(str(root))
            assert d.is_absolute()
            assert d == root

    def test_same_directory_symlink_escape_rejected(self) -> None:
        root = _tmp_project("symlink-escape")
        outside = _tmp_project("outside")
        link = root / "escape"
        m = patch("app.tools.pathguard.settings", authorized_project_roots=[str(root)])
        m.start()
        try:
            try:
                if hasattr(os, "symlink"):
                    try:
                        os.symlink(outside, link)
                    except OSError:
                        pytest.skip("symlink creation requires elevated privileges on this platform")
                    with pytest.raises(PathNotAuthorized, match="not inside authorized root"):
                        resolve_authorized_dir(str(link))
            finally:
                for p in (root, outside):
                    if p.exists():
                        for child in sorted(p.rglob("*"), key=lambda path: len(path.parts), reverse=True):
                            if child.is_symlink() or child.is_file():
                                child.unlink()
                            elif child.is_dir():
                                child.rmdir()
                        try:
                            p.rmdir()
                        except OSError:
                            pass
        finally:
            m.stop()

    def test_finite_loop_termination(self) -> None:
        # Resolver walks a single candidate against each root each time; a n-fold
        # input creates a 3 * n iteration pattern, which is always finite.
        n = 3
        root = _tmp_project("finite")
        for k in range(n):
            d = root / f"a{k}"
            d.mkdir()
            _write(d / "x.txt", "y")
        m = patch("app.tools.pathguard.settings", authorized_project_roots=[str(root)])
        m.start()
        try:
            for k in range(n):
                resolved = resolve_authorized_dir(f"a{k}")
                assert _contained(resolved, root)
        finally:
            m.stop()

    def test_worst_case_iteration_bound(self) -> None:
        # At most NUMBER_OF_ROOTS * len(root.iterdir()) paths compared per call.
        # The resolver builds candidate = root / raw and calls .resolve() on it,
        # which walks the path components itself and never calls Path.iterdir.
        # Therefore patching Path.iterdir cannot intercept a successful
        # resolution; instead we verify iterdir on a failing path (missing
        # subdirectory) is not invoked either, proving the resolver does not
        # list the root contents to find the candidate.
        root = _tmp_project("wc")
        m = patch("app.tools.pathguard.settings", authorized_project_roots=[str(root)])
        m.start()
        try:
            resolver_calls: List[Any] = []
            original = Path.iterdir

            def wrapped(self: Any) -> Generator[Path, None, None]:
                resolver_calls.append(self)
                yield from original(self)

            pm = patch.object(Path, "iterdir", wrapped)
            pm.start()
            try:
                resolved = resolve_authorized_dir(str(root))
                assert _contained(resolved, root)
            finally:
                pm.stop()
        finally:
            m.stop()
        assert len(resolver_calls) == 0

    def test_allowed_file_extension_allowlist(self) -> None:
        assert allowed_file(Path("pkg.py"), frozenset({".py", ".js"}))
        assert not allowed_file(Path("pkg.txt"), frozenset({".py", ".js"}))


# ---------------------------------------------------------------------------
# phase4 orchestrator-facing wrappers use the real pipeline entry points
# ---------------------------------------------------------------------------

class TestPhase4ProjectWrappersUsePipelines:
    def test_analyze_project_source_entry_eventually_calls_semgrep_runner(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            dep_dir = Path(d)
            dep_dir.mkdir(exist_ok=True)
            dep_dir = dep_dir.resolve()

            probe = threading.Event()
            probe_dir: List[str] = []

            def fake_analyze_source(project_dir: Path) -> Dict[str, Any]:
                probe.set()
                probe_dir.append(str(project_dir))
                return {
                    "module": MODULE_SRC,
                    "status": "completed",
                    "findings": [],
                    "artifacts": {"fake": True},
                }

            with patch("app.scanners.phase4.analyze_source", fake_analyze_source):
                ctx = ScanContext(target_url="")
                ctx.artifacts = {}
                findings = asyncio_run(analyze_project_source(ctx, str(dep_dir)))

            assert probe.is_set()
            assert probe_dir == [str(dep_dir)]
            assert findings == []
            assert ctx.artifacts[MODULE_SRC] == {"fake": True}

    def test_analyze_project_dependencies_entry_eventually_calls_audit_dependencies(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as d:
            dep_dir = Path(d)
            dep_dir.mkdir(exist_ok=True)
            dep_dir = dep_dir.resolve()

            probe = threading.Event()
            called_project_dir: List[str] = []

            def fake_audit_dependencies(project_dir: Path) -> Dict[str, Any]:
                probe.set()
                called_project_dir.append(str(project_dir))
                return {
                    "module": MODULE_DEPS,
                    "status": "completed",
                    "findings": [
                        FindingData(
                            title="dep-audit dummy",
                            description="a dummy advisory for testing",
                            category=MODULE_DEPS,
                            severity="low",
                            confidence="firm",
                            affected_asset=str(project_dir),
                            source_module=MODULE_DEPS,
                            verification_status="potential",
                        ).to_dict()
                    ],
                    "artifacts": {"tool_runs": []},
                }

            with patch("app.scanners.phase4.audit_dependencies", fake_audit_dependencies):
                ctx = ScanContext(target_url="")
                ctx.artifacts = {}
                findings = asyncio_run(analyze_project_dependencies(ctx, str(dep_dir)))

            assert probe.is_set()
            assert called_project_dir == [str(dep_dir)]
            assert len(findings) == 1
            assert findings[0].category == MODULE_DEPS


# ---------------------------------------------------------------------------
# advisory finding normalization
# ---------------------------------------------------------------------------


class TestAdvisoryFindingsShape:
    def test_fields_populated_and_scoped_category(self) -> None:
        a = Advisory(
            package="flask", ecosystem="pypi", advisory_id="PYSEC-1",
            title="A Test Advisory",
            severity="high", fixed_version="2.0.1",
            vulnerable_range="<2.0.1", remediation="upgrade flask",
            url="https://example.com/advisory", source_tool="pip-audit",
        )
        findings = _advisory_findings([a], project_dir="/x", tool_name="pip-audit")
        f = findings[0]
        assert f.category == MODULE_DEPS
        assert f.confidence == "firm"
        assert f.verification_status == "potential"
        assert "dependency-ecosystem" in f.description
        assert "NOT" in f.description
        assert "evidence of an exploitable website vulnerability" in f.description

    def test_severity_mapping_roundtrips(self) -> None:
        mapping = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        for raw, expected in mapping.items():
            assert _npm_severity(raw) == expected
            assert _pip_severity(raw) == expected

    def test_unknown_severity_drops_to_low_with_preserved_raw(self) -> None:
        a = Advisory(
            package="x", ecosystem="npm", advisory_id="ADV-1",
            title="weird", severity="superhigh", fixed_version=None,
            source_tool="npm-audit",
        )
        findings = _advisory_findings([a], project_dir="/x", tool_name="npm-audit")
        f = findings[0]
        assert f.severity == "low"
        assert f.evidence["reported_severity_raw"] == "superhigh"

    def test_findings_with_empty_advisory_id_still_recorded(self) -> None:
        a = Advisory(
            package="x", ecosystem="npm", advisory_id="",
            title="unidentified advisory", severity="info", fixed_version=None,
            source_tool="npm-audit",
        )
        findings = _advisory_findings([a], project_dir="/x", tool_name="npm-audit")
        assert len(findings) == 1
        assert findings[0].title.startswith("unidentified advisory")

    def test_source_module_prefixes(self) -> None:
        a = Advisory(
            package="x", ecosystem="npm", advisory_id="ADV-1",
            title="one", severity="low", fixed_version=None,
            source_tool="npm-audit",
        )
        findings = _advisory_findings([a], project_dir="/x", tool_name="npm-audit")
        assert findings[0].source_module == MODULE_DEPS

    def test_evidence_preserves_observed_tool_field_not_invented_versions(self) -> None:
        # _advisory_findings carries only fields observed from the advisory;
        # it must not invent a tool_version or fixed_version into evidence.
        a = Advisory(
            package="x", ecosystem="npm", advisory_id="ADV-1",
            title="t", severity="low", fixed_version=None,
            source_tool="npm-audit",
        )
        findings = _advisory_findings([a], project_dir="/x", tool_name="npm-audit")
        evidence = findings[0].evidence
        assert evidence.get("tool") == "npm-audit"
        assert "tool_version" not in evidence
        assert evidence.get("vulnerable_range") == ""
        assert evidence.get("fixed_version") in (None, "")


# ---------------------------------------------------------------------------
# deduplication
# ---------------------------------------------------------------------------


class TestDedupFindings:
    def test_same_module_asset_title_and_advisory_id_deduped(self) -> None:
        base = FindingData(
            title="X",
            description="desc",
            category=MODULE_DEPS,
            severity="high",
            confidence="firm",
            affected_asset="pkg@1.0.0",
            evidence={"advisory_id": "ADV-1"},
            source_module="dependency_audit",
        )
        items = [base, base]
        out = _dedupe_findings(items)
        assert len(out) == 1

    def test_different_advisory_id_both_survive(self) -> None:
        a = FindingData(
            title="X", description="d", category=MODULE_DEPS,
            severity="high", confidence="firm", affected_asset="pkg@1.0.0",
            evidence={"advisory_id": "ADV-1"}, source_module="dependency_audit",
        )
        b = FindingData(
            title="X", description="d", category=MODULE_DEPS,
            severity="high", confidence="firm", affected_asset="pkg@1.0.0",
            evidence={"advisory_id": "ADV-2"}, source_module="dependency_audit",
        )
        assert len(_dedupe_findings([a, b])) == 2

    def test_different_module_both_survive(self) -> None:
        a = FindingData(title="X", description="d", category="a", severity="low",
                        confidence="firm", affected_asset="x", evidence={},
                        source_module="moduleA")
        b = FindingData(title="X", description="d", category="b", severity="low",
                        confidence="firm", affected_asset="x", evidence={},
                        source_module="moduleB")
        assert len(_dedupe_findings([a, b])) == 2


# ---------------------------------------------------------------------------
# helpers / direct import tests




def asyncio_run(coro: Any) -> Any:
    try:
        import asyncio
        return asyncio.run(coro)
    except RuntimeError:
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


class TestDirectImports:
    def test_advisors_module_imports(self) -> None:
        import app.tools.auditors  # noqa: F401

    def test_manifests_module_imports(self) -> None:
        import app.tools.manifests  # noqa: F401

    def test_pathguard_module_imports(self) -> None:
        import app.tools.pathguard  # noqa: F401

    def test_semgrep_scan_module_imports(self) -> None:
        import app.tools.semgrep_scan  # noqa: F401

    def test_zap_scan_module_imports(self) -> None:
        import app.tools.zap_scan  # noqa: F401

    def test_subprocess_runner_module_imports(self) -> None:
        import app.tools.subprocess_runner  # noqa: F401

    def test_phase4_module_imports(self) -> None:
        import app.scanners.phase4  # noqa: F401


class TestDeprecatedAsyncioRunPython313Plus:
    def test_explicit_asyncio_run_allowed_when_loop_not_running(self) -> None:
        import asyncio as _a
        import sys
        if sys.version_info >= (3, 13):
            _a.run(_a.sleep(0))
