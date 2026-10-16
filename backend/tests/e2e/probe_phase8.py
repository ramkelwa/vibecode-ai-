"""Phase 8 probe: direct module investigation against the running fixture.

1. validate_url (the sync url_validation entry) and analyze_redirects on
   /chain1, /loop_a, /redir_ftp - findings + artifacts
2. where does FAKE_SECRET leak into report artifacts?
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("SCAN_ALLOW_PRIVATE_TARGETS", "true")
# backend/tests/e2e -> project backend dir is three levels up
BACKEND_DIR = os.path.abspath(os.path.join(HERE, "..", ".."))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
sys.path.insert(0, BACKEND_DIR)
sys.path.insert(0, HERE)

from fixture_vuln_app import FAKE_SECRET, start_fixture_server  # noqa: E402
from app.scanners.context import ScanContext  # noqa: E402
from app.scanners import url_validation, html_analysis  # noqa: E402

srv, port = start_fixture_server()
base = f"http://127.0.0.1:{port}"


async def probe(path: str) -> None:
    ctx = ScanContext(target_url=base + path)
    findings = url_validation.validate_url(base + path)
    print(f"### validate_url({path}) -> {len(findings)} finding(s)")
    for f in findings:
        print("   -", f.title, "|", f.evidence.get("error", ""))
    print("   artifacts:", json.dumps({k: v for k, v in ctx.artifacts.items() if "redirect" in k})[:400])
    r = await url_validation.analyze_redirects(ctx)
    print(f"### analyze_redirects({path}) -> {len(r)} finding(s)")
    for f in r:
        print("   -", f.title, "| sev", f.severity, "|", f.evidence.get("path", ""))
    print("   artifacts:", json.dumps({k: v for k, v in ctx.artifacts.items() if "redirect" in k})[:400])


async def probe_secret_leak() -> None:
    ctx = ScanContext(target_url=base + "/")
    await html_analysis.analyze_html(ctx)
    blob = json.dumps(ctx.artifacts, ensure_ascii=False)
    print(f"### html artifacts contain FAKE_SECRET: {FAKE_SECRET in blob}")
    # hunt the leaking key
    def hunt(d, prefix=""):
        if isinstance(d, dict):
            for k, v in d.items():
                hunt(v, f"{prefix}.{k}")
        elif isinstance(d, list):
            for i, v in enumerate(d):
                hunt(v, f"{prefix}[{i}]")
        elif isinstance(d, str) and FAKE_SECRET in d:
            print("   LEAK at", prefix, "=", d[:120])
    hunt(ctx.artifacts)


async def main() -> None:
    for p in ("/chain1", "/loop_a", "/redir_ftp"):
        await probe(p)
    await probe_secret_leak()


if __name__ == "__main__":
    asyncio.run(main())
