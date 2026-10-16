"""Phase 8 probe #2: hunt FAKE_SECRET across a real pipeline run + npm audit.

1. Run the real orchestrator pipeline against the fixture site, then check
   every persisted artifact key and every finding field for FAKE_SECRET.
2. Run `npm audit --package-lock-only` on the project fixture to see what the
   dependency_audit stage may have been waiting on.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(HERE, "..", ".."))
os.environ.setdefault("SCAN_ALLOW_PRIVATE_TARGETS", "true")
_tmp = tempfile.mkdtemp(prefix="vibeshield-probe-")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_tmp}/probe.db")
sys.path.insert(0, BACKEND_DIR)
sys.path.insert(0, HERE)

from app.core.database import Base, engine, SessionLocal  # noqa: E402
from app.scanners.context import ScanContext  # noqa: E402
from app.scanners.orchestrator import (  # noqa: E402
    MODULE_PIPELINE,
    _run_module,
    validate_url_entry,
)
from app.models import Finding, Scan  # noqa: E402
from fixture_vuln_app import FAKE_SECRET, start_fixture_server  # noqa: E402

Base.metadata.create_all(bind=engine)

srv, port = start_fixture_server()
base = f"http://127.0.0.1:{port}"

test_db = SessionLocal()
scan_row = Scan(target_url=base + "/", status="running")
test_db.add(scan_row)
test_db.commit()
scan_id = scan_row.id

ctx = ScanContext(target_url=base + "/")
import asyncio  # noqa: E402


def run_pipeline() -> None:
    for module_name, module_path in MODULE_PIPELINE[:4]:  # first few modules incl http_headers
        _run_module(test_db, scan_id, module_name, module_path, ctx)
    # js pipeline
    for module_name, module_path in MODULE_PIPELINE[6:]:
        _run_module(test_db, scan_id, module_name, module_path, ctx)


run_pipeline()
blob_all = json.dumps(ctx.artifacts, default=str, ensure_ascii=False)
print("### artifacts contain FAKE_SECRET:", FAKE_SECRET in blob_all)


def hunt(d, prefix: str) -> None:
    if isinstance(d, dict):
        for k, v in d.items():
            hunt(v, f"{prefix}.{k}")
    elif isinstance(d, list):
        for i, v in enumerate(d):
            hunt(v, f"{prefix}[{i}]")
    elif isinstance(d, str) and FAKE_SECRET in d:
        print("   LEAK at", prefix, "=", d[:160])


hunt(ctx.artifacts, "artifacts")

rows = test_db.query(Finding).filter(Finding.scan_id == scan_id).all()
for r in rows:
    fdict = {
        "title": r.title, "description": r.description, "impact": r.impact,
        "remediation": r.remediation, "evidence": r.evidence,
    }
    blob = json.dumps(fdict, default=str, ensure_ascii=False)
    if FAKE_SECRET in blob:
        print("### FINDING ROW leaks:", r.title)
        hunt(fdict, "finding")
print("### row count:", len(rows))

test_db.close()

# ---------------- npm audit on the fixture project --------------------------
proj = Path(HERE) / "project_fixture"
cmd = ["npm", "audit", "--package-lock-only", "--json"]
print("### running:", " ".join(cmd), "in", proj)
try:
    r = subprocess.run(cmd, cwd=str(proj), capture_output=True, text=True,
                       timeout=60, encoding="utf-8", errors="replace")
    print("### npm audit exit", r.returncode)
    print("### stdout head:", (r.stdout or "")[:300])
    print("### stderr head:", (r.stderr or "")[-500:])
except subprocess.TimeoutExpired:
    print("### npm audit TIMEOUT after 60s")
