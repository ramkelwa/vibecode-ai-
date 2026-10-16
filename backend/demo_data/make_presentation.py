"""Generate the VibeShield AI project presentation (.pptx).

Run:  python demo_data/make_presentation.py
Output: demo_data/VibeShield_AI_Presentation.pptx
"""

from __future__ import annotations

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Inches, Pt

# --- palette -----------------------------------------------------------------
BG = RGBColor(0x0F, 0x17, 0x2A)          # slate-950-ish dark blue
PANEL = RGBColor(0x1E, 0x29, 0x3B)       # slate-800
ACCENT = RGBColor(0x38, 0xBD, 0xF8)      # sky-500
GREEN = RGBColor(0x34, 0xD3, 0x99)       # emerald-400
AMBER = RGBColor(0xFB, 0xBF, 0x24)       # amber-400
TEXT = RGBColor(0xE2, 0xE8, 0xF0)        # slate-200
MUTED = RGBColor(0x94, 0xA3, 0xB8)       # slate-400

SW, SH = Inches(13.333), Inches(7.5)


def add_slide(prs: Presentation) -> "tuple":  # (slide, blank page shape host)
    slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank
    bg = slide.shapes.add_shape(1, 0, 0, SW, SH)        # rectangle
    bg.fill.solid()
    bg.fill.fore_color.rgb = BG
    bg.line.fill.background()
    bg.shadow.inherit = False
    return slide, bg


def txt(slide, x, y, w, h, text, size=18, color=TEXT, bold=False,
        align=PP_ALIGN.LEFT, wrap=True, line_spacing=1.0):
    box = slide.shapes.add_textbox(x, y, w, h)
    tf = box.text_frame
    tf.word_wrap = wrap
    lines = text.split("\n")
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.line_spacing = line_spacing
        r = p.add_run()
        r.text = line
        r.font.size = Pt(size)
        r.font.color.rgb = color
        r.font.bold = bold
        r.font.name = "Segoe UI"
    return box


def bullets(slide, x, y, w, h, items, size=16, color=TEXT, spacing=1.15):
    box = slide.shapes.add_textbox(x, y, w, h)
    tf = box.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.line_spacing = spacing
        if isinstance(item, tuple):  # (lead, rest)
            r1 = p.add_run(); r1.text = "• " + item[0]
            r1.font.size = Pt(size); r1.font.bold = True
            r1.font.color.rgb = ACCENT; r1.font.name = "Segoe UI"
            r2 = p.add_run(); r2.text = " " + item[1]
            r2.font.size = Pt(size); r2.font.color.rgb = color
            r2.font.name = "Segoe UI"
        else:
            r = p.add_run(); r.text = "• " + item
            r.font.size = Pt(size); r.font.color.rgb = color
            r.font.name = "Segoe UI"
    return box


def panel(slide, x, y, w, h, fill=PANEL):
    sh = slide.shapes.add_shape(1, x, y, w, h)
    sh.fill.solid()
    sh.fill.fore_color.rgb = fill
    sh.line.color.rgb = RGBColor(0x33, 0x41, 0x55)
    sh.line.width = Pt(0.75)
    sh.shadow.inherit = False
    return sh


def header(slide, title, subtitle=None):
    txt(slide, Inches(0.6), Inches(0.35), Inches(12), Inches(0.8), title,
        size=30, bold=True, color=TEXT)
    if subtitle:
        txt(slide, Inches(0.6), Inches(1.05), Inches(12), Inches(0.5), subtitle,
            size=14, color=MUTED)
    bar = slide.shapes.add_shape(1, Inches(0.6), Inches(1.55), Inches(1.6), Pt(3))
    bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT
    bar.line.fill.background(); bar.shadow.inherit = False


def footer(slide, idx, total):
    txt(slide, Inches(0.6), Inches(7.05), Inches(1.2), Inches(0.35),
        f"{idx:02d} / {total:02d}", size=10, color=MUTED)
    txt(slide, Inches(10.5), Inches(7.05), Inches(2.4), Inches(0.35),
        "VibeShield AI", size=10, color=MUTED, align=PP_ALIGN.RIGHT)


def chip(slide, x, y, w, text, color=MUTED, size=11):
    c = slide.shapes.add_shape(1, x, y, w, Inches(0.32))
    c.fill.solid(); c.fill.fore_color.rgb = PANEL
    c.line.color.rgb = RGBColor(0x47, 0x55, 0x69); c.line.width = Pt(0.75)
    c.shadow.inherit = False
    tf = c.text_frame; tf.word_wrap = False
    p = tf.paragraphs[0]; p.alignment = PP_ALIGN.CENTER
    r = p.add_run(); r.text = text
    r.font.size = Pt(size); r.font.color.rgb = color
    r.font.name = "Consolas"; r.font.bold = False
    return c


prs = Presentation()
prs.slide_width = SW
prs.slide_height = SH

TOTAL = 12

# #1 ---------------------------------------------------------------- title
s, _ = add_slide(prs)
txt(s, Inches(0.9), Inches(2.35), Inches(11.5), Inches(1.2),
    "VibeShield AI", size=54, bold=True, color=TEXT)
txt(s, Inches(0.9), Inches(3.5), Inches(11.5), Inches(0.6),
    "Authorized, passive web security assessment — real tool runs, honest evidence, deterministic reports",
    size=20, color=ACCENT)
txt(s, Inches(0.9), Inches(4.15), Inches(11.5), Inches(0.5),
    "FastAPI + PostgreSQL backend · React dashboard · AI-assisted finding explanations",
    size=15, color=MUTED)
chip(s, Inches(0.9), Inches(4.95), Inches(1.9), "Passive scanning")
chip(s, Inches(2.95), Inches(4.95), Inches(2.2), "Safety-first controls")
chip(s, Inches(5.30), Inches(4.95), Inches(2.2), "PDF / JSON reports")
chip(s, Inches(7.65), Inches(4.95), Inches(2.4), "Grounded AI (optional)")
txt(s, Inches(0.9), Inches(6.6), Inches(8), Inches(0.4),
    "Project demo & documentation — 172 backend tests, 64/64 E2E checks green",
    size=12, color=MUTED)

# #2 ---------------------------------------------------------------- problem
s, _ = add_slide(prs)
header(s, "The Problem", "Security testing cannot guess — it must prove")
bullets(s, Inches(0.6), Inches(1.9), Inches(6.0), Inches(4.9), [
    ("Teams need evidence, not vibes.", "Most 'scan reports' mix fabricated findings with guesses, making triage impossible."),
    ("Scanning is risky by nature.", "Aggressive scanners can take down targets or wander outside authorized scope."),
    ("AI tools are tempting but dangerous.", "LLM hallucinations in a security report are worse than no report."),
    ("Dependencies get forgotten.", "Vulnerable npm/pip packages and unsafe source patterns rarely get checked."),
], size=16)
panel(s, Inches(7.0), Inches(1.9), Inches(5.7), Inches(4.3))
txt(s, Inches(7.3), Inches(2.15), Inches(5.1), Inches(0.4),
    "VibeShield's answer", size=18, bold=True, color=ACCENT)
bullets(s, Inches(7.3), Inches(2.7), Inches(5.1), Inches(3.4), [
    "Passive, rate-limited, scope-locked scanning — authorization is confirmed explicitly",
    "Every finding stores its raw, redacted evidence for review",
    "AI is optional and clearly labeled — never the source of truth",
    "Deterministic risk engine ranks findings from real data only",
], size=14)
footer(s, 2, TOTAL)

# #3 ---------------------------------------------------------------- what it does
s, _ = add_slide(prs)
header(s, "What VibeShield AI Does", "One pipeline: assess → correlate → report")
panel(s, Inches(0.6), Inches(1.9), Inches(4.0), Inches(4.4))
txt(s, Inches(0.85), Inches(2.1), Inches(3.5), Inches(0.35), "1 · Assess", size=17, bold=True, color=ACCENT)
bullets(s, Inches(0.85), Inches(2.6), Inches(3.5), Inches(3.6), [
    "URL & redirect validation",
    "DNS + TLS posture",
    "HTTP security headers",
    "Cookie attributes",
    "HTML forms & resources",
    "JS secret/API analysis",
    "API endpoint inventory",
], size=13, spacing=1.05)
panel(s, Inches(4.85), Inches(1.9), Inches(4.0), Inches(4.4))
txt(s, Inches(5.1), Inches(2.1), Inches(3.5), Inches(0.35), "2 · Correlate", size=17, bold=True, color=ACCENT)
bullets(s, Inches(5.1), Inches(2.6), Inches(3.5), Inches(3.6), [
    "Project scans: npm/pip audits + semgrep static analysis",
    "Findings normalized, deduplicated",
    "Cautious correlation links (with reasons)",
    "Deterministic priority = severity × confidence × verification weight",
], size=13, spacing=1.05)
panel(s, Inches(9.1), Inches(1.9), Inches(3.6), Inches(4.4))
txt(s, Inches(9.35), Inches(2.1), Inches(3.1), Inches(0.35), "3 · Report", size=17, bold=True, color=ACCENT)
bullets(s, Inches(9.35), Inches(2.6), Inches(3.1), Inches(3.6), [
    "Curated JSON report",
    "Styled PDF report (ReportLab)",
    "Methodology & limitations stated honestly",
    "Optional AI explanations, explicitly labeled",
], size=13, spacing=1.05)
footer(s, 3, TOTAL)

# #4 ---------------------------------------------------------------- architecture
s, _ = add_slide(prs)
header(s, "Architecture", "React SPA · FastAPI monolith · SQL persistence · pluggable tooling")
panel(s, Inches(0.6), Inches(2.0), Inches(3.6), Inches(3.6))
txt(s, Inches(0.85), Inches(2.2), Inches(3.2), Inches(0.3), "Frontend", size=16, bold=True, color=GREEN)
bullets(s, Inches(0.85), Inches(2.7), Inches(3.2), Inches(2.8), [
    "React 18 + TypeScript",
    "Vite dev proxy → /api",
    "Tailwind dashboard",
    "7 views: overview, scans, explorer, inventory, config, reports…",
], size=12)
panel(s, Inches(4.5), Inches(2.0), Inches(3.6), Inches(3.6))
txt(s, Inches(4.75), Inches(2.2), Inches(3.2), Inches(0.3), "Backend", size=16, bold=True, color=GREEN)
bullets(s, Inches(4.75), Inches(2.7), Inches(3.2), Inches(2.8), [
    "FastAPI (async) + SQLAlchemy",
    "Scan orchestrator + stages",
    "Rate limiter, token bucket",
    "JWT-ready auth primitives",
    "ReportLab PDF engine",
], size=12)
panel(s, Inches(8.4), Inches(2.0), Inches(4.3), Inches(3.6))
txt(s, Inches(8.65), Inches(2.2), Inches(3.8), Inches(0.3), "Tools & data", size=16, bold=True, color=GREEN)
bullets(s, Inches(8.65), Inches(2.7), Inches(3.8), Inches(2.9), [
    "SQLite (dev) / PostgreSQL (prod)",
    "npm audit, pip-audit, semgrep, nmap, nuclei, OWASP ZAP (auto-detected)",
    "Strict path guard for authorized dirs",
    "Everything redacted before storage",
], size=12)
bar = slide_shapes = s.shapes.add_shape(1, Inches(0.6), Inches(5.8), Inches(12.1), Inches(0.55))
bar.fill.solid(); bar.fill.fore_color.rgb = PANEL
bar.line.color.rgb = RGBColor(0x33, 0x41, 0x55); bar.shadow.inherit = False
txt(s, Inches(0.85), Inches(5.9), Inches(11.6), Inches(0.35),
    "Frontend  →(Vite proxy / HTTPS)→  FastAPI /api  →(async tasks)→  scanner modules  →(SQLAlchemy)→  database",
    size=13, color=MUTED, align=PP_ALIGN.CENTER)
footer(s, 4, TOTAL)

# #5 ---------------------------------------------------------------- safety
s, _ = add_slide(prs)
header(s, "Safety & Trust Controls", "The scanner must never endanger the product it protects")
bullets(s, Inches(0.6), Inches(1.95), Inches(5.9), Inches(4.7), [
    ("Explicit authorization", "Every scan requires confirm_authorized; project scans resolve only within configured AUTHORIZED_PROJECT_ROOTS (symlink-escaping paths rejected)."),
    ("Rate limited", "Async token bucket, default 4 req/s per target, hard-capped 20 req/s."),
    ("Bounded scope", "Max 250 outbound requests per scan, 15s per request timeout, 900s total."),
    ("Private targets opt-in", "SCAN_ALLOW_PRIVATE_TARGETS defaults disallow internal hosts in production."),
], size=15)
bullets(s, Inches(6.9), Inches(1.95), Inches(5.9), Inches(4.7), [
    ("No secrets stored", "Secret-like values redacted at ingestion; logging filter scrubs tokens/cookies/auth headers."),
    ("Honest tool status", "tool_missing / timeout / unparsed_output are reported as-is — never dressed up as 'no findings'."),
    ("Verification labels", "Findings carry verification_status: confirmed / potential / unverified."),
    ("Cancel anytime", "Server-side cancellation for pending/running scans."),
], size=15)
footer(s, 5, TOTAL)

# #6 ---------------------------------------------------------------- pipeline detail
s, _ = add_slide(prs)
header(s, "Security Modules", "What each scan actually executes")
modules = [
    ("url_validation", "URL structure, credentials in URLs, redirect chains (5-hop limit), scheme checks"),
    ("dns_analysis", "DNS posture from real lookups"),
    ("tls_analysis", "Certificate/expiry + plain-HTTP detection"),
    ("http_headers", "CSP, HSTS, X-Frame-Options, etc."),
    ("cookie_analysis", "Secure / HttpOnly / SameSite attributes"),
    ("html_analysis", "Forms, actions, password fields, external endpoints"),
    ("js_discovery", "Inline/external script inventory with SHA-256 hashes"),
    ("js_analysis", "Secret candidates (redacted), eval(), debug APIs, http:// refs"),
    ("api_discovery", "Endpoint inventory — recorded, never probed"),
    ("dependency_audit", "npm audit + pip-audit on authorized dirs"),
    ("source_analysis", "Semgrep static analysis of authorized source"),
    ("zap_dynamic", "OWASP ZAP safe-mode scan (optional, when on PATH)"),
]
for i, (name, desc) in enumerate(modules):
    col, row = i % 2, i // 2
    x = Inches(0.6) + col * Inches(6.45)
    y = Inches(1.95) + row * Inches(0.86)
    chip(s, x, y, Inches(2.35), name, color=ACCENT, size=10)
    txt(s, x + Inches(2.5), y - Inches(0.015), Inches(3.9), Inches(0.8), desc,
        size=10.5, color=TEXT, wrap=True)
footer(s, 6, TOTAL)

# #7 ---------------------------------------------------------------- risk engine
s, _ = add_slide(prs)
header(s, "Phase 5 — Deterministic Risk Engine", "Same inputs always produce the same ranked output")
panel(s, Inches(0.6), Inches(1.95), Inches(6.1), Inches(4.5))
txt(s, Inches(0.85), Inches(2.15), Inches(5.6), Inches(0.3), "Pipeline", size=16, bold=True, color=ACCENT)
bullets(s, Inches(0.85), Inches(2.6), Inches(5.6), Inches(3.7), [
    "Normalize finding schemas from every module",
    "Deduplicate identical issues into groups (originals preserved)",
    "Cross-module correlation links, each with a written reason",
    "Prioritize: severity × confidence × verification weight",
    "Malformed records are skipped and counted — never invented around",
    "All errors surfaced, nothing silently dropped",
], size=13)
panel(s, Inches(7.0), Inches(1.95), Inches(5.8), Inches(4.5))
txt(s, Inches(7.25), Inches(2.15), Inches(5.3), Inches(0.3),
    "Served to the dashboard", size=16, bold=True, color=ACCENT)
bullets(s, Inches(7.25), Inches(2.6), Inches(5.3), Inches(3.7), [
    "GET /api/scans/{id}/risk-summary — counts, prioritized list, formula + limitations",
    "GET /api/scans/{id}/correlations — link list with reasons",
    "Both feed the Report panel and the downloadable report payloads",
    "No LLM in this path — fully reproducible",
], size=13)
footer(s, 7, TOTAL)

# #8 ---------------------------------------------------------------- AI layer
s, _ = add_slide(prs)
header(s, "Phase 7 — Grounded, Optional AI", "AI explains stored evidence; it never invents findings")
bullets(s, Inches(0.6), Inches(1.95), Inches(6.0), Inches(4.6), [
    ("Off by default", "AI_PROVIDER_FAMILY=offline — the product is fully functional without it."),
    ("Provider families", "offline · openai_compat (OpenRouter etc.) · GLM-family transport."),
    ("Grounded prompts", "Only stored, redacted evidence is sent — secrets never leave the DB un-redacted."),
    ("Clearly separated", "ai_explanation stored apart from findings; UI labels every AI paragraph."),
    ("Failures honest", "ai_error surfaces to the user instead of a confident blank."),
], size=15)
panel(s, Inches(7.0), Inches(1.95), Inches(5.8), Inches(4.5))
txt(s, Inches(7.25), Inches(2.15), Inches(5.3), Inches(0.35),
    "Guardrails in practice", size=16, bold=True, color=ACCENT)
bullets(s, Inches(7.25), Inches(2.65), Inches(5.3), Inches(3.4), [
    "Per-finding “Explain (AI)” button — user opts in per finding",
    "Max 40 findings explained per scan (AI_MAX_FINDINGS_TO_EXPLAIN)",
    "Provider keys live only in env vars, never in DB or reports",
    "Status endpoint exposes configuration, never keys",
], size=13)
footer(s, 8, TOTAL)

# #9 ---------------------------------------------------------------- reports
s, _ = add_slide(prs)
header(s, "Reports", "Curated JSON + styled PDF, built strictly from stored evidence")
panel(s, Inches(0.6), Inches(1.95), Inches(6.1), Inches(4.4))
txt(s, Inches(0.85), Inches(2.15), Inches(5.6), Inches(0.3), "What they contain", size=16, bold=True, color=ACCENT)
bullets(s, Inches(0.85), Inches(2.6), Inches(5.6), Inches(3.6), [
    "Scan metadata, authorized scope, methodology, limitations",
    "Module coverage: executed / failed / skipped / unavailable",
    "Severity counts + prioritized findings with remediation",
    "Correlation links with reasons",
    "Tool errors list — reported, not hidden",
], size=13)
panel(s, Inches(7.0), Inches(1.95), Inches(5.8), Inches(4.4))
txt(s, Inches(7.25), Inches(2.15), Inches(5.3), Inches(0.3), "Guarantees", size=16, bold=True, color=ACCENT)
bullets(s, Inches(7.25), Inches(2.6), Inches(5.3), Inches(3.6), [
    "Same redaction rules as the scanner",
    "Empty sections say so — no fabricated content",
    "Missing risk summary → HTTP 400 with explanation (not fake data)",
    "Content-Disposition filenames: vibeshield-report-{scan_id}.pdf/.json",
], size=13)
footer(s, 9, TOTAL)

# #10 ---------------------------------------------------------------- demo
s, _ = add_slide(prs)
header(s, "Live Demo", "Local run against the controlled vulnerable fixture")
panel(s, Inches(0.6), Inches(1.95), Inches(6.1), Inches(4.4))
txt(s, Inches(0.85), Inches(2.15), Inches(5.6), Inches(0.3), "Links used in the demo", size=16, bold=True, color=ACCENT)
txt(s, Inches(0.85), Inches(2.6), Inches(5.6), Inches(3.6),
    "App (React):            http://localhost:5173/\n"
    "API health:             http://127.0.0.1:8000/api/health\n"
    "Demo scan detail:       /api/scans/74c91147…\n"
    "Artifacts:              /api/scans/{id}/artifacts\n"
    "Risk summary:           /api/scans/{id}/risk-summary\n"
    "JSON / PDF report:      /api/reports/{id}/json | /pdf",
    size=12, color=TEXT)
panel(s, Inches(7.0), Inches(1.95), Inches(5.8), Inches(4.4))
txt(s, Inches(7.25), Inches(2.15), Inches(5.3), Inches(0.3), "Start it yourself", size=16, bold=True, color=ACCENT)
txt(s, Inches(7.25), Inches(2.6), Inches(5.3), Inches(3.7),
    'Backend:\n'
    '  cd vibeshield-ai/backend\n'
    "  export DATABASE_URL='sqlite:///./demo_mvp.db'\n"
    '  export SCAN_ALLOW_PRIVATE_TARGETS=true\n'
    '  export AUTHORIZED_PROJECT_ROOTS="$PWD/tests/e2e/project_fixture"\n'
    '  python -m uvicorn app.main:app --port 8000\n\n'
    'Frontend:\n'
    '  cd vibeshield-ai/frontend\n'
    '  npm run dev',
    size=12, color=MUTED)
footer(s, 10, TOTAL)

# #11 ---------------------------------------------------------------- deployment
s, _ = add_slide(prs)
header(s, "Deployment Plan", "Recommended: single VPS with Docker Compose")
bullets(s, Inches(0.6), Inches(1.95), Inches(6.0), Inches(4.6), [
    ("Why containers", "Backend Dockerfile + compose file already exist; one box is easiest to run and control."),
    ("Compose layout", "postgres 16 · uvicorn backend · reverse proxy serving built React assets."),
    ("Production env", "Strong SECRET_KEY, FIRST_ADMIN_* changed, CORS pinned to real hosts, Postgres DATABASE_URL."),
    ("Safety posture", "SCAN_ALLOW_PRIVATE_TARGETS=false in production; explicit target authorization always required."),
], size=15)
panel(s, Inches(7.0), Inches(1.95), Inches(5.8), Inches(4.5))
txt(s, Inches(7.25), Inches(2.15), Inches(5.3), Inches(0.3), "Hardening before exposure", size=16, bold=True, color=AMBER)
bullets(s, Inches(7.25), Inches(2.65), Inches(5.3), Inches(3.4), [
    "Auth primitives exist (bcrypt + JWT + RBAC); login endpoints being added next",
    "Protect scan/report endpoints behind real login before going public",
    "Keep external tools (nmap/ZAP) opt-in and scope-validated",
    "Backups for postgres volume; TLS at the proxy",
], size=13)
footer(s, 11, TOTAL)

# #12 ---------------------------------------------------------------- roadmap
s, _ = add_slide(prs)
header(s, "Status & Roadmap")
mid = RGBColor(0x6B, 0xA8, 0x5F)
panel(s, Inches(0.6), Inches(1.95), Inches(6.1), Inches(4.5))
txt(s, Inches(0.85), Inches(2.15), Inches(5.6), Inches(0.4),
    "Done today", size=17, bold=True, color=GREEN)
bullets(s, Inches(0.85), Inches(2.65), Inches(5.6), Inches(3.6), [
    "Phases 1–7 complete: pipeline, risk engine, reports, AI layer",
    "172 backend tests + 64/64 E2E green; frontend 27/27",
    "Demo scan verified end-to-end (HTTP 200 on all endpoints)",
    "Frontend/backend shape mismatches fixed (inventory crash)",
], size=13)
panel(s, Inches(7.0), Inches(1.95), Inches(5.8), Inches(4.5))
txt(s, Inches(7.25), Inches(2.15), Inches(5.3), Inches(0.4),
    "Next", size=17, bold=True, color=ACCENT)
bullets(s, Inches(7.25), Inches(2.65), Inches(5.3), Inches(3.7), [
    "Docker Compose deploy package for VPS (config, env, checklist)",
    "Real login (JWT) on scan/report endpoints",
    "Frontend served by reverse proxy in the same deploy",
    "Optional: managed Postgres / OWASP Juice Shop full demo via Docker",
], size=13)
txt(s, Inches(0.6), Inches(6.85), Inches(12), Inches(0.4),
    "VibeShield AI — authorized testing, honest evidence, reproducible risk.",
    size=14, bold=True, color=MUTED, align=PP_ALIGN.CENTER)
footer(s, 12, TOTAL)

OUT = "demo_data/VibeShield_AI_Presentation.pptx"
prs.save(OUT)
print(f"saved {OUT}")
