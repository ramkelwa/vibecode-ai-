# VibeShield AI

AI-assisted web application security assessment platform (Phases 1–8: application shell, passive scanner pipeline, client-side artifact analysis, dependency/source auditing, risk normalization, SOC dashboard, AI-assisted explanations and downloadable reports, and Phase 8 validation + release preparation).

## What is implemented

**Backend (FastAPI + SQLAlchemy):**
- `/api/health` — real database connectivity probe; reports DB-dependent features as unavailable when PostgreSQL/SQLite is down (the API itself stays up).
- `/api/scans` — `POST` create a scan (requires `confirm_authorized: true`), `GET` list, `GET /{id}` status with per-module stages and findings, `POST /{id}/cancel`.
- `/api/scans/{id}/artifacts` — Phase 3 artifact inventory: parsed HTML document, fetched JS asset inventory with SHA-256 digests, static JS analysis results, and discovered API endpoint references. Nothing is synthesized: each artifact is only present if its module actually produced data; a failed module records its error instead.
- Persistent `Scan`, `ScanStage`, `Finding` records, plus a JSON `artifacts` column persisted when the pipeline completes (works on SQLite locally, PostgreSQL in Docker).
- Passive scanner modules, one per responsibility, each emitting a shared normalized `FindingData` schema:

| Module | What it can detect | What it cannot detect |
|---|---|---|
| `url_validation` | non-HTTP schemes, missing host, cross-origin redirects, redirect chains over the safe limit (5) | client-side (JS) redirects; open redirects requiring attacker parameters |
| `dns_analysis` | missing A records, MX-without-SPF, internal-name hints in public records | subdomain takeover, zone transfers, DNSSEC depth |
| `tls_analysis` | expired/expiring certs, self-signed, hostname mismatch, weak protocol versions (TLS 1.0/1.1), plain HTTP | cipher enumeration, revocation status |
| `http_headers` | missing/weak CSP, nosniff, Referrer-Policy, framing protection, HSTS, permissive CORS, version disclosure | CSP bypassability, behavior on routes other than the fetched one |
| `cookie_analysis` | missing Secure/HttpOnly/SameSite on observed Set-Cookie headers, unrelated Domain scoping | JS-set cookies, value entropy, session fixation |

**Phase 3 client-side modules:**

| Module | What it can detect | What it cannot detect |
|---|---|---|
| `html_analysis` | document title, meta tags, external resources, forms and their action origin, malformed-HTML parse notes | DOM mutations at runtime, shadow DOM content, behaviour after load |
| `js_discovery` | inline vs. external script inventory; for each fetched asset: same-origin/cross-origin classification, Content-Type, size, SHA-256 digest; unreachable assets recorded as fetch errors | assets loaded dynamically only at runtime, bundled/vendor maps blocked by CORS |
| `js_analysis` | secret candidates (API-key/AWS-key/JWT patterns) with values redacted, dangerous API usage (eval/innerHTML/document.write), insecure `http://` references, `debugger` statements | whether a secret is live/valid, actual data flows into sinks (no taint analysis) |
| `api_discovery` | API endpoint references from fetch/XMLHttpRequest/axios/WebSocket/base-URL constants, with method (when statically extractable), source, line, same-origin classification and confidence | endpoints reachable only via complex runtime logic; it never probes endpoints (observation only) |

**Safety controls:** explicit authorization confirmation, target allowlist policy, destination-IP validation on every request and redirect hop (SSRF/DNS-rebinding guard), request timeouts, per-scan request budget, token-bucket rate limiting, response size cap, secret redaction in logs.

**Frontend (React + TypeScript + Vite + Tailwind):** health/status header, new-scan form with module selection (all 9 modules), live scan progress polling (stops when finished), findings table with severity badges, filterable Phase 3 artifact inventory (HTML metadata, JS assets, JS analysis, API endpoints) with empty states, scan history — all data from real backend responses.

**No findings are ever invented:** every stored finding carries real observed evidence, a source module, confidence, and verification status. A failed fetch is recorded as a module limitation, never as a vulnerability.

## Setup (Windows PowerShell)

```powershell
cd vibeshield-ai

# --- Backend ---
cd backend
python -m venv ..\.venv
..\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env   # adjust values if needed

# --- Frontend ---
cd ..\frontend
npm install
Copy-Item .env.example .env   # local backend URL; adjust for deployment
```

Both local `.env` files are ignored by Git. Keep provider credentials in
`backend\.env`; the frontend only needs the backend API origin in
`frontend\.env` (`VITE_API_BASE_URL`).

## Run (development)

```powershell
# Terminal 1 - backend (from vibeshield-ai\backend, venv active)
uvicorn app.main:app --reload --port 8000

# Terminal 2 - frontend (from vibeshield-ai\frontend)
npm run dev
```

Open http://localhost:5173. The Vite dev server proxies `/api/*` to `http://localhost:8000`.

The backend runs with SQLite (`DATABASE_URL=sqlite:///./vibeshield.db`) by default. To use PostgreSQL via Docker:

```powershell
docker compose up --build -d postgres
# then in .env:
# DATABASE_URL=postgresql+psycopg://vibeshield:vibeshield@localhost:5432/vibeshield
```

Or run the whole stack:

```powershell
docker compose up --build
```

## CI/CD and deployments

The GitHub Actions workflow at `.github/workflows/ci-cd.yml` runs backend tests,
frontend tests/build, and a backend Docker build on pull requests and pushes to
`main`. After a successful push to `main`, it deploys the backend to Render and
the frontend to Vercel when the required repository settings are configured.
Deployment steps are skipped with a workflow notice until those settings exist.

### Configure Render

1. Create a Render Blueprint from this repository and select `render.yaml`.
   The blueprint creates the backend web service and PostgreSQL database.
2. Set `CORS_ORIGINS` in the Render service to the exact Vercel production
   origin, such as `https://your-project.vercel.app` (add any custom origin
   separated by commas).
3. Set `AI_API_KEY` in the Render dashboard if AI explanations should be
   enabled. Keep credentials in Render's environment settings, never in Git.
   Rotate any credential that was pasted into chat or added to a tracked file.
4. Create a Render Deploy Hook for the service and save its URL as the
   `RENDER_DEPLOY_HOOK` GitHub Actions repository secret.

### Configure Vercel

1. Import the repository into Vercel and set the project Root Directory to
   `frontend`.
2. Add these GitHub Actions repository secrets:
   `VERCEL_TOKEN`, `VERCEL_ORG_ID`, and `VERCEL_PROJECT_ID`.
3. Add the GitHub Actions repository variable `VITE_API_BASE_URL` with the
   Render service origin, for example `https://your-service.onrender.com`
   (no trailing slash).

Once configured, each successful push to `main` triggers both deployments.
Vercel previews and pull requests run validation only.

### Push local commits automatically

This checkout is configured to push each explicit Git commit to its upstream
branch using `.githooks/post-commit`. This does not commit file saves. To enable
the hook in another clone, run:

```powershell
git config core.hooksPath .githooks
```

To disable automatic pushes in this checkout:

```powershell
git config --unset core.hooksPath
```

## Tests

```powershell
# Backend (from vibeshield-ai\backend, venv active)
python -m pytest -v

# Frontend type-check + build
cd ..\frontend
npm run build
```

Current status: **175 backend tests passing, 1 skipped** (platform-specific symlink test; health incl. DB-outage behavior, persistence round-trips, URL/redirect/header/cookie modules via controlled stubs, scans API incl. validation errors and stage tracking, Phase 3 HTML/JS/API modules via controlled fixtures, Phase 4 manifest/advisory/audit-tooling tests via fixtures + mocked subprocess calls, Phase 5 normalization/dedup/correlation/risk tests, Phase 7 provider/report/AI-explanation tests) and **frontend 27 vitest tests passing + `tsc -b && vite build` clean**.

## What is implemented (continued)

**Phase 4 — dependency audit + static source analysis (optional)**

A separate workspace scan for an authorized local project directory, distinct from passive website scanning. Runs only on a path the operator explicitly authorizes through `AUTHORIZED_PROJECT_ROOTS`. Website scans and project scans are never mixed: a website scan looks at one public URL; a project scan looks at one chosen source tree.

| Module | What it can detect | What it cannot detect |
|---|---|---|
| `dependency_audit` | npm/pip advisories visible from manifest lockfiles, parsed into structured findings with package name, advisory id, affected version range, and remediation when the tool reports it | whether the dependency is actually reachable/exploitable by the site; advisory truth is preserved as tool-reported, not as a confirmed website vuln |
| `source_analysis` | semgrep static-analysis findings (rule id, severity, source location, evidence with secrets redacted) when semgrep is on PATH | runtime behavior, data flows / taint, business logic bugs |
| `zap_dynamic` | OWASP ZAP safe-mode active scan results when the operator explicitly configures ZAP_API_URL and ZAP_API_KEY | anything when ZAP is not configured; the integration stays disabled by default |

Requirements honored for Phase 4:
- Manifests supported: package.json + npm lockfiles (package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml) for Node projects; requirements.txt and pyproject.toml for Python projects. Manifest and lockfile parsers never invent a version: an unpinned dependency is recorded with an empty version and flagged as unpinned.
- Audits: npm-audit (with --package-lock-only, no install) for pinned node projects; pip-audit for pinned python deps. Unpiped or unpinned deps are recorded as a coverage gap, not audited against invented versions.
- Advisory handling: advisory ids, packages, versions, ranges, and remediations are recorded only as observed from tool output. A CVE or fixed version is never invented. Missing advisory DB / failed tool / unparseable output are all distinguishable from a genuinely clean audit.
- Source analysis: explicit file extension allowlist (.py/.js/.jsx/.ts/.tsx/.mjs/.cjs/.go/.java/.rb/.php/.cs/.c/.cc/.cpp/.h/.hpp plus common config formats); tool output parsed as JSON, never as instructions; rule metadata (id, message, severity, CWE/CVE where reported) preserved; confirmation status stays firm (tool-reported), verification status stays unverified.
- Safety: every external tool run uses a pre-built argument list with shell=False, a hard timeout, and a per-run output cap. Filesystem access is restricted to explicitly authorized project directories (symlink escape rejected). No lifecycle scripts are run and nothing from the target repo is executed.
- Findings reuse the shared finding schema. Dependency advisories are clearly labeled as dependency-ecosystem findings (category `dependency_audit`) and never presented as exploitable website vulnerabilities by themselves.

**Phase 4 is opt-in and requires configuration:**

- Set `AUTHORIZED_PROJECT_ROOTS` to one or more absolute directories the user is authorized to have scanned; leave empty and project scanning is disabled.
- Install the tools you want to run: `npm` (for node projects), `pip-audit` (for python projects), `semgrep` (for source analysis), and optionally configure ZAP for dynamic scanning. If a tool is missing, the scan records that fact and continues.

### Project scan API

In addition to the website scan endpoints, Phase 4 adds:

- `POST /api/scans/project` — create a project scan. Body:
  - `project_dir` — absolute path inside an authorized project root
  - `modules` — optional subset of `["dependency_audit", "source_analysis", "zap_dynamic"]` (defaults to `["dependency_audit", "source_analysis"]`)
  - `confirm_authorized` — must be `true`
- `GET /api/scans/{id}` / `GET /api/scans` — same status and findings endpoints as website scans; project scans appear in the same listing with their target field set to the project directory path.
- `POST /api/scans/{id}/cancel` — cancels a running project scan the same way.

Project scans populate `Scan.artifacts["dependency_audit"]` and `Scan.artifacts["source_analysis"]` with the tool-run records and parsed inventories.

### Tool installation (Windows dev default)

```powershell
# Node audit (only needed for node projects)
npm install -g npm@latest

# Python audit
python -m pip install pip-audit

# Static source analysis
python -m pip install semgrep

# Optional dynamic scan via ZAP REST API
# 1. Install ZAP locally (or run it in Docker)
# 2. Set ZAP_API_URL and ZAP_API_KEY in .env
```

Limitations:
- `pip-audit` requires pinned versions; unpinned python deps are recorded as `unpinned` and skipped rather than guessed.
- `npm-audit` uses your local npm registry config and network; advisory coverage depends on the registry state at scan time. An offline or flaky network can produce a tool_failed/timeout outcome rather than a clean result.
- semgrep runs only the default rule set configured on the machine; no custom rule packs are loaded.
- ZAP is disabled unless `ZAP_API_URL` is set; even then, only the safe scan policy is used and the scan is bound to the authorized target host.
- Project scanning requires a directory the user has already authorized; no arbitrary filesystem access is performed.

## What is implemented (continued)

**Phase 5 — normalization, deduplication, correlation, and risk prioritization (deterministic post-processing)**

A pure engine (`app/scanners/phase5.py`) over the findings the Phase 1-4 modules already stored. It never scans, never invents evidence, and no LLM participates anywhere in this path.

| Capability | What it does | What it deliberately does not do |
|---|---|---|
| Normalization | canonicalizes categories (`headers`→`http_headers`, `deps`→`dependency_audit`, ...), severity labels (`moderate`→`medium`, `unspecified`→`unknown`), confidence (`confirmed`→`certain`); standardizes URL assets (scheme+host lowercase, default ports and fragments removed, path/query case preserved); keeps originals and a `category_recognized` flag; malformed records degrade to an `errors` list | does not invented a severity when the source gave none (`unknown` instead), does not reclassify unknown categories |
| Deduplication | merges only identical observations keyed by (category, asset, title, CWE, CVE); keeps ALL contributing source modules + original finding ids; distinct assets or titles are never merged; conflicting severity labels → most severe kept with every raw label and its basis recorded in evidence; merged verification status is the most conservative (weakest claim) observed | never merges findings merely for sharing a title; never upgrades a weak claim during a merge |
| Correlation | three cautious, reason-carrying rules: `insecure_transport_resource` (JS `http://` reference ↔ TLS/transport finding on the same host), `secret_and_endpoint_same_asset`, `dangerous_sink_and_endpoint_same_asset`; each link explains WHY and states the limitation explicitly | correlation NEVER mutates severity, confidence, or verification status; a weak finding stays weak |
| Risk priority | documented deterministic formula (below), kept separate from severity/confidence | no CVSS, no EPSS, no exploit feed, no opaque single score |

**Risk priority formula** (`vibeshield-phase5-priority-1`):

```
priority = severity_weight × confidence_weight × verification_weight   (0..100)
severity_weight:      critical=100 high=75 medium=50 low=25 info=10 unknown=15
confidence_weight:    certain=1.0 firm=0.85 uncertain=0.6 unknown=0.5
verification_weight:  confirmed=1.0 potential=0.9 unverified=0.7
                      informational=0.4 false_positive=0.05 unknown=0.3
```

Limitations (surfaced with every summary): linear heuristic over reported labels — a review-ordering aid, not a vulnerability score or exploit probability; no CVSS/exploit-feed/business context; `unknown` values fall to conservative defaults rather than guesses; cross-asset blast radius is not modeled.

**Phase 5 API (computed from stored results; nothing hardcoded):**
- `GET /api/scans/{id}/risk-summary` — counts by severity/confidence/status/category, dedup stats, prioritized findings (priority descending, deterministic tie-breakers), remediation suggestions, formula + limitations, malformed-record errors.
- `GET /api/scans/{id}/correlations` — links with their reasons.
- Both sets are also persisted on `Scan.artifacts["correlations"]` / `Scan.artifacts["risk_summary"]` at scan completion; stored copy and request-time computation agree by construction (same deterministic function over the same rows).

**Frontend:** live risk-summary panel (severity chips, prioritized review table with source modules and status, remediation suggestions, formula limitation footnote), correlated-review-context panel (relation name, linked titles, reason), the artifacts inventory exposes Phase 4 project sections (`dependency_audit`, `source_analysis`) with manifest and tool-run tables, and the new-scan area gains a project-scan form (authorized directory + module selection) completing the Phase 4 UI gap.

### Phase 4 completion note

The project-scan creation path now works end to end: `POST /api/scans/project` no longer references an unimported launcher, and the frontend can create project scans and render their manifests/tool-runs/source-analysis artifacts.

## What is implemented (continued)

**Phase 6 — SOC-style dashboard (frontend, real backend data only)**

Sidebar-driven layout with seven views; plain Tailwind + `lucide-react` icons (no chart library — severity distributions are CSS bars, no unnecessary dependencies).

| View | Data source |
|---|---|
| Overview | aggregate counts computed live from `GET /api/scans` + the newest completed scan's findings; severity distribution bars |
| New scan | `POST /api/scans` and `POST /api/scans/project`; validates URL/path format before submit, shows scope + authorization requirements, displays the real returned scan ID, prevents duplicate submissions while pending, surfaces actual API validation errors, polling of real scan status, module-stage progress with partial-failure notes, and cancel via `POST /{id}/cancel` |
| Scan history | `GET /api/scans` with loading/empty/error-retry states |
| Findings explorer | search, severity/confidence/category filters, sorting, pagination, detail panel (redacted evidence as stored, source module, affected asset, remediation, verification status) |
| Endpoint & script inventory | real `GET /api/scans/{id}/artifacts` (endpoints, inline scripts, external JS assets with digests) |
| Configuration & dependencies | header/cookie findings + Phase 4 project artifact tool-run records |
| Report | Phase 5 `risk-summary` + `correlations` endpoints — deterministic engine output with formula and limitations |
| VirusTotal threat intelligence | Optional third-party URL report lookup and user-confirmed analysis submission; results stay separate from VibeShield findings |

Data-integrity rules honored: every metric derives from real API responses; nothing is simulated, no dashboard totals are hardcoded; missing data renders as unavailable/empty (e.g. "artifact not recorded for this scan"); DB-unavailable state disables new scans and says so honestly. The API client is centralized in `src/api.ts` with typed models and a typed `ApiError` carrying HTTP status (network failures map to status 0 and are never confused with HTTP responses). No secrets or server credentials exist client-side.

VirusTotal is an optional integration configured on the backend with `VIRUSTOTAL_API_KEY` (see `backend/.env.example`). The key is never sent to the browser. Looking up an existing report also sends the complete URL, including query parameters, to VirusTotal; submitting a new analysis requires confirmation and may make the URL available through VirusTotal. Do not use confidential URLs or URLs containing secrets. Private or non-public URL destinations are rejected. VirusTotal data is third-party intelligence, not a VibeShield scan result, and zero detections do not prove a site is safe.

**Frontend testing (vitest + Testing Library, jsdom):** 42 tests across 5 files — API client success/typed-error/network-failure/cancel behavior; new-scan flow (URL validation hint, real submit + scan-ID display, duplicate-submit prevention with pending state, backend error surfacing, scope notices, DB-down disable); findings explorer (rendering, severity/category filters, search, pagination movement, no-results and empty states, error+retry, detail panel with evidence/status/remediation, severity sorting); scan history (loading/error-retry/empty/selection); VirusTotal lookup/submission, polling, error states, and stale-result handling.

Run with: `npm test` (from `vibeshield-ai/frontend`).

## What is implemented (continued)

**Phase 7 — AI-assisted explanations (optional) and downloadable reports**

**AI provider abstraction (`app/providers.py`):**

- Families: `offline` (default; no AI, core functionality unaffected), `openai_compat` (OpenRouter and other OpenAI-compatible chat-completions endpoints), `glm` (GLM-family models over an OpenAI-compatible transport).
- Configuration lives only in backend environment variables (see `.env.example`):
  - `AI_PROVIDER_FAMILY` — `offline` | `openai_compat` | `glm`
  - `AI_PROVIDER_BASE_URL` — chat-completions base URL (no trailing slash)
  - `AI_API_KEY` — provider key, read from env only; never hardcoded, never exposed to the browser
  - `AI_MODEL` — model hint (e.g. `glm-4-flash` or an OpenRouter model id)
- Explicit connection (8 s) and read (20 s) timeouts; 401, 429, 5xx, malformed JSON, missing `choices`, missing message content, and empty content all degrade to a structured error — never an exception and never unvalidated text.
- Provider responses are validated before being stored or displayed; the model's GLM-family name is sanity-checked when family is `glm`.
- The GLM-5.3 Flash model used inside the VS Code coding extension is NOT a runtime provider for VibeShield AI: the QR extension exposes no API endpoint or credential. AI stays disabled until a real endpoint + key are configured.

**Evidence-grounded explanations (optional, per finding):**

- `GET /api/ai-provider/status` — non-secret provider status (family, configured, enabled, notes; no keys).
- `POST /api/ai-provider/explain/{scan_id}` — builds a prompt strictly from stored fields (title, category, severity, confidence, verification status, source module, description, CWE/CVE, affected asset, redacted evidence, stored remediation, optional correlation reasons). The prompt forbids inventing evidence/CVEs, forbids upgrading `potential` findings, forbids claiming verification, and instructs the model to treat target-controlled content as untrusted data (never as instructions).
- `POST /api/ai-provider/explain-and-store/{scan_id}` — same, persisting provider/model/text/timestamp on the finding row (`ai_explanation`, `ai_provider`, `ai_error`, `ai_generated_at`).
- Server-side redaction masks well-known sensitive evidence keys before they reach a prompt.
- The frontend renders AI output in a separate, clearly labeled block ("AI-generated interpretation — provider X / model Y"), distinct from scanner evidence; provider failures render honestly as "AI explanation unavailable".

**Reports (from stored scan data only, nothing fabricated):**

- `GET /api/reports/{scan_id}/json` — curated JSON report: scan id, target + authorized scope, timestamps, modules requested/executed/skipped/failed/unavailable, methodology + limitations, severity/confidence breakdowns, prioritized findings with the documented formula, correlation links with reasons, curated artifact inventories, per-finding details with redacted evidence, and tool errors/partial results.
- `GET /api/reports/{scan_id}/pdf` — ReportLab PDF of the same curated content; escaping of all target-controlled strings, secret-key redaction applied to evidence, uncompressed streams for auditability; empty sections state why they are empty.
- Reports are only available for completed scans with a stored risk summary; otherwise the endpoint returns an honest 400.
- Frontend: completed scans expose JSON/PDF download buttons in the scan detail panel.

**Phase 7 testing (24 backend tests):** provider status (incl. no-key-leak assertion), explanation endpoint incl. offline graceful degradation and persistence, evidence-redaction before prompting, zero findings, multiple findings, Unicode content, missing evidence, redacted secrets in both JSON and PDF, prompt-injection-like target content (verified inert in the PDF stream, no `/JavaScript` or `/OpenAction`), module-unavailable honesty, provider-unavailable → structured error, malformed provider responses (validated parser), and a connection-dead timeout path that fails fast instead of hanging.

Report limitations: passive-assessment observations only; no active exploitation; severity/confidence come from the modules, unknowns are shown as unknown; no CVSS/EPSS/exploit-feed or business context; AI text (when enabled) is labeled interpretation and is never part of the report itself.

## Current status

**Backend**: 172 tests pass (1 platform-skip) — Phases 1-7 suites plus Phase 8 E2E validation.

**Phase 8 — validation, regression fixes, and release preparation**

Phase 8 is a validation and hardening pass over the completed application. It does not add product features; it runs the full automated quality gate, runs a controlled end-to-end test against a deliberately vulnerable local fixture app, performs a security review of the implemented controls, fixes reproducible bugs found during validation, and records an honest release-readiness position.

### Automated quality checks run in Phase 8

- Backend pytest suite: `python -m pytest` from `vibeshield-ai/backend`.
- Frontend tests: `npm test` from `vibeshield-ai/frontend`.
- Frontend TypeScript + production build: `npm run build` from `vibeshield-ai/frontend`.
- Frontend dependency vulnerability check: `npm audit` from `vibeshield-ai/frontend` (development dependencies are included because the vulnerability posture of the dev toolchain matters for local/CI workstations).
- Python lint/type tooling: no separate ruff/mypy/pyright configuration is committed in this repository; the backend quality gate is the pytest suite plus import-time validation via the app. If a stricter lint gate is desired before deployment, add a `pyproject.toml`/`ruff.toml` config and a pre-commit hook.

### Controlled end-to-end testing

- File: `backend/tests/e2e/run_e2e.py`.
- Runs the real backend over HTTP against a local, deliberately vulnerable fixture app (`backend/tests/e2e/fixture_vuln_app.py`), a local npm project fixture (`backend/tests/e2e/project_fixture/`), and the production frontend build.
- Everything targets `127.0.0.1`; no unrelated live websites and no destructive operations.
- Validates: scan submission, target validation (bad scheme, unconfirmed authorization), scan progress, per-module stages, header/cookie/TLS observations, redirect-chain limit, redirect-loop detection, prohibited-scheme redirect refusal, SSRF guard behavior with a second backend instance, HTML + JS discovery, JS secret redaction, API endpoint inventory, dependency audit via real npm-audit, source-analysis honesty when semgrep is absent, artifact shape, risk summary consistency, correlations, JSON and PDF reports (secret never emitted raw), cancellation semantics, health, and AI-offline behavior.

### Security review summary

- Authorization is enforced at scan creation time via `confirm_authorized: true`. The codebase includes auth primitives (password hashing, JWT, RBAC) but the scan endpoints in this release do not require an authenticated session; do not treat this as production-grade authentication.
- CORS is configured via `CORS_ORIGINS`; the dev default allows localhost frontend origins.
- Secrets are read from environment variables only and are never returned to the browser; logging and report generation redact well-known sensitive keys.
- SSRF/DNS-rebinding controls: destination IP is validated pre-request and pinned at connect time on the relevant transport; redirect hops are re-validated.
- Redirect validation rejects unsupported schemes and re-validates every hop.
- Resource-exhaustion controls: per-request timeout, response size cap, per-scan request budget, token-bucket rate limiting, global scan concurrency semaphore.
- Subprocess safety: external tools run via `shell=False`, pre-built argument lists, hard timeout, output cap.
- Path traversal: Phase 4 project scanning is restricted to `AUTHORIZED_PROJECT_ROOTS`; symlink escape is rejected.
- Untrusted HTML/JS: parsed with a lenient parser; never executed; JS analysis is static pattern-based.
- AI prompt injection and evidence grounding: AI prompts are built only from stored fields, with capped/escaped untrusted strings and explicit instructions not to invent evidence/CVEs or upgrade findings; provider responses are validated before use.
- Report content escaping: PDF/JSON rendering escapes target-controlled strings and redacts sensitive evidence; source-controlled PDF payloads are verified inert in the PDF stream.

### Known limitations and unverified behavior

- Production-grade authentication/authorization UI and per-user access control are not implemented for the scan endpoints.
- `semgrep` is not installed in the default dev environment; source analysis will record that honestly rather than fabricate results.
- `npm-audit` advisory coverage depends on the configured registry and network at scan time.
- Project scanning is disabled unless `AUTHORIZED_PROJECT_ROOTS` is configured.
- Phase 5 risk priority is a deterministic review-ordering heuristic, not a CVSS/exploitability score.
- `npm audit` reports 12 vulnerabilities in the frontend dev dependencies (4 moderate, 6 high, 2 critical). Those are in the local/CI dev toolchain (vite, esbuild, vitest/tinypool, postcss-selector-parser and dependents), not in the production frontend bundle shipped to end users. Treat this as a dev-workstation/CI hygiene and update-task item, not as a shipped-product vulnerability.

### Steps needed before real-world deployment

- Replace default `SECRET_KEY` and `FIRST_ADMIN_PASSWORD` with strong values.
- Decide whether scan endpoints require authenticated users and implement the corresponding auth enforcement if so.
- Tighten `CORS_ORIGINS` for the target deployment host(s).
- Set `SCAN_ALLOW_PRIVATE_TARGETS` according to policy.
- Configure `AUTHORIZED_PROJECT_ROOTS` only for directories the operator is authorized to scan.
- If AI explanations are enabled, configure a real provider endpoint + key and review the provider’s data-handling terms.
- Add a lint/type gate (e.g. ruff/mypy) and a CI pipeline if one is not already present.
- Run the Phase 8 E2E suite as part of release verification.
- Update frontend dev dependencies to audited-safe versions; verify `npm audit` results and resolve or document any remaining items before publishing developer tooling/config.
