# VibeShield AI

**Evidence-based web application security assessment — for sites and code you are authorized to test.**

[![Live App](https://img.shields.io/badge/Live%20App-vibecode--ai--five.vercel.app-6366f1?style=for-the-badge&logo=vercel&logoColor=white)](https://vibecode-ai-five.vercel.app)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React%2018-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-3178C6?style=flat-square&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?style=flat-square&logo=githubactions&logoColor=white)](.github/workflows/ci-cd.yml)

> **Website:** <https://vibecode-ai-five.vercel.app>

VibeShield AI is a web application security assessment dashboard for **authorized testing**. It combines passive website checks, optional scans of explicitly authorized source-code projects, evidence-based findings, and downloadable reports in one interface.

The application helps developers and security teams identify issues that deserve review. It is **not** a penetration-testing platform, a replacement for a professional security assessment, or proof that a target is safe.

---

## Table of contents

- [Why VibeShield AI](#why-vibeshield-ai)
- [Features](#features)
- [How it works](#how-it-works)
- [Technology stack](#technology-stack)
- [Project structure](#project-structure)
- [Typical uses](#typical-uses)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Usage](#usage)
- [API overview](#api-overview)
- [Configuration](#configuration)
- [Safety model and limitations](#safety-model-and-limitations)
- [Testing and CI/CD](#testing-and-cicd)
- [Deployment](#deployment)

---

## Why VibeShield AI

Security reviews often produce scattered notes, screenshots, and tool output that are hard to prioritize or share. VibeShield AI keeps the whole review in one place:

- **One scan, many checks.** URL, DNS, TLS, headers, cookies, HTML, JavaScript, and API endpoints are assessed together.
- **Evidence over verdicts.** Every observation is stored with the evidence that produced it. Missing or failed modules are reported as coverage gaps — never as a clean result.
- **Consistent triage.** Findings are normalized, deduplicated, cautiously correlated, and given a deterministic review priority so teams can focus in the same order.
- **Actionable output.** Results can be exported as JSON or PDF for developer follow-up.

## Features

- **Website assessment:** inspect URL and redirect behavior, DNS records, TLS certificates and protocols, HTTP security headers, cookies, HTML metadata, forms, JavaScript assets, and statically referenced API endpoints.
- **Client-side code review:** report selected risky JavaScript patterns and candidate secrets with their values **redacted**. JavaScript is analyzed statically and is never executed.
- **Authorized project scans:** optionally audit supported Node and Python dependency manifests and run Semgrep source analysis. Project scanning is separate from website scanning and restricted to configured directories.
- **Findings explorer:** follow scan progress, inspect module stages and evidence, filter findings, browse discovered endpoints and scripts, and review remediation guidance.
- **Consistent prioritization:** normalize and deduplicate observations, cautiously correlate related findings, and calculate a deterministic review priority. The priority is a triage aid, not a vulnerability or exploitability score.
- **Reports:** download JSON or PDF reports generated from stored scan results.
- **Optional integrations:** request evidence-based AI explanations or VirusTotal threat intelligence when configured. Both are off or unavailable without their server-side credentials.

## How it works

A website scan runs a bounded, passive pipeline. Each stage records its own status and evidence:

```text
url_validation → dns_analysis → tls_analysis → http_headers → cookie_analysis
      → html_analysis → js_discovery → js_analysis → api_discovery → risk summary
```

1. **Validate the target.** The URL, redirects, and destination IPs are checked against the configured network policy.
2. **Collect observations.** Passive modules fetch the site within request, timeout, size, and rate limits.
3. **Normalize and correlate.** Observations become structured findings; related findings are linked with a stated reason.
4. **Prioritize.** A deterministic review priority is calculated from severity and confidence signals.
5. **Report.** Stored results can be reviewed in the dashboard and exported as JSON or PDF.

These are passive checks and bounded fetches. The scanner does **not** attempt exploitation, authentication bypass, or business-logic testing. It cannot observe behavior that requires a browser session, runtime JavaScript, or application-specific context.

## Technology stack

| Area | Technologies |
|---|---|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Lucide icons |
| Backend API | Python 3.12, FastAPI, Pydantic v2, Uvicorn |
| Scanning and HTTP | HTTPX, dnspython, Beautiful Soup; purpose-specific scanner modules |
| Persistence | SQLAlchemy 2 with SQLite (local development) or PostgreSQL |
| Auth primitives | PyJWT, bcrypt (configuration exists; scan endpoints are not currently gated) |
| Optional project tools | npm audit, pip-audit, Semgrep; configured tools run as subprocesses |
| Reports and integrations | ReportLab (PDF), optional OpenAI-compatible AI providers, optional VirusTotal API |
| Tests and CI | pytest, Vitest, Testing Library, TypeScript build, GitHub Actions, Docker |
| Hosting | Backend on Render (Docker + PostgreSQL), frontend on Vercel |

## Project structure

```text
vibeshield-ai/
├── backend/
│   ├── app/
│   │   ├── api/          # FastAPI routers: scans, artifacts, risk, AI, VirusTotal
│   │   ├── core/         # Settings, database, logging, URL guard
│   │   ├── models/       # SQLAlchemy models
│   │   ├── scanners/     # URL, DNS, TLS, headers, cookies, HTML, JS, API modules
│   │   ├── services/     # VirusTotal service
│   │   ├── tools/        # External tool runners (Semgrep, ZAP, subprocess)
│   │   ├── providers.py  # AI provider abstraction
│   │   ├── report.py     # JSON/PDF report generation
│   │   └── main.py       # Application entry point
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/   # Dashboard, scan form, findings explorer, reports
│   │   ├── api.ts        # API client
│   │   └── App.tsx
│   ├── package.json
│   └── .env.example
├── .github/workflows/ci-cd.yml
├── docker-compose.yml
└── render.yaml
```

## Typical uses

- Check an application you own or are explicitly authorized to assess for common web-configuration and client-side issues.
- Inventory observed scripts and API endpoint references during a security review.
- Review dependency advisories or static-analysis results for an authorized local project directory.
- Keep scan results, review priorities, evidence, and reports together for developer follow-up.
- Demonstrate a security-review workflow in a local or controlled lab environment.

## Requirements

- **Python 3.12** recommended (CI uses Python 3.12).
- **Node.js 20** and npm.
- Windows (PowerShell or Git Bash), macOS, or Linux for local development.
- Optional: Docker Desktop / Docker Engine for the PostgreSQL or full-stack Docker setup.

## Quick start

### 1. Configure the backend

```powershell
cd backend
python -m venv ..\.venv
..\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

On macOS/Linux or Git Bash:

```bash
cd backend
python3 -m venv ../.venv
source ../.venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

The backend defaults to SQLite and reads `backend/.env`.

### 2. Configure the frontend

```powershell
cd ..\frontend
npm install
Copy-Item .env.example .env
```

Set `VITE_API_BASE_URL=http://localhost:8000` for local development. Keep real credentials in the backend environment — never in frontend variables or committed files.

### 3. Run both services

```powershell
# Terminal 1 — from the backend directory, with the virtual environment active
uvicorn app.main:app --reload --port 8000

# Terminal 2 — from the frontend directory
npm run dev
```

Open <http://localhost:5173>. During development, Vite proxies `/api` requests to the backend at `http://localhost:8000`. The FastAPI interactive documentation is available at <http://localhost:8000/api/docs>.

### PostgreSQL or Docker

Run PostgreSQL in Docker and the application locally:

```bash
docker compose up --build -d postgres
```

Then set `DATABASE_URL` in `backend/.env`:

```text
DATABASE_URL=postgresql+psycopg://vibeshield:vibeshield@localhost:5432/vibeshield
```

To start the services defined by Docker Compose:

```bash
docker compose up --build
```

The Compose backend is configured to reject private network targets. Review the Compose configuration and replace development credentials before using this setup beyond a local environment.

## Usage

### Website scans

1. Open the dashboard and create a scan for an `http://` or `https://` URL.
2. Confirm that you are authorized to test the target.
3. Follow scan progress and inspect each module stage.
4. Review findings, discovered scripts, and API endpoints.
5. Export a JSON or PDF report when the scan completes.

### Authorized project scans

Project scans operate on a local directory, not a website URL. To enable them, set `AUTHORIZED_PROJECT_ROOTS` in `backend/.env` to one or more absolute paths the operator is authorized to scan. Leave it empty to keep project scans disabled. The requested project directory must be within one of those roots.

Supported checks include dependency audits for Node/Python manifests and lockfiles plus static source analysis with Semgrep. Install the external tools you intend to use (for example `pip-audit` and `semgrep`) and ensure they are available to the backend process. Missing tools, unsupported or unpinned dependencies, and tool failures are reported as coverage gaps or errors, not as clean results. Project scanning does not execute the target project's code or package lifecycle scripts.

## API overview

The API is served under `/api`. Interactive documentation is at `/api/docs`.

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | API and database health |
| `POST /api/scans` | Create an authorized website scan |
| `POST /api/scans/project` | Create an authorized local project scan |
| `GET /api/scans` | List recent scans |
| `GET /api/scans/{id}` | Get scan status, stages, and findings |
| `POST /api/scans/{id}/cancel` | Request cancellation of a running scan |
| `GET /api/scans/{id}/artifacts` | Get recorded HTML, JavaScript, endpoint, and project artifacts |
| `GET /api/scans/{id}/risk-summary` | Get finding counts and deterministic review priorities |
| `GET /api/scans/{id}/correlations` | Get reasoned links between findings |
| `GET /api/reports/{id}/json` | Download a JSON report |
| `GET /api/reports/{id}/pdf` | Download a PDF report |
| `GET /api/ai-provider/status` | Check whether AI explanations are configured |
| `POST /api/ai-provider/explain/{id}` | Request an AI explanation of a finding |
| `POST /api/ai-provider/explain-and-store/{id}` | Request and store an AI explanation |
| `GET /api/virustotal/report?url=...` | Look up an existing VirusTotal URL report |
| `GET /api/virustotal/file-report/{sha256}` | Look up a VirusTotal file report by hash |
| `POST /api/virustotal/scan` | Submit a URL for analysis (explicit user action) |
| `POST /api/virustotal/files/scan` | Submit a file for analysis (explicit user action) |

## Configuration

The full list of backend settings and example values is in [`backend/.env.example`](backend/.env.example). The frontend has a separate [`frontend/.env.example`](frontend/.env.example).

Important operational settings:

- `DATABASE_URL` — SQLite or PostgreSQL database connection.
- `CORS_ORIGINS` — comma-separated frontend origins allowed by the API.
- `SECRET_KEY` — replace the development default with a strong random value.
- `SCAN_ALLOW_PRIVATE_TARGETS` — controls whether private and local targets may be scanned. Private targets are allowed by the local backend default; the provided Compose backend disables them.
- `SCAN_REQUEST_TIMEOUT`, `SCAN_TOTAL_TIMEOUT`, `SCAN_MAX_REQUESTS_PER_TARGET`, `SCAN_REQUESTS_PER_SECOND`, `SCAN_MAX_CONCURRENCY` — bound scan resource use.
- `AUTHORIZED_PROJECT_ROOTS` — filesystem scope for project scans.

### Optional integrations

**AI explanations** are off by default. Configure `AI_PROVIDER_FAMILY`, `AI_PROVIDER_BASE_URL`, `AI_MODEL`, and `AI_API_KEY` to enable them. Supported families include OpenAI-compatible endpoints and GLM-family models over a compatible transport. Explanations are generated from stored finding data and are labeled separately from scanner evidence. Review the provider's data-handling terms first — finding details may be sent to that provider.

**VirusTotal** is an optional, separate source of third-party threat intelligence; its results are not VibeShield findings. Set `VIRUSTOTAL_API_KEY` in the backend environment to enable it. The key is server-side only. URL lookups send the complete URL, including its query string. Do not submit confidential URLs, URLs containing secrets, or private files. File uploads require explicit user confirmation and are capped at 32 MiB.

## Safety model and limitations

The application includes target and redirect validation, destination-IP checks, request limits, timeouts, response-size caps, rate limiting, and restricted project paths. These controls do not replace deployment security or an authorization process.

- **Not a pentest platform.** No exploitation, authentication bypass, or business-logic testing.
- **No runtime JavaScript.** Client-side analysis is static only.
- **No clean-scan guarantee.** Unavailable or failed modules are reported as coverage gaps.
- **Auth gap.** Although auth-related configuration and primitives exist, scan endpoints do not currently require authenticated sessions or provide per-user access control. Do not expose an unprotected instance to untrusted users or the public internet.
- **Third-party data leaves the app** only when optional AI or VirusTotal features are configured and used.

## Testing and CI/CD

Backend tests (from `backend`, with the virtual environment active):

```bash
python -m pytest
```

Frontend tests and production type-check/build (from `frontend`):

```bash
npm test
npm run build
```

The GitHub Actions workflow (`.github/workflows/ci-cd.yml`) runs backend tests, frontend tests, the frontend production build, and the backend Docker build on pushes and pull requests to `main`. Deployment to Render and Vercel occurs only on pushes to `main` and only when the corresponding repository secrets and variables are configured.

## Deployment

| Component | Platform | Configuration |
|---|---|---|
| Frontend | Vercel | `frontend/`, `VITE_API_BASE_URL` build variable |
| Backend | Render (Docker) | `render.yaml`, `/api/health` health check, managed PostgreSQL |
| CI/CD | GitHub Actions | `.github/workflows/ci-cd.yml` |

Before deploying for real users:

1. Replace all development/default credentials and set a strong `SECRET_KEY`.
2. Decide whether authentication and per-user authorization are required; they are not currently enforced by the scan endpoints.
3. Set restrictive `CORS_ORIGINS` and `SCAN_ALLOW_PRIVATE_TARGETS` values for the environment.
4. Configure project scan roots only for directories explicitly in scope.
5. Add optional AI and VirusTotal credentials only after reviewing their data handling and user-consent requirements.
6. Run the tests and controlled end-to-end checks for the deployment version.

---

**Live application:** <https://vibecode-ai-five.vercel.app>

Use VibeShield AI only on systems you own or are explicitly authorized to assess.
