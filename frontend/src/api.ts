/** Typed API client - every call targets a real backend endpoint. */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type StageStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped'
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

export interface Health {
  status: string
  app: string
  environment: string
  database: { state: 'ok' | 'unavailable'; detail: string }
  features: { scans: boolean; findings: boolean }
}

export interface ScanSummary {
  id: string
  target_url: string
  status: ScanStatus
  modules_requested: string[]
  error: string | null
  created_at: string
  started_at: string | null
  finished_at: string | null
}

export interface ScanStage {
  module: string
  status: StageStatus
  detail: string
  started_at: string | null
  finished_at: string | null
}

export interface Finding {
  id: string
  scan_id: string
  title: string
  description: string
  category: string
  severity: Severity
  confidence: string
  affected_asset: string
  evidence: Record<string, unknown>
  source_module: string
  cwe: string | null
  impact: string
  remediation: string
  verification_status: string
}

export interface ScanDetail {
  scan: ScanSummary
  stages: ScanStage[]
  findings: Finding[]
}

/** Phase 3 artifact inventory exposed by GET /api/scans/{id}/artifacts */

export interface HtmlArtifact {
  title: string | null
  meta: Array<{ name: string; content: string }>
  links: Array<{ rel: string; href: string; is_external: boolean }>
  /** Scripts observed in the document; inline entries carry `inline_length`, external ones carry `src`. */
  scripts: Array<{ inline: boolean; src?: string | null; inline_length?: number }>
  resources: Array<{ tag: string; url: string }>
  forms: Array<{
    method: string
    action: string
    action_external: boolean
    input_count: number
    input_types: string[]
    has_password_field: boolean
  }>
  has_password_field?: boolean
  parse_error?: string
}

/** One external JS asset recorded by js_discovery (fetched + hashed). */
export interface JsAsset {
  url: string
  origin: string
  same_origin: boolean
  status: number
  content_type: string | null
  size: number
  sha256: string
  content: string
}

/** js_discovery inventory: inline scripts as lengths, external as fetched assets. */
export interface JsAssets {
  inline: Array<{ length: number }>
  external: JsAsset[]
  errors: Record<string, unknown>
  source_maps_fetched: boolean
}

export interface JsAnalysisArtifact {
  assets_analyzed: number
}

export interface ApiEndpoint {
  url: string
  method: string
  source: string
  line: number | null
  same_origin: boolean
  confidence: string
  dynamically_constructed: boolean
  partial: boolean
}

export interface Artifacts {
  scan_id: string
  status: string
  document_url: string | null
  html: HtmlArtifact | null
  js_assets: JsAssets | null
  js_analysis: JsAnalysisArtifact | null
  api_endpoints: ApiEndpoint[]
  dns: unknown | null
  tls: unknown | null
  http_headers: unknown | null
  cookies: unknown | null
  /** Phase 4 project-scan inventories (present when those modules ran). */
  dependency_audit: DependencyAuditArtifact | null
  source_analysis: SourceAnalysisArtifact | null
  zap_dynamic: unknown | null
  /** Phase 5 post-processing results persisted at completion. */
  correlations: CorrelationLink[] | null
  risk_summary: RiskSummary | null
}

/** Phase 4 dependency-audit artifact (real tool-run records only). */
export interface DependencyAuditArtifact {
  root: string
  manifests: Array<{
    path: string
    ecosystem: string
    dependency_count: number
    errors: string[]
    unsupported: boolean
    dependencies: Array<{ name: string; version: string; pinned: boolean; from_lockfile: boolean }>
  }>
  tool_runs: Array<Record<string, unknown>>
  duration_seconds?: number
}

/** Phase 4 source-analysis artifact (semgrep metadata only). */
export interface SourceAnalysisArtifact {
  tool?: string
  scanned_file_count?: number
  tool_version?: string | null
  errors: string[]
  duration_seconds?: number
  root?: string
}

/** Phase 5: one correlation link with its reason (context only). */
export interface CorrelationLink {
  id: string
  relation: string
  finding: string
  related_to: string
  finding_title: string
  related_title: string
  reason: string
}

/** Phase 5: deterministic risk summary computed from stored findings. */
export interface RiskSummary {
  scan_id: string | null
  formula: {
    name: string
    expression: string
    limitations: string[]
  }
  counts: {
    total: number
    normalized: number
    deduplicated: number
    duplicate_groups: number
    malformed_skipped: number
    correlations_considered: number
    by_severity: Record<string, number>
    by_confidence: Record<string, number>
    by_verification_status: Record<string, number>
    by_category: Record<string, number>
  }
  prioritized: Array<{
    id: string
    title: string
    category: string
    severity: Severity
    confidence: string
    verification_status: string
    affected_asset: string
    source_modules: string[]
    priority: number
    remediation: string
    cwe: string | null
    cve: string | null
    contributing_original_ids: string[]
  }>
  remediation_suggestions: string[]
  errors: Array<{ index: number; reason: string; finding_preview: unknown }>
}


/** Typed API error carrying the HTTP status so the UI can react honestly. */
export class ApiError extends Error {
  status: number
  detail: string

  constructor(status: number, detail: string) {
    super(`API ${status}: ${detail}`)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '')

function apiUrl(path: string): string {
  return `${API_BASE_URL}${path}`
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let resp: Response
  try {
    resp = await fetch(apiUrl(path), {
      headers: { 'Content-Type': 'application/json' },
      ...init,
    })
  } catch (e: unknown) {
    // Network-level failure (server down, connection reset) — never mistaken
    // for an HTTP error response.
    throw new ApiError(0, e instanceof Error ? e.message : String(e))
  }
  if (!resp.ok) {
    // FastAPI validation errors arrive as {detail: string | [{loc, msg}]}
    const raw = await resp.text().catch(() => resp.statusText)
    let detail = raw
    try {
      const parsed: unknown = JSON.parse(raw)
      if (
        parsed && typeof parsed === 'object' && 'detail' in parsed
      ) {
        const d = (parsed as { detail: unknown }).detail
        if (typeof d === 'string') detail = d
        else if (Array.isArray(d)) {
          detail = d
            .map((it) => {
              const o = it as { loc?: unknown; msg?: unknown }
              return `${Array.isArray(o.loc) ? o.loc.join('.') : 'field'} ${String(o.msg ?? '')}`
            })
            .join('; ')
        }
      }
    } catch {
      /* keep raw text */
    }
    throw new ApiError(resp.status, detail || resp.statusText)
  }
  return (await resp.json()) as T
}

export interface CancelResult {
  cancelled: boolean
  status: string
}

/** Phase 7: non-secret AI provider status. */
export interface AiProviderStatus {
  family: string
  configured: boolean
  model_hint: string
  enabled: boolean
  notes: string
}

/** Phase 7: AI-generated explanation, clearly labeled and kept separate
 * from scanner evidence. `text` is empty until a real provider runs. */
export interface AiExplanation {
  finding_id: string
  provider: string
  model: string
  text: string
  error: string | null
  warning: string | null
  generated_at: string
  label: string
}

/** Download URL helpers for Phase 7 reports (plain GET endpoints). */
export const reportUrls = (scanId: string) => ({
  json: apiUrl(`/api/reports/${scanId}/json`),
  pdf: apiUrl(`/api/reports/${scanId}/pdf`),
})

export const api = {
  health: () => request<Health>('/api/health'),
  listScans: () => request<{ scans: ScanSummary[] }>('/api/scans'),
  getScan: (id: string) => request<ScanDetail>(`/api/scans/${id}`),
  getArtifacts: (id: string) => request<Artifacts>(`/api/scans/${id}/artifacts`),
  createScan: (targetUrl: string, modules: string[]) =>
    request<{ scan: ScanSummary }>('/api/scans', {
      method: 'POST',
      body: JSON.stringify({
        target_url: targetUrl,
        modules: modules.length > 0 ? modules : null,
        confirm_authorized: true,
      }),
    }),
  /** Phase 4: project scan over an authorized local directory. */
  createProjectScan: (projectDir: string, modules: string[]) =>
    request<{ scan: ScanSummary }>('/api/scans/project', {
      method: 'POST',
      body: JSON.stringify({
        project_dir: projectDir,
        modules: modules.length > 0 ? modules : null,
        confirm_authorized: true,
      }),
    }),
  /** Phase 5: deterministic risk summary for a scan. */
  getRiskSummary: (id: string) => request<RiskSummary>(`/api/scans/${id}/risk-summary`),
  /** Cancel a pending/running scan (server-side, no client simulation). */
  cancelScan: (id: string) =>
    request<CancelResult>(`/api/scans/${id}/cancel`, { method: 'POST' }),
  /** Phase 5: correlation links between related findings. */
  getCorrelations: (id: string) =>
    request<{ scan_id: string; links: CorrelationLink[]; count: number; note: string }>(
      `/api/scans/${id}/correlations`,
    ),
  /** Phase 7: provider status (never includes keys). */
  aiProviderStatus: () => request<AiProviderStatus>('/api/ai-provider/status'),
  /** Phase 7: request an AI explanation for one finding (optional action). */
  explainFinding: (scanId: string, findingId: string) =>
    request<AiExplanation>(`/api/ai-provider/explain/${scanId}`, {
      method: 'POST',
      body: JSON.stringify({
        finding_id: findingId,
        include_evidence: true,
        include_remediation: true,
      }),
    }),
}
