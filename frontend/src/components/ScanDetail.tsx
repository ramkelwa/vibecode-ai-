import { useEffect, useRef, useState } from 'react'
import {
  Clock,
  FileJson,
  FileText,
  Globe,
  Loader2,
  Sparkles,
  XCircle,
} from 'lucide-react'
import {
  api,
  ApiError,
  reportUrls,
  type AiExplanation,
  type AiProviderStatus,
  type ScanDetail as ScanDetailData,
  type ScanStage,
} from '../api'
import { STAGE_LABEL } from './moduleList'
import { ErrorState, Panel, SeverityBadge, StatusDot } from './ui'

export default function ScanDetail({
  detail,
  onScanUpdated,
  onFocusFindings,
}: {
  detail: ScanDetailData | null
  onScanUpdated: () => void
  onFocusFindings: () => void
}) {
  const [cancelPending, setCancelPending] = useState(false)
  const [cancelError, setCancelError] = useState<string | null>(null)
  const [explainPendingId, setExplainPendingId] = useState<string | null>(null)
  const [explanations, setExplanations] = useState<Record<string, AiExplanation>>({})
  const [explainErrors, setExplainErrors] = useState<Record<string, string>>({})
  const [aiStatus, setAiStatus] = useState<AiProviderStatus | null>(null)
  const aiStatusLoaded = useRef(false)
  const scanId = detail?.scan.id ?? null

  useEffect(() => {
    if (!scanId || aiStatusLoaded.current) return
    aiStatusLoaded.current = true
    let cancelled = false
    api
      .aiProviderStatus()
      .then((status) => {
        if (!cancelled) setAiStatus(status)
      })
      .catch(() => {
        if (!cancelled) setAiStatus(null)
      })
    return () => {
      cancelled = true
    }
  }, [scanId])

  if (!detail) {
    return (
      <Panel title="Scan details" testId="scan-detail-panel">
        <p className="text-sm text-zinc-400 py-2">Select a scan to see details.</p>
      </Panel>
    )
  }

  const { scan, stages, findings } = detail
  const active = scan.status === 'pending' || scan.status === 'running'
  const completed = scan.status === 'completed'
  const downloads = reportUrls(scan.id)

  const cancel = async () => {
    setCancelPending(true)
    setCancelError(null)
    try {
      await api.cancelScan(scan.id)
      onScanUpdated()
    } catch (err: unknown) {
      setCancelError(
        err instanceof ApiError ? err.detail : err instanceof Error ? err.message : String(err),
      )
    } finally {
      setCancelPending(false)
    }
  }

  const explain = async (findingId: string) => {
    setExplainPendingId(findingId)
    setExplainErrors((prev) => ({ ...prev, [findingId]: '' }))
    try {
      const result = await api.explainFinding(scan.id, findingId)
      setExplanations((prev) => ({ ...prev, [findingId]: result }))
    } catch (err: unknown) {
      const msg =
        err instanceof ApiError ? err.detail : err instanceof Error ? err.message : String(err)
      setExplainErrors((prev) => ({ ...prev, [findingId]: msg }))
    } finally {
      setExplainPendingId(null)
    }
  }

  const failed = stages.filter((s) => s.status === 'failed')
  const aiEnabled = aiStatus?.enabled === true

  return (
    <div className="space-y-6">
      <Panel
        title="Scan details"
        testId="scan-detail-panel"
        actions={
          active ? (
            <button
              type="button"
              onClick={cancel}
              disabled={cancelPending}
              aria-busy={cancelPending}
              className="vin-btn-ghost flex items-center gap-1.5 px-3 py-1.5 text-xs text-red-300 hover:text-red-200 hover:border-red-500/40 disabled:opacity-50"
            >
              <XCircle className="h-3.5 w-3.5" aria-hidden />
              {cancelPending ? 'Cancelling…' : 'Cancel scan'}
            </button>
          ) : (
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={onFocusFindings}
                className="vin-btn-primary px-3 py-1.5 text-xs font-medium"
              >
                Open findings
              </button>
              {completed && downloads && (
                <>
                  <a
                    href={downloads.json}
                    download
                    data-testid="download-json-report"
                    className="vin-btn-ghost flex items-center gap-1.5 px-3 py-1.5 text-xs"
                  >
                    <FileJson className="h-3.5 w-3.5" aria-hidden />
                    JSON report
                  </a>
                  <a
                    href={downloads.pdf}
                    download
                    data-testid="download-pdf-report"
                    className="vin-btn-ghost flex items-center gap-1.5 px-3 py-1.5 text-xs"
                  >
                    <FileText className="h-3.5 w-3.5" aria-hidden />
                    PDF report
                  </a>
                </>
              )}
            </div>
          )
        }
      >
        {/* Metadata summary grid */}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4 rounded-lg border border-zinc-800/60 bg-zinc-900/40 p-4">
          <div className="sm:col-span-2">
            <dt className="text-xs font-medium text-zinc-400">Target</dt>
            <dd className="mt-1 flex items-center gap-2 truncate font-mono text-sm font-semibold text-zinc-200">
              <Globe className="h-4 w-4 text-sky-400 shrink-0" aria-hidden />
              <span className="truncate">{scan.target_url}</span>
            </dd>
          </div>

          <div>
            <dt className="text-xs font-medium text-zinc-400">Status</dt>
            <dd className="mt-1 flex items-center gap-2 text-sm font-semibold text-zinc-200 capitalize">
              <StatusDot status={scan.status} />
              <span>{scan.status}</span>
            </dd>
          </div>

          <div>
            <dt className="text-xs font-medium text-zinc-400">Scan ID</dt>
            <dd className="mt-1 font-mono text-xs text-zinc-400 select-all" data-testid="scan-detail-id">
              {scan.id}
            </dd>
          </div>

          <div className="sm:col-span-2 lg:col-span-4 border-t border-zinc-800/40 pt-2 flex flex-wrap items-center justify-between text-xs text-zinc-400">
            <span className="flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5 text-zinc-500" aria-hidden />
              Started: {scan.started_at ? new Date(scan.started_at).toLocaleString() : 'not started'}
            </span>
            <span>
              Finished: {scan.finished_at ? new Date(scan.finished_at).toLocaleString() : '—'}
            </span>
          </div>

          {scan.error && (
            <div className="col-span-full border-t border-red-500/20 pt-2 text-xs text-red-400" role="alert">
              <strong>Error:</strong> {scan.error}
            </div>
          )}
        </div>

        {/* Module stages list */}
        <div className="mt-5" data-testid="stage-list">
          <div className="mb-2 flex items-center justify-between text-xs text-zinc-400">
            <span className="font-semibold uppercase tracking-wider text-zinc-400">
              Module stages ({stages.filter((s) => s.status === 'completed').length}/{stages.length}{' '}
              completed)
            </span>
          </div>
          <div className="rounded-lg border border-zinc-800/60 bg-zinc-900/30 divide-y divide-zinc-800/40">
            {stages.map((s: ScanStage) => (
              <div key={s.module} className="flex items-center justify-between gap-3 px-3.5 py-2.5 text-xs">
                <div className="flex items-center gap-2.5 min-w-0">
                  <StatusDot status={s.status} />
                  <span className="font-medium text-zinc-200 truncate">
                    {STAGE_LABEL[s.module] ?? s.module}
                  </span>
                  {s.detail && (
                    <span className="hidden truncate text-zinc-500 md:inline">
                      — {s.detail}
                    </span>
                  )}
                </div>
                <span className="rounded border border-zinc-800 bg-zinc-900 px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider text-zinc-400 shrink-0">
                  {s.status}
                </span>
              </div>
            ))}
          </div>

          {failed.length > 0 && (
            <p className="mt-2 text-xs text-amber-300" role="note" data-testid="partial-failures">
              {failed.length} module stage(s) failed ({failed.map((s) => STAGE_LABEL[s.module] ?? s.module).join(', ')}); results cover the modules that completed.
            </p>
          )}
          {scan.status === 'cancelled' && (
            <p className="mt-2 text-xs text-zinc-400" role="note" data-testid="cancelled-note">
              This scan was cancelled.
            </p>
          )}
          {cancelError && (
            <div className="mt-2">
              <ErrorState message={cancelError} onRetry={cancel} />
            </div>
          )}
        </div>
      </Panel>

      {/* Stored findings panel with AI explanations */}
      <Panel title={`Findings stored for this scan (${findings.length})`}>
        {aiStatus && !aiEnabled && (
          <div
            className="mb-4 rounded-lg border border-violet-500/20 bg-violet-950/15 p-3 text-xs text-zinc-300"
            role="note"
            data-testid="ai-provider-note"
          >
            AI explanations are off: no AI provider is configured on this server, so
            &ldquo;Explain locally&rdquo; builds a rule-based interpretation from the stored
            finding fields. Set{' '}
            <span className="font-mono text-violet-300">AI_PROVIDER_FAMILY</span> and{' '}
            <span className="font-mono text-violet-300">AI_API_KEY</span> on the backend to enable
            AI-generated text.
          </div>
        )}
        {findings.length === 0 ? (
          <p className="text-sm text-zinc-400 py-3" role="note">
            No findings recorded by this scan's modules.
          </p>
        ) : (
          <ul className="max-h-80 space-y-2 overflow-y-auto pr-1 text-sm">
            {findings.slice(0, 50).map((f) => {
              const explanation = explanations[f.id]
              const explainError = explainErrors[f.id]
              const isExplaining = explainPendingId === f.id
              return (
                <li
                  key={f.id}
                  className="rounded-lg border border-zinc-800/60 bg-zinc-900/40 p-3 transition-colors hover:border-zinc-700/80"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex min-w-0 items-center gap-2.5">
                      <SeverityBadge severity={f.severity} />
                      <span className="truncate font-medium text-zinc-200" title={f.title}>
                        {f.title}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => explain(f.id)}
                        disabled={explainPendingId !== null}
                        aria-busy={isExplaining}
                        data-testid={`explain-finding-${f.id}`}
                        title={
                          aiEnabled
                            ? 'Ask the configured AI provider to interpret this finding'
                            : 'No AI provider configured — build a local interpretation from stored data'
                        }
                        className="vin-btn-ghost flex shrink-0 items-center gap-1.5 border-violet-500/30 bg-violet-950/20 px-2.5 py-1 text-xs text-violet-300 hover:bg-violet-900/40 hover:text-violet-200 disabled:opacity-50"
                      >
                        {isExplaining ? (
                          <Loader2 className="h-3 w-3 animate-spin" aria-hidden />
                        ) : (
                          <Sparkles className="h-3 w-3" aria-hidden />
                        )}
                        {isExplaining
                          ? aiEnabled
                            ? 'Asking…'
                            : 'Working…'
                          : aiEnabled
                            ? 'Explain with AI'
                            : 'Explain locally'}
                      </button>
                      <span className="hidden font-mono text-[11px] text-zinc-400 sm:inline">
                        {f.source_module}
                      </span>
                    </div>
                  </div>

                  {explanation && (
                    <div
                      className="mt-3 rounded-md border border-violet-500/30 bg-violet-950/25 p-3 text-xs"
                      data-testid={`ai-explanation-${f.id}`}
                      role={explanation.text ? 'note' : 'alert'}
                    >
                      <p className="mb-1.5 flex items-center gap-1.5 font-semibold text-violet-300">
                        <Sparkles className="h-3.5 w-3.5" aria-hidden />
                        <span>{explanation.label}</span>
                        {!explanation.text && (
                          <span className="font-mono text-zinc-400">
                            — provider {String(explanation.provider).trim() || '—'}
                          </span>
                        )}
                      </p>
                      {explanation.text ? (
                        <p className="whitespace-pre-wrap leading-relaxed text-zinc-200">
                          {explanation.text}
                        </p>
                      ) : (
                        <p className="text-amber-300">
                          {explanation.error || 'AI explanation is not available for this scan.'}
                        </p>
                      )}
                      {explanation.warning && explanation.provider !== 'local' && (
                        <p className="mt-1.5 text-amber-300">{explanation.warning}</p>
                      )}
                    </div>
                  )}

                  {explainError && (
                    <p className="mt-2 text-xs text-amber-300" role="alert">
                      AI explanation unavailable: {explainError}
                    </p>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </Panel>
    </div>
  )
}
