import { useState } from 'react'
import { FileJson, FileText, Sparkles, XCircle } from 'lucide-react'
import {
  api,
  ApiError,
  reportUrls,
  type AiExplanation,
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
  // Phase 7: per-finding AI explanation state (optional, clearly labeled).
  const [explainPendingId, setExplainPendingId] = useState<string | null>(null)
  const [explanations, setExplanations] = useState<Record<string, AiExplanation>>({})
  const [explainErrors, setExplainErrors] = useState<Record<string, string>>({})

  if (!detail) {
    return (
      <Panel title="Scan details" testId="scan-detail-panel">
        <p className="text-sm text-slate-500">Select a scan to see details.</p>
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

  return (
    <div className="space-y-4">
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
              className="flex items-center gap-1 rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 disabled:opacity-50"
            >
              <XCircle className="h-3.5 w-3.5" aria-hidden />
              {cancelPending ? 'Cancelling…' : 'Cancel scan'}
            </button>
          ) : (
            <>
              <button
                type="button"
                onClick={onFocusFindings}
                className="rounded border border-sky-800 px-2 py-1 text-xs text-sky-300 hover:bg-sky-900/40"
              >
                Open findings
              </button>
              {completed && downloads && (
                <>
                  <a
                    href={downloads.json}
                    download
                    data-testid="download-json-report"
                    className="flex items-center gap-1 rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
                  >
                    <FileJson className="h-3.5 w-3.5" aria-hidden />
                    JSON report
                  </a>
                  <a
                    href={downloads.pdf}
                    download
                    data-testid="download-pdf-report"
                    className="flex items-center gap-1 rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800"
                  >
                    <FileText className="h-3.5 w-3.5" aria-hidden />
                    PDF report
                  </a>
                </>
              )}
            </>
          )
        }
      >
        <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm md:grid-cols-3">
          <div className="col-span-2 md:col-span-3">
            <dt className="text-xs text-slate-500">Scan ID (returned by the API)</dt>
            <dd className="font-mono text-xs text-slate-300" data-testid="scan-detail-id">
              {scan.id}
            </dd>
          </div>
          <div className="col-span-2">
            <dt className="text-xs text-slate-500">Target</dt>
            <dd className="truncate font-mono text-xs text-slate-300">{scan.target_url}</dd>
          </div>
          <div>
            <dt className="text-xs text-slate-500">Status</dt>
            <dd className="flex items-center gap-1.5 text-xs">
              <StatusDot status={scan.status} />
              {scan.status}
            </dd>
          </div>
          <div className="col-span-2">
            <dt className="text-xs text-slate-500">Started / finished</dt>
            <dd className="text-xs text-slate-400">
              {scan.started_at ?? 'not started'}
              {' → '}
              {scan.finished_at ?? '—'}
            </dd>
          </div>
          {scan.error && (
            <div className="col-span-2 md:col-span-3">
              <dt className="text-xs text-slate-500">API error</dt>
              <dd className="text-xs text-red-400" role="alert">
                {scan.error}
              </dd>
            </div>
          )}
        </dl>

        <div className="mt-4" data-testid="stage-list">
          <div className="mb-1 text-xs text-slate-500">
            Module stages ({stages.filter((s) => s.status === 'completed').length}/{stages.length}{' '}
            completed)
          </div>
          <ul className="space-y-1.5">
            {stages.map((s: ScanStage) => (
              <li key={s.module} className="flex items-center gap-2 text-sm">
                <StatusDot status={s.status} />
                <span className="w-48 shrink-0">{STAGE_LABEL[s.module] ?? s.module}</span>
                <span className="text-xs text-slate-500">{s.status}</span>
                {s.detail && <span className="truncate text-xs text-slate-600">{s.detail}</span>}
              </li>
            ))}
          </ul>
          {failed.length > 0 && (
            <p className="mt-2 text-xs text-amber-400" role="note" data-testid="partial-failures">
              {failed.length} module stage(s) failed ({failed.map((s) => STAGE_LABEL[s.module] ?? s.module).join(', ')}); results cover the modules that completed.
            </p>
          )}
          {scan.status === 'cancelled' && (
            <p className="mt-2 text-xs text-slate-400" role="note" data-testid="cancelled-note">
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

      <Panel title={`Findings stored for this scan (${findings.length})`}>
        {findings.length === 0 ? (
          <p className="text-sm text-slate-500" role="note">
            No findings recorded by this scan's modules.
          </p>
        ) : (
          <ul className="max-h-72 space-y-1 overflow-y-auto text-sm">
            {findings.slice(0, 50).map((f) => {
              const explanation = explanations[f.id]
              const explainError = explainErrors[f.id]
              return (
                <li key={f.id} className="border-b border-slate-900 py-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="min-w-0 flex-1 truncate" title={f.title}>
                      {f.title}
                    </span>
                    <button
                      type="button"
                      onClick={() => explain(f.id)}
                      disabled={explainPendingId !== null}
                      aria-busy={explainPendingId === f.id}
                      data-testid={`explain-finding-${f.id}`}
                      className="flex shrink-0 items-center gap-1 rounded border border-violet-700 px-2 py-0.5 text-xs text-violet-300 hover:bg-violet-900/40 disabled:opacity-50"
                    >
                      <Sparkles className="h-3 w-3" aria-hidden />
                      {explainPendingId === f.id ? 'Asking…' : 'Explain (AI)'}
                    </button>
                    <span className="shrink-0 font-mono text-xs text-slate-600">{f.source_module}</span>
                  </div>
                  {/* AI output is rendered separately from scanner evidence.
                     When no text is returned, the panel is shown clearly as an unavailable
                     note rather than as an AI-generated interpretation. */}
                  {explanation && (
                    <div
                      className="mt-1.5 rounded border border-violet-900/60 bg-violet-950/30 p-2 text-xs"
                      data-testid={`ai-explanation-${f.id}`}
                      role={explanation.text ? 'note' : 'alert'}
                    >
                      <p className="mb-1 flex items-center gap-1 font-medium text-violet-300">
                        {explanation.label}
                        {!explanation.text && (
                          <>
                            {' '}— provider <span className="font-mono hover:underline cursor-help">{String(explanation.provider).trim() || '—'}</span>
                          </>
                        )}
                      </p>
                      {explanation.text ? (
                        <p className="whitespace-pre-wrap text-slate-300">{explanation.text}</p>
                      ) : (
                        <p className="text-amber-400">
                          {explanation.error || 'AI explanation is not available for this scan.'}
                        </p>
                      )}
                      {explanation.warning && <p className="mt-1 text-amber-400">{explanation.warning}</p>}
                    </div>
                  )}
                  {explainError && (
                    <p className="mt-1 text-xs text-amber-400" role="alert">
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
