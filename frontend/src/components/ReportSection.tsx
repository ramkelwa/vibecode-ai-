import type { CorrelationLink, RiskSummary } from '../api'
import { ErrorState, EmptyState, LoadingState, Panel, SeverityBadge } from './ui'

export default function ReportSection({
  summary,
  summaryError,
  summaryLoading,
  onRetry,
  correlations,
  correlationsError,
}: {
  summary: RiskSummary | null
  summaryError: string | null
  summaryLoading: boolean
  onRetry: () => void
  correlations: CorrelationLink[] | null
  correlationsError: string | null
}) {
  return (
    <div className="space-y-4">
      <Panel title="Risk report (deterministic engine output)" testId="report-panel">
        {summaryError ? (
          <ErrorState message={summaryError} onRetry={onRetry} />
        ) : summaryLoading && !summary ? (
          <LoadingState label="Computing report from stored findings…" />
        ) : !summary ? (
          <EmptyState message="Select a completed scan to see its report." />
        ) : (
          <div className="space-y-3 text-sm">
            <dl className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Kpi label="Findings (stored)" value={summary.counts.total} />
              <Kpi label="After dedup" value={summary.counts.deduplicated} />
              <Kpi label="Duplicate groups" value={summary.counts.duplicate_groups} />
              <Kpi label="Correlation links" value={summary.counts.correlations_considered} />
            </dl>
            {summary.counts.malformed_skipped > 0 && (
              <p className="text-xs text-amber-400" role="note">
                {summary.counts.malformed_skipped} malformed record(s) skipped and recorded (no data
                invented).
              </p>
            )}
            <div>
              <h3 className="mb-1 text-xs font-medium text-slate-400">
                Prioritized for review — priority = severity × confidence × verification weight
              </h3>
              {summary.prioritized.length === 0 ? (
                <p className="text-xs text-slate-500">No findings to prioritize.</p>
              ) : (
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-500">
                      <th className="pb-1 pr-2" scope="col">Priority</th>
                      <th className="pb-1 pr-2" scope="col">Severity</th>
                      <th className="pb-1 pr-2" scope="col">Title</th>
                      <th className="pb-1 pr-2" scope="col">Status</th>
                      <th className="pb-1" scope="col">Sources</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.prioritized.map((f) => (
                      <tr key={f.id} className="border-b border-slate-900">
                        <td className="py-1 pr-2 font-mono">{f.priority.toFixed(1)}</td>
                        <td className="py-1 pr-2"><SeverityBadge severity={f.severity} /></td>
                        <td className="py-1 pr-2">{f.title}</td>
                        <td className="py-1 pr-2 text-slate-400">{f.verification_status}</td>
                        <td className="py-1 font-mono text-slate-600">{f.source_modules.join(', ')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
            <p className="text-[11px] text-slate-600">{summary.formula.limitations[0]}</p>
          </div>
        )}
      </Panel>

      <Panel title="Correlated review context" testId="correlations-panel">
        {correlationsError ? (
          <ErrorState message={correlationsError} />
        ) : !correlations ? (
          <EmptyState message="Select a completed scan." />
        ) : correlations.length === 0 ? (
          <EmptyState message="No cautious correlations between this scan's findings." />
        ) : (
          <ul className="space-y-2">
            {correlations.map((c) => (
              <li key={c.id} className="rounded border border-slate-800 p-2 text-xs" data-testid="correlation-item">
                <div className="font-mono text-slate-500">{c.relation}</div>
                <div className="text-slate-300">
                  {c.finding_title} ↔ {c.related_title}
                </div>
                <div className="text-slate-500">{c.reason}</div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}

function Kpi({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-slate-800 bg-slate-950/60 p-3">
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="mt-1 font-mono text-lg text-slate-200">{value}</dd>
    </div>
  )
}
