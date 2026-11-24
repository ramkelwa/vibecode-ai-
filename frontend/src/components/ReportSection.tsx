import { ArrowLeftRight, FileBarChart, Layers, Network } from 'lucide-react'
import type { CorrelationLink, RiskSummary } from '../api'
import { EmptyState, ErrorState, LoadingState, Panel, SeverityBadge } from './ui'

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
    <div className="space-y-6">
      <Panel title="Risk report (deterministic engine output)" testId="report-panel">
        {summaryError ? (
          <ErrorState message={summaryError} onRetry={onRetry} />
        ) : summaryLoading && !summary ? (
          <LoadingState label="Computing report from stored findings…" />
        ) : !summary ? (
          <EmptyState message="Select a completed scan to see its report." />
        ) : (
          <div className="space-y-5 text-sm">
            <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Kpi label="Findings (stored)" value={summary.counts.total} icon={FileBarChart} />
              <Kpi label="After dedup" value={summary.counts.deduplicated} icon={Layers} />
              <Kpi label="Duplicate groups" value={summary.counts.duplicate_groups} icon={Layers} />
              <Kpi label="Correlation links" value={summary.counts.correlations_considered} icon={Network} />
            </dl>

            {summary.counts.malformed_skipped > 0 && (
              <p className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-300" role="note">
                {summary.counts.malformed_skipped} malformed record(s) skipped and recorded (no data
                invented).
              </p>
            )}

            <div className="space-y-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
                Prioritized for review — priority = severity &times; confidence &times; verification weight
              </h3>
              {summary.prioritized.length === 0 ? (
                <p className="text-xs text-zinc-500 py-2">No findings to prioritize.</p>
              ) : (
                <div className="overflow-x-auto rounded-lg border border-zinc-800/60 bg-zinc-900/30">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-zinc-800 bg-zinc-900/60 text-zinc-400 font-semibold uppercase tracking-wider">
                        <th className="py-2.5 px-3" scope="col">Priority</th>
                        <th className="py-2.5 px-3" scope="col">Severity</th>
                        <th className="py-2.5 px-3" scope="col">Title</th>
                        <th className="py-2.5 px-3" scope="col">Status</th>
                        <th className="py-2.5 px-3" scope="col">Sources</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/40">
                      {summary.prioritized.map((f) => (
                        <tr key={f.id} className="transition-colors hover:bg-zinc-800/40">
                          <td className="py-2.5 px-3 font-mono font-semibold text-sky-400">
                            {f.priority.toFixed(1)}
                          </td>
                          <td className="py-2.5 px-3">
                            <SeverityBadge severity={f.severity} />
                          </td>
                          <td className="py-2.5 px-3 font-medium text-zinc-200">{f.title}</td>
                          <td className="py-2.5 px-3 font-mono text-[11px] text-zinc-400">
                            {f.verification_status}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[11px] text-zinc-500">
                            {f.source_modules.join(', ')}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <p className="text-[11px] text-zinc-500 leading-relaxed">
              {summary.formula.limitations[0]}
            </p>
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
          <ul className="space-y-2.5">
            {correlations.map((c) => (
              <li
                key={c.id}
                className="vin-panel-soft p-3.5 text-xs transition-colors hover:border-zinc-700/80"
                data-testid="correlation-item"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="rounded border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 font-mono text-[10px] uppercase font-semibold text-sky-400">
                    {c.relation}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-sm font-semibold text-zinc-200 my-1">
                  <span>{c.finding_title}</span>
                  <ArrowLeftRight className="h-3.5 w-3.5 text-zinc-500 shrink-0" aria-hidden />
                  <span>{c.related_title}</span>
                </div>
                <div className="text-zinc-400 leading-relaxed">{c.reason}</div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}

function Kpi({
  label,
  value,
  icon: Icon,
}: {
  label: string
  value: number
  icon: typeof FileBarChart
}) {
  return (
    <div className="vin-tile p-3.5 flex flex-col justify-between">
      <div className="flex items-center justify-between gap-2">
        <dt className="vin-kicker !text-[10px] text-zinc-400">{label}</dt>
        <div className="flex h-6 w-6 items-center justify-center rounded border border-zinc-800 bg-zinc-800/40 text-zinc-400">
          <Icon className="h-3 w-3" aria-hidden />
        </div>
      </div>
      <dd className="vin-figure mt-2 text-zinc-100">{value}</dd>
    </div>
  )
}
