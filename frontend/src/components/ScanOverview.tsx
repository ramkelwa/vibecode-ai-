import type { ScanSummary } from '../api'
import { ErrorState, LoadingState, Panel, SeverityBarCounts, StatusDot } from './ui'
import type { ViewKey } from './Sidebar'

export interface OverviewMetrics {
  totalScans: number
  running: number
  completed: number
  failedOrCancelled: number
  findingsTotal: number
  bySeverity: Record<string, number>
}

export default function ScanOverview({
  metrics,
  latestScans,
  loading,
  error,
  onRetry,
  onOpenScan,
  onSelect,
}: {
  metrics: OverviewMetrics | null
  latestScans: ScanSummary[]
  loading: boolean
  error: string | null
  onRetry: () => void
  onOpenScan: (id: string) => void
  onSelect: (v: ViewKey) => void
}) {
  return (
    <div className="space-y-4">
      <Panel
        title="Fleet overview"
        testId="overview-panel"
        actions={
          <button
            type="button"
            onClick={() => onSelect('new-scan')}
            className="rounded bg-sky-700 px-2.5 py-1 text-xs font-medium hover:bg-sky-600"
          >
            Start new scan
          </button>
        }
      >
        {error ? (
          <ErrorState message={error} onRetry={onRetry} />
        ) : loading && !metrics ? (
          <LoadingState label="Loading overview…" />
        ) : metrics ? (
          <dl className="grid grid-cols-2 gap-3 text-sm md:grid-cols-5" data-testid="overview-metrics">
            <Metric label="Total scans" value={metrics.totalScans} />
            <Metric label="Running" value={metrics.running} />
            <Metric label="Completed" value={metrics.completed} />
            <Metric
              label="Failed / cancelled"
              value={metrics.failedOrCancelled}
            />
            <Metric label="Findings stored" value={metrics.findingsTotal} />
          </dl>
        ) : null}
        {error && metrics ? null : null}
      </Panel>

      {metrics && (
        <Panel title="Findings by severity (latest 100 scans)">
          <SeverityBarCounts bySeverity={metrics.bySeverity} />
        </Panel>
      )}

      <Panel title="Recent scans">
        {latestScans.length === 0 ? (
          <p className="text-sm text-slate-500" role="note">
            No scans recorded yet.
          </p>
        ) : (
          <ul className="divide-y divide-slate-900 text-sm">
            {latestScans.slice(0, 6).map((s) => (
              <li key={s.id}>
                <button
                  type="button"
                  onClick={() => onOpenScan(s.id)}
                  className="flex w-full items-center justify-between gap-2 py-2 text-left hover:text-sky-400"
                >
                  <span className="flex min-w-0 items-center gap-2">
                    <StatusDot status={s.status} />
                    <span className="truncate font-mono text-xs text-slate-500">
                      {s.id.slice(0, 8)}
                    </span>
                    <span className="truncate">{s.target_url}</span>
                  </span>
                  <span className="shrink-0 text-xs text-slate-500">{s.status}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-slate-800 bg-slate-950/60 p-3">
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="mt-1 font-mono text-lg text-slate-200">{value}</dd>
    </div>
  )
}
