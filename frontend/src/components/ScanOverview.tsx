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
            className="vin-btn-primary px-3 py-1.5 text-xs"
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
            <Metric label="Total scans" value={metrics.totalScans} accent="cyan" />
            <Metric label="Running" value={metrics.running} accent="amber" />
            <Metric label="Completed" value={metrics.completed} accent="emerald" />
            <Metric
              label="Failed / cancelled"
              value={metrics.failedOrCancelled}
              accent="red"
            />
            <Metric label="Findings stored" value={metrics.findingsTotal} accent="violet" />
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
          <ul className="divide-y divide-slate-900/5 text-sm">
            {latestScans.slice(0, 6).map((s) => (
              <li key={s.id}>
                <button
                  type="button"
                  onClick={() => onOpenScan(s.id)}
                  className="vin-row-hover flex w-full items-center justify-between gap-2 rounded-lg px-2 py-2.5 text-left transition-colors hover:text-cyan-700"
                >
                  <span className="flex min-w-0 items-center gap-2.5">
                    <StatusDot status={s.status} />
                    <span className="truncate rounded border border-slate-900/5 bg-slate-950 px-1.5 py-0.5 font-mono text-[11px] text-slate-500">
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

const ACCENTS: Record<string, string> = {
  cyan: 'text-cyan-700 shadow-[0_0_22px_-6px_rgba(45,106,86,0.9)]',
  amber: 'text-amber-700 shadow-[0_0_22px_-6px_rgba(252,211,77,0.9)]',
  emerald: 'text-emerald-600 shadow-[0_0_22px_-6px_rgba(45,106,86,0.9)]',
  red: 'text-red-700 shadow-[0_0_22px_-6px_rgba(248,113,113,0.9)]',
  violet: 'text-violet-700 shadow-[0_0_22px_-6px_rgba(167,139,250,0.9)]',
}

function Metric({
  label,
  value,
  accent = 'cyan',
}: {
  label: string
  value: number
  accent?: keyof typeof ACCENTS
}) {
  return (
    <div className="vin-tile p-3.5" data-testid="overview-metric">
      <dt className="vin-kicker !text-[9px]">{label}</dt>
      <dd className={`mt-1.5 font-mono text-2xl font-semibold tabular-nums ${ACCENTS[accent]}`}>
        {value}
      </dd>
    </div>
  )
}
