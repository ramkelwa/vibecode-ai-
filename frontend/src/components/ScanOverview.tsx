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

const TONES: Record<string, string> = {
  ink: 'text-slate-100',
  emerald: 'text-emerald-300',
  amber: 'text-amber-300',
  red: 'text-red-300',
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
    <div className="space-y-10">
      <Panel
        title="Fleet overview"
        testId="overview-panel"
        actions={
          <button
            type="button"
            onClick={() => onSelect('new-scan')}
            className="vin-btn-primary px-4 py-1.5 text-xs"
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
          <dl className="grid grid-cols-2 gap-x-6 md:grid-cols-5" data-testid="overview-metrics">
            <Metric label="Total scans" value={metrics.totalScans} />
            <Metric label="Running" value={metrics.running} tone="amber" />
            <Metric label="Completed" value={metrics.completed} tone="emerald" />
            <Metric label="Failed / cancelled" value={metrics.failedOrCancelled} tone="red" />
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
          <ul>
            {latestScans.slice(0, 6).map((s, index) => (
              <li key={s.id}>
                <button
                  type="button"
                  onClick={() => onOpenScan(s.id)}
                  className="vin-row text-sm text-slate-300"
                >
                  <span className="flex min-w-0 items-center gap-3">
                    <span className="vin-kicker w-5 shrink-0 tabular-nums">
                      {String(index + 1).padStart(2, '0')}
                    </span>
                    <StatusDot status={s.status} />
                    <span className="shrink-0 font-mono text-[11px] text-slate-500">
                      {s.id.slice(0, 8)}
                    </span>
                    <span className="vin-row-target truncate text-slate-200">{s.target_url}</span>
                  </span>
                  <span className="vin-kicker shrink-0 pr-5">{s.status}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}

function Metric({
  label,
  value,
  tone = 'ink',
}: {
  label: string
  value: number
  tone?: keyof typeof TONES
}) {
  return (
    <div className="vin-tile py-5 pr-4" data-testid="overview-metric">
      <dt className="vin-kicker">{label}</dt>
      <dd className={`vin-figure mt-3 ${TONES[tone] ?? TONES.ink}`}>{value}</dd>
    </div>
  )
}
