import {
  Activity,
  AlertOctagon,
  ArrowRight,
  CheckCircle2,
  FileSearch,
  Globe,
  PlayCircle,
  Plus,
} from 'lucide-react'
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

const TONES = {
  ink: { text: 'text-zinc-100', bg: 'bg-zinc-800/40', border: 'border-zinc-700/60' },
  emerald: { text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20' },
  amber: { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20' },
  red: { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
} as const

type ToneKey = keyof typeof TONES

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
    <div className="space-y-6">
      {/* Fleet Overview Panel */}
      <Panel
        title="Fleet overview"
        testId="overview-panel"
        actions={
          <button
            type="button"
            onClick={() => onSelect('new-scan')}
            className="vin-btn-primary px-3.5 py-1.5 text-xs font-medium"
          >
            <Plus className="h-3.5 w-3.5" aria-hidden />
            Start new scan
          </button>
        }
      >
        {error ? (
          <ErrorState message={error} onRetry={onRetry} />
        ) : loading && !metrics ? (
          <LoadingState label="Loading overview…" />
        ) : metrics ? (
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5" data-testid="overview-metrics">
            <MetricCard
              label="Total scans"
              value={metrics.totalScans}
              icon={Activity}
              tone="ink"
            />
            <MetricCard
              label="Running"
              value={metrics.running}
              icon={PlayCircle}
              tone="amber"
              pulse={metrics.running > 0}
            />
            <MetricCard
              label="Completed"
              value={metrics.completed}
              icon={CheckCircle2}
              tone="emerald"
            />
            <MetricCard
              label="Failed / cancelled"
              value={metrics.failedOrCancelled}
              icon={AlertOctagon}
              tone="red"
            />
            <MetricCard
              label="Findings stored"
              value={metrics.findingsTotal}
              icon={FileSearch}
              tone="ink"
            />
          </dl>
        ) : null}
      </Panel>

      {/* Severity distribution */}
      {metrics && (
        <Panel title="Findings by severity (latest 100 scans)">
          <div className="pt-1">
            <SeverityBarCounts bySeverity={metrics.bySeverity} />
          </div>
        </Panel>
      )}

      {/* Recent scans */}
      <Panel title="Recent scans">
        {latestScans.length === 0 ? (
          <p className="text-sm text-zinc-400 py-3" role="note">
            No scans recorded yet.
          </p>
        ) : (
          <ul className="divide-y divide-zinc-800/60 -mx-2">
            {latestScans.slice(0, 8).map((s, index) => (
              <li key={s.id}>
                <button
                  type="button"
                  onClick={() => onOpenScan(s.id)}
                  className="vin-row text-sm text-zinc-300 hover:bg-zinc-800/40"
                >
                  <span className="flex min-w-0 items-center gap-3">
                    <span className="vin-kicker w-6 shrink-0 tabular-nums text-zinc-500">
                      {String(index + 1).padStart(2, '0')}
                    </span>
                    <StatusDot status={s.status} />
                    <span className="hidden font-mono text-[11px] text-zinc-400 sm:inline shrink-0">
                      {s.id.slice(0, 8)}
                    </span>
                    <Globe className="h-3.5 w-3.5 text-zinc-400 shrink-0 hidden sm:inline" aria-hidden />
                    <span className="vin-row-target truncate font-medium text-zinc-200">
                      {s.target_url}
                    </span>
                  </span>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="vin-kicker text-zinc-400 font-mono">
                      {s.status}
                    </span>
                    <ArrowRight className="h-3.5 w-3.5 text-zinc-500 group-hover:text-sky-400 transition-colors" aria-hidden />
                  </div>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}

function MetricCard({
  label,
  value,
  icon: Icon,
  tone = 'ink',
  pulse = false,
}: {
  label: string
  value: number
  icon: typeof Activity
  tone?: ToneKey
  pulse?: boolean
}) {
  const currentTone = TONES[tone]
  return (
    <div
      className="vin-tile p-4 flex flex-col justify-between"
      data-testid="overview-metric"
    >
      <div className="flex items-center justify-between gap-2">
        <dt className="vin-kicker truncate text-zinc-400">{label}</dt>
        <div className={`flex h-7 w-7 items-center justify-center rounded-md border ${currentTone.border} ${currentTone.bg} ${currentTone.text}`}>
          <Icon className={`h-3.5 w-3.5 ${pulse ? 'animate-pulse' : ''}`} aria-hidden />
        </div>
      </div>
      <dd className={`vin-figure mt-3 ${currentTone.text}`}>{value}</dd>
    </div>
  )
}
