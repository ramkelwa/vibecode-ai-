import { ShieldCheck } from 'lucide-react'
import type { ReactNode } from 'react'
import type { Severity } from '../api'

// --- shared tokens ----------------------------------------------------------

/* Severity is carried by a hairline outline and coloured type only: no fills,
   so a badge never competes with the black editorial accent. */
export const SEVERITY_CLASS: Record<Severity, string> = {
  critical: 'border-severity-critical/60 text-severity-critical',
  high: 'border-severity-high/60 text-severity-high',
  medium: 'border-severity-medium/60 text-severity-medium',
  low: 'border-severity-low/60 text-severity-low',
  info: 'border-slate-900/20 text-slate-400',
}

export const SEVERITY_BAR = 'bg-severity-critical'

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center border px-1.5 py-[1px] text-[10px] uppercase tracking-[0.12em] ${SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.info}`}
      aria-label={`severity ${severity}`}
    >
      {severity}
    </span>
  )
}

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  const map: Record<string, string> = {
    certain: 'text-emerald-700 border-emerald-700/50',
    firm: 'text-slate-300 border-slate-900/25',
    uncertain: 'text-amber-700 border-amber-700/50',
    unknown: 'text-slate-500 border-slate-900/20',
  }
  const c = map[confidence] ?? map.unknown
  return (
    <span
      className={`inline-flex items-center border px-1.5 py-[1px] text-[10px] uppercase tracking-[0.12em] ${c}`}
      aria-label={`confidence ${confidence}`}
    >
      {confidence}
    </span>
  )
}

export function StatusDot({ status, label }: { status: string; label?: string }) {
  const color =
    status === 'completed'
      ? 'bg-emerald-600'
      : status === 'running'
        ? 'bg-amber-500 animate-pulse'
        : status === 'failed'
          ? 'bg-red-600'
          : status === 'cancelled'
            ? 'bg-slate-600'
            : status === 'skipped'
              ? 'bg-slate-700'
              : 'bg-slate-400'
  return (
    <span
      className={`inline-block h-1.5 w-1.5 shrink-0 rounded-full ${color}`}
      role="status"
      aria-label={label ?? status}
    />
  )
}

export function Panel({
  title,
  actions,
  children,
  testId,
}: {
  title: string
  actions?: ReactNode
  children: ReactNode
  testId?: string
}) {
  return (
    <section data-testid={testId} className="vin-panel" aria-label={title}>
      <div className="mb-4 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-2">
        <h2 className="vin-section-label flex items-baseline gap-2.5">
          <span aria-hidden className="text-slate-600">
            /
          </span>
          <span>{title}</span>
        </h2>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  )
}

export function EmptyState({ message, hint }: { message: string; hint?: string }) {
  return (
    <div className="flex flex-col items-start gap-2 border border-dashed border-slate-900/15 px-6 py-8">
      <ShieldCheck className="mb-1 h-4 w-4 text-slate-500" aria-hidden />
      <p className="text-sm text-slate-300" role="note">
        {message}
      </p>
      {hint && <p className="max-w-md text-xs leading-relaxed text-slate-500">{hint}</p>}
    </div>
  )
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-3" role="status">
      <span className="h-1.5 w-1.5 animate-pulse bg-slate-100" aria-hidden />
      <span className="vin-kicker !text-slate-400">{label}</span>
    </div>
  )
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string
  onRetry?: () => void
}) {
  return (
    <div
      className="flex flex-wrap items-center justify-between gap-3 border-l-2 border-red-600 bg-slate-50 px-3.5 py-3"
      role="alert"
    >
      <p className="text-sm text-red-700">{message}</p>
      {onRetry && (
        <button type="button" onClick={onRetry} className="vin-btn-primary px-3 py-1 text-xs">
          Retry
        </button>
      )}
    </div>
  )
}

/** Horizontal severity distribution bar — plain CSS, no chart dependency. */
export function SeverityBarCounts({ bySeverity }: { bySeverity: Record<string, number> }) {
  const order = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const
  const total = Object.values(bySeverity).reduce((s, n) => s + n, 0)
  if (total === 0)
    return <p className="text-xs text-slate-500">No findings recorded.</p>
  return (
    <div
      className="flex h-2 w-full overflow-hidden bg-slate-900/10"
      role="img"
      aria-label="findings by severity"
    >
      {order.map((sev) => {
        const n = bySeverity[sev] ?? 0
        if (!n) return null
        const colors: Record<string, string> = {
          critical: 'bg-severity-critical',
          high: 'bg-severity-high',
          medium: 'bg-severity-medium',
          low: 'bg-severity-low',
          info: 'bg-slate-400',
          unknown: 'bg-slate-700',
        }
        return (
          <span
            key={sev}
            className={`h-full ${colors[sev]}`}
            style={{ width: `${(n / total) * 100}%` }}
            title={`${sev}: ${n}`}
          />
        )
      })}
    </div>
  )
}
