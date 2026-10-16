import { ShieldCheck } from 'lucide-react'
import type { ReactNode } from 'react'
import type { Severity } from '../api'

// --- shared tokens ----------------------------------------------------------

export const SEVERITY_CLASS: Record<Severity, string> = {
  critical: 'bg-severity-critical/20 text-severity-critical border-severity-critical/40',
  high: 'bg-severity-high/20 text-severity-high border-severity-high/40',
  medium: 'bg-severity-medium/20 text-severity-medium border-severity-medium/40',
  low: 'bg-severity-low/20 text-severity-low border-severity-low/40',
  info: 'bg-severity-info/20 text-severity-info border-severity-info/40',
}

export const SEVERITY_BAR = 'bg-severity-critical'

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`rounded border px-1.5 py-0.5 text-xs font-medium uppercase ${SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.info}`}
      aria-label={`severity ${severity}`}
    >
      {severity}
    </span>
  )
}

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  const map: Record<string, string> = {
    certain: 'text-emerald-400 border-emerald-800',
    firm: 'text-sky-400 border-sky-800',
    uncertain: 'text-amber-400 border-amber-800',
    unknown: 'text-slate-400 border-slate-700',
  }
  const c = map[confidence] ?? map.unknown
  return (
    <span className={`rounded border px-1.5 py-0.5 text-xs ${c}`} aria-label={`confidence ${confidence}`}>
      {confidence}
    </span>
  )
}

export function StatusDot({ status, label }: { status: string; label?: string }) {
  const color =
    status === 'completed'
      ? 'bg-emerald-500'
      : status === 'running'
        ? 'bg-amber-400 animate-pulse'
        : status === 'failed'
          ? 'bg-red-500'
          : status === 'cancelled'
            ? 'bg-slate-500'
            : status === 'skipped'
              ? 'bg-slate-600'
              : 'bg-slate-400'
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full ${color}`}
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
    <section
      data-testid={testId}
      className="rounded-lg border border-slate-800 bg-slate-900/60 p-4"
      aria-label={title}
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium text-slate-300">{title}</h2>
        {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  )
}

export function EmptyState({ message, hint }: { message: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center rounded border border-dashed border-slate-800 p-8 text-center">
      <ShieldCheck className="mb-2 h-6 w-6 text-slate-600" aria-hidden />
      <p className="text-sm text-slate-500" role="note">
        {message}
      </p>
      {hint && <p className="mt-1 max-w-md text-xs text-slate-600">{hint}</p>}
    </div>
  )
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-slate-500" role="status">
      <span className="h-2 w-2 animate-pulse rounded-full bg-sky-500" aria-hidden />
      {label}
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
      className="flex flex-wrap items-center justify-between gap-2 rounded border border-red-900 bg-red-950/40 p-3"
      role="alert"
    >
      <p className="text-sm text-red-400">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="rounded border border-red-800 px-2 py-1 text-xs text-red-300 hover:bg-red-900/40"
        >
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
  if (total === 0) return <p className="text-xs text-slate-500">No findings recorded.</p>
  return (
    <div
      className="flex h-2.5 w-full overflow-hidden rounded bg-slate-800"
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
          info: 'bg-severity-info',
          unknown: 'bg-slate-500',
        }
        return (
          <span
            key={sev}
            className={colors[sev]}
            style={{ width: `${(n / total) * 100}%` }}
            title={`${sev}: ${n}`}
          />
        )
      })}
    </div>
  )
}
