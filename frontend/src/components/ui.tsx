import { ShieldCheck } from 'lucide-react'
import type { ReactNode } from 'react'
import type { Severity } from '../api'

// --- shared tokens ----------------------------------------------------------

export const SEVERITY_CLASS: Record<Severity, string> = {
  critical:
    'bg-severity-critical/20 text-fuchsia-700 border-severity-critical/50 shadow-[inset_0_1px_0_rgba(255,255,255,0.12),0_0_16px_-4px_rgba(162,28,175,0.8)]',
  high: 'bg-severity-high/20 text-red-700 border-severity-high/50 shadow-[inset_0_1px_0_rgba(255,255,255,0.12),0_0_16px_-4px_rgba(220,38,38,0.8)]',
  medium:
    'bg-severity-medium/20 text-amber-700 border-severity-medium/50 shadow-[inset_0_1px_0_rgba(255,255,255,0.12),0_0_16px_-4px_rgba(217,119,6,0.7)]',
  low: 'bg-severity-low/20 text-sky-700 border-severity-low/50 shadow-[inset_0_1px_0_rgba(255,255,255,0.12),0_0_16px_-4px_rgba(37,99,235,0.7)]',
  info: 'bg-severity-info/20 text-slate-300 border-severity-info/50 shadow-[inset_0_1px_0_rgba(255,255,255,0.1)]',
}

export const SEVERITY_BAR = 'bg-severity-critical'

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.info}`}
      aria-label={`severity ${severity}`}
    >
      {severity}
    </span>
  )
}

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  const map: Record<string, string> = {
    certain: 'text-emerald-600 border-emerald-700/60 bg-emerald-50/40',
    firm: 'text-sky-700 border-sky-700/60 bg-sky-50/40',
    uncertain: 'text-amber-700 border-amber-700/60 bg-amber-50/40',
    unknown: 'text-slate-400 border-slate-700 bg-slate-900/60',
  }
  const c = map[confidence] ?? map.unknown
  return (
    <span
      className={`rounded-md border px-1.5 py-0.5 text-[10px] uppercase tracking-wider shadow-[inset_0_1px_0_rgba(255,255,255,0.08)] ${c}`}
      aria-label={`confidence ${confidence}`}
    >
      {confidence}
    </span>
  )
}

export function StatusDot({ status, label }: { status: string; label?: string }) {
  const color =
    status === 'completed'
      ? 'bg-emerald-400 shadow-[0_0_10px_rgba(45,106,86,0.9)]'
      : status === 'running'
        ? 'bg-amber-300 shadow-[0_0_10px_rgba(252,211,77,0.9)] animate-pulse'
        : status === 'failed'
          ? 'bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.9)]'
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
      className="vin-panel p-4 md:p-5"
      aria-label={title}
    >
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2.5 text-sm font-semibold tracking-tight text-slate-200">
          <span
            aria-hidden
            className="inline-block h-2.5 w-2.5 rounded-[3px] bg-gradient-to-br from-cyan-300 to-violet-500 shadow-[0_0_12px_rgba(45,106,86,0.8),inset_0_1px_0_rgba(255,255,255,0.6)]"
          />
          {title}
        </h2>
        {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  )
}

export function EmptyState({ message, hint }: { message: string; hint?: string }) {
  return (
    <div className="relative flex flex-col items-center justify-center overflow-hidden rounded-xl border border-dashed border-sky-300/15 bg-[radial-gradient(120%_120%_at_50%_0%,rgba(45,106,86,0.08),transparent_60%)] p-8 text-center shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
      <span className="mb-3 grid h-11 w-11 place-items-center rounded-xl border border-sky-300/20 bg-slate-900/5 shadow-[inset_0_1px_0_rgba(255,255,255,0.25),0_10px_20px_-12px_rgba(45,106,86,0.9)]">
        <ShieldCheck className="h-5 w-5 text-sky-700/80" aria-hidden />
      </span>
      <p className="text-sm text-slate-400" role="note">
        {message}
      </p>
      {hint && <p className="mt-1 max-w-md text-xs text-slate-600">{hint}</p>}
    </div>
  )
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2.5 text-sm text-slate-400" role="status">
      <span className="relative grid h-4 w-4 place-items-center" aria-hidden>
        <span className="absolute inset-0 rounded-full border border-cyan-300/25" />
        <span className="h-1.5 w-1.5 animate-ping rounded-full bg-cyan-300" />
      </span>
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
      className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-red-500/30 bg-[linear-gradient(160deg,rgba(254,242,242,0.95),rgba(255,251,251,0.9))] p-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.7),0_14px_28px_-24px_rgba(220,38,38,0.45)]"
      role="alert"
    >
      <p className="text-sm text-red-700">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="vin-btn-ghost px-2.5 py-1 text-xs !text-red-700"
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
      className="flex h-3 w-full overflow-hidden rounded-full border border-slate-900/5 bg-slate-950 p-[2px] shadow-[inset_0_1px_3px_rgba(11,31,29,0.12)]"
      role="img"
      aria-label="findings by severity"
    >
      {order.map((sev) => {
        const n = bySeverity[sev] ?? 0
        if (!n) return null
        const colors: Record<string, string> = {
          critical: 'bg-severity-critical shadow-[0_0_12px_rgba(162,28,175,0.9)]',
          high: 'bg-severity-high shadow-[0_0_12px_rgba(220,38,38,0.9)]',
          medium: 'bg-severity-medium shadow-[0_0_12px_rgba(217,119,6,0.8)]',
          low: 'bg-severity-low shadow-[0_0_12px_rgba(37,99,235,0.8)]',
          info: 'bg-severity-info',
          unknown: 'bg-slate-500',
        }
        return (
          <span
            key={sev}
            className={`h-full first:rounded-l-full last:rounded-r-full ${colors[sev]}`}
            style={{ width: `${(n / total) * 100}%` }}
            title={`${sev}: ${n}`}
          />
        )
      })}
    </div>
  )
}
