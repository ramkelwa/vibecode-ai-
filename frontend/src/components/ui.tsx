import { ShieldCheck } from 'lucide-react'
import type { ReactNode } from 'react'
import type { Severity } from '../api'

// --- shared tokens ----------------------------------------------------------

/* Severity pill badge styling: crisp colors, subtle glow, WCAG AA compliant */
export const SEVERITY_CLASS: Record<Severity, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-400',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-400',
  low: 'border-sky-500/40 bg-sky-500/10 text-sky-400',
  info: 'border-zinc-700/60 bg-zinc-800/40 text-zinc-300',
}

export const SEVERITY_BAR = 'bg-red-500'

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] shadow-sm ${SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.info}`}
      aria-label={`severity ${severity}`}
    >
      {severity}
    </span>
  )
}

export function ConfidenceBadge({ confidence }: { confidence: string }) {
  const map: Record<string, string> = {
    certain: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    firm: 'text-sky-400 bg-sky-500/10 border-sky-500/30',
    uncertain: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    unknown: 'text-zinc-400 bg-zinc-800/50 border-zinc-700/40',
  }
  const c = map[confidence] ?? map.unknown
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] shadow-sm ${c}`}
      aria-label={`confidence ${confidence}`}
    >
      {confidence}
    </span>
  )
}

export function StatusDot({ status, label }: { status: string; label?: string }) {
  const color =
    status === 'completed'
      ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]'
      : status === 'running'
        ? 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.5)] animate-pulse'
        : status === 'failed'
          ? 'bg-red-400 shadow-[0_0_8px_rgba(248,113,113,0.5)]'
          : status === 'cancelled'
            ? 'bg-zinc-500'
            : status === 'skipped'
              ? 'bg-zinc-600'
              : 'bg-zinc-400'
  return (
    <span
      className={`inline-block h-2 w-2 shrink-0 rounded-full ${color}`}
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
      <div className="mb-4 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-white/[0.06] pb-3">
        <h2 className="vin-section-label flex items-center gap-2">
          <span aria-hidden className="inline-block h-1.5 w-1.5 rounded-full bg-sky-400" />
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
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-white/10 bg-white/[0.015] px-6 py-10 text-center">
      <div className="flex h-9 w-9 items-center justify-center rounded-full border border-white/10 bg-white/[0.04]">
        <ShieldCheck className="h-4 w-4 text-zinc-400" aria-hidden />
      </div>
      <p className="text-sm font-medium text-zinc-200" role="note">
        {message}
      </p>
      {hint && <p className="max-w-md text-xs leading-relaxed text-zinc-400">{hint}</p>}
    </div>
  )
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2.5 py-1" role="status">
      <span className="relative flex h-2 w-2">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-sky-400 opacity-75" />
        <span className="relative inline-flex h-2 w-2 rounded-full bg-sky-500" />
      </span>
      <span className="text-xs font-medium text-zinc-400">{label}</span>
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
      className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-red-500/30 bg-red-950/20 px-4 py-3 text-sm text-red-300 shadow-sm"
      role="alert"
    >
      <div className="flex items-center gap-2">
        <span className="inline-block h-2 w-2 shrink-0 rounded-full bg-red-400" aria-hidden />
        <p>{message}</p>
      </div>
      {onRetry && (
        <button type="button" onClick={onRetry} className="vin-btn-primary px-3 py-1 text-xs">
          Retry
        </button>
      )}
    </div>
  )
}

/** Horizontal severity distribution bar */
export function SeverityBarCounts({ bySeverity }: { bySeverity: Record<string, number> }) {
  const order = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const
  const total = Object.values(bySeverity).reduce((s, n) => s + n, 0)
  if (total === 0)
    return <p className="text-xs text-zinc-400">No findings recorded.</p>

  const colors: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-amber-500',
    low: 'bg-sky-400',
    info: 'bg-zinc-400',
    unknown: 'bg-zinc-600',
  }

  return (
    <div className="space-y-3">
      <div
        className="flex h-2.5 w-full overflow-hidden rounded-full bg-zinc-800/80 p-0.5 shadow-inner"
        role="img"
        aria-label="findings by severity"
      >
        {order.map((sev) => {
          const n = bySeverity[sev] ?? 0
          if (!n) return null
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
      <div className="flex flex-wrap gap-4 text-xs">
        {order.map((sev) => {
          const n = bySeverity[sev] ?? 0
          if (!n) return null
          return (
            <div key={sev} className="flex items-center gap-1.5">
              <span className={`h-2 w-2 rounded-full ${colors[sev]}`} />
              <span className="capitalize text-zinc-400">{sev}:</span>
              <span className="font-semibold text-zinc-200 tabular-nums">{n}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
