import type { ScanSummary } from '../api'
import { EmptyState, ErrorState, LoadingState, Panel, StatusDot } from './ui'

export default function ScanHistory({
  scans,
  loading,
  error,
  onRetry,
  onOpen,
}: {
  scans: ScanSummary[]
  loading: boolean
  error: string | null
  onRetry: () => void
  onOpen: (id: string) => void
}) {
  return (
    <Panel title="Scan history" testId="history-panel">
      {loading && scans.length === 0 ? (
        <LoadingState label="Loading scan history…" />
      ) : error && scans.length === 0 ? (
        <ErrorState message={error} onRetry={onRetry} />
      ) : scans.length === 0 ? (
        <EmptyState message="No scans recorded yet." hint="Start a scan from the New scan view." />
      ) : (
        <ul>
          {scans.map((s) => (
            <li key={s.id}>
              <button
                type="button"
                onClick={() => onOpen(s.id)}
                className="vin-row flex-col items-start gap-1.5 text-sm text-slate-300"
              >
                <span className="flex w-full items-center justify-between gap-3">
                  <span className="flex min-w-0 items-center gap-3">
                    <StatusDot status={s.status} />
                    <span className="vin-row-target truncate text-slate-200">{s.target_url}</span>
                    <span className="shrink-0 font-mono text-[11px] text-slate-500">
                      {s.id.slice(0, 8)}
                    </span>
                  </span>
                  <span className="vin-kicker shrink-0 pr-5">
                    {s.status}
                    {s.finished_at ? ` · ${new Date(s.finished_at).toLocaleString()}` : ''}
                  </span>
                </span>
                <span className="block truncate pl-[18px] text-xs text-slate-600">
                  {s.modules_requested.join(', ') || 'no modules requested'}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
