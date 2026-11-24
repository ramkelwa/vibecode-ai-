import { Globe, ListFilter } from 'lucide-react'
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
        <ul className="divide-y divide-zinc-800/60 -mx-2">
          {scans.map((s) => (
            <li key={s.id}>
              <button
                type="button"
                onClick={() => onOpen(s.id)}
                className="vin-row flex-col items-start gap-2 text-sm text-zinc-300 hover:bg-zinc-800/40 p-3"
              >
                <div className="flex w-full items-center justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-2.5">
                    <StatusDot status={s.status} />
                    <Globe className="h-3.5 w-3.5 text-zinc-500 shrink-0 hidden sm:inline" aria-hidden />
                    <span className="vin-row-target truncate font-semibold text-zinc-200">
                      {s.target_url}
                    </span>
                    <span className="shrink-0 font-mono text-[11px] text-zinc-400">
                      {s.id.slice(0, 8)}
                    </span>
                  </div>
                  <span className="vin-kicker shrink-0 text-zinc-400 font-mono">
                    {s.status}
                    {s.finished_at ? ` · ${new Date(s.finished_at).toLocaleString()}` : ''}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-xs text-zinc-500 pl-5">
                  <ListFilter className="h-3 w-3 shrink-0" aria-hidden />
                  <span className="truncate">
                    {s.modules_requested.join(', ') || 'no modules requested'}
                  </span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}
