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
        <ul className="divide-y divide-slate-900">
          {scans.map((s) => (
            <li key={s.id}>
              <button
                type="button"
                onClick={() => onOpen(s.id)}
                className="w-full rounded px-1 py-2 text-left hover:bg-slate-900"
              >
                <span className="flex items-center justify-between gap-2">
                  <span className="flex min-w-0 items-center gap-2 text-sm">
                    <StatusDot status={s.status} />
                    <span className="truncate">{s.target_url}</span>
                    <span className="font-mono text-xs text-slate-500">{s.id.slice(0, 8)}</span>
                  </span>
                  <span className="shrink-0 text-xs text-slate-500">
                    {s.status}
                    {s.finished_at ? ` · ${new Date(s.finished_at).toLocaleString()}` : ''}
                  </span>
                </span>
                <span className="mt-1 block truncate pl-4 text-xs text-slate-600">
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
