import type { Artifacts } from '../api'
import { EmptyState, Panel } from './ui'

export default function InventoryPanel({
  artifacts,
  artifactsError,
  onRetryArtifacts,
}: {
  artifacts: Artifacts | null
  artifactsError: string | null
  onRetryArtifacts: () => void
}) {
  if (artifactsError) {
    return (
      <Panel title="Endpoint & script inventory" testId="inventory-panel">
        <div className="flex items-center justify-between text-sm text-red-300">
          <span>{artifactsError}</span>
          <button type="button" onClick={onRetryArtifacts} className="vin-btn-ghost px-3 py-1 text-xs">
            Retry
          </button>
        </div>
      </Panel>
    )
  }
  if (!artifacts) {
    return (
      <Panel title="Endpoint & script inventory" testId="inventory-panel">
        <p className="text-sm text-zinc-400 py-3" role="note">
          Not available — select a completed scan.
        </p>
      </Panel>
    )
  }

  const endpoints = artifacts.api_endpoints ?? []
  const scriptsInline = artifacts.html?.scripts.filter((s) => s.inline) ?? []
  const scriptsExternal = artifacts.js_assets?.external ?? []

  return (
    <div className="space-y-6">
      <Panel title={`Discovered API endpoints (${endpoints.length})`} testId="inventory-panel">
        {endpoints.length === 0 ? (
          <EmptyState
            message="No API endpoint references recorded by this scan."
            hint="api_discovery only records inventory — it never probes endpoints."
          />
        ) : (
          <Table
            head={['URL', 'Method', 'Source', 'Line', 'Same-origin', 'Confidence']}
            rows={endpoints.map((e) => [
              <span key="u" className="break-all font-mono text-zinc-200">{e.url}</span>,
              <MethodBadge key="m" method={e.method} />,
              <span key="s" className="text-zinc-400">{e.source}</span>,
              <span key="l" className="font-mono text-zinc-400">{e.line ?? '—'}</span>,
              <span key="o" className="font-mono text-xs">{e.same_origin ? 'yes' : 'no'}</span>,
              <span key="c" className="font-mono text-xs text-zinc-400">{e.confidence}</span>,
            ])}
          />
        )}
      </Panel>

      <Panel title={`Inline scripts (${scriptsInline.length})`}>
        {artifacts.html == null ? (
          <EmptyState
            message="HTML artifact not recorded for this scan."
            hint="Shown only when the scan's html_analysis module ran."
          />
        ) : scriptsInline.length === 0 ? (
          <p className="text-sm text-zinc-400 py-2" role="note">No inline scripts observed.</p>
        ) : (
          <Table
            head={['Length (chars)']}
            rows={scriptsInline.map((s, idx) => [
              <span key={idx} className="font-mono text-zinc-200">{s.inline_length ?? 0}</span>,
            ])}
          />
        )}
      </Panel>

      <Panel title={`External JS assets (${scriptsExternal.length})`}>
        {scriptsExternal.length === 0 ? (
          <EmptyState
            message="No external JS assets recorded."
            hint="Shown only when the scan's js_discovery module fetched assets."
          />
        ) : (
          <Table
            head={['URL', 'Origin', 'HTTP status', 'Size (B)', 'SHA-256']}
            rows={scriptsExternal.map((a) => [
              <span key="u" className="break-all font-mono text-zinc-200" title={a.url}>{a.url}</span>,
              <span key="o" className="text-zinc-400">{a.same_origin ? 'same-origin' : `cross-origin (${a.origin})`}</span>,
              <span key="s" className="font-mono text-emerald-400">{a.status}</span>,
              <span key="z" className="font-mono text-zinc-300">{a.size}</span>,
              <span key="h" className="break-all font-mono text-zinc-400 text-[11px]" title={a.sha256}>
                {a.sha256.slice(0, 16)}…
              </span>,
            ])}
          />
        )}
      </Panel>
    </div>
  )
}

function MethodBadge({ method }: { method: string }) {
  const m = method.toUpperCase()
  const color =
    m === 'GET'
      ? 'bg-sky-500/10 text-sky-400 border-sky-500/20'
      : m === 'POST'
        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
        : m === 'PUT' || m === 'PATCH'
          ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
          : m === 'DELETE'
            ? 'bg-red-500/10 text-red-400 border-red-500/20'
            : 'bg-zinc-800 text-zinc-300 border-zinc-700'
  return (
    <span className={`inline-block rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${color}`}>
      {method}
    </span>
  )
}

function Table({ head, rows }: { head: string[]; rows: React.ReactNode[][] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-800/60 bg-zinc-900/30">
      <table className="w-full text-left text-xs">
        <thead>
          <tr className="border-b border-zinc-800 bg-zinc-900/60 text-zinc-400 font-semibold uppercase tracking-wider">
            {head.map((h, i) => (
              <th key={i} className="py-2.5 px-3" scope="col">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800/40">
          {rows.map((r, i) => (
            <tr key={i} className="transition-colors hover:bg-zinc-800/40">
              {r.map((cell, j) => (
                <td key={j} className="py-2.5 px-3 text-zinc-300">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
