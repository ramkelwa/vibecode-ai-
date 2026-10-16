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
        {artifactsError}
        <button type="button" onClick={onRetryArtifacts} className="ml-3 text-xs text-sky-400 underline">
          Retry
        </button>
      </Panel>
    )
  }
  if (!artifacts) {
    return (
      <Panel title="Endpoint & script inventory" testId="inventory-panel">
        <p className="text-sm text-slate-500" role="note">
          Not available — select a completed scan.
        </p>
      </Panel>
    )
  }

  const endpoints = artifacts.api_endpoints ?? []
  const scriptsInline = artifacts.html?.scripts.filter((s) => s.inline) ?? []
  const scriptsExternal = artifacts.js_assets?.external ?? []

  return (
    <div className="space-y-4">
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
              <span key="u" className="break-all font-mono">{e.url}</span>,
              e.method,
              e.source,
              e.line ?? '—',
              e.same_origin ? 'yes' : 'no',
              e.confidence,
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
          <p className="text-sm text-slate-500" role="note">No inline scripts observed.</p>
        ) : (
          <Table
            head={['Length (chars)']}
            rows={scriptsInline.map((s) => [
              <span key="i" className="font-mono">{s.inline_length ?? 0}</span>,
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
              <span key="u" className="break-all font-mono" title={a.url}>{a.url}</span>,
              a.same_origin ? 'same-origin' : `cross-origin (${a.origin})`,
              a.status,
              a.size,
              <span key="h" className="break-all font-mono" title={a.sha256}>{a.sha256.slice(0, 16)}…</span>,
            ])}
          />
        )}
      </Panel>
    </div>
  )
}

function Table({ head, rows }: { head: string[]; rows: React.ReactNode[][] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead>
          <tr className="border-b border-slate-800 text-slate-500">
            {head.map((h, i) => (
              <th key={i} className="pb-1 pr-3" scope="col">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-b border-slate-900">
              {r.map((cell, j) => (
                <td key={j} className="py-1.5 pr-3 text-slate-300">
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
