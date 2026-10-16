import type { Artifacts, Finding } from '../api'
import { EmptyState, Panel, SeverityBadge } from './ui'

export default function ConfigFindings({
  artifacts,
  findings,
}: {
  artifacts: Artifacts | null
  findings: Finding[]
}) {
  const depAudit = artifacts?.dependency_audit ?? null
  const sourceAnalysis = artifacts?.source_analysis ?? null
  const configFindings = findings.filter((f) => f.category === 'dependency_audit' || f.category === 'source_analysis' || f.category === 'cookie_analysis' || f.category === 'http_headers')

  return (
    <div className="space-y-4">
      <Panel title="Configuration findings (headers, cookies)" testId="config-panel">
        {configFindings.length === 0 ? (
          <EmptyState message="No configuration findings recorded for this scan." />
        ) : (
          <ul className="divide-y divide-slate-900 text-sm">
            {configFindings.map((f) => (
              <li key={f.id} className="flex items-center gap-2 py-1.5">
                <SeverityBadge severity={f.severity} />
                <span className="min-w-0 flex-1 truncate">{f.title}</span>
                <span className="shrink-0 font-mono text-xs text-slate-600">{f.source_module}</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Dependency audit tool runs" testId="dep-audit-panel">
        {!depAudit ? (
          <EmptyState
            message="Dependency audit artifact not available."
            hint="Shown only for project scans whose dependency_audit module ran (and where AUTHORIZED_PROJECT_ROOTS is configured on the backend)."
          />
        ) : (
          <div className="space-y-2 text-xs">
            <p className="text-slate-500">
              Root: <span className="font-mono break-all">{depAudit.root}</span>
            </p>
            <ul className="space-y-1">
              {depAudit.tool_runs.map((t, i) => (
                <li key={i} className="rounded border border-slate-800 p-2">
                  <span className="font-mono text-slate-300">{String(t.tool ?? '?')}</span>{' '}
                  <span className={String(t.status).includes('ok') || String(t.status) === 'no_findings' || String(t.status) === 'completed' ? 'text-emerald-400' : 'text-amber-400'}>
                    {String(t.status ?? '?')}
                  </span>
                  {t.advisory_count != null && <span className="text-slate-500"> — {String(t.advisory_count)} advisory(ies)</span>}
                  {t.detail ? <span className="text-slate-500"> — {String(t.detail)}</span> : null}
                  {Array.isArray(t.errors) && t.errors.length > 0 ? (
                    <div className="mt-1 text-amber-400">{String((t.errors as string[]).join('; '))}</div>
                  ) : null}
                </li>
              ))}
            </ul>
          </div>
        )}
      </Panel>

      <Panel title="Static source analysis" testId="source-analysis-panel">
        {!sourceAnalysis ? (
          <EmptyState
            message="Source-analysis artifact not available."
            hint="Shown only for project scans whose source_analysis module ran with semgrep available."
          />
        ) : (
          <ul className="list-disc pl-4 text-xs text-slate-400">
            <li>
              Scanner: {String(sourceAnalysis.tool ?? 'semgrep')}
              {sourceAnalysis.tool_version ? ` (${String(sourceAnalysis.tool_version)})` : ''}
            </li>
            <li>
              Scanned files: <span className="font-mono">{String(sourceAnalysis.scanned_file_count ?? 0)}</span>
            </li>
            {sourceAnalysis.root && (
              <li className="font-mono break-all">{String(sourceAnalysis.root)}</li>
            )}
          </ul>
        )}
      </Panel>
    </div>
  )
}
