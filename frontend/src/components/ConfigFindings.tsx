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
  const configFindings = findings.filter(
    (f) =>
      f.category === 'dependency_audit' ||
      f.category === 'source_analysis' ||
      f.category === 'cookie_analysis' ||
      f.category === 'http_headers',
  )

  return (
    <div className="space-y-6">
      <Panel title="Configuration findings (headers, cookies)" testId="config-panel">
        {configFindings.length === 0 ? (
          <EmptyState message="No configuration findings recorded for this scan." />
        ) : (
          <ul className="divide-y divide-zinc-800/60 rounded-lg border border-zinc-800/60 bg-zinc-900/30 text-sm">
            {configFindings.map((f) => (
              <li key={f.id} className="flex items-center gap-3 px-3.5 py-2.5">
                <SeverityBadge severity={f.severity} />
                <span className="min-w-0 flex-1 truncate font-medium text-zinc-200">{f.title}</span>
                <span className="shrink-0 font-mono text-xs text-zinc-400">{f.source_module}</span>
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
          <div className="space-y-3 text-xs">
            <p className="text-zinc-400">
              Root: <span className="font-mono break-all text-zinc-300">{depAudit.root}</span>
            </p>
            <ul className="space-y-2">
              {depAudit.tool_runs.map((t, i) => (
                <li key={i} className="vin-panel-soft p-3 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-medium text-zinc-200">{String(t.tool ?? '?')}</span>
                    <span
                      className={`rounded px-1.5 py-0.5 text-[11px] font-mono ${
                        String(t.status).includes('ok') ||
                        String(t.status) === 'no_findings' ||
                        String(t.status) === 'completed'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                      }`}
                    >
                      {String(t.status ?? '?')}
                    </span>
                    {t.advisory_count != null && (
                      <span className="text-zinc-400"> — {String(t.advisory_count)} advisory(ies)</span>
                    )}
                  </div>
                  {t.detail ? <p className="mt-1 text-zinc-400">{String(t.detail)}</p> : null}
                  {Array.isArray(t.errors) && t.errors.length > 0 ? (
                    <div className="mt-2 rounded bg-amber-950/20 p-2 text-amber-300 border border-amber-500/20">
                      {String((t.errors as string[]).join('; '))}
                    </div>
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
          <div className="rounded-lg border border-zinc-800/60 bg-zinc-900/30 p-4">
            <ul className="space-y-2 text-xs text-zinc-300">
              <li className="flex items-center gap-2">
                <span className="text-zinc-400">Scanner:</span>
                <span className="font-semibold text-zinc-200">{String(sourceAnalysis.tool ?? 'semgrep')}</span>
                {sourceAnalysis.tool_version ? (
                  <span className="text-zinc-500">({String(sourceAnalysis.tool_version)})</span>
                ) : null}
              </li>
              <li className="flex items-center gap-2">
                <span className="text-zinc-400">Scanned files:</span>
                <span className="font-mono font-semibold text-sky-400">
                  {String(sourceAnalysis.scanned_file_count ?? 0)}
                </span>
              </li>
              {sourceAnalysis.root && (
                <li className="flex items-center gap-2">
                  <span className="text-zinc-400">Root:</span>
                  <span className="font-mono break-all text-zinc-300">{String(sourceAnalysis.root)}</span>
                </li>
              )}
            </ul>
          </div>
        )}
      </Panel>
    </div>
  )
}
