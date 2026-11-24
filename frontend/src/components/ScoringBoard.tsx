import type { Finding } from '../api'
import { Panel, SeverityBadge } from './ui'

// Risk priority formula (ported from backend app/scanners/phase5.py)
// priority = severity_weight × confidence_weight × verification_weight  -> 0..100
const SEVERITY_WEIGHT: Record<string, number> = { critical: 100, high: 75, medium: 50, low: 25, info: 10, unknown: 15 }
const CONFIDENCE_WEIGHT: Record<string, number> = { certain: 1.0, firm: 0.85, uncertain: 0.6, unknown: 0.5 }
const VERIFICATION_WEIGHT: Record<string, number> = {
  confirmed: 1.0,
  potential: 0.9,
  unverified: 0.7,
  informational: 0.4,
  false_positive: 0.05,
  unknown: 0.3,
}

function severityWeight(s: string): number {
  return SEVERITY_WEIGHT[s.toLowerCase() as keyof typeof SEVERITY_WEIGHT] ?? 15
}
function confidenceWeight(c: string): number {
  return CONFIDENCE_WEIGHT[c.toLowerCase() as keyof typeof CONFIDENCE_WEIGHT] ?? 0.5
}
function verificationWeight(v: string): number {
  return VERIFICATION_WEIGHT[v.toLowerCase() as keyof typeof VERIFICATION_WEIGHT] ?? 0.3
}

function computePriority(f: Finding): number {
  const sev = severityWeight(f.severity)
  const conf = confidenceWeight(f.confidence)
  const stat = verificationWeight(f.verification_status)
  return Math.round(sev * conf * stat * 10) / 10 // one decimal, 0..100
}

interface ScoringBoardProps {
  findings: Finding[]
  className?: string
}

export default function ScoringBoard({ findings, className }: ScoringBoardProps) {
  // Sort by priority descending, skip findings missing required fields
  const sorted: Finding[] = [...findings].sort((a, b) => computePriority(b) - computePriority(a))
  const visible: Finding[] = sorted.filter(
    (f): f is Finding => f.title !== '' && typeof f.severity === 'string' && f.confidence !== '' && typeof f.verification_status === 'string',
  )
  const topItems: Finding[] = visible.slice(0, 20)

  if (topItems.length === 0) {
    return null
  }

  const firstItem = topItems[0]
  const lastItem = topItems[topItems.length - 1]
  if (!firstItem || !lastItem) {
    return null
  }
  const highestPriority = computePriority(firstItem)
  const lowestShown = computePriority(lastItem)

  // Panel content with optional extra className via wrapping div
  const extraClass = className ?? ''
  const panelContent = (
    <div className={extraClass}>
      <p className="text-xs text-slate-500">
        Priority = severity × confidence × verification weight (0–100). Higher
        score = higher reported risk. This is a deterministic heuristic, not a
        probability or CVSS score.
      </p>

      <dl className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <div>
          <dt className="vin-kicker !text-[9px] text-slate-400">Highest priority</dt>
          <dd className="vin-figure mt-2">
            {highestPriority.toFixed(1)}
          </dd>
        </div>
        <div>
          <dt className="vin-kicker !text-[9px] text-slate-400">Lowest shown</dt>
          <dd className="vin-figure mt-2">
            {lowestShown.toFixed(1)}
          </dd>
        </div>
      </dl>

      <table className="w-full text-left text-xs">
        <thead>
          <tr className="border-b border-white/10 text-slate-500">
            <th className="pb-1 pr-2" scope="col">Priority</th>
            <th className="pb-1 pr-2" scope="col">Severity</th>
            <th className="pb-1 pr-2" scope="col">Title</th>
            <th className="pb-1" scope="col">Status</th>
            <th className="pb-1 font-mono text-slate-600" scope="col">Sources</th>
          </tr>
        </thead>
        <tbody>
          {topItems.map((finding: Finding) => (
            <tr
              key={finding.id}
              className="border-b border-white/5 transition-colors hover:bg-white/[0.03]"
            >
              <td className="py-1 pr-2 font-mono">
                {computePriority(finding).toFixed(1)}
              </td>
              <td className="py-1 pr-2">
                <SeverityBadge severity={finding.severity} />
              </td>
              <td className="py-1 pr-2">{finding.title}</td>
              <td className="py-1 pr-2 text-slate-400">
                {finding.verification_status}
              </td>
              <td className="py-1 font-mono text-slate-600">
                {finding.source_module ?? ''}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {visible.length > 20 && (
        <p className="mt-2 text-xs text-slate-500">
          {visible.length - 20 + ' more findings shown (view full report for all)'}
        </p>
      )}
    </div>
  )

  return (
    <Panel
      title={`Risk Scoring Board (top ${topItems.length} findings)`}
      testId="scoring-board-panel"
    >
      {panelContent}
    </Panel>
  )
}