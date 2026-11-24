import { Calculator } from 'lucide-react'
import type { Finding } from '../api'
import { Panel, SeverityBadge } from './ui'

// Risk priority formula (ported from backend app/scanners/phase5.py)
// priority = severity_weight × confidence_weight × verification_weight  -> 0..100
const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 100,
  high: 75,
  medium: 50,
  low: 25,
  info: 10,
  unknown: 15,
}
const CONFIDENCE_WEIGHT: Record<string, number> = {
  certain: 1.0,
  firm: 0.85,
  uncertain: 0.6,
  unknown: 0.5,
}
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
  return Math.round(sev * conf * stat * 10) / 10
}

interface ScoringBoardProps {
  findings: Finding[]
  className?: string
}

export default function ScoringBoard({ findings, className }: ScoringBoardProps) {
  const sorted: Finding[] = [...findings].sort((a, b) => computePriority(b) - computePriority(a))
  const visible: Finding[] = sorted.filter(
    (f): f is Finding =>
      f.title !== '' &&
      typeof f.severity === 'string' &&
      f.confidence !== '' &&
      typeof f.verification_status === 'string',
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

  const extraClass = className ?? ''
  const panelContent = (
    <div className={`space-y-4 ${extraClass}`}>
      <div className="flex items-start gap-2.5 rounded-lg border border-zinc-800/60 bg-zinc-900/40 p-3 text-xs text-zinc-400">
        <Calculator className="h-4 w-4 text-sky-400 shrink-0 mt-0.5" aria-hidden />
        <p>
          Priority = severity &times; confidence &times; verification weight (0–100). Higher
          score = higher reported risk. This is a deterministic heuristic, not a
          probability or CVSS score.
        </p>
      </div>

      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="vin-tile p-3.5">
          <dt className="vin-kicker !text-[10px] text-zinc-400">Highest priority</dt>
          <dd className="vin-figure mt-2 text-rose-400">
            {highestPriority.toFixed(1)}
          </dd>
        </div>
        <div className="vin-tile p-3.5">
          <dt className="vin-kicker !text-[10px] text-zinc-400">Lowest shown</dt>
          <dd className="vin-figure mt-2 text-zinc-300">
            {lowestShown.toFixed(1)}
          </dd>
        </div>
      </dl>

      <div className="overflow-x-auto rounded-lg border border-zinc-800/60 bg-zinc-900/30">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-zinc-800 bg-zinc-900/60 text-zinc-400 font-semibold uppercase tracking-wider">
              <th className="py-2.5 px-3" scope="col">Priority</th>
              <th className="py-2.5 px-3" scope="col">Severity</th>
              <th className="py-2.5 px-3" scope="col">Title</th>
              <th className="py-2.5 px-3" scope="col">Status</th>
              <th className="py-2.5 px-3 font-mono" scope="col">Sources</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/40">
            {topItems.map((finding: Finding) => {
              const priority = computePriority(finding)
              return (
                <tr
                  key={finding.id}
                  className="transition-colors hover:bg-zinc-800/40"
                >
                  <td className="py-2.5 px-3 font-mono font-semibold">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-[11px] ${
                        priority >= 70
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                          : priority >= 40
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            : 'bg-zinc-800 text-zinc-300'
                      }`}
                    >
                      {priority.toFixed(1)}
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={finding.severity} />
                  </td>
                  <td className="py-2.5 px-3 font-medium text-zinc-200">{finding.title}</td>
                  <td className="py-2.5 px-3 text-zinc-400 font-mono text-[11px]">
                    {finding.verification_status}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-zinc-500 text-[11px]">
                    {finding.source_module ?? ''}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {visible.length > 20 && (
        <p className="mt-2 text-xs text-zinc-500">
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
