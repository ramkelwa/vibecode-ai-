import type { ScanSummary } from '../api'
import type { RiskSummary } from '../api'
import { Panel } from './ui'

// Determine visit recommendation and suspicion level based on scan risk summary
function getScanAssessment(
  riskSummary: RiskSummary | null,
  scanStatus: string
): {
  visitRecommendation: 'safe' | 'caution' | 'avoid'
  suspicionLevel: 'none' | 'low' | 'medium' | 'high'
  score: number
  scoreLabel: string
} {
  if (!riskSummary) {
    return {
      visitRecommendation: 'caution',
      suspicionLevel: 'low',
      score: 25,
      scoreLabel: 'No risk data',
    }
  }

  const counts = riskSummary.counts
  const bySeverity = counts.by_severity
  const byVerification = counts.by_verification_status

  // Severity weights
  const severityWeights: Record<string, number> = {
    critical: 100,
    high: 75,
    medium: 50,
    low: 25,
    info: 10,
    unknown: 15,
  }

  // Base priority on highest severity finding's priority formula
  let score = 25 // default neutral
  if (riskSummary.prioritized && riskSummary.prioritized.length > 0) {
    const topFinding = riskSummary.prioritized[0] as NonNullable<typeof riskSummary.prioritized>[0]
    const sevWeight = severityWeights[topFinding.severity] || 10
    // Confidence weight - use default since we don't have a reliable confidence weight from the counts
    const confWeight = 0.5
    // Verification weight
    const verWeights: Record<string, number> = {
      confirmed: 1,
      potential: 0.9,
      unverified: 0.7,
      informational: 0.4,
      false_positive: 0.05,
      unknown: 0.3,
    }
    const verWeight = verWeights[topFinding.verification_status] || 0.3
    score = Math.round((sevWeight * confWeight * verWeight) / 100 * 100)
  } else {
    // No prioritized findings - check counts
    const totalFindings = counts.total ?? 0

    // If there are findings with medium+ severity, it's caution-worthy
    const hasMediumOrHigher =
      (bySeverity.medium ?? 0) > 0 ||
      (bySeverity.high ?? 0) > 0 ||
      (bySeverity.critical ?? 0) > 0

    // If there are unverified findings, increase suspicion
    const hasUnverified =
      (byVerification.unverified ?? 0) > 0 ||
      (byVerification.unknown ?? 0) > 0

    if (totalFindings === 0) {
      score = 10
      if (scanStatus === 'completed') {
        return {
          visitRecommendation: 'safe',
          suspicionLevel: 'none',
          score,
          scoreLabel: 'Clean scan',
        }
      }
    }

    if (hasMediumOrHigher) {
      score = 75
      if (hasUnverified) {
        return {
          visitRecommendation: 'avoid',
          suspicionLevel: 'high',
          score,
          scoreLabel: 'High risk',
        }
      }
      return {
        visitRecommendation: 'caution',
        suspicionLevel: 'medium',
        score,
        scoreLabel: 'Medium risk',
      }
    }

    if (hasUnverified && totalFindings > 0) {
      score = 50
      return {
        visitRecommendation: 'caution',
        suspicionLevel: 'low',
        score,
        scoreLabel: 'Some concerns',
      }
    }

    score = 25
  }

  // Adjust based on overall counts
  const criticalCount = bySeverity.critical ?? 0
  const highCount = bySeverity.high ?? 0

  if (criticalCount > 0) {
    // Increase score and likely avoid
    score = Math.min(100, score + 30)
    return {
      visitRecommendation: 'avoid',
      suspicionLevel: 'high',
      score,
      scoreLabel: 'Critical findings',
    }
  }

  if (highCount > 0 && score < 50) {
    score = Math.min(75, score + 20)
    return {
      visitRecommendation: 'avoid',
      suspicionLevel: 'medium',
      score,
      scoreLabel: 'High severity findings',
    }
  }

  // Determine recommendation based on final score
  let visitRecommendation: 'safe' | 'caution' | 'avoid'
  let suspicionLevel: 'none' | 'low' | 'medium' | 'high'

  if (score >= 70) {
    visitRecommendation = 'avoid'
    suspicionLevel = 'high'
  } else if (score >= 40) {
    visitRecommendation = 'caution'
    suspicionLevel = 'medium'
  } else {
    visitRecommendation = 'safe'
    suspicionLevel = 'none'
  }

  const scoreLabel = score >= 70 ? 'High risk' : score >= 40 ? 'Medium risk' : 'Low risk'

  return {
    visitRecommendation,
    suspicionLevel,
    score,
    scoreLabel,
  }
}

interface ScanScoringBoardProps {
  scans: ScanSummary[]
  riskSummaries: Record<string, RiskSummary | null>
}

export default function ScanScoringBoard({
  scans,
  riskSummaries,
}: ScanScoringBoardProps) {
  const assessments = scans.map((scan) => {
    const riskSummary = riskSummaries[scan.id] ?? null
    return {
      scan,
      assessment: getScanAssessment(riskSummary, scan.status),
    }
  })

  if (scans.length === 0) {
    return null
  }

  const highestScore = Math.max(
    ...assessments.map((a) => a.assessment.score),
  )
  const lowestScore = Math.min(
    ...assessments.map((a) => a.assessment.score),
  )

  // Compute visit recommendation counts
  const avoidCount = assessments.filter(
    (a) => a.assessment.visitRecommendation === 'avoid',
  ).length
  const cautionCount = assessments.filter(
    (a) => a.assessment.visitRecommendation === 'caution',
  ).length
  const safeCount = assessments.filter(
    (a) => a.assessment.visitRecommendation === 'safe',
  ).length

  return (
    <Panel
      title={`Scan Risk Scoring Board (${scans.length} scans)`}
      testId="scan-scoring-board-panel"
    >
      <div className="space-y-4">
        <div className="flex items-start gap-2.5 rounded-lg border border-zinc-800/60 bg-zinc-900/40 p-3 text-xs text-zinc-400">
          <svg
            className="h-4 w-4 text-sky-400 shrink-0 mt-0.5 aria-hidden"
            viewBox="0 0 24 24"
          >
            <path d="M12 2a1 1 0 011 1v2a1 1 0 01-2 0V3a1 1 0 011-1zm0 7.667a1 1 0 011 1v2a1 1 0 01-2 0v-2a1 1 0 011-1zm0 7.667a1 1 0 011 1v2a1 1 0 01-2 0v-2a1 1 0 011-1z" />
          </svg>
          <p>
            Score = deterministic heuristic (0-100). Higher score = higher reported risk.
            Based on severity × confidence × verification weight of findings.
          </p>
        </div>

        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <div className="vin-tile p-3.5">
            <dt className="vin-kicker !text-[10px] text-zinc-400">Highest score</dt>
            <dd className="vin-figure mt-2 text-rose-400">
              {highestScore.toFixed(0)}
            </dd>
          </div>
          <div className="vin-tile p-3.5">
            <dt className="vin-kicker !text-[10px] text-zinc-400">Lowest score</dt>
            <dd className="vin-figure mt-2 text-zinc-300">
              {lowestScore.toFixed(0)}
            </dd>
          </div>
        </dl>

        <div className="overflow-x-auto rounded-lg border border-zinc-800/60 bg-zinc-900/30">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/60 text-zinc-400 font-semibold uppercase tracking-wider">
                <th className="py-2.5 px-3" scope="col">Target</th>
                <th className="py-2.5 px-3" scope="col">Status</th>
                <th className="py-2.5 px-3" scope="col">Visit Rec.</th>
                <th className="py-2.5 px-3" scope="col">Suspicion</th>
                <th className="py-2.5 px-3 font-mono" scope="col">Score</th>
                <th className="py-2.5 px-3 font-mono" scope="col">Findings</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/40">
              {assessments.map((item) => {
                const { scan, assessment } = item
                const { visitRecommendation, suspicionLevel, score } =
                  assessment

                // Color code the visit recommendation
                const recColor = visitRecommendation === 'safe'
                  ? 'text-emerald-400'
                  : visitRecommendation === 'caution'
                    ? 'text-amber-400'
                    : 'text-rose-400'

                const recLabel = visitRecommendation === 'safe'
                  ? 'Safe to visit'
                  : visitRecommendation === 'caution'
                    ? 'Use with caution'
                    : 'Avoid'

                return (
                  <tr
                    key={scan.id}
                    className="transition-colors hover:bg-zinc-800/40"
                  >
                    <td className="py-2.5 px-3 font-medium text-zinc-200">
                      {scan.target_url}
                    </td>
                    <td className="py-2.5 px-3 text-zinc-400 font-mono text-[11px]">
                      {scan.status}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={recColor}>
                        {recLabel}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-zinc-400">
                      {suspicionLevel}
                    </td>
                    <td className="py-2.5 px-3 font-mono font-semibold">
                      {score}
                    </td>
                    <td className="py-2.5 px-3 text-zinc-500 text-[11px]">
                      {scan.modules_requested.length > 0
                        ? scan.modules_requested.join(', ')
                        : '0'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        <p className="mt-2 text-xs text-zinc-500">
          Score range: {lowestScore.toFixed(0)} - {highestScore.toFixed(0)}
          ({avoidCount} avoid, {cautionCount} caution, {safeCount} safe)
        </p>
      </div>
    </Panel>
  )
}