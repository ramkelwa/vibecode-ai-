import { useCallback, useEffect, useRef, useState } from 'react'
import { ExternalLink, ShieldAlert, ShieldQuestion } from 'lucide-react'
import { api, ApiError, type VirustotalResult } from '../api'
import { isValidTargetUrl } from './NewScanForm'
import { Panel, LoadingState, ErrorState } from './ui'

/**
 * VirusTotal Threat Intelligence panel.
 *
 * Distinct from VibeShield's own scanner: every result shown here is labeled as
 * third-party data from VirusTotal. Zero detections are NEVER presented as
 * "safe" — the neutral wording required by the product spec is used instead.
 *
 * Two separate actions:
 *  1. "Check for existing report" — read-only lookup, but the URL is still
 *     sent to the VirusTotal API to identify the public report.
 *  2. "Submit new scan" — shares the URL with the third-party service
 *     VirusTotal and requires explicit confirmation first.
 */

// Polling constraints (spec: bounded attempts + duration, no overlap).
const POLL_INTERVAL_MS = 10_000
const POLL_MAX_ATTEMPTS = 30 // ~5 minutes

type Phase =
  | 'idle'
  | 'checking'
  | 'found'
  | 'not_found'
  | 'submitting'
  | 'queued'
  | 'polling'
  | 'submit_error'
  | 'check_error'

const STATUS_LABELS: Record<string, string> = {
  queued: 'Analysis pending',
  polling: 'Analysis pending',
  found: 'Analysis completed',
  not_found: 'No existing report',
  submit_error: 'Analysis unavailable',
  check_error: 'Analysis unavailable',
}

function resultStatusLine(r: VirustotalResult): string {
  if (r.status === 'not_found') return 'No existing report'
  if (r.stats) {
    const mal = r.stats.malicious ?? 0
    const susp = r.stats.suspicious ?? 0
    if (mal > 0) return 'Potentially malicious detections reported'
    if (susp > 0) return 'Suspicious detections reported'
    return 'No detections reported by the available engines.'
  }
  return 'Analysis completed'
}

const isVtGuiLink = (url: string): boolean =>
  /^https:\/\/www\.virustotal\.com\/gui\/url\//.test(url)

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

export default function VirusTotalPanel({ configured }: { configured: boolean | null }) {
  const [url, setUrl] = useState('')
  const [phase, setPhase] = useState<Phase>('idle')
  const [result, setResult] = useState<VirustotalResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirmOpen, setConfirmOpen] = useState(false)

  // Polling lifecycle refs — all attempts stop on unmount or when a new
  // action (new URL / new scan) starts, so no stale background polling.
  const aliveRef = useRef(true)
  const runIdRef = useRef(0)
  useEffect(() => {
    aliveRef.current = true
    return () => {
      aliveRef.current = false
    }
  }, [])

  /** Reset all volatile state — used whenever a new URL or scan starts so
   * results from a previous URL can never be displayed for a new one. */
  const reset = useCallback(() => {
    runIdRef.current += 1 // cancels any in-flight poll loop
    setResult(null)
    setError(null)
  }, [])

  useEffect(() => {
    reset()
    setPhase('idle')
    setConfirmOpen(false)
  }, [reset, url])

  const errorMessage = (e: unknown): string =>
    e instanceof ApiError ? e.detail : e instanceof Error ? e.message : String(e)

  const lookupReport = useCallback(async () => {
    reset()
    const run = runIdRef.current
    setPhase('checking')
    try {
      const r = await api.virustotalReport(url)
      if (!aliveRef.current || runIdRef.current !== run) return
      setResult(r)
      setPhase(r.status === 'not_found' ? 'not_found' : 'found')
    } catch (e: unknown) {
      if (!aliveRef.current || runIdRef.current !== run) return
      setError(errorMessage(e))
      setPhase('check_error')
    }
  }, [reset, url])

  const pollAnalysis = useCallback(
    async (analysisId: string, run: number) => {
      for (let attempt = 1; attempt <= POLL_MAX_ATTEMPTS; attempt++) {
        if (!aliveRef.current || runIdRef.current !== run) return
        setPhase('polling')
        let r: VirustotalResult
        try {
          r = await api.virustotalAnalysis(analysisId)
        } catch (e: unknown) {
          if (!aliveRef.current || runIdRef.current !== run) return
          setError(errorMessage(e))
          setPhase('submit_error')
          return
        }
        if (!aliveRef.current || runIdRef.current !== run) return
        if (r.status === 'completed' || r.status === 'failed') {
          setResult(r)
          setPhase(r.status === 'completed' ? 'found' : 'submit_error')
          if (r.status === 'failed') setError('The VirusTotal analysis failed upstream.')
          return
        }
        setResult(r) // keep latest queued status visible
        if (attempt >= POLL_MAX_ATTEMPTS) {
          setPhase('submit_error')
          setError('Analysis is still pending after the polling limit. Try again later or open the VirusTotal report link.')
          return
        }
        await sleep(POLL_INTERVAL_MS)
      }
    },
    [],
  )

  const submitNewScan = useCallback(async () => {
    reset()
    const run = runIdRef.current
    setConfirmOpen(false)
    setPhase('submitting')
    try {
      const r = await api.virustotalScan(url)
      if (!aliveRef.current || runIdRef.current !== run) return
      setResult(r)
      if (r.analysis_id && (r.status === 'queued' || r.status === 'pending')) {
        setPhase('queued')
        void pollAnalysis(r.analysis_id, run)
      } else if (r.status === 'completed') {
        setPhase('found')
      } else {
        setPhase('submit_error')
      }
    } catch (e: unknown) {
      if (!aliveRef.current || runIdRef.current !== run) return
      setError(errorMessage(e))
      setPhase('submit_error')
    }
  }, [reset, url, pollAnalysis])

  const startSubmitFlow = () => {
    setError(null)
    if (!isValidTargetUrl(url)) {
      setPhase('submit_error')
      setError('Enter a valid http:// or https:// URL with a hostname.')
      return
    }
    setConfirmOpen(true)
  }

  const busy = phase === 'checking' || phase === 'submitting'
  const showResult =
    result && (phase === 'found' || phase === 'not_found' || phase === 'queued' || phase === 'polling')
  const reportLink =
    showResult && result.report_url && isVtGuiLink(result.report_url) ? result.report_url : null

  return (
    <Panel title="VirusTotal Threat Intelligence" testId="virustotal-panel">
      <p className="mb-3 text-xs text-slate-500">
        Third-party data from VirusTotal — distinct from VibeShield&apos;s own security checks.
        Checking or submitting sends the URL, including query parameters, to VirusTotal. Do not
        use confidential URLs or URLs containing secrets. Zero detections never means a site is
        proven safe.
      </p>

      {configured === false && (
        <p className="mb-3 rounded border border-amber-900 bg-amber-950/40 p-2 text-xs text-amber-300" role="note">
          VirusTotal is not configured on this server (missing API key). This panel is disabled.
        </p>
      )}

      <form
        className="flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault()
          // Primary action = read-only lookup; separate button handles submission.
          setError(null)
          if (!isValidTargetUrl(url)) {
            reset()
            setPhase('check_error')
            setError('Enter a valid http:// or https:// URL with a hostname.')
            return
          }
          void lookupReport()
        }}
      >
        <label htmlFor="vt-url" className="text-xs font-medium text-slate-400">
          URL to check (THIRD-PARTY THREAT INTELLIGENCE, not from VibeShield&apos;s scanner)
        </label>
        <div className="flex gap-2">
          <input
            id="vt-url"
            type="text"
            required
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://target.example.com"
            className="flex-1 rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm outline-none focus:border-sky-600"
          />
          <button
            type="submit"
            disabled={busy || configured === false}
            className="rounded bg-sky-800 px-3 py-2 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50"
          >
            Check with VirusTotal
          </button>
          <button
            type="button"
            disabled={busy || configured === false}
            onClick={startSubmitFlow}
            className="rounded border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:bg-slate-900 disabled:opacity-50"
          >
            Submit new scan
          </button>
        </div>
      </form>

      {/* New-submission privacy confirmation (required before sharing) */}
      {confirmOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Confirm third-party submission"
          data-testid="vt-consent"
          className="mt-3 rounded border border-amber-900 bg-amber-950/40 p-3 text-sm text-amber-200"
        >
          <p className="mb-2 font-medium flex items-center gap-2">
            <ShieldAlert className="h-4 w-4" aria-hidden /> Share this URL with VirusTotal?
          </p>
          <ul className="mb-2 list-disc pl-5 text-xs text-amber-200/90">
            <li>
              The URL (full address incl.<b>query parameters</b>) is sent to the third-party
              service VirusTotal and may be stored and publicly shared per their terms.
            </li>
            <li>Query parameters can contain session IDs, tokens, or email addresses.</li>
            <li>Do not submit confidential internal URLs, private links, or URLs with secrets.</li>
          </ul>
          <div className="flex gap-2">
            <button
              type="button"
              data-testid="vt-consent-confirm"
              onClick={() => void submitNewScan()}
              className="rounded bg-amber-700 px-3 py-1 text-xs font-medium text-white hover:bg-amber-600"
            >
              I understand, submit
            </button>
            <button
              type="button"
              onClick={() => setConfirmOpen(false)}
              className="rounded border border-amber-800 px-3 py-1 text-xs text-amber-200"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* States */}
      {(busy || phase === 'queued' || phase === 'polling') && (
        <div className="mt-3">
          <LoadingState
            label={
              phase === 'checking'
                ? 'Checking VirusTotal report…'
                : phase === 'submitting'
                  ? 'Submitting URL to VirusTotal…'
                  : 'Analysis pending — polling VirusTotal…'
            }
          />
        </div>
      )}

      {error && (phase === 'check_error' || phase === 'submit_error') && (
        <div className="mt-3">
          <ErrorState message={error} onRetry={phase === 'check_error' ? lookupReport : undefined} />
        </div>
      )}

      {showResult && result && (
        <div className="mt-3 rounded border border-slate-800 bg-slate-950/60 p-3" data-testid="vt-result">
          <p className="mb-1 text-xs font-medium text-slate-400">
            <span role="status" aria-label={STATUS_LABELS[phase] ?? result.status}>
              ● {STATUS_LABELS[phase] ?? result.status}
            </span>
            {result.last_analysis_date
              ? ` — last analysis ${new Date(result.last_analysis_date).toLocaleString()}`
              : ''}
          </p>
          <p className="mb-2 text-sm text-slate-300" data-testid="vt-verdict">
            {resultStatusLine(result)}
          </p>
          {result.stats ? (
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-slate-400 sm:grid-cols-3">
              {(
                [
                  ['Malicious', result.stats.malicious],
                  ['Suspicious', result.stats.suspicious],
                  ['Harmless', result.stats.harmless],
                  ['Undetected', result.stats.undetected],
                  ['Engine timeouts', result.stats.timeout],
                  ['Engines reporting', result.engines_reporting],
                ] as Array<[string, number | null]>
              ).map(([label, value]) => (
                <div key={label} className="flex justify-between gap-2">
                  <dt>{label}</dt>
                  <dd data-testid={`vt-stat-${label.toLowerCase().replace(/\s+/g, '-')}`}>
                    {value === null ? 'unknown' : value}
                  </dd>
                </div>
              ))}
            </dl>
          ) : result.status === 'not_found' ? (
            <p className="text-xs text-slate-500">
              VirusTotal has no existing report for this URL. Use “Submit new scan” to request an
              analysis (the URL will be shared with the third-party service — see the privacy
              notice).
            </p>
          ) : (
            <p className="text-xs text-slate-500">Engine statistics are not available yet.</p>
          )}
          {reportLink && (
            <a
              href={reportLink}
              target="_blank"
              rel="noopener noreferrer"
              data-testid="vt-report-link"
              className="mt-2 inline-flex items-center gap-1 text-xs text-sky-400 underline"
            >
              <ExternalLink className="h-3 w-3" aria-hidden /> View report on VirusTotal
            </a>
          )}
        </div>
      )}

      {phase === 'idle' && !result && (
        <p className="mt-3 flex items-center gap-2 text-xs text-slate-500">
          <ShieldQuestion className="h-4 w-4" aria-hidden /> Enter a URL above, then check for an
          existing report.
        </p>
      )}
    </Panel>
  )
}
