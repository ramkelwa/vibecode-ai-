import { useCallback, useEffect, useRef, useState } from 'react'
import { ExternalLink, Globe, Search, Send, ShieldAlert, ShieldQuestion } from 'lucide-react'
import { api, ApiError, type VirustotalResult } from '../api'
import { isValidTargetUrl } from './NewScanForm'
import { ErrorState, LoadingState, Panel } from './ui'

const POLL_INTERVAL_MS = 10_000
const POLL_MAX_ATTEMPTS = 30

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

export default function VirusTotalPanel({
  configured,
  initialUrl = '',
  autoLookup = false,
  autoLookupKey = '',
}: {
  configured: boolean | null
  initialUrl?: string
  autoLookup?: boolean
  autoLookupKey?: string
}) {
  const [url, setUrl] = useState(initialUrl)
  const [phase, setPhase] = useState<Phase>('idle')
  const [result, setResult] = useState<VirustotalResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [confirmOpen, setConfirmOpen] = useState(false)

  const aliveRef = useRef(true)
  const runIdRef = useRef(0)
  const lastAutoLookupRef = useRef('')

  useEffect(() => {
    aliveRef.current = true
    return () => {
      aliveRef.current = false
    }
  }, [])

  const reset = useCallback(() => {
    runIdRef.current += 1
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

  const lookupReport = useCallback(async (targetUrl = url) => {
    reset()
    const run = runIdRef.current
    setPhase('checking')
    try {
      const r = await api.virustotalReport(targetUrl)
      if (!aliveRef.current || runIdRef.current !== run) return
      setResult(r)
      setPhase(r.status === 'not_found' ? 'not_found' : 'found')
    } catch (e: unknown) {
      if (!aliveRef.current || runIdRef.current !== run) return
      setError(errorMessage(e))
      setPhase('check_error')
    }
  }, [reset, url])

  useEffect(() => {
    if (!autoLookup || configured !== true || !initialUrl) return
    const lookupKey = autoLookupKey || initialUrl
    if (lastAutoLookupRef.current === lookupKey) return
    lastAutoLookupRef.current = lookupKey
    setUrl(initialUrl)
    void lookupReport(initialUrl)
  }, [autoLookup, autoLookupKey, configured, initialUrl, lookupReport])

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
        setResult(r)
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
      <div className="space-y-4">
        <p className="text-xs text-zinc-400 leading-relaxed">
          Third-party data from VirusTotal — distinct from VibeShield&apos;s own security checks.
          Checking or submitting sends the URL, including query parameters, to VirusTotal. Do not
          use confidential URLs or URLs containing secrets. Zero detections never means a site is
          proven safe.
        </p>

        {configured === false && (
          <p className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-300" role="note">
            VirusTotal is not configured on this server (missing API key). This panel is disabled.
          </p>
        )}

        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault()
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
          <label htmlFor="vt-url" className="text-xs font-medium text-zinc-400">
            URL to check (THIRD-PARTY THREAT INTELLIGENCE, not from VibeShield&apos;s scanner)
          </label>
          <div className="flex flex-wrap gap-2.5">
            <div className="relative flex-1 min-w-[260px]">
              <Globe className="absolute left-3.5 top-3 h-4 w-4 text-zinc-500" aria-hidden />
              <input
                id="vt-url"
                type="text"
                required
                aria-label="URL to check"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://target.example.com"
                className="vin-input w-full pl-10 text-sm"
              />
            </div>
            <button
              type="submit"
              disabled={busy || configured === false}
              className="vin-btn-primary px-4 py-2 text-sm font-medium"
            >
              <Search className="h-4 w-4" aria-hidden />
              Check with VirusTotal
            </button>
            <button
              type="button"
              disabled={busy || configured === false}
              onClick={startSubmitFlow}
              className="vin-btn-ghost px-4 py-2 text-sm font-medium"
            >
              <Send className="h-3.5 w-3.5" aria-hidden />
              Submit new scan
            </button>
          </div>
        </form>

        {/* Confirmation dialog */}
        {confirmOpen && (
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Confirm third-party submission"
            data-testid="vt-consent"
            className="rounded-xl border border-amber-500/40 bg-zinc-900/95 p-4 shadow-xl backdrop-blur-xl"
          >
            <p className="mb-2 font-semibold text-amber-400 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4" aria-hidden /> Share this URL with VirusTotal?
            </p>
            <ul className="mb-3 list-disc pl-5 text-xs text-zinc-300 space-y-1">
              <li>
                The URL (full address incl. <b>query parameters</b>) is sent to the third-party
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
                className="vin-btn-primary bg-amber-500 text-zinc-950 hover:bg-amber-400 px-4 py-1.5 text-xs font-semibold"
              >
                I understand, submit
              </button>
              <button
                type="button"
                onClick={() => setConfirmOpen(false)}
                className="vin-btn-ghost px-3.5 py-1.5 text-xs"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* States */}
        {(busy || phase === 'queued' || phase === 'polling') && (
          <div className="py-2">
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
          <div className="py-1">
            <ErrorState
              message={error}
              onRetry={phase === 'check_error' ? () => lookupReport() : undefined}
            />
          </div>
        )}

        {showResult && result && (
          <div className="rounded-lg border border-zinc-800/60 bg-zinc-900/40 p-4" data-testid="vt-result">
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
                <span role="status" aria-label={STATUS_LABELS[phase] ?? result.status}>
                  ● {STATUS_LABELS[phase] ?? result.status}
                </span>
                {result.last_analysis_date
                  ? ` — last analysis ${new Date(result.last_analysis_date).toLocaleString()}`
                  : ''}
              </p>
            </div>
            <p className="mb-3 text-sm font-medium text-zinc-200" data-testid="vt-verdict">
              {resultStatusLine(result)}
            </p>
            {result.stats ? (
              <dl className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-3">
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
                  <div key={label} className="vin-tile p-2.5 flex justify-between gap-2">
                    <dt className="text-zinc-400 font-medium">{label}</dt>
                    <dd
                      data-testid={`vt-stat-${label.toLowerCase().replace(/\s+/g, '-')}`}
                      className="font-semibold text-zinc-200 tabular-nums font-mono"
                    >
                      {value === null ? 'unknown' : value}
                    </dd>
                  </div>
                ))}
              </dl>
            ) : result.status === 'not_found' ? (
              <p className="text-xs text-zinc-500">
                VirusTotal has no existing report for this URL. Use “Submit new scan” to request an
                analysis (the URL will be shared with the third-party service — see the privacy
                notice).
              </p>
            ) : (
              <p className="text-xs text-zinc-500">Engine statistics are not available yet.</p>
            )}
            {reportLink && (
              <a
                href={reportLink}
                target="_blank"
                rel="noopener noreferrer"
                data-testid="vt-report-link"
                className="mt-3 inline-flex items-center gap-1.5 text-xs text-sky-400 hover:text-sky-300 font-medium hover:underline"
              >
                <ExternalLink className="h-3.5 w-3.5" aria-hidden /> View report on VirusTotal
              </a>
            )}
          </div>
        )}

        {phase === 'idle' && !result && (
          <p className="flex items-center gap-2 text-xs text-zinc-500 py-1">
            <ShieldQuestion className="h-4 w-4" aria-hidden /> Enter a URL above, then check for an
            existing report.
          </p>
        )}
      </div>
    </Panel>
  )
}
