import { useRef, useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import { api, ApiError, type VirustotalResult } from '../api'
import { LoadingState, Panel } from './ui'

const MAX_FILE_BYTES = 32 * 1024 * 1024
const POLL_DELAY_MS = 5_000
const POLL_ATTEMPTS = 24

type Phase = 'idle' | 'checking' | 'not_found' | 'confirm' | 'submitting' | 'pending' | 'done' | 'error'

const reportUrl = (result: VirustotalResult | null, sha256: string): string | null => {
  const candidate =
    result?.report_url ?? `https://www.virustotal.com/gui/file/${sha256}`
  return /^https:\/\/www\.virustotal\.com\/gui\/file\/[a-f0-9]{64}$/i.test(candidate)
    ? candidate
    : null
}

const readFile = (file: File): Promise<ArrayBuffer> => {
  if (typeof file.arrayBuffer === 'function') return file.arrayBuffer()
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) resolve(reader.result)
      else reject(new Error('Could not read the selected file.'))
    }
    reader.onerror = () => reject(reader.error ?? new Error('Could not read the selected file.'))
    reader.readAsArrayBuffer(file)
  })
}

export default function VirusTotalFilePanel({ configured }: { configured: boolean | null }) {
  const [file, setFile] = useState<File | null>(null)
  const [sha256, setSha256] = useState('')
  const [phase, setPhase] = useState<Phase>('idle')
  const [result, setResult] = useState<VirustotalResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const operationRef = useRef(0)

  const checkSelectedFile = async (selected: File, operation: number) => {
    if (selected.size > MAX_FILE_BYTES) {
      setPhase('error')
      setError('VirusTotal public uploads are limited to 32 MiB per file.')
      return
    }
    if (!globalThis.crypto?.subtle) {
      setPhase('error')
      setError('This browser cannot calculate a SHA-256 hash for the selected file.')
      return
    }
    setPhase('checking')
    setError(null)
    setResult(null)
    try {
      const digest = await crypto.subtle.digest('SHA-256', await readFile(selected))
      if (operationRef.current !== operation) return
      const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
      setSha256(hash)
      const report = await api.virustotalFileReport(hash)
      if (operationRef.current !== operation) return
      setResult(report)
      setPhase(report.status === 'not_found' ? 'not_found' : 'done')
    } catch (e: unknown) {
      if (operationRef.current !== operation) return
      setPhase('error')
      setError(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : String(e))
    }
  }

  const chooseFile = (selected: File | null) => {
    operationRef.current += 1
    const operation = operationRef.current
    setFile(selected)
    setSha256('')
    setResult(null)
    setError(null)
    setPhase('idle')
    if (selected && configured === true) void checkSelectedFile(selected, operation)
  }

  const submitFile = async () => {
    if (!file || !sha256 || phase === 'submitting') return
    const operation = operationRef.current
    setPhase('submitting')
    setError(null)
    try {
      let analysis = await api.virustotalFileScan(file)
      if (operationRef.current !== operation) return
      setResult(analysis)
      const analysisId = analysis.analysis_id
      if (!analysisId) {
        setPhase('done')
        return
      }
      for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt += 1) {
        if (operationRef.current !== operation) return
        if (analysis.status === 'completed' || analysis.status === 'failed') {
          setPhase('done')
          return
        }
        setPhase('pending')
        await new Promise((resolve) => window.setTimeout(resolve, POLL_DELAY_MS))
        if (operationRef.current !== operation) return
        analysis = await api.virustotalAnalysis(analysisId)
        if (operationRef.current !== operation) return
        setResult({ ...analysis, sha256, object_type: 'file' })
      }
      setPhase('error')
      setError('VirusTotal analysis is still pending. Try again later or open its report.')
    } catch (e: unknown) {
      if (operationRef.current !== operation) return
      setPhase('error')
      setError(e instanceof ApiError ? e.detail : e instanceof Error ? e.message : String(e))
    }
  }

  const link = reportUrl(result, sha256)
  const isBusy = phase === 'checking' || phase === 'submitting' || phase === 'pending'

  return (
    <Panel title="File / APK threat check" testId="virustotal-file-panel">
      <div className="space-y-4">
        <p className="text-xs text-zinc-400 leading-relaxed">
          This is a VirusTotal-only file check; VibeShield does not currently inspect file/APK
          binaries itself. Selecting a file calculates its SHA-256 locally and checks that hash for
          an existing public report. The file is uploaded to VirusTotal only after you confirm.
          Uploads may be retained and shared by VirusTotal. Do not select confidential files.
        </p>

        {configured === false && (
          <p role="note" className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-300">
            VirusTotal is not configured on this server. Configure its API key to enable file checks.
          </p>
        )}

        <div>
          <label className="mb-2 block text-xs font-medium text-zinc-300" htmlFor="vt-file">
            Choose a file or APK (maximum 32 MiB)
          </label>
          <input
            id="vt-file"
            type="file"
            disabled={configured !== true || isBusy}
            onChange={(event) => chooseFile(event.currentTarget.files?.[0] ?? null)}
            className="vin-input block w-full text-sm file:mr-3 file:rounded-md file:border-0 file:bg-zinc-800 file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-zinc-200 hover:file:bg-zinc-700 disabled:opacity-50"
          />
          {file && (
            <p className="mt-2 break-all text-xs text-zinc-400">
              Selected: {file.name} ({(file.size / (1024 * 1024)).toFixed(2)} MiB)
            </p>
          )}
        </div>

        {phase === 'checking' && (
          <div className="py-1">
            <LoadingState label="Checking the file hash with VirusTotal…" />
          </div>
        )}
        {phase === 'submitting' && (
          <div className="py-1">
            <LoadingState label="Uploading the confirmed file to VirusTotal…" />
          </div>
        )}
        {phase === 'pending' && (
          <div className="py-1">
            <LoadingState label="VirusTotal analysis pending…" />
          </div>
        )}

        {phase === 'not_found' && (
          <div className="rounded-lg border border-zinc-800/60 bg-zinc-900/40 p-4" data-testid="vt-file-not-found">
            <p className="text-sm font-medium text-zinc-200">No existing VirusTotal report for this file hash.</p>
            <p className="mt-1 break-all font-mono text-xs text-zinc-400">SHA-256: {sha256}</p>
            <button
              type="button"
              onClick={() => setPhase('confirm')}
              className="vin-btn-primary mt-3 px-3.5 py-1.5 text-xs font-medium"
            >
              Submit file to VirusTotal…
            </button>
          </div>
        )}

        {phase === 'confirm' && (
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Confirm file upload to VirusTotal"
            className="rounded-xl border border-amber-500/40 bg-zinc-900/95 p-4 shadow-xl backdrop-blur-xl"
          >
            <p className="font-semibold text-amber-400 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4" aria-hidden /> Share this file with VirusTotal?
            </p>
            <p className="my-2.5 text-xs text-zinc-300 leading-relaxed">
              The complete file, filename, and its hash will be sent to a third party for analysis.
              It may be retained and shared publicly. This is separate from VibeShield scanning.
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => void submitFile()}
                className="vin-btn-primary bg-amber-500 text-zinc-950 hover:bg-amber-400 px-4 py-1.5 text-xs font-semibold"
              >
                I understand, upload file
              </button>
              <button
                type="button"
                onClick={() => setPhase('not_found')}
                className="vin-btn-ghost px-3.5 py-1.5 text-xs"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {phase === 'error' && error && (
          <p role="alert" className="rounded-lg border border-red-500/30 bg-red-950/20 p-3 text-xs text-red-300">
            {error}
          </p>
        )}

        {phase === 'done' && result && (
          <div className="rounded-lg border border-zinc-800/60 bg-zinc-900/40 p-4 space-y-3" data-testid="vt-file-result">
            <p className="text-sm font-medium text-zinc-200">
              {result.status === 'not_found'
                ? 'No existing report'
                : result.status === 'queued' || result.status === 'pending'
                  ? 'Analysis pending'
                  : result.stats?.malicious
                    ? 'Potentially malicious detections reported'
                    : result.stats?.suspicious
                      ? 'Suspicious detections reported'
                      : result.status === 'completed'
                        ? 'Analysis completed; no detections reported by available engines.'
                        : 'VirusTotal analysis finished.'}
            </p>
            {result.stats && (
              <dl className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
                {[
                  ['Malicious', result.stats.malicious],
                  ['Suspicious', result.stats.suspicious],
                  ['Harmless', result.stats.harmless],
                  ['Undetected', result.stats.undetected],
                ].map(([label, count]) => (
                  <div key={String(label)} className="vin-tile p-2.5 flex justify-between gap-2">
                    <dt className="text-zinc-400">{label}</dt>
                    <dd className="font-semibold text-zinc-200 font-mono">{count ?? 0}</dd>
                  </div>
                ))}
              </dl>
            )}
            {link && (
              <a
                href={link}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs text-sky-400 hover:text-sky-300 font-medium hover:underline pt-1"
              >
                View report on VirusTotal
              </a>
            )}
          </div>
        )}
      </div>
    </Panel>
  )
}
