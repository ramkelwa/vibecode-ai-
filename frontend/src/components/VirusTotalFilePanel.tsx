import { useRef, useState } from 'react'
import { api, ApiError, type VirustotalResult } from '../api'
import { Panel, LoadingState } from './ui'

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
      <p className="mb-3 text-xs text-slate-400">
        This is a VirusTotal-only file check; VibeShield does not currently inspect file/APK
        binaries itself. Selecting a file calculates its SHA-256 locally and checks that hash for
        an existing public report. The file is uploaded to VirusTotal only after you confirm.
        Uploads may be retained and shared by VirusTotal. Do not select confidential files.
      </p>
      {configured === false && (
        <p role="note" className="mb-3 rounded border border-amber-900 bg-amber-950/40 p-2 text-xs text-amber-300">
          VirusTotal is not configured on this server. Configure its API key to enable file checks.
        </p>
      )}
      <label className="mb-2 block text-xs font-medium text-slate-300" htmlFor="vt-file">
        Choose a file or APK (maximum 32 MiB)
      </label>
      <input
        id="vt-file"
        type="file"
        disabled={configured !== true || isBusy}
        onChange={(event) => chooseFile(event.currentTarget.files?.[0] ?? null)}
        className="block w-full text-sm text-slate-300 file:mr-3 file:rounded file:border-0 file:bg-slate-800 file:px-3 file:py-2 file:text-xs file:text-slate-200 disabled:opacity-50"
      />
      {file && (
        <p className="mt-2 break-all text-xs text-slate-400">
          Selected: {file.name} ({(file.size / (1024 * 1024)).toFixed(2)} MiB)
        </p>
      )}
      {phase === 'checking' && <div className="mt-3"><LoadingState label="Checking the file hash with VirusTotal…" /></div>}
      {phase === 'submitting' && <div className="mt-3"><LoadingState label="Uploading the confirmed file to VirusTotal…" /></div>}
      {phase === 'pending' && <div className="mt-3"><LoadingState label="VirusTotal analysis pending…" /></div>}
      {phase === 'not_found' && (
        <div className="mt-3 rounded border border-slate-800 bg-slate-950/60 p-3" data-testid="vt-file-not-found">
          <p className="text-sm text-slate-300">No existing VirusTotal report for this file hash.</p>
          <p className="mt-1 break-all font-mono text-xs text-slate-500">SHA-256: {sha256}</p>
          <button
            type="button"
            onClick={() => setPhase('confirm')}
            className="mt-3 rounded bg-sky-800 px-3 py-2 text-xs font-medium text-white hover:bg-sky-700"
          >
            Submit file to VirusTotal…
          </button>
        </div>
      )}
      {phase === 'confirm' && (
        <div role="dialog" aria-modal="true" aria-label="Confirm file upload to VirusTotal" className="mt-3 rounded border border-amber-900 bg-amber-950/40 p-3 text-sm text-amber-200">
          <p className="font-medium">Share this file with VirusTotal?</p>
          <p className="my-2 text-xs">
            The complete file, filename, and its hash will be sent to a third party for analysis.
            It may be retained and shared publicly. This is separate from VibeShield scanning.
          </p>
          <div className="flex gap-2">
            <button type="button" onClick={() => void submitFile()} className="rounded bg-amber-700 px-3 py-1 text-xs font-medium text-white">
              I understand, upload file
            </button>
            <button type="button" onClick={() => setPhase('not_found')} className="rounded border border-amber-800 px-3 py-1 text-xs text-amber-200">
              Cancel
            </button>
          </div>
        </div>
      )}
      {phase === 'error' && error && (
        <p role="alert" className="mt-3 rounded border border-red-900 bg-red-950/40 p-2 text-xs text-red-300">{error}</p>
      )}
      {phase === 'done' && result && (
        <div className="mt-3 rounded border border-slate-800 bg-slate-950/60 p-3" data-testid="vt-file-result">
          <p className="text-sm text-slate-300">
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
            <p className="mt-1 text-xs text-slate-400">
              Malicious: {result.stats.malicious ?? 'unknown'} · Suspicious: {result.stats.suspicious ?? 'unknown'} · Harmless: {result.stats.harmless ?? 'unknown'} · Undetected: {result.stats.undetected ?? 'unknown'}
            </p>
          )}
          {link && (
            <a href={link} target="_blank" rel="noopener noreferrer" className="mt-2 inline-block text-xs text-sky-400 underline">
              View VirusTotal file report
            </a>
          )}
          <p className="mt-2 text-xs text-slate-500">VirusTotal results are third-party intelligence and do not prove a file is safe.</p>
        </div>
      )}
    </Panel>
  )
}
