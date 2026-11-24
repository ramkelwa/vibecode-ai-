import { useEffect, useState } from 'react'
import { Download, ExternalLink, Shield, ShieldAlert } from 'lucide-react'
import { api, ApiError, type ScanDetail as ScanDetailData, type VirustotalResult } from '../api'
import type { ScanSubmission } from './NewScanForm'
import { LoadingState, Panel } from './ui'
import ScanDetail from './ScanDetail'

const POLL_DELAY_MS = 5_000
const POLL_ATTEMPTS = 24
const MAX_FILE_BYTES = 32 * 1024 * 1024

type VirusTotalState =
  | { status: 'checking' | 'submitting' | 'pending'; result: VirustotalResult | null; error: null }
  | { status: 'done'; result: VirustotalResult; error: null }
  | { status: 'error'; result: VirustotalResult | null; error: string }

const errorText = (error: unknown): string =>
  error instanceof ApiError ? error.detail : error instanceof Error ? error.message : String(error)

const sha256File = async (file: File): Promise<string> => {
  if (!globalThis.crypto?.subtle) {
    throw new Error('This browser does not support local SHA-256 calculation.')
  }
  if (file.size > MAX_FILE_BYTES) {
    throw new Error('VirusTotal file submissions are limited to 32 MiB.')
  }
  const buffer =
    typeof file.arrayBuffer === 'function'
      ? await file.arrayBuffer()
      : await new Promise<ArrayBuffer>((resolve, reject) => {
          const reader = new FileReader()
          reader.onload = () => {
            if (reader.result instanceof ArrayBuffer) resolve(reader.result)
            else reject(new Error('Could not read the selected file.'))
          }
          reader.onerror = () => reject(reader.error ?? new Error('Could not read the selected file.'))
          reader.readAsArrayBuffer(file)
        })
  const digest = await crypto.subtle.digest('SHA-256', buffer)
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export default function CombinedScanReport({
  submission,
  detail,
  configured,
  onScanUpdated,
  onFocusFindings,
}: {
  submission: Extract<ScanSubmission, { kind: 'website' | 'file' }>
  detail: ScanDetailData | null
  configured: boolean
  onScanUpdated: () => void
  onFocusFindings: () => void
}) {
  const [virusTotal, setVirusTotal] = useState<VirusTotalState>({
    status: 'checking',
    result: null,
    error: null,
  })

  useEffect(() => {
    let cancelled = false
    const setCurrent = (state: VirusTotalState) => {
      if (!cancelled) setVirusTotal(state)
    }

    const poll = async (analysisId: string, initial: VirustotalResult) => {
      let result = initial
      for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt += 1) {
        if (cancelled) return
        if (result.status === 'completed' || result.status === 'failed') {
          setCurrent({ status: 'done', result, error: null })
          return
        }
        setCurrent({ status: 'pending', result, error: null })
        await new Promise((resolve) => window.setTimeout(resolve, POLL_DELAY_MS))
        if (cancelled) return
        result = await api.virustotalAnalysis(analysisId)
      }
      setCurrent({
        status: 'error',
        result,
        error: 'VirusTotal analysis is still pending. Open the report or try again later.',
      })
    }

    const run = async () => {
      if (!configured || (submission.kind === 'website' && !submission.includeVirusTotal)) {
        setCurrent({
          status: 'error',
          result: null,
          error: 'VirusTotal is not enabled for this scan.',
        })
        return
      }
      try {
        let result: VirustotalResult
        if (submission.kind === 'website') {
          result = await api.virustotalReport(submission.targetUrl)
          if (cancelled) return
          if (result.status === 'not_found') {
            setCurrent({ status: 'submitting', result, error: null })
            result = await api.virustotalScan(submission.targetUrl)
          }
        } else {
          const sha256 = await sha256File(submission.file)
          if (cancelled) return
          result = await api.virustotalFileReport(sha256)
          if (cancelled) return
          if (result.status === 'not_found') {
            setCurrent({ status: 'submitting', result, error: null })
            result = await api.virustotalFileScan(submission.file)
          }
        }
        if (cancelled) return
        if (result.analysis_id && result.status !== 'completed' && result.status !== 'failed') {
          await poll(result.analysis_id, result)
        } else {
          setCurrent({ status: 'done', result, error: null })
        }
      } catch (error: unknown) {
        setCurrent({ status: 'error', result: null, error: errorText(error) })
      }
    }

    void run()
    return () => {
      cancelled = true
    }
  }, [configured, submission])

  const downloadCombinedReport = () => {
    const report = {
      report_type: 'vibeshield_virustotal_combined',
      generated_at: new Date().toISOString(),
      target:
        submission.kind === 'website'
          ? { type: 'website', url: submission.targetUrl }
          : {
              type: 'file',
              filename: submission.file.name,
              size_bytes: submission.file.size,
              sha256: result?.sha256 ?? null,
            },
      sources: {
        vibeshield:
          submission.kind === 'website'
            ? {
                scan: detail?.scan ?? null,
                stages: detail?.stages ?? [],
                findings: detail?.findings ?? [],
              }
            : {
                status: 'not_scanned',
                note: 'VibeShield binary/APK scanning is not currently supported.',
              },
        virustotal: result ?? {
          status: virusTotal.status,
          error: virusTotal.status === 'error' ? virusTotal.error : null,
        },
      },
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const downloadUrl = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = downloadUrl
    anchor.download = 'vibeshield-combined-report.json'
    anchor.click()
    URL.revokeObjectURL(downloadUrl)
  }

  const result = virusTotal.result
  const categoryLabel: Record<string, string> = {
    malicious: 'Malicious',
    suspicious: 'Suspicious',
    harmless: 'Harmless',
    undetected: 'Undetected',
    timeout: 'Timed out',
    'confirmed-timeout': 'Timed out',
    failure: 'Failed',
    'type-unsupported': 'Unsupported',
  }

  return (
    <div className="space-y-6" data-testid="combined-scan-report">
      <Panel title="Combined scan report" testId="combined-report-summary">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <p className="max-w-3xl text-xs text-zinc-400 leading-relaxed">
            VibeShield and VirusTotal results are shown together for this target, with their sources
            identified separately. VirusTotal findings are third-party intelligence and do not
            change VibeShield&apos;s scan findings or risk score.
          </p>
          <button
            type="button"
            onClick={downloadCombinedReport}
            className="vin-btn-ghost px-3 py-1.5 text-xs font-medium"
          >
            <Download className="h-3.5 w-3.5" aria-hidden />
            Download combined JSON
          </button>
        </div>

        <div className="mt-4 grid gap-4 md:grid-cols-2">
          {/* VibeShield Card */}
          <div className="vin-panel-soft p-4">
            <div className="flex items-center gap-2 mb-2">
              <Shield className="h-4 w-4 text-sky-400" aria-hidden />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
                VibeShield
              </h3>
            </div>
            {submission.kind === 'file' ? (
              <p className="text-xs text-zinc-400 leading-relaxed">
                VibeShield&apos;s scanner does not currently inspect APK/binary files. This target
                has VirusTotal results only.
              </p>
            ) : detail ? (
              <div className="space-y-1.5">
                <p className="text-sm font-semibold text-zinc-200 capitalize">
                  {detail.scan.status} &middot; {detail.findings.length} findings
                </p>
                <p className="break-all font-mono text-xs text-zinc-400">
                  Target: {submission.targetUrl}
                </p>
                <button
                  type="button"
                  onClick={onFocusFindings}
                  className="mt-2 text-xs text-sky-400 hover:text-sky-300 font-medium hover:underline inline-block"
                >
                  Open VibeShield findings and report &rarr;
                </button>
              </div>
            ) : (
              <LoadingState label="VibeShield scan started; loading its results…" />
            )}
          </div>

          {/* VirusTotal Card */}
          <div className="vin-panel-soft p-4">
            <div className="flex items-center gap-2 mb-2">
              <ShieldAlert className="h-4 w-4 text-violet-400" aria-hidden />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-violet-300">
                VirusTotal Threat Intelligence
              </h3>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed">
              {submission.kind === 'website'
                ? 'Public URL report checked; a new analysis is automatically requested if no report exists.'
                : 'File hash checked first; if no report exists, the consented file is uploaded for analysis.'}
            </p>
            {configured ? (
              <p className="mt-2.5 text-xs font-medium text-zinc-300" data-testid="combined-vt-status">
                {virusTotal.status === 'checking'
                  ? submission.kind === 'website'
                    ? 'Checking the existing VirusTotal URL report…'
                    : 'Calculating file hash and checking VirusTotal…'
                  : virusTotal.status === 'submitting'
                    ? 'No existing report; automatically requesting a new VirusTotal analysis…'
                    : virusTotal.status === 'pending'
                      ? 'VirusTotal analysis is in progress…'
                      : virusTotal.status === 'error'
                        ? `VirusTotal check failed: ${virusTotal.error}`
                        : result?.status === 'not_found'
                          ? 'No VirusTotal report was found.'
                          : 'VirusTotal report is ready.'}
              </p>
            ) : (
              <p className="mt-2.5 text-xs text-amber-300">
                VirusTotal is not configured on this backend. VibeShield results are unaffected.
              </p>
            )}
            {virusTotal.status === 'error' && (
              <p role="alert" className="mt-2 text-xs text-red-300">{virusTotal.error}</p>
            )}
          </div>
        </div>
      </Panel>

      {submission.kind === 'website' && (
        <ScanDetail
          detail={detail}
          onScanUpdated={onScanUpdated}
          onFocusFindings={onFocusFindings}
        />
      )}

      <Panel title="VirusTotal detailed findings" testId="combined-vt-details">
        {result?.stats ? (
          <>
            <dl className="mb-4 grid grid-cols-2 gap-2 text-xs sm:grid-cols-5">
              {[
                ['Malicious', result.stats.malicious],
                ['Suspicious', result.stats.suspicious],
                ['Harmless', result.stats.harmless],
                ['Undetected', result.stats.undetected],
                ['Engines reporting', result.engines_reporting],
              ].map(([label, count]) => (
                <div key={String(label)} className="vin-tile p-2.5 flex justify-between gap-2">
                  <dt className="text-zinc-400">{label}</dt>
                  <dd className="font-semibold text-zinc-200 font-mono">{count ?? 'Unknown'}</dd>
                </div>
              ))}
            </dl>
            {result.last_analysis_date && (
              <p className="mb-3 text-xs text-zinc-500">
                Last analysis: {new Date(result.last_analysis_date).toLocaleString()}
              </p>
            )}
          </>
        ) : null}

        {virusTotal.status === 'checking' || virusTotal.status === 'submitting' || virusTotal.status === 'pending' ? (
          <div className="py-2">
            <LoadingState
              label={
                virusTotal.status === 'checking'
                  ? 'Retrieving VirusTotal engine details…'
                  : virusTotal.status === 'submitting'
                    ? 'Submitting the consented target to VirusTotal…'
                    : 'Waiting for VirusTotal engines…'
              }
            />
          </div>
        ) : result?.engine_results?.length ? (
          <div className="max-h-96 overflow-auto rounded-lg border border-zinc-800/60 bg-zinc-900/30">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-zinc-900 text-zinc-400 border-b border-zinc-800 font-semibold uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-3">Engine</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Detection / result</th>
                  <th className="py-2.5 px-3">Method</th>
                  <th className="py-2.5 px-3">Updated</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/40">
                {result.engine_results.map((engine) => (
                  <tr key={engine.engine} className="transition-colors hover:bg-zinc-800/40">
                    <td className="py-2 px-3 font-semibold text-zinc-200">{engine.engine}</td>
                    <td className="py-2 px-3 text-zinc-300">
                      <span
                        className={`inline-block rounded px-2 py-0.5 text-[10px] uppercase font-semibold font-mono ${
                          engine.category === 'malicious'
                            ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                            : engine.category === 'suspicious'
                              ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                              : 'bg-zinc-800 text-zinc-400'
                        }`}
                      >
                        {categoryLabel[engine.category] ?? engine.category}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono text-zinc-300">{engine.result ?? '—'}</td>
                    <td className="py-2 px-3 text-zinc-500 font-mono text-[11px]">{engine.method ?? '—'}</td>
                    <td className="py-2 px-3 text-zinc-500 font-mono text-[11px]">{engine.engine_update ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : virusTotal.status === 'done' ? (
          <p className="text-sm text-zinc-400 py-2">
            {result?.status === 'not_found'
              ? 'No report or engine findings are available yet.'
              : 'No per-engine details were returned by VirusTotal for this response.'}
          </p>
        ) : configured ? (
          <p className="text-sm text-zinc-400 py-2">Waiting for VirusTotal results.</p>
        ) : (
          <p className="text-sm text-zinc-400 py-2">Configure VirusTotal to include its report.</p>
        )}

        {result?.report_url && (
          <a
            href={result.report_url}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-3 inline-flex items-center gap-1.5 text-xs text-sky-400 hover:text-sky-300 font-medium hover:underline"
          >
            <ExternalLink className="h-3.5 w-3.5" aria-hidden /> Open full VirusTotal report
          </a>
        )}
        <p className="mt-3 text-xs text-zinc-500">
          VirusTotal results are not VibeShield findings. Detections are engine opinions; absence
          of detections does not establish that a target is safe.
        </p>
      </Panel>
    </div>
  )
}
