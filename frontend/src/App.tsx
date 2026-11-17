import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  api,
  type Artifacts,
  type CorrelationLink,
  type Finding,
  type RiskSummary,
  type ScanDetail as ScanDetailData,
  type ScanSummary,
} from './api'
import type { ScanSubmission } from './components/NewScanForm'
import Sidebar, { type ViewKey } from './components/Sidebar'
import ScanOverview, { type OverviewMetrics } from './components/ScanOverview'
import ScanHistory from './components/ScanHistory'
import NewScanForm from './components/NewScanForm'
import ScanDetail from './components/ScanDetail'
import FindingsExplorer from './components/FindingsExplorer'
import InventoryPanel from './components/InventoryPanel'
import ConfigFindings from './components/ConfigFindings'
import ReportSection from './components/ReportSection'
import CombinedScanReport from './components/CombinedScanReport'
import VirusTotalPanel from './components/VirusTotalPanel'
import VirusTotalFilePanel from './components/VirusTotalFilePanel'
import { ErrorState } from './components/ui'
import Scene3D from './components/Scene3D'
import Cursor from './components/Cursor'

const VIEW_TITLES: Record<ViewKey, string> = {
  overview: 'Overview',
  'new-scan': 'New scan',
  history: 'Scan history',
  explorer: 'Findings explorer',
  inventory: 'Endpoint & script inventory',
  config: 'Configuration & dependencies',
  virustotal: 'VirusTotal threat intelligence',
  reports: 'Report',
}

export default function App() {
  const [view, setView] = useState<ViewKey>('overview')
  const [navOpen, setNavOpen] = useState(false)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Global data — always real backend responses.
  const [health, setHealth] = useState<Awaited<ReturnType<typeof api.health>> | null>(null)
  const [healthError, setHealthError] = useState<string | null>(null)
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [scansError, setScansError] = useState<string | null>(null)
  const [scansLoading, setScansLoading] = useState(true)

  // Selected-scan data.
  const [scanId, setScanId] = useState<string | null>(null)
  const [combinedSubmission, setCombinedSubmission] = useState<
    Extract<ScanSubmission, { kind: 'website' | 'file' }> | null
  >(null)
  const [detail, setDetail] = useState<ScanDetailData | null>(null)
  const [artifacts, setArtifacts] = useState<Artifacts | null>(null)
  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null)
  const [riskSummaryError, setRiskSummaryError] = useState<string | null>(null)
  const [riskSummaryLoading, setRiskSummaryLoading] = useState(false)
  const [correlations, setCorrelations] = useState<CorrelationLink[] | null>(null)
  const [correlationsError, setCorrelationsError] = useState<string | null>(null)

  const dbUp = health?.database.state === 'ok'
  const scanFinished =
    !!scanId && !!detail && !['pending', 'running'].includes(detail.scan.status)

  const refreshScans = useCallback(() => {
    api
      .listScans()
      .then((r) => {
        setScans(r.scans)
        setScansError(null)
      })
      .catch((e: unknown) => setScansError(e instanceof Error ? e.message : String(e)))
      .finally(() => setScansLoading(false))
  }, [])

  const refreshHealth = useCallback(() => {
    api
      .health()
      .then((h) => {
        setHealth(h)
        setHealthError(null)
      })
      .catch((e: unknown) => setHealthError(e instanceof Error ? e.message : String(e)))
  }, [])

  useEffect(() => {
    refreshHealth()
    refreshScans()
  }, [refreshHealth, refreshScans])

  // Poll the selected scan's real status while it is pending/running.
  useEffect(() => {
    if (!scanId) {
      setDetail(null)
      return
    }
    const poll = () => {
      api
        .getScan(scanId)
        .then((d) => {
          setDetail(d)
          if (['completed', 'failed', 'cancelled'].includes(d.scan.status)) {
            if (pollRef.current !== null) {
              clearInterval(pollRef.current)
              pollRef.current = null
            }
            refreshScans()
          }
        })
        .catch(() => undefined) // transient API errors keep the last shown state
    }
    poll()
    pollRef.current = setInterval(poll, 1500)
    return () => {
      if (pollRef.current !== null) clearInterval(pollRef.current)
      pollRef.current = null
    }
  }, [scanId, refreshScans])

  // Artifacts + Phase 5 results once the selected scan finished.
  const loadScanExtras = useCallback(() => {
    setArtifacts(null)
    setCorrelations(null)
    setCorrelationsError(null)
    setRiskSummary(null)
    setRiskSummaryError(null)
    if (!scanFinished || !scanId) return
    setRiskSummaryLoading(true)
    let cancelled = false
    api
      .getArtifacts(scanId)
      .then((a) => {
        if (!cancelled) setArtifacts(a)
      })
      .catch(() => undefined)
    api
      .getRiskSummary(scanId)
      .then((s) => {
        if (cancelled) return
        setRiskSummary(s)
        setRiskSummaryError(null)
      })
      .catch((e: unknown) => {
        if (!cancelled) setRiskSummaryError(e instanceof Error ? e.message : String(e))
      })
      .finally(() => {
        if (!cancelled) setRiskSummaryLoading(false)
      })
    api
      .getCorrelations(scanId)
      .then((c) => {
        if (!cancelled) {
          setCorrelations(c.links)
          setCorrelationsError(null)
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) setCorrelationsError(e instanceof Error ? e.message : String(e))
      })
    return () => {
      cancelled = true
    }
  }, [scanId, scanFinished])

  useEffect(() => {
    const cleanup = loadScanExtras()
    return cleanup
  }, [loadScanExtras])

  // Findings for the explorer come strictly from the selected scan detail.
  const findings: Finding[] = detail?.findings ?? []

  // Severity distribution comes from the newest completed scan's real data.
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({})
  const newestCompleted = useMemo(
    () => scans.find((s) => s.status === 'completed') ?? null,
    [scans],
  )
  useEffect(() => {
    let cancelled = false
    if (!newestCompleted) {
      setSeverityCounts({})
      return () => {
        cancelled = true
      }
    }
    api
      .getScan(newestCompleted.id)
      .then((d) => {
        if (cancelled) return
        const by: Record<string, number> = {}
        for (const f of d.findings) by[f.severity] = (by[f.severity] ?? 0) + 1
        setSeverityCounts(by)
      })
      .catch(() => {
        if (!cancelled) setSeverityCounts({})
      })
    return () => {
      cancelled = true
    }
  }, [newestCompleted])

  const metrics: OverviewMetrics | null = useMemo(() => {
    if (scans.length === 0 && scansError) return null
    return {
      totalScans: scans.length,
      running: scans.filter((s) => s.status === 'running' || s.status === 'pending').length,
      completed: scans.filter((s) => s.status === 'completed').length,
      failedOrCancelled: scans.filter(
        (s) => s.status === 'failed' || s.status === 'cancelled',
      ).length,
      findingsTotal: detail?.findings.length ?? 0,
      bySeverity: severityCounts,
    }
  }, [scans, scansError, detail, severityCounts])

  const openScan = (id: string) => {
    setCombinedSubmission(null)
    setScanId(id)
    setView('explorer')
  }

  const retryScanDetail = () => {
    if (scanId) {
      api.getScan(scanId).then(setDetail).catch(() => undefined)
    }
  }

  const viewIndex = String(Object.keys(VIEW_TITLES).indexOf(view) + 1).padStart(2, '0')
  const ticker = [
    'Passive assessment',
    'Real backend data',
    'No simulated results',
    'Rate-limited scanning',
    'Read-only by default',
  ]

  return (
    <div className="relative min-h-screen">
      <Scene3D />
      <Cursor />
      <Sidebar
        active={view}
        onSelect={(v) => {
          setView(v)
          setNavOpen(false)
        }}
        opened={navOpen}
        onToggle={() => setNavOpen((v) => !v)}
      />
      <main className="relative z-10 mx-auto w-full max-w-[1440px] px-5 pb-24 md:px-10">
        <header className="pb-7 pt-9 md:pt-12">
          <div className="mb-7 flex flex-wrap items-start justify-between gap-x-8 gap-y-3">
            <p className="vin-kicker">{viewIndex} — Security console</p>
            <div
              className="flex flex-wrap items-center gap-x-6 gap-y-2 md:justify-end"
              data-testid="backend-status"
            >
              {health ? (
                <>
                  <span className="vin-status-chip">
                    <span
                      className={`inline-block h-1.5 w-1.5 rounded-full ${health.status === 'ok' ? 'bg-emerald-600' : 'bg-red-600'}`}
                      role="status"
                      aria-label={`API ${health.status}`}
                    />
                    API {health.status}
                  </span>
                  <span className={`vin-status-chip ${dbUp ? '' : '!text-red-700'}`}>
                    <span
                      className={`inline-block h-1.5 w-1.5 rounded-full ${dbUp ? 'bg-emerald-600' : 'bg-red-600'}`}
                      role="status"
                      aria-label={dbUp ? 'database connected' : 'database unavailable'}
                    />
                    Database {dbUp ? 'connected' : 'unavailable'}
                  </span>
                </>
              ) : (
                <span className="vin-status-chip !text-red-700">
                  {healthError ? `API unreachable: ${healthError}` : 'Checking API…'}
                </span>
              )}
            </div>
          </div>

          <h1 className="vin-title max-w-[22ch]">{VIEW_TITLES[view]}</h1>

          <div className="mt-7 flex flex-wrap items-end justify-between gap-x-8 gap-y-3 border-b border-slate-900/10 pb-5">
            <p className="max-w-md text-sm leading-relaxed text-slate-500">
              Passive web security assessment — real backend data only.
            </p>
            <p className="vin-kicker">VibeShield / AI Security</p>
          </div>
        </header>

        <div className="vin-marquee mb-9" aria-hidden="true">
          <div className="vin-marquee-track">
            {[...ticker, ...ticker].map((item, index) => (
              <span key={`${item}-${index}`}>{item}</span>
            ))}
          </div>
        </div>

        {health && !dbUp && (
          <div className="mb-4" data-testid="db-down-note">
            <ErrorState message="Database unavailable — scan persistence is disabled. Data below reflects last successful API reads; nothing is simulated." />
          </div>
        )}

        {view === 'overview' && (
          <ScanOverview
            metrics={metrics}
            latestScans={scans}
            loading={scansLoading}
            error={scansError}
            onRetry={refreshScans}
            onOpenScan={openScan}
            onSelect={setView}
          />
        )}

        {view === 'new-scan' && (
          <div className="space-y-4">
            <NewScanForm
              allowedToScan={dbUp}
              virustotalConfigured={health?.features.virustotal ?? false}
              onError={() => undefined}
              onSubmitted={(submission) => {
                if (submission.kind === 'file') {
                  setScanId(null)
                  setCombinedSubmission(submission)
                  return
                }
                setScanId(submission.scan.id)
                setCombinedSubmission(
                  submission.kind === 'website' && submission.includeVirusTotal
                    ? submission
                    : null,
                )
                refreshScans()
              }}
            />
            {combinedSubmission ? (
              <CombinedScanReport
                key={
                  combinedSubmission.kind === 'website'
                    ? combinedSubmission.scan.id
                    : `${combinedSubmission.file.name}-${combinedSubmission.file.size}-${combinedSubmission.file.lastModified}`
                }
                submission={combinedSubmission}
                detail={detail}
                configured={health?.features.virustotal ?? false}
                onScanUpdated={refreshScans}
                onFocusFindings={() => setView('explorer')}
              />
            ) : (
              <ScanDetail
                detail={detail}
                onScanUpdated={refreshScans}
                onFocusFindings={() => setView('explorer')}
              />
            )}
          </div>
        )}

        {view === 'history' && (
          <div className="space-y-4">
            <ScanHistory
              scans={scans}
              loading={scansLoading}
              error={scansError}
              onRetry={refreshScans}
              onOpen={openScan}
            />
            <ScanDetail
              detail={detail}
              onScanUpdated={refreshScans}
              onFocusFindings={() => setView('explorer')}
            />
          </div>
        )}

        {view === 'explorer' && (
          <div className="space-y-4">
            <ScanDetail
              detail={detail}
              onScanUpdated={refreshScans}
              onFocusFindings={() => setView('explorer')}
            />
            <FindingsExplorer
              findings={findings}
              loading={!detail && !!scanId}
              error={
                scanId && !detail
                  ? 'Scan data could not be loaded.'
                  : null
              }
              onRetry={retryScanDetail}
            />
          </div>
        )}

        {view === 'inventory' && (
          <div className="space-y-4">
            <ScanDetail
              detail={detail}
              onScanUpdated={refreshScans}
              onFocusFindings={() => setView('explorer')}
            />
            <InventoryPanel
              artifacts={artifacts}
              artifactsError=""
              onRetryArtifacts={() => {
                if (scanId) api.getArtifacts(scanId).then(setArtifacts).catch(() => undefined)
              }}
            />
          </div>
        )}

        {view === 'config' && <ConfigFindings artifacts={artifacts} findings={findings} />}

        {view === 'virustotal' && (
          <div className="space-y-4">
            <VirusTotalPanel configured={health?.features.virustotal ?? null} />
            <VirusTotalFilePanel configured={health?.features.virustotal ?? null} />
          </div>
        )}

        {view === 'reports' && (
          <ReportSection
            summary={riskSummary}
            summaryError={riskSummaryError}
            summaryLoading={riskSummaryLoading}
            onRetry={loadScanExtras}
            correlations={correlations}
            correlationsError={correlationsError}
          />
        )}
      </main>
    </div>
  )
}
