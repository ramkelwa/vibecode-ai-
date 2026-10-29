import { render, screen, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom/vitest'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ScanSummary, VirustotalResult } from '../api'
import type { ScanSubmission } from './NewScanForm'
import CombinedScanReport from './CombinedScanReport'

const scan: ScanSummary = {
  id: 'scan-123',
  target_url: 'https://example.com/',
  status: 'completed',
  modules_requested: ['http_headers'],
  error: null,
  created_at: '2026-10-29T00:00:00Z',
  started_at: '2026-10-29T00:00:00Z',
  finished_at: '2026-10-29T00:01:00Z',
}

const notFound: VirustotalResult = {
  source: 'virustotal',
  status: 'not_found',
  object_type: 'url',
  analysis_id: null,
  url: 'https://example.com/',
  sha256: null,
  last_analysis_date: null,
  stats: null,
  engine_results: [],
  engines_reporting: null,
  report_url: null,
  message: 'No existing report',
}

const completed: VirustotalResult = {
  ...notFound,
  status: 'completed',
  stats: { malicious: 1, suspicious: 0, harmless: 30, undetected: 12, timeout: 0 },
  engines_reporting: 43,
  engine_results: [
    {
      engine: 'Example AV',
      category: 'malicious',
      result: 'Example.Trojan',
      method: 'signature',
      engine_update: '20261029',
    },
  ],
  report_url: 'https://www.virustotal.com/gui/url/report-id',
}

const websiteSubmission: ScanSubmission = {
  kind: 'website',
  scan,
  targetUrl: scan.target_url,
  includeVirusTotal: true,
}

afterEach(() => vi.unstubAllGlobals())

describe('CombinedScanReport', () => {
  it('automatically checks, submits when absent, and shows detailed source-labeled results', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(notFound), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(completed), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    vi.stubGlobal('fetch', fetchMock)
    render(
      <CombinedScanReport
        submission={websiteSubmission}
        detail={null}
        configured
        onScanUpdated={() => undefined}
        onFocusFindings={() => undefined}
      />,
    )
    await waitFor(() => expect(screen.getByText('Example.Trojan')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls[0]?.[0]).toContain('/api/virustotal/report?')
    expect(fetchMock.mock.calls[1]?.[0]).toContain('/api/virustotal/scan')
    expect(screen.getByText('43')).toBeInTheDocument()
    expect(screen.getByText('VibeShield')).toBeInTheDocument()
    expect(screen.getByText('VirusTotal Threat Intelligence')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Download combined JSON/i })).toBeInTheDocument()
  })

  it('shows that APK reports are VirusTotal-only and automatically submits after no hash report', async () => {
    const file = new File(['apk content'], 'sample.apk')
    const fileSubmission: ScanSubmission = { kind: 'file', scan: null, file }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ...notFound, object_type: 'file' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ...completed, object_type: 'file' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      )
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('crypto', {
      subtle: { digest: vi.fn().mockResolvedValue(new Uint8Array(32).buffer) },
    })
    render(
      <CombinedScanReport
        submission={fileSubmission}
        detail={null}
        configured
        onScanUpdated={() => undefined}
        onFocusFindings={() => undefined}
      />,
    )
    await waitFor(() => expect(screen.getByText('Example.Trojan')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls[0]?.[0]).toContain('/file-report/')
    expect(fetchMock.mock.calls[1]?.[0]).toContain('/files/scan')
    expect(screen.getByText(/does not currently inspect APK\/binary files/i)).toBeInTheDocument()
  })
})
