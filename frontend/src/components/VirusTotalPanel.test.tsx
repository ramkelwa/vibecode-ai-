import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { VirustotalResult } from '../api'
import VirusTotalPanel from './VirusTotalPanel'

const vtOk: VirustotalResult = {
  source: 'virustotal',
  status: 'queued',
  analysis_id: 'abc123',
  url: 'https://example.com/',
  last_analysis_date: null,
  stats: null,
  engines_reporting: null,
  report_url: 'https://www.virustotal.com/gui/url/abc123',
  message: 'URL submitted successfully for analysis.',
}

const vtCompleted: VirustotalResult = {
  source: 'virustotal',
  status: 'completed',
  analysis_id: 'abc123',
  url: 'https://example.com/',
  last_analysis_date: '2024-01-01T00:00:00.000Z',
  stats: {
    malicious: 2,
    suspicious: 1,
    harmless: 80,
    undetected: 60,
    timeout: 0,
  },
  engines_reporting: 143,
  report_url: 'https://www.virustotal.com/gui/url/abc123',
  message: null,
}

const vtNoReport: VirustotalResult = {
  source: 'virustotal',
  status: 'not_found',
  analysis_id: null,
  url: 'https://example.org/',
  last_analysis_date: null,
  stats: null,
  engines_reporting: null,
  report_url: null,
  message: 'VirusTotal has no existing report for this URL. Submit a new scan to request one.',
}

beforeEach(() => {
  vi.unstubAllGlobals()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function stubFetch(body: unknown, status = 200): void {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  ))
}

describe('VirusTotalPanel', () => {
  it('renders the section header and disambiguation note', () => {
    render(<VirusTotalPanel configured={true} />)
    expect(screen.getByText('VirusTotal Threat Intelligence')).toBeInTheDocument()
    expect(
      screen.getByText(
        /Third-party data from VirusTotal|VibeShield's own security checks|Zero detections/i,
      ),
    ).toBeInTheDocument()
  })

  it('renders an accessible URL input and two action buttons', () => {
    render(<VirusTotalPanel configured={true} />)
    expect(
      screen.getByRole('textbox', { name: /URL to check/i }),
    ).toHaveValue('')
    expect(
      screen.getByRole('button', { name: /Check with VirusTotal/i }),
    ).toBeEnabled()
    expect(
      screen.getByRole('button', { name: /Submit new scan/i }),
    ).toBeEnabled()
  })

  it('disables both buttons and shows a note when not configured', () => {
    const { container } = render(<VirusTotalPanel configured={false} />)
    expect(container.innerHTML).toContain('not configured on this server')
    expect(screen.getByRole('button', { name: /Check with VirusTotal/i })).toBeDisabled()
    expect(screen.getByRole('button', { name: /Submit new scan/i })).toBeDisabled()
  })

  it('validates the URL locally and shows an error for invalid input on lookup', async () => {
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'not-a-url' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Check with VirusTotal/i }))
    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('Enter a valid')
    })
  })

  it('performs a read-only lookup and shows a no-existing-report state', async () => {
    stubFetch(vtNoReport)
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://example.org/' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Check with VirusTotal/i }))
    await waitFor(() => {
      expect(screen.getByText('No existing report')).toBeInTheDocument()
    })
  })

  it('automatically checks the requested URL report after the opted-in new scan', async () => {
    stubFetch(vtCompleted)
    render(
      <VirusTotalPanel
        configured
        initialUrl="https://example.com/"
        autoLookup
        autoLookupKey="scan-123"
      />,
    )
    await waitFor(() => {
      expect(screen.getByTestId('vt-result')).toBeInTheDocument()
    })
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/virustotal/report?url=https%3A%2F%2Fexample.com%2F'),
      expect.any(Object),
    )
  })

  it('does not require consent to check an existing report', async () => {
    stubFetch(vtNoReport)
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://example.org/' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Check with VirusTotal/i }))
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })
  })

  it('requires privacy confirmation before submitting a new scan', () => {
    stubFetch(vtOk)
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://example.com/' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Submit new scan/i }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /I understand, submit/i }),
    ).toBeInTheDocument()
  })

  it('only submits after explicit consent is given', async () => {
    let calls: any[] = []
    const fetchStub = vi.fn(async (input) => {
      calls.push(input)
      return new Response(JSON.stringify(vtOk), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetchStub)
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://example.com/' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Submit new scan/i }))
    expect(calls.length).toBe(0) // no POST before consent
    await act(() => {
      fireEvent.click(screen.getByRole('button', { name: /I understand, submit/i }))
    })
    expect(
      screen.getByText(/Analysis pending — polling/i),
    ).toBeInTheDocument()
  })

  it('polls analysis status and displays completed statistics', async () => {
    let calls: any[] = []
    const fetchStub = vi.fn(async (url: string) => {
      calls.push(url)
      if (calls.length === 1) {
        return new Response(JSON.stringify(vtCompleted), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (calls.length === 2) {
        return new Response(JSON.stringify(vtOk), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (calls.length === 1) {
        return new Response(JSON.stringify(vtOk), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return new Response(JSON.stringify(vtCompleted), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetchStub)
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://example.com/' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Submit new scan/i }))
    await act(() => {
      fireEvent.click(screen.getByRole('button', { name: /I understand, submit/i }))
    })
    await waitFor(() => {
      expect(screen.getByText(/Analysis completed/)).toBeInTheDocument()
    })
    expect(screen.getByText('Potentially malicious detections reported')).toBeInTheDocument()
    expect(screen.getByTestId('vt-stat-malicious')).toHaveTextContent('2')
    expect(screen.getByTestId('vt-stat-suspicious')).toHaveTextContent('1')
    expect(screen.getByTestId('vt-stat-harmless')).toHaveTextContent('80')
    expect(screen.getByTestId('vt-stat-undetected')).toHaveTextContent('60')
    expect(screen.getByTestId('vt-stat-engine-timeouts')).toHaveTextContent('0')
    expect(screen.getByTestId('vt-stat-engines-reporting')).toHaveTextContent('143')
  })

  it('shows "unknown" for missing statistics rather than fabricated zeros', async () => {
    const calls: any[] = []
    const fetchStub = vi.fn(async (url: string) => {
      calls.push(url)
      if (url.includes('/virustotal/report')) {
        return new Response(
          JSON.stringify({
            ...vtCompleted,
            stats: {
              malicious: 0,
              suspicious: 0,
              harmless: null,
              undetected: null,
              timeout: null,
            },
            engines_reporting: null,
            report_url: 'https://www.virustotal.com/gui/url/abc123',
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        )
      }
      return new Response('not expected', { status: 500 })
    })
    vi.stubGlobal('fetch', fetchStub)
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://example.com/' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Check with VirusTotal/i }))
    await waitFor(() => {
      expect(screen.getByText('No detections reported by the available engines.')).toBeInTheDocument()
    })
    expect(screen.getByTestId('vt-stat-harmless')).toHaveTextContent('unknown')
    expect(screen.getByTestId('vt-stat-undetected')).toHaveTextContent('unknown')
  })

  it('does not display a stale completed result for a different URL after a new check', async () => {
    let calls: any[] = []
    const fetchStub = vi.fn(async (url: string) => {
      calls.push(url)
      return new Response(JSON.stringify(vtCompleted), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetchStub)
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://first.example/' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Check with VirusTotal/i }))
    await waitFor(() => {
      expect(screen.getByTestId('vt-stat-malicious')).toHaveTextContent('2')
    })
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://second.example/' },
    })
    expect(screen.queryByTestId('vt-stat-malicious')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Check with VirusTotal/i }))
    await waitFor(() => {
      expect(screen.getByTestId('vt-stat-malicious')).toHaveTextContent('2')
    })
    expect(calls).toHaveLength(2)
    expect(calls[1]).toContain('second.example')
  })

  it('shows a retry action when a rate-limit error occurs', async () => {
    let callCount = 0
    const fetchStub = vi.fn(async () => {
      callCount += 1
      if (callCount === 1) {
        return new Response(
          JSON.stringify({ detail: 'VirusTotal rate limit reached. Please wait.' }),
          {
            status: 429,
            headers: { 'Content-Type': 'application/json' },
          },
        )
      }
      return new Response(JSON.stringify(vtCompleted), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetchStub)
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://example.com/' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Check with VirusTotal/i }))
    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('rate limit')
    })
    fireEvent.click(screen.getByRole('button', { name: /Retry/i }))
    await waitFor(() => {
      expect(screen.getByText(/Analysis completed/)).toBeInTheDocument()
    })
  })

  it('shows a friendly error and retry for a network failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network offline')))
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://example.com/' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Check with VirusTotal/i }))
    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent('network')
    })
    expect(screen.getByRole('button', { name: /Retry/i })).toBeInTheDocument()
  })

  it('clears previous results when a new URL is entered before submitting', async () => {
    let calls: any[] = []
    const fetchStub = vi.fn(async (url: string) => {
      calls.push(url)
      return new Response(JSON.stringify(vtCompleted), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })
    vi.stubGlobal('fetch', fetchStub)
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://first.example/' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Check with VirusTotal/i }))
    await waitFor(() => {
      expect(screen.getByTestId('vt-stat-malicious')).toHaveTextContent('2')
    })
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://second.example/' },
    })
    expect(screen.queryByTestId('vt-stat-malicious')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Check with VirusTotal/i }))
    await waitFor(() => {
      expect(screen.getByTestId('vt-stat-malicious')).toHaveTextContent('2')
    })
    expect(calls).toHaveLength(2)
    expect(calls[1]).toContain('second.example')
  })

  it('does not display a stale completed result for a different URL on submit', async () => {
    let calls: any[] = []
    const fetchStub = vi.fn(async (url: string) => {
      calls.push(url)
      if (calls.length === 1) {
        return new Response(JSON.stringify(vtCompleted), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (url.includes('/virustotal/scan')) {
        return new Response(JSON.stringify(vtOk), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return new Promise(() => {})
    })
    vi.stubGlobal('fetch', fetchStub)
    render(<VirusTotalPanel configured={true} />)
    fireEvent.change(screen.getByRole('textbox', { name: /URL to check/i }), {
      target: { value: 'https://first.example/' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Check with VirusTotal/i }))
    await waitFor(() => {
      expect(screen.getByText(/Analysis completed/)).toBeInTheDocument()
      expect(screen.getByTestId('vt-stat-malicious')).toHaveTextContent('2')
    })
    fireEvent.click(screen.getByRole('button', { name: /Submit new scan/i }))
    await act(() => {
      fireEvent.click(screen.getByRole('button', { name: /I understand, submit/i }))
    })
    await waitFor(() => {
      expect(screen.getByRole('status', { name: 'Analysis pending' })).toBeInTheDocument()
    })
    expect(calls[0]).toContain('/api/virustotal/report')
    expect(calls[1]).toContain('/api/virustotal/scan')
    expect(screen.queryByTestId('vt-stat-malicious')).not.toBeInTheDocument()
  })
})
