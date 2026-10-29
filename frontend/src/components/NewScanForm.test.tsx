import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import NewScanForm, { isValidTargetUrl } from './NewScanForm'
import type { ScanSummary } from '../api'

const scan: ScanSummary = {
  id: 'abc123def456',
  target_url: 'https://target.example.com',
  status: 'pending',
  modules_requested: ['http_headers'],
  error: null,
  created_at: new Date().toISOString(),
  started_at: null,
  finished_at: null,
}

beforeEach(() => vi.stubGlobal('fetch', vi.fn()))
afterEach(() => vi.unstubAllGlobals())

describe('isValidTargetUrl', () => {
  it('accepts only http(s) URLs with a hostname', () => {
    expect(isValidTargetUrl('https://target.example.com')).toBe(true)
    expect(isValidTargetUrl('http://localhost:8000/x')).toBe(true)
    expect(isValidTargetUrl('ftp://host')).toBe(false)
    expect(isValidTargetUrl('target.example.com')).toBe(false)
    expect(isValidTargetUrl('https://')).toBe(false)
  })
})

describe('NewScanForm', () => {
  it('blocks submission with a validation hint for an invalid URL', async () => {
    render(<NewScanForm allowedToScan onError={() => undefined} onSubmitted={() => undefined} />)
    await userEvent.type(await screen.findByLabelText(/Target URL/i), 'not-a-url')
    await userEvent.click(screen.getByRole('button', { name: /Start scan/i }))
    expect(await screen.findByTestId('validation-hint')).toHaveTextContent(/valid http/i)
    expect(fetch).not.toHaveBeenCalled()
  })

  it('submits to the real API and displays the returned scan id', async () => {
    stubFetchCreate(scan)
    render(<NewScanForm allowedToScan onError={() => undefined} onSubmitted={() => undefined} />)
    await userEvent.type(await screen.findByLabelText(/Target URL/i), 'https://target.example.com')
    await userEvent.click(screen.getByRole('button', { name: /Start scan/i }))
    expect(await screen.findByTestId('submitted-scan-id')).toHaveTextContent('abc123def456')
  })

  it('asks before checking a website URL with VirusTotal and allows VibeShield-only scans', async () => {
    stubFetchCreate(scan)
    const onSubmitted = vi.fn()
    render(
      <NewScanForm
        allowedToScan
        virustotalConfigured
        onError={() => undefined}
        onSubmitted={onSubmitted}
      />,
    )
    await userEvent.type(await screen.findByLabelText(/Target URL/i), 'https://target.example.com')
    await userEvent.click(screen.getByRole('button', { name: /Start scan/i }))
    expect(await screen.findByTestId('vt-url-consent')).toBeInTheDocument()
    expect(screen.getByText(/complete URL, including query parameters/i)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /VibeShield only/i }))
    await screen.findByTestId('submitted-scan-id')
    expect(onSubmitted).toHaveBeenCalledWith(scan, 'website', false)
  })

  it('starts the requested URL report check only after the user opts in', async () => {
    stubFetchCreate(scan)
    const onSubmitted = vi.fn()
    render(
      <NewScanForm
        allowedToScan
        virustotalConfigured
        onError={() => undefined}
        onSubmitted={onSubmitted}
      />,
    )
    await userEvent.type(await screen.findByLabelText(/Target URL/i), 'https://target.example.com')
    await userEvent.click(screen.getByRole('button', { name: /Start scan/i }))
    await userEvent.click(
      await screen.findByRole('button', { name: /Start VibeShield \+ VirusTotal check/i }),
    )
    await screen.findByTestId('submitted-scan-id')
    expect(onSubmitted).toHaveBeenCalledWith(scan, 'website', true)
  })

  it('prevents duplicate submissions while a request is pending', async () => {
    let resolve!: (r: Response) => void
    const fetchMock = vi.fn().mockImplementation(
      () => new Promise<Response>((r) => { resolve = r }),
    )
    vi.stubGlobal('fetch', fetchMock)
    render(<NewScanForm allowedToScan onError={() => undefined} onSubmitted={() => undefined} />)
    await userEvent.type(await screen.findByLabelText(/Target URL/i), 'https://target.example.com')
    await userEvent.click(screen.getByRole('button', { name: /Start scan/i }))
    const pendingButton = screen.getByRole('button', { name: /Submitting…/i })
    expect(pendingButton).toBeDisabled()
    await userEvent.click(pendingButton)
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    resolve(
      new Response(JSON.stringify({ scan }), { status: 201, headers: { 'Content-Type': 'application/json' } }),
    )
    await screen.findByTestId('submitted-scan-id')
  })

  it('shows the real API error when the backend rejects the scan', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({ detail: 'you must confirm you are authorized to test this target' }),
          { status: 400, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )
    const onErrorSpy = vi.fn()
    render(<NewScanForm allowedToScan onError={onErrorSpy} onSubmitted={() => undefined} />)
    await userEvent.type(await screen.findByLabelText(/Target URL/i), 'https://target.example.com')
    await userEvent.click(screen.getByRole('button', { name: /Start scan/i }))
    expect(await screen.findByTestId('form-error')).toHaveTextContent(/confirm you are authorized/i)
    expect(onErrorSpy).toHaveBeenCalled()
  })

  it('shows scope and authorization requirements', async () => {
    render(<NewScanForm allowedToScan onError={() => undefined} onSubmitted={() => undefined} />)
    expect(await screen.findByTestId('scope-notice')).toHaveTextContent(/authorized/i)
  })

  it('disables the form when the backend database is down', async () => {
    render(<NewScanForm allowedToScan={false} onError={() => undefined} onSubmitted={() => undefined} />)
    expect(await screen.findByRole('button', { name: /Start scan/i })).toBeDisabled()
    expect(await screen.findByRole('note')).toHaveTextContent(/new scans are disabled/i)
  })

  it('shows the project scope notice in project mode', async () => {
    render(<NewScanForm allowedToScan onError={() => undefined} onSubmitted={() => undefined} />)
    await userEvent.click(await screen.findByRole('tab', { name: /project scan/i }))
    expect(await screen.findByTestId('scope-notice-project')).toHaveTextContent(/AUTHORIZED_PROJECT_ROOTS/i)
  })
})

// Helper: single stubbed fetch response for POST /api/scans.
function stubFetchCreate(body: unknown) {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ scan: body }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  )
}
