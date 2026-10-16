import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import ScanHistory from './ScanHistory'
import type { ScanSummary } from '../api'

const scan: ScanSummary = {
  id: 'abc123',
  target_url: 'https://target.tld',
  status: 'completed',
  modules_requested: ['http_headers'],
  error: null,
  created_at: new Date().toISOString(),
  started_at: null,
  finished_at: null,
}

describe('ScanHistory', () => {
  it('shows a loading state while data is being fetched', () => {
    render(<ScanHistory scans={[]} loading error={null} onRetry={vi.fn()} onOpen={vi.fn()} />)
    expect(screen.getByRole('status')).toHaveTextContent(/loading scan history/i)
  })

  it('shows an error state with retry, without faking data', () => {
    const onRetry = vi.fn()
    render(<ScanHistory scans={[]} loading={false} error="API 500: nope" onRetry={onRetry} onOpen={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(onRetry).toHaveBeenCalledOnce()
    expect(screen.getByRole('alert')).toHaveTextContent('API 500: nope')
  })

  it('shows an empty state with honest guidance', () => {
    render(<ScanHistory scans={[]} loading={false} error={null} onRetry={vi.fn()} onOpen={vi.fn()} />)
    expect(screen.getByRole('note')).toHaveTextContent(/no scans recorded yet/i)
  })

  it('renders real scans and opens the selected one', () => {
    const onOpen = vi.fn()
    render(<ScanHistory scans={[scan]} loading={false} error={null} onRetry={vi.fn()} onOpen={onOpen} />)
    fireEvent.click(screen.getByText('https://target.tld'))
    expect(onOpen).toHaveBeenCalledWith('abc123')
  })
})
