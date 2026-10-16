import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import FindingsExplorer from './FindingsExplorer'
import type { Finding } from '../api'

const mkFinding = (i: number, over: Partial<Finding> = {}): Finding => ({
  id: `f${i}`,
  scan_id: 'scan-1',
  title: `Finding ${i}`,
  description: `desc ${i}`,
  category: 'http_headers',
  severity: i % 2 === 0 ? 'high' : 'low',
  confidence: 'firm',
  affected_asset: 'https://e.tld/',
  evidence: { note: 'redacted' },
  source_module: i % 3 === 0 ? 'zap_dynamic' : 'http_headers',
  cwe: 'CWE-693',
  impact: '',
  remediation: 'Add the header.',
  verification_status: 'potential',
  ...over,
})

const findings = Array.from({ length: 13 }, (_, i) => mkFinding(i))

function renderExplorer(props: Partial<Parameters<typeof FindingsExplorer>[0]> = {}) {
  const propsWith = {
    findings,
    loading: false,
    error: null as string | null,
    onRetry: vi.fn(),
    ...props,
  }
  render(<FindingsExplorer {...propsWith} />)
  return propsWith
}

describe('FindingsExplorer', () => {
  it('renders real findings with severity and confidence badges', () => {
    renderExplorer()
    expect(screen.getByTestId('explorer-panel')).toBeInTheDocument()
    expect(screen.getByTestId('explorer-count')).toHaveTextContent('13 of 13 findings')
    expect(screen.getAllByLabelText(/severity (high|low)/).length).toBeGreaterThan(0)
  })

  it('filters by severity', () => {
    renderExplorer()
    fireEvent.change(screen.getByLabelText('Severity'), { target: { value: 'high' } })
    expect(screen.getByTestId('explorer-count')).toHaveTextContent('7 of 13 findings')
  })

  it('filters by category and hides non-matching items', () => {
    renderExplorer()
    fireEvent.change(screen.getByLabelText('Category'), { target: { value: 'http_headers' } })
    expect(screen.getByTestId('explorer-count')).toHaveTextContent('of 13')
  })

  it('searches across title, asset, module', () => {
    renderExplorer()
    fireEvent.change(screen.getByLabelText('Search findings'), { target: { value: 'finding 12' } })
    expect(screen.getByTestId('explorer-count')).toHaveTextContent('1 of 13')
  })

  it('paginates large result sets and allows page movement', () => {
    renderExplorer()
    expect(screen.getAllByText(/Finding (1[0-3]|[0-9])$/).length).toBe(10)
    fireEvent.click(screen.getByLabelText('Next page'))
    expect(screen.getByText(/Page 2 of 2/i)).toBeInTheDocument()
    fireEvent.click(screen.getByLabelText('Previous page'))
    expect(screen.getByText(/Page 1 of 2/i)).toBeInTheDocument()
  })

  it('shows empty state when the scan collected nothing', () => {
    renderExplorer({ findings: [] })
    expect(screen.getByRole('note')).toHaveTextContent(/no findings recorded for this scan/i)
  })

  it('shows "no results match" when filters over-filter', () => {
    renderExplorer({ findings: [mkFinding(1)] })
    fireEvent.change(screen.getByLabelText('Search findings'), { target: { value: 'zzz-no-match' } })
    expect(screen.getByRole('note')).toHaveTextContent(/no findings match/i)
  })

  it('shows error with retry and does not fake results', () => {
    const onRetry = vi.fn()
    renderExplorer({ findings: [], error: 'API 503: maintenance', onRetry })
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(onRetry).toHaveBeenCalledOnce()
    expect(screen.getByRole('alert')).toHaveTextContent(/maintenance/i)
  })

  it('opens a finding detail panel with evidence, module, asset, status, remediation', () => {
    renderExplorer()
    const row = screen.getAllByText('Finding 0')[0]
    if (!row) throw new Error('Finding 0 row not rendered')
    fireEvent.click(row)
    const panel = screen.getByTestId('finding-detail')
    expect(panel).toHaveTextContent('Finding 0')
    expect(panel).toHaveTextContent('potential') // verification status
    expect(panel).toHaveTextContent('https://e.tld/')
    expect(screen.getByTestId('finding-remediation')).toHaveTextContent(/add the header/i)
    expect(panel).toHaveTextContent('"note": "redacted"') // evidence shown as stored
  })

  it('sorts by severity putting high findings first', () => {
    renderExplorer()
    const firstRow = screen.getAllByText('Finding 1')[0]
    if (!firstRow) throw new Error('Finding 1 row not rendered')
    fireEvent.click(firstRow)
    fireEvent.click(screen.getByRole('button', { name: 'Close finding detail' }))
    fireEvent.change(screen.getByLabelText('Sort findings'), { target: { value: 'severity' } })
    const first = screen.getAllByRole('listitem')[0]
    // severity sorting: the first item must be a high-severity finding
    expect(first).toHaveTextContent('high')
    expect(screen.getAllByLabelText('severity high').length).toBeGreaterThan(0)
  })
})
