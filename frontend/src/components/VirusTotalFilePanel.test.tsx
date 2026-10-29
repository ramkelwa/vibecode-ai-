import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom/vitest'
import { afterEach, describe, expect, it, vi } from 'vitest'
import VirusTotalFilePanel from './VirusTotalFilePanel'

const notFound = {
  source: 'virustotal',
  status: 'not_found',
  object_type: 'file',
  analysis_id: null,
  url: null,
  sha256: 'a'.repeat(64),
  last_analysis_date: null,
  stats: null,
  engines_reporting: null,
  report_url: `https://www.virustotal.com/gui/file/${'a'.repeat(64)}`,
  message: 'No existing report',
}

afterEach(() => vi.unstubAllGlobals())

describe('VirusTotalFilePanel', () => {
  it('checks only the local file hash and asks before uploading the file', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(notFound), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('crypto', {
      subtle: { digest: vi.fn().mockResolvedValue(new Uint8Array(32).fill(170).buffer) },
    })
    render(<VirusTotalFilePanel configured />)
    fireEvent.change(screen.getByLabelText(/Choose a file or APK/i), {
      target: { files: [new File(['apk contents'], 'sample.apk')] },
    })
    await screen.findByTestId('vt-file-not-found')
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0]?.[0]).toContain('/file-report/')
    expect(fetchMock.mock.calls[0]?.[0]).not.toContain('sample.apk')

    fireEvent.click(screen.getByRole('button', { name: /Submit file to VirusTotal/i }))
    expect(screen.getByRole('dialog', { name: /Confirm file upload/i })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: /Cancel/i }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('uploads only after explicit confirmation and renders the report link', async () => {
    const completed = {
      ...notFound,
      status: 'completed',
      stats: { malicious: 0, suspicious: 0, harmless: 12, undetected: 5, timeout: 0 },
      analysis_id: null,
    }
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
    vi.stubGlobal('crypto', {
      subtle: { digest: vi.fn().mockResolvedValue(new Uint8Array(32).fill(170).buffer) },
    })
    render(<VirusTotalFilePanel configured />)
    fireEvent.change(screen.getByLabelText(/Choose a file or APK/i), {
      target: { files: [new File(['apk contents'], 'sample.apk')] },
    })
    await screen.findByTestId('vt-file-not-found')
    fireEvent.click(screen.getByRole('button', { name: /Submit file to VirusTotal/i }))
    expect(fetchMock).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: /I understand, upload file/i }))
    await waitFor(() => expect(screen.getByTestId('vt-file-result')).toBeInTheDocument())
    expect(fetchMock).toHaveBeenCalledTimes(2)
    const options = fetchMock.mock.calls[1]?.[1]
    expect(options?.method).toBe('POST')
    expect(options?.body).toBeInstanceOf(FormData)
  })
})
