import { afterEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from './api'

const okResponse = (body: unknown) =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })

const errResponse = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

afterEach(() => vi.unstubAllGlobals())

describe('api client', () => {
  it('parses typed success payloads', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(okResponse({ scans: [] })))
    const r = await api.listScans()
    expect(r.scans).toEqual([])
  })

  it('surfaces FastAPI validation detail as ApiError.detail', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        errResponse(400, { detail: 'you must confirm you are authorized to test this target' }),
      ),
    )
    const err = await api.createScan('https://x.tld', []).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(400)
    expect((err as ApiError).detail).toContain('confirm you are authorized')
  })

  it('formats FastAPI field errors into a readable string', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        errResponse(422, {
          detail: [{ loc: ['body', 'target_url'], msg: 'start with http:// or https://' }],
        }),
      ),
    )
    const err = await api.createScan('x', []).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).detail).toContain('body.target_url')
  })

  it('maps network failures to ApiError status 0 (no fake data)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new TypeError('Failed to fetch')),
    )
    const err = await api.listScans().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(0)
  })

  it('cancelScan posts to the real cancel endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue(okResponse({ cancelled: true, status: 'cancelled' }))
    vi.stubGlobal('fetch', fetchMock)
    const r = await api.cancelScan('abc123')
    expect(r.cancelled).toBe(true)
    const apiBase = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/+$/, '')
    expect(fetchMock).toHaveBeenCalledWith(
      `${apiBase}/api/scans/abc123/cancel`,
      expect.objectContaining({ method: 'POST' }),
    )
  })

  it('sends file uploads as multipart data without setting a JSON content type', async () => {
    const fetchMock = vi.fn().mockResolvedValue(okResponse({ status: 'queued' }))
    vi.stubGlobal('fetch', fetchMock)
    await api.virustotalFileScan(new File(['sample'], 'sample.apk'))
    const options = fetchMock.mock.calls[0]?.[1]
    expect(options?.method).toBe('POST')
    expect(options?.body).toBeInstanceOf(FormData)
    expect(options?.headers).toEqual({})
  })
})
