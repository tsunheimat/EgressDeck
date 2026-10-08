import { describe, expect, it, vi } from 'vitest'
import { ControllerApi } from './client'

const page = (body: unknown) => new Response(JSON.stringify(body), { status: 200 })

describe('collection pagination', () => {
  it('follows pages and propagates one abort signal', async () => {
    const fetcher = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(page({ items: [{ id: 'a', name: 'A' }], next_cursor: 'next/cursor' }))
      .mockResolvedValueOnce(page({ items: [{ id: 'b', name: 'B' }] }))
    const controller = new AbortController()
    const result = await new ControllerApi('/api/v1', fetcher).devices(controller.signal)
    expect(result.map(item => item.id)).toEqual(['a', 'b'])
    expect(fetcher.mock.calls.map(call => call[0])).toEqual(['/api/v1/devices?limit=100', '/api/v1/devices?limit=100&cursor=next%2Fcursor'])
    expect(fetcher.mock.calls.every(call => call[1]?.signal === controller.signal)).toBe(true)
  })

  it('rejects stale snapshots without returning a partial collection', async () => {
    const fetcher = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(page({ items: [{ id: 'a' }], next_cursor: 'next' }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ error: { code: 'stale_cursor', message: 'Collection changed.' } }), { status: 409 }))
    await expect(new ControllerApi('/api/v1', fetcher).devices()).rejects.toMatchObject({ status: 409, code: 'stale_cursor' })
  })

  it('rejects repeated cursors and a list beyond the browser page bound', async () => {
    const repeated = vi.fn<typeof fetch>().mockImplementation(async () => page({ items: [{ id: 'a' }], next_cursor: 'same' }))
    await expect(new ControllerApi('/api/v1', repeated).devices()).rejects.toMatchObject({ code: 'invalid_cursor' })
    expect(repeated).toHaveBeenCalledTimes(2)
    let n = 0
    const endless = vi.fn<typeof fetch>().mockImplementation(async () => page({ items: [{ id: String(n) }], next_cursor: `page-${++n}` }))
    await expect(new ControllerApi('/api/v1', endless).devices()).rejects.toMatchObject({ code: 'collection_limit' })
    expect(endless).toHaveBeenCalledTimes(100)
  })

  it('stops before the next page when cancelled', async () => {
    const controller = new AbortController()
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => {
      controller.abort()
      return page({ items: [{ id: 'a' }], next_cursor: 'next' })
    })
    await expect(new ControllerApi('/api/v1', fetcher).devices(controller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetcher).toHaveBeenCalledTimes(1)
  })

  it('bounds collection response bytes before parsing', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response('x'.repeat(4 * 1024 * 1024 + 1)))
    await expect(new ControllerApi('/api/v1', fetcher).devices()).rejects.toThrow('4 MiB')
  })
})
