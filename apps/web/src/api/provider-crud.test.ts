import { describe, expect, it, vi } from 'vitest'
import { ControllerApi } from './client'

describe('provider inventory writes', () => {
  it('sends an inventory CAS and preserves source omission for a settings edit', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ id: 'provider/1', name: 'Updated', revision: 8, source: '[redacted]', format: 'auto', fetch_route: 'verified-route' }), { status: 200 }))
    const result = await new ControllerApi('/api/v1', fetcher).updateProvider('provider/1', { name: 'Updated', fetch_route: 'verified-route' }, 7)
    expect(fetcher).toHaveBeenCalledWith('/api/v1/providers/provider%2F1', expect.objectContaining({ method: 'PATCH', headers: expect.objectContaining({ 'If-Match': '7' }) }))
    expect(JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body))).toEqual({ name: 'Updated', fetch_route: 'verified-route' })
    expect(result).toMatchObject({ revision: 8, source: '[redacted]', fetchRoute: 'verified-route' })
  })

  it('binds deletion to the captured inventory revision and accepts an empty 204 response', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }))
    await expect(new ControllerApi('/api/v1', fetcher).deleteProvider('provider/1', 8)).resolves.toBeUndefined()
    expect(fetcher).toHaveBeenCalledWith('/api/v1/providers/provider%2F1', expect.objectContaining({ method: 'DELETE', headers: expect.objectContaining({ 'If-Match': '8' }) }))
  })
})
