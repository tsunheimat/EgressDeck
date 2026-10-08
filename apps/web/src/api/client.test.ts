import { describe, expect, it, vi } from 'vitest'
import { ControllerApi, ControllerApiError } from './client'

describe('ControllerApi', () => {
  it('sends controller credentials and returns overview JSON', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ gateways: [], bindings: [], providers: [], deviceGroups: [], operations: [], coverage: { ipv4: 0, ipv6: 0, dualStack: 0, incomplete: 0 } }), { status: 200 }))
    const api = new ControllerApi('/api/v1', fetcher)
    await expect(api.overview()).resolves.toMatchObject({ gateways: [], providers: [] })
    expect(fetcher).toHaveBeenCalledWith('/api/v1/overview', expect.objectContaining({ credentials: 'include', headers: { Accept: 'application/json' } }))
  })

  it('returns typed server errors with the operation identifier', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ code: 'CONFLICT', message: 'stale generation', operationId: 'op-1' }), { status: 409 }))
    const api = new ControllerApi('/api/v1', fetcher)
    await expect(api.overview()).rejects.toEqual(expect.objectContaining({ name: 'ControllerApiError', status: 409, code: 'CONFLICT', operationId: 'op-1' }))
    await expect(api.overview()).rejects.toBeInstanceOf(ControllerApiError)
  })

  it('includes idempotency and revision headers for selection changes', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ operation_id: 'op-2', status: 'applying' }), { status: 202 }))
    const api = new ControllerApi('/api/v1', fetcher)
    await api.setSelection('group/1', { nodeId: 'node-1', gatewayId: 'gw-1', expectedRevision: 'rev-3' }, 'idem-1')
    expect(fetcher).toHaveBeenCalledWith('/api/v1/outbound-groups/group%2F1/selection', expect.objectContaining({ method: 'PUT', headers: expect.objectContaining({ 'Idempotency-Key': 'idem-1', 'If-Match': 'rev-3' }) }))
    expect(JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body))).toEqual({ node_id: 'node-1', gateway_id: 'gw-1' })
  })

  it('sends per-transport revisions for shared selection', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ operation_id: 'op-shared', status: 'applying' }), { status: 202 }))
    const api = new ControllerApi('/api/v1', fetcher)
    await api.setSelection('group/1', { nodeId: 'node-1', gatewayId: 'gw-1', transportScopes: ['tcp', 'udp'], expectedRevision: '3', expectedRevisions: { tcp: 3, udp: 1 } }, 'idem-shared')
    expect(JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body))).toEqual({ node_id: 'node-1', gateway_id: 'gw-1', transport_scopes: ['tcp', 'udp'], expected_revisions: { tcp: 3, udp: 1 } })
    expect(fetcher.mock.calls[0]?.[1]?.headers).toEqual(expect.objectContaining({ 'If-Match': '3', 'Idempotency-Key': 'idem-shared' }))
  })

  it('publishes outbound group configuration with a durable precondition', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ operation_id: 'op-group', status: 'applying' }), { status: 202 }))
    const api = new ControllerApi('/api/v1', fetcher)
    await api.applyOutboundGroup('group/1', 8, 'idem-group')
    expect(fetcher).toHaveBeenCalledWith('/api/v1/outbound-groups/group%2F1/apply', expect.objectContaining({ method: 'POST', headers: expect.objectContaining({ 'If-Match': '8', 'Idempotency-Key': 'idem-group' }), body: '{}' }))
  })

  it('unwraps the paginated list envelope used by the controller contract', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ items: [{ id: 'gw-1', name: 'lab', endpoint: 'https://gw', health: 'healthy', capabilities: { supported: [] } }] }), { status: 200 }))
    const api = new ControllerApi('/api/v1', fetcher)
    await expect(api.gateways()).resolves.toEqual([expect.objectContaining({ id: 'gw-1', name: 'lab' })])
  })

  it('does not turn absent coverage into zero or claim unverified coverage', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ gateways: [], device_groups: [], coverage: null, coverage_status: 'unavailable' }), { status: 200 }))
    const overview = await new ControllerApi('/api/v1', fetcher).overview()
    expect(overview.coverage).toMatchObject({ ipv4: null, ipv6: null, available: false })
  })

  it('refuses acceptance without a durable operation identifier', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ status: 'applied' }), { status: 202 }))
    await expect(new ControllerApi('/api/v1', fetcher).applyProvider('p1', '2', 'key')).rejects.toMatchObject({ code: 'operation_identifier_missing' })
  })

  it('maps persisted device identity and revision without inventing verification', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ items: [{ id: 'd1', name: 'device', primary_group_id: 'g1', revision: 4, enrollment_state: 'unenrolled', addresses: [{ address: '192.0.2.1', family: 'ipv4', provenance: 'manual' }] }] }), { status: 200 }))
    const devices = await new ControllerApi('/api/v1', fetcher).devices()
    expect(devices[0]).toMatchObject({ groupId: 'g1', revision: 4, enrollment: 'unenrolled', coverage: 'incomplete', addresses: [expect.objectContaining({ valid: false })] })
  })
})
