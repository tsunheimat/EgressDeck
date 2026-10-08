import { describe, expect, it, vi } from 'vitest'
import { ControllerApi } from './client'

const binding = {
  id: 'binding-1', gateway_id: 'gateway-1', alias: 'managed', alias_uuid: 'alias-1',
  address_family: 'ipv4', interface_scope: 'lan', rule_ids: ['rule-1'], desired_count: 2,
  state: 'desired', observation_status: 'never_read', verified: false,
}

function reply(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('firewall controller projections', () => {
  it('keeps unknown observations distinct from a confirmed empty table across list and overview', async () => {
    const confirmed = { ...binding, id: 'binding-2', state: 'observed', observation_status: 'fresh', persisted_count: 0, active_count: 0, drift: false, observed_at: '2026-10-08T08:00:00Z' }
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(reply({ items: [binding, confirmed] })).mockResolvedValueOnce(reply({ bindings: [binding, confirmed] }))
    const api = new ControllerApi('/api/v1', fetcher)
    const items = await api.bindings()
    expect(items[0]).toMatchObject({ desiredCount: 2, persistedCount: undefined, activeCount: undefined, drift: undefined, observationStatus: 'never_read', verified: false })
    expect(items[1]).toMatchObject({ persistedCount: 0, activeCount: 0, drift: false, observationStatus: 'fresh', observedAt: '2026-10-08T08:00:00Z', verified: false })
    expect((await api.overview()).bindings).toEqual(items)
  })

  it('submits a typed association and reads projected attachment/readback envelopes', async () => {
    const view = { ...binding, state: 'observed', observation_status: 'fresh', persisted_count: 2, active_count: 1, drift: true, observed_at: '2026-10-08T08:00:00Z' }
    const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(reply({ binding: { alias: { name: 'native object' } }, observed: {}, verified: false, view }, 201)).mockResolvedValueOnce(reply(view)).mockResolvedValueOnce(reply({ desired: {}, observed: {}, verified: false, view }))
    const api = new ControllerApi('/api/v1', fetcher)
    const request = { gateway_id: 'gateway-1', alias: 'managed', alias_type: 'host' as const, family: 'ipv4' as const, interface_scope: 'lan', rule_ids: ['rule-1'] }
    const attached = await api.attachBinding(request)
    expect(attached).toMatchObject({ id: 'binding-1', alias: 'managed', desiredCount: 2, drift: true, state: 'observed', verified: false })
    expect(fetcher.mock.calls[0]?.[0]).toBe('/api/v1/firewall-bindings')
    expect(fetcher.mock.calls[0]?.[1]?.method).toBe('POST')
    expect(JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body))).toEqual(request)
    expect(await api.binding(attached.id)).toEqual(attached)
    expect(await api.readbackBinding(attached.id)).toEqual(attached)
    expect(fetcher.mock.calls[2]?.[0]).toBe('/api/v1/firewall-bindings/binding-1/readback')
    expect(fetcher.mock.calls[2]?.[1]?.method).toBeUndefined()
  })

  it('reports a failed read instead of manufacturing an empty observed binding', async () => {
    const api = new ControllerApi('/api/v1', vi.fn<typeof fetch>().mockResolvedValue(reply({ error: { code: 'firewall_readback_failed', message: 'Firewall readback failed.' } }, 502)))
    await expect(api.readbackBinding('binding-1')).rejects.toMatchObject({ status: 502, code: 'firewall_readback_failed', message: 'Firewall readback failed.' })
  })
})
