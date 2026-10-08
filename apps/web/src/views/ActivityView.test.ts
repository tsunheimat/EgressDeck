// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, h, KeepAlive, nextTick, ref, type App } from 'vue'
import { ControllerApi } from '../api/client'
import { useControllerState } from '../state'
import type { Capability, GatewayConnectionsResponse, GatewayCountersResponse, GatewaySummary } from '../types'
import ActivityView from './ActivityView.vue'

const observedAt = '2026-10-08T08:00:00Z'
const gateway: GatewaySummary = {
  id: 'gateway-1', name: 'Home gateway', endpoint: 'https://gateway.example', health: 'healthy',
  capabilities: { supported: ['connections.observe', 'traffic.proxy_counters'] }, revision: 1, adapter: 'dae',
}
const otherGateway: GatewaySummary = { ...gateway, id: 'gateway-2', name: 'Office gateway', endpoint: 'https://office.example' }

function connectionReadback(source = gateway, connectionId = 'home-connection'): GatewayConnectionsResponse {
  return {
    gateway_id: source.id, gateway_name: source.name, observed_at: observedAt,
    items: [{ id: connectionId, group_id: 'outbound-1', node_id: 'node-1', transport: 'tcp', state: 'open', opened_at: observedAt }],
  }
}

function counterReadback(source = gateway, bytes = '0'): GatewayCountersResponse {
  return {
    gateway_id: source.id, gateway_name: source.name, observed_at: observedAt,
    proxy: { available: true, bytes, packets: '0' }, direct: { available: false }, provider_quota: { available: false },
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: Error) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

let app: App | undefined
let container: HTMLDivElement

async function mount(options: {
  supported?: Capability[]
  connections?: (gatewayId: string, signal?: AbortSignal) => Promise<GatewayConnectionsResponse>
  counters?: (gatewayId: string, signal?: AbortSignal) => Promise<GatewayCountersResponse>
} = {}) {
  const api = {
    operations: vi.fn().mockResolvedValue([]),
    auditEvents: vi.fn().mockResolvedValue([]),
    gatewayConnections: vi.fn(options.connections ?? (async (_gatewayId: string, _signal?: AbortSignal) => connectionReadback())),
    gatewayCounters: vi.fn(options.counters ?? (async (_gatewayId: string, _signal?: AbortSignal) => counterReadback())),
  }
  const state = useControllerState(api as unknown as ControllerApi)
  state.session.value = { subject: 'viewer', roles: ['viewer'] }
  state.gateways.value = [{ ...gateway, capabilities: { supported: options.supported ?? gateway.capabilities.supported } }, otherGateway]
  state.selectedGatewayId.value = gateway.id
  const active = ref(true)
  container = document.createElement('div')
  document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => active.value ? h(ActivityView, { state }) : h('div', 'Another view') }) })
  app.mount(container)
  await vi.waitFor(() => expect(api.operations).toHaveBeenCalledOnce())
  await nextTick()
  return { api, state, active }
}

afterEach(() => {
  app?.unmount()
  app = undefined
  container?.remove()
})

function diagnostics() { return container.querySelector<HTMLElement>('section[aria-label="Gateway diagnostics"]')! }
function counter(label: string) { return [...diagnostics().querySelectorAll<HTMLElement>('.counter')].find(item => item.querySelector('strong')?.textContent === label)! }
function readButton() { return diagnostics().querySelector<HTMLButtonElement>('button')! }
async function readGateway() {
  expect(readButton().disabled).toBe(false)
  readButton().click()
  await nextTick()
}
async function settle() {
  await Promise.resolve()
  await nextTick()
  await Promise.resolve()
  await nextTick()
}

describe('gateway activity diagnostics', () => {
  it('shows observed zero traffic separately from unavailable counters and provider quota', async () => {
    const { api } = await mount()
    await vi.waitFor(() => expect(diagnostics().textContent).toContain('home-connection'))
    expect(api.operations).toHaveBeenCalledOnce()
    expect(api.auditEvents).toHaveBeenCalledOnce()
    expect(api.gatewayConnections).toHaveBeenCalledWith(gateway.id, expect.any(AbortSignal))
    expect(api.gatewayCounters).toHaveBeenCalledWith(gateway.id, expect.any(AbortSignal))
    expect(counter('Proxy traffic').querySelector('span')?.textContent).toBe('0 bytes')
    expect(counter('Proxy traffic').querySelector('small')?.textContent).toBe('0 packets')
    expect(counter('Direct traffic').querySelector('span')?.textContent).toBe('Unavailable')
    expect(counter('Direct traffic').querySelector('small')?.textContent).toBe('Unavailable')
    expect(counter('Provider quota').querySelector('span')?.textContent).toBe('Unavailable')
    expect(counter('Provider quota').textContent).toContain('Gateway traffic counters do not measure subscription allowance.')
    expect(counter('Provider quota').textContent).not.toContain('0 bytes')
    expect(diagnostics().textContent).toContain(`Counter readback: ${gateway.name} · ${observedAt}`)
    expect(diagnostics().textContent).toContain(`Connection readback: ${gateway.name} · ${observedAt}`)
  })

  it('continues loading activity without calling unsupported diagnostic endpoints', async () => {
    const { api } = await mount({ supported: [] })
    await settle()
    expect(api.operations).toHaveBeenCalledOnce()
    expect(api.auditEvents).toHaveBeenCalledOnce()
    expect(api.gatewayConnections).not.toHaveBeenCalled()
    expect(api.gatewayCounters).not.toHaveBeenCalled()
    expect(readButton().disabled).toBe(true)
    expect(diagnostics().textContent).toContain('does not advertise connection or traffic counter support')
    expect(counter('Proxy traffic').querySelector('span')?.textContent).toBe('Unavailable')
    expect(diagnostics().textContent).not.toContain('Counter readback:')
    expect(diagnostics().textContent).not.toContain('Connection readback:')
  })

  it.each([
    { capability: 'connections.observe' as Capability, connections: 1, counters: 0 },
    { capability: 'traffic.direct_counters' as Capability, connections: 0, counters: 1 },
  ])('uses only the endpoint advertised by $capability', async ({ capability, connections, counters }) => {
    const { api } = await mount({ supported: [capability] })
    await settle()
    expect(api.gatewayConnections).toHaveBeenCalledTimes(connections)
    expect(api.gatewayCounters).toHaveBeenCalledTimes(counters)
    expect(readButton().disabled).toBe(false)
  })

  it('ignores late responses from the previously selected gateway even when requests ignore abort', async () => {
    const oldConnections = deferred<GatewayConnectionsResponse>()
    const oldCounters = deferred<GatewayCountersResponse>()
    const newConnections = deferred<GatewayConnectionsResponse>()
    const newCounters = deferred<GatewayCountersResponse>()
    const { api, state } = await mount({
      connections: id => id === gateway.id ? oldConnections.promise : newConnections.promise,
      counters: id => id === gateway.id ? oldCounters.promise : newCounters.promise,
    })
    const oldSignal = api.gatewayConnections.mock.calls[0]![1]!
    expect(oldSignal.aborted).toBe(false)
    state.selectedGatewayId.value = otherGateway.id
    await vi.waitFor(() => expect(api.gatewayConnections).toHaveBeenCalledWith(otherGateway.id, expect.any(AbortSignal)))
    expect(oldSignal.aborted).toBe(true)
    expect(diagnostics().textContent).toContain(`Measurements from ${otherGateway.name}`)
    expect(diagnostics().textContent).not.toContain('Counter readback:')
    newConnections.resolve(connectionReadback(otherGateway, 'office-connection'))
    newCounters.resolve(counterReadback(otherGateway, '18446744073709551615'))
    await vi.waitFor(() => expect(diagnostics().textContent).toContain('office-connection'))
    oldConnections.resolve(connectionReadback(gateway, 'late-home-connection'))
    oldCounters.resolve(counterReadback(gateway, '999999'))
    await settle()
    expect(counter('Proxy traffic').querySelector('span')?.textContent).toBe('18446744073709551615 bytes')
    expect(diagnostics().textContent).toContain(`Counter readback: ${otherGateway.name}`)
    expect(diagnostics().textContent).toContain('office-connection')
    expect(diagnostics().textContent).not.toContain('late-home-connection')
    expect(diagnostics().textContent).not.toContain('999999 bytes')
    expect(diagnostics().textContent).not.toContain(`Connection readback: ${gateway.name}`)
    expect(readButton().disabled).toBe(false)
  })

  it('clears previous successful observations while rereading and after read errors', async () => {
    const { api } = await mount()
    await vi.waitFor(() => expect(diagnostics().textContent).toContain('home-connection'))
    const failedConnections = deferred<GatewayConnectionsResponse>()
    const failedCounters = deferred<GatewayCountersResponse>()
    api.gatewayConnections.mockReturnValueOnce(failedConnections.promise)
    api.gatewayCounters.mockReturnValueOnce(failedCounters.promise)
    await readGateway()
    expect(diagnostics().textContent).not.toContain('home-connection')
    expect(counter('Proxy traffic').querySelector('span')?.textContent).toBe('Unavailable')
    expect(diagnostics().textContent).not.toContain('Counter readback:')
    failedConnections.reject(new Error('Connections temporarily unavailable'))
    failedCounters.reject(new Error('Counter read timed out'))
    await vi.waitFor(() => expect(diagnostics().querySelector('[role="alert"]')?.textContent).toContain('Counter read timed out'))
    expect(diagnostics().querySelector('[role="alert"]')?.textContent).toContain('Connections temporarily unavailable')
    expect(diagnostics().textContent).not.toContain('home-connection')
    expect(diagnostics().textContent).not.toContain('0 bytes')
    expect(diagnostics().textContent).not.toContain('Connection readback:')
    expect(readButton().disabled).toBe(false)
    await readGateway()
    await vi.waitFor(() => expect(diagnostics().textContent).toContain('home-connection'))
    expect(diagnostics().querySelector('[role="alert"]')).toBeNull()
    expect(counter('Proxy traffic').querySelector('span')?.textContent).toBe('0 bytes')
  })

  it('refuses observations whose source gateway differs from the selected gateway', async () => {
    await mount({
      connections: async () => connectionReadback(otherGateway, 'wrong-source-connection'),
      counters: async () => counterReadback(otherGateway, '456789'),
    })
    await vi.waitFor(() => expect(diagnostics().textContent).toContain('Counter readback did not match the selected gateway'))
    expect(diagnostics().textContent).toContain('Connection readback did not match the selected gateway')
    expect(diagnostics().textContent).not.toContain('wrong-source-connection')
    expect(diagnostics().textContent).not.toContain('456789 bytes')
    expect(diagnostics().textContent).not.toContain(`Counter readback: ${otherGateway.name}`)
    expect(counter('Proxy traffic').querySelector('span')?.textContent).toBe('Unavailable')
  })

  it('aborts on native KeepAlive deactivation and reads the current gateway on reactivation', async () => {
    const inactiveConnections = deferred<GatewayConnectionsResponse>()
    const inactiveCounters = deferred<GatewayCountersResponse>()
    const { api, state, active } = await mount({
      connections: id => id === gateway.id ? inactiveConnections.promise : Promise.resolve(connectionReadback(otherGateway, 'reactivated-connection')),
      counters: id => id === gateway.id ? inactiveCounters.promise : Promise.resolve(counterReadback(otherGateway, '789')),
    })
    const signal = api.gatewayCounters.mock.calls[0]![1]!
    active.value = false
    await nextTick()
    expect(signal.aborted).toBe(true)
    state.selectedGatewayId.value = otherGateway.id
    await settle()
    inactiveConnections.resolve(connectionReadback(gateway, 'inactive-connection'))
    inactiveCounters.resolve(counterReadback(gateway, '123'))
    await settle()
    expect(api.gatewayConnections).toHaveBeenCalledOnce()
    expect(api.gatewayCounters).toHaveBeenCalledOnce()
    expect(container.textContent).toBe('Another view')
    active.value = true
    await vi.waitFor(() => expect(diagnostics().textContent).toContain('reactivated-connection'))
    expect(api.operations).toHaveBeenCalledTimes(2)
    expect(api.auditEvents).toHaveBeenCalledTimes(2)
    expect(api.gatewayConnections).toHaveBeenLastCalledWith(otherGateway.id, expect.any(AbortSignal))
    expect(counter('Proxy traffic').querySelector('span')?.textContent).toBe('789 bytes')
    expect(diagnostics().textContent).not.toContain('inactive-connection')
    expect(diagnostics().textContent).not.toContain('123 bytes')
  })
})
