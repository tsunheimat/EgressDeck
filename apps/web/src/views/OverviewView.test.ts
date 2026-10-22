// @vitest-environment jsdom
import { createApp, h, KeepAlive, nextTick, ref, type App } from 'vue'
import { afterEach, expect, it, vi } from 'vitest'
import OverviewView from './OverviewView.vue'
import { useControllerState } from '../state'
import type { ControllerApi } from '../api/client'
import type { DeviceSummary, OutboundGroupSummary, OverviewResponse } from '../types'

let app: App | undefined
let container: HTMLDivElement | undefined
afterEach(() => { app?.unmount(); container?.remove(); app = undefined; container = undefined })
const data = (): OverviewResponse => ({ gateways: [{ id: 'gw', name: 'Lab gateway', endpoint: 'https://gateway.test', health: 'healthy', adapter: 'dae', revision: 1, capabilities: { supported: [] } }], bindings: [], providers: [], deviceGroups: [], operations: [], coverage: { ipv4: null, ipv6: null, dualStack: null, incomplete: null, available: false } })
function mount(overrides: Partial<{ devices: () => Promise<DeviceSummary[]>; outboundGroups: () => Promise<OutboundGroupSummary[]> }> = {}) {
  const overview = data()
  const api = { overview: vi.fn().mockResolvedValue(overview), gateways: vi.fn().mockResolvedValue(overview.gateways), session: vi.fn().mockResolvedValue({ subject: 'admin', roles: ['admin'] }), capabilities: vi.fn().mockResolvedValue({ capabilities: {} }), devices: vi.fn().mockResolvedValue([]), outboundGroups: vi.fn().mockResolvedValue([]), ...overrides }
  const state = useControllerState(api as unknown as ControllerApi)
  state.overview.value = overview
  state.gateways.value = overview.gateways
  state.selectedGatewayId.value = 'gw'
  state.session.value = { subject: 'admin', roles: ['admin'] }
  const visible = ref(true)
  container = document.createElement('div'); document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => visible.value ? h(OverviewView, { state }) : h('div', 'Other page') }) })
  app.mount(container)
  return { api, state, visible }
}
const metric = (id: string) => container!.querySelector(`[data-metric="${id}"] strong`)?.textContent

it('shows unknown verification and real empty inventory without inventing online counts', async () => {
  const { api } = mount()
  await vi.waitFor(() => expect(metric('devices')).toBe('0'))
  expect(api.devices).toHaveBeenCalledTimes(1)
  expect(api.outboundGroups).toHaveBeenCalledTimes(1)
  expect(container!.querySelector('[data-step="verification"]')?.getAttribute('data-state')).toBe('unknown')
  expect(container!.querySelector('.coverage-ring')?.textContent).toContain('待验证')
  expect(container!.textContent).toContain('登记数量不代表在线')
  expect(container!.textContent).not.toContain('100%')
})

it('does not turn an unavailable supplementary inventory into zero or a complete attention count', async () => {
  mount({ devices: vi.fn().mockRejectedValue(new Error('offline')) })
  await vi.waitFor(() => expect(container!.textContent).toContain('设备清单读取失败'))
  expect(metric('devices')).toBe('—')
  expect(metric('outbounds')).toBe('0')
  expect(metric('attention')).toBe('—')
})

it('removes green setup claims when the retained overview becomes stale', async () => {
  const { state } = mount()
  await vi.waitFor(() => expect(metric('devices')).toBe('0'))
  expect(container!.querySelector('[data-step="gateway"]')?.getAttribute('data-state')).toBe('complete')
  state.error.value = 'Readback failed'
  await nextTick()
  expect(metric('gateways')).toBe('—')
  expect(container!.querySelectorAll('.step--complete')).toHaveLength(0)
  expect(container!.querySelector('[role="alert"]')?.textContent).toContain('Readback failed')
})

it('discards an in-flight inventory response after the session disappears', async () => {
  let resolve!: (value: DeviceSummary[]) => void
  const pending = new Promise<DeviceSummary[]>(done => { resolve = done })
  const { state } = mount({ devices: vi.fn().mockReturnValue(pending) })
  state.session.value = undefined
  await nextTick()
  resolve([{ id: 'private', name: 'Private device', revision: 1, addresses: [], coverage: 'incomplete', enrollment: 'unenrolled' }])
  await pending; await nextTick(); await nextTick()
  expect(metric('devices')).toBe('—')
  expect(container!.textContent).not.toContain('Private device')
})

it('refreshes the overview on return from another setup page', async () => {
  const { api, visible } = mount()
  await vi.waitFor(() => expect(metric('devices')).toBe('0'))
  visible.value = false; await nextTick()
  visible.value = true; await nextTick()
  await vi.waitFor(() => expect(api.overview).toHaveBeenCalledTimes(1))
  await vi.waitFor(() => expect(api.devices).toHaveBeenCalledTimes(2))
})
