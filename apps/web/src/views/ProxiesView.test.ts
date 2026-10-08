// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest'
import { createApp, h, KeepAlive, type App } from 'vue'
import { ControllerApi } from '../api/client'
import { useControllerState } from '../state'
import ProxiesView from './ProxiesView.vue'

let app: App | undefined
let container: HTMLDivElement | undefined
afterEach(() => { app?.unmount(); container?.remove() })
async function mount() {
  const api = {
    nodes: vi.fn().mockResolvedValue([{ id: 'n1', providerId: 'p1', name: 'Node one', protocol: 'socks5', supported: true, health: 'unknown', usedBy: [] }]),
    outboundGroups: vi.fn().mockResolvedValue([{ id: 'g1', name: 'Scoped group', nodeIds: ['n1'], gatewayId: 'gw1', revision: 1, mode: 'manual', replacementPolicy: 'block', candidateCount: 1, transportScopes: ['tcp'], usedBy: [] }]),
    selections: vi.fn().mockResolvedValue([]), policyDocuments: vi.fn().mockResolvedValue([]), ruleSetDocuments: vi.fn().mockResolvedValue([]), deviceGroups: vi.fn().mockResolvedValue([]),
    gatewayProbeNode: vi.fn().mockResolvedValue({ gateway_id: 'gw1', gateway_name: 'Gateway one', target_kind: 'node', target_id: 'n1', observed_at: '2026-10-08T08:00:00Z', probe: { target: 'n1', ok: true, latency_ms: 12, observed_at: '2026-10-08T08:00:00Z' } }),
    gatewayProbeGroup: vi.fn(),
  }
  const state = useControllerState(api as unknown as ControllerApi)
  state.session.value = { subject: 'operator', roles: ['operator'] }
  state.capabilities.value = { 'probe.node': true, 'probe.group': true }
  state.gateways.value = [{ id: 'gw1', name: 'Gateway one', endpoint: 'https://gw1', adapter: 'test', revision: 1, health: 'unknown', capabilities: { supported: ['probe.node'] } }]
  container = document.createElement('div'); document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => h(ProxiesView, { state }) }) }); app.mount(container)
  await vi.waitFor(() => expect(container!.textContent).toContain('Scoped group'))
  return { api, state }
}

it('requires actual assigned gateway probe capability and labels gateway measurements', async () => {
  const { api } = await mount()
  const group = container!.querySelector<HTMLButtonElement>('[aria-label="Test group Scoped group from gateway"]')!
  const node = container!.querySelector<HTMLButtonElement>('[aria-label="Test node Node one from gateway for Scoped group"]')!
  expect(group.disabled).toBe(true)
  expect(node.disabled).toBe(false)
  node.click()
  await vi.waitFor(() => expect(api.gatewayProbeNode).toHaveBeenCalledWith('gw1', 'n1'))
  await vi.waitFor(() => expect(container!.textContent).toContain('Gateway one: 12 ms gateway measurement'))
  expect(api.gatewayProbeGroup).not.toHaveBeenCalled()
})

it('discards mismatched probe targets and hides a previous successful measurement during failure', async () => {
  const { api } = await mount()
  const node = container!.querySelector<HTMLButtonElement>('[aria-label="Test node Node one from gateway for Scoped group"]')!
  node.click()
  await vi.waitFor(() => expect(container!.textContent).toContain('12 ms gateway measurement'))
  api.gatewayProbeNode.mockResolvedValueOnce({ gateway_id: 'other', gateway_name: 'Wrong gateway', target_kind: 'node', target_id: 'n1', observed_at: '2026-10-08T08:01:00Z', probe: { target: 'n1', ok: true, latency_ms: 1, observed_at: '2026-10-08T08:01:00Z' } })
  node.click()
  await vi.waitFor(() => expect(container!.textContent).toContain('Gateway probe returned a different target'))
  expect(container!.textContent).not.toContain('12 ms gateway measurement')
  expect(container!.textContent).not.toContain('1 ms gateway measurement')
})
