// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest'
import { createApp, h, KeepAlive, type App } from 'vue'
import { ControllerApi } from '../api/client'
import { useControllerState } from '../state'
import ProxiesView from './ProxiesView.vue'

let app: App | undefined
let container: HTMLDivElement | undefined
afterEach(() => { app?.unmount(); container?.remove() })
async function mount(selectionScope = 'independent_transport', initialSelections: unknown[] = [], groupOverrides: Record<string, unknown> = {}, role: 'operator' | 'admin' = 'operator') {
  const api = {
    nodes: vi.fn().mockResolvedValue([{ id: 'n1', providerId: 'p1', name: 'Node one', protocol: 'socks5', supported: true, health: 'unknown', usedBy: [] }]),
    outboundGroups: vi.fn().mockResolvedValue([{ id: 'g1', name: 'Scoped group', nodeIds: ['n1'], gatewayId: 'gw1', revision: 1, mode: 'manual', replacementPolicy: 'block', candidateCount: 1, selectionScope, transportScopes: ['tcp'], usedBy: [], ...groupOverrides }]),
    selections: vi.fn().mockResolvedValue(initialSelections), policyDocuments: vi.fn().mockResolvedValue([]), ruleSetDocuments: vi.fn().mockResolvedValue([]), deviceGroups: vi.fn().mockResolvedValue([]),
    setSelection: vi.fn().mockResolvedValue({ operationId: 'selection-op', status: 'applied' }),
    applyOutboundGroup: vi.fn().mockResolvedValue({ operationId: 'apply-op', status: 'applied' }),
    waitForOperation: vi.fn().mockResolvedValue({ id: 'selection-op', status: 'applied', target: 'outbound_group:g1', action: 'selection' }),
    gatewayProbeNode: vi.fn().mockResolvedValue({ gateway_id: 'gw1', gateway_name: 'Gateway one', target_kind: 'node', target_id: 'n1', observed_at: '2026-10-08T08:00:00Z', probe: { target: 'n1', ok: true, latency_ms: 12, observed_at: '2026-10-08T08:00:00Z' } }),
    gatewayProbeGroup: vi.fn(),
  }
  const state = useControllerState(api as unknown as ControllerApi)
  state.session.value = { subject: role, roles: [role] }
  state.capabilities.value = { 'probe.node': true, 'probe.group': true, 'selection.set_runtime': true, 'group.publish_hot': true }
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

it('selects shared TCP and UDP with both observed revisions and avoids claiming convergence from only TCP', async () => {
  const { api } = await mount('shared_tcp_udp', [
    { scope: { gateway_id: 'gw1', transport: 'tcp' }, revision: 3, desired_node_id: 'n1', applied_node_id: 'n1', observed_node_id: 'n1' },
    { scope: { gateway_id: 'gw1', transport: 'udp' }, revision: 1, desired_node_id: 'old-node', applied_node_id: 'old-node', observed_node_id: 'old-node' },
  ])
  expect([...container!.querySelectorAll('.node-card')].map(node => node.getAttribute('aria-label'))).toEqual(['Select Node one for Scoped group (TCP + UDP)'])
  const node = container!.querySelector<HTMLButtonElement>('.node-card')!
  expect(node.getAttribute('aria-pressed')).toBe('false')
  expect(container!.querySelector('[aria-label="Selection transport for Scoped group"]')).toBeNull()
  expect(container!.textContent).toContain('TCP / UDP differ')
  node.click()
  await vi.waitFor(() => expect(api.setSelection).toHaveBeenCalledWith('g1', {
    nodeId: 'n1', gatewayId: 'gw1', transportScopes: ['tcp', 'udp'], expectedRevision: '3', expectedRevisions: { tcp: 3, udp: 1 },
  }, expect.any(String)))
  await vi.waitFor(() => expect(api.selections).toHaveBeenCalledTimes(2))
})

it('preserves independent UDP selection and its own revision', async () => {
  const { api } = await mount('independent_transport', [
    { scope: { gateway_id: 'gw1', transport: 'tcp' }, revision: 3 },
    { scope: { gateway_id: 'gw1', transport: 'udp' }, revision: 1 },
  ])
  const transport = container!.querySelector<HTMLSelectElement>('[aria-label="Selection transport for Scoped group"]')!
  transport.value = 'udp'; transport.dispatchEvent(new Event('change'))
  await vi.waitFor(() => expect(container!.querySelector('[aria-label="Select Node one for Scoped group (UDP)"]')).not.toBeNull())
  container!.querySelector<HTMLButtonElement>('[aria-label="Select Node one for Scoped group (UDP)"]')!.click()
  await vi.waitFor(() => expect(api.setSelection).toHaveBeenCalledWith('g1', {
    nodeId: 'n1', gatewayId: 'gw1', transportScopes: ['udp'], expectedRevision: '1',
  }, expect.any(String)))
})

it('requires applied group readback before selecting and verifies publication after an edit', async () => {
  const { api } = await mount('shared_tcp_udp', [], { revision: 2, appliedRevision: 1, observedRevision: 1 }, 'admin')
  expect(container!.querySelector<HTMLButtonElement>('.node-card')!.disabled).toBe(true)
  expect(container!.textContent).toContain('Group configuration is not applied')
  const current = (await api.outboundGroups())[0]!
  api.outboundGroups.mockResolvedValue([{ ...current, appliedRevision: 2, observedRevision: 2 }])
  const apply = container!.querySelector<HTMLButtonElement>('[aria-label="Apply configuration for Scoped group"]')!
  expect(apply.disabled).toBe(false)
  apply.click()
  await vi.waitFor(() => expect(api.applyOutboundGroup).toHaveBeenCalledWith('g1', 2, expect.any(String)))
  await vi.waitFor(() => expect(container!.textContent).toContain('Group configuration revision 2 applied and observed'))
  expect(container!.querySelector<HTMLButtonElement>('.node-card')!.disabled).toBe(false)
  expect(api.setSelection).not.toHaveBeenCalled()
})

it('does not claim group publication when operation succeeds but readback remains old', async () => {
  const { api } = await mount('shared_tcp_udp', [], { revision: 2, appliedRevision: 1, observedRevision: 1 }, 'admin')
  container!.querySelector<HTMLButtonElement>('[aria-label="Apply configuration for Scoped group"]')!.click()
  await vi.waitFor(() => expect(api.applyOutboundGroup).toHaveBeenCalledTimes(1))
  await vi.waitFor(() => expect(container!.textContent).toContain('readback has not confirmed the requested revision'))
  expect(container!.querySelector<HTMLButtonElement>('.node-card')!.disabled).toBe(true)
})

it('keeps applying saved group configuration restricted to administrators', async () => {
  const { api, state } = await mount('shared_tcp_udp', [], { revision: 2, appliedRevision: 1, observedRevision: 1 })
  const apply = container!.querySelector<HTMLButtonElement>('[aria-label="Apply configuration for Scoped group"]')!
  expect(apply.disabled).toBe(true)
  expect(apply.title).toBe('An administrator session is required to apply group configuration.')
  apply.click()
  expect(api.applyOutboundGroup).not.toHaveBeenCalled()
  state.session.value = { subject: 'admin', roles: ['admin'] }
  await vi.waitFor(() => expect(apply.disabled).toBe(false))
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
