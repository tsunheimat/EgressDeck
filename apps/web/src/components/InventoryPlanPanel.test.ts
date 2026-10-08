// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, h, KeepAlive, nextTick, ref, type App } from 'vue'
import { ControllerApi, ControllerApiError } from '../api/client'
import { useControllerState } from '../state'
import type { GatewaySummary, InventoryPlan } from '../types'
import InventoryPlanPanel from './InventoryPlanPanel.vue'

const checksum = 'a'.repeat(64)
const gateway: GatewaySummary = {
  id: 'gateway-1', name: 'Lab gateway', endpoint: 'https://gateway.example',
  health: 'healthy', capabilities: { supported: [] }, revision: 3, adapter: 'dae',
}
const otherGateway = { ...gateway, id: 'gateway-2', name: 'Second gateway' }

function fixture(overrides: Record<string, unknown> = {}): InventoryPlan {
  const manifest = { version: 1, content_hash: 'c'.repeat(64), gateway_id: gateway.id, groups: [{ id: 'group-1' }], enrollments: [], source_map: [] }
  const plan: InventoryPlan = {
    version: 1, checksum, created_at: '2026-10-08T09:00:00Z', scope: 'gateway',
    consistency: 'revision_rechecked', valid: true, deployable: false,
    resource_revisions: [{ kind: 'gateway', id: gateway.id, revision: 3, sha256: 'b'.repeat(64) }],
    input: { gateway: { id: gateway.id }, device_groups: [], devices: [], policies: [] },
    target: { gateway_id: gateway.id, observation_status: 'observed', capabilities: { implementation: 'test-adapter', version: '1', capabilities: [{ name: 'policy.validate', supported: true }, { name: 'policy.apply_generation', supported: true }] } },
    previous: { status: 'unavailable' },
    blockers: [{ severity: 'error', code: 'coverage_unqualified', message: 'Runtime transport and IPv6 enforcement coverage is not qualified.' }],
    compilation: {
      manifest, normalized: [], source_map: [],
      impact: { changed_groups: ['group-1'], unchanged_groups: [], enrollment_changed: true, requires_policy_apply: true },
    },
    native_artifact: { format: 'dae-routing', dae_base: 'test-base', gateway_id: gateway.id, manifest, routing_config: 'routing { fallback: block }', routing_sha256: 'd'.repeat(64), content_hash: 'e'.repeat(64), requires_guard: false, outbound_bindings: [], source_map: [], required_globals: { dial_mode: 'ip', auto_sniff_punt: false } },
  }
  return { ...plan, ...overrides }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (cause: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => { resolve = resolvePromise; reject = rejectPromise })
  return { promise, resolve, reject }
}

let app: App | undefined
let container: HTMLDivElement

async function mount(realApi?: ControllerApi) {
  const api = {
    createInventoryPlan: vi.fn().mockResolvedValue(fixture()),
    inventoryPlan: vi.fn().mockResolvedValue(fixture()),
  }
  const state = useControllerState(realApi ?? api as unknown as ControllerApi)
  state.session.value = { subject: 'administrator', roles: ['administrator'] }
  state.capabilities.value = { 'policy.validate': true }
  state.gateways.value = [gateway, otherGateway]
  state.selectedGatewayId.value = gateway.id
  const visible = ref(true)
  container = document.createElement('div')
  document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => visible.value ? h(InventoryPlanPanel, { state }) : null }) })
  app.mount(container)
  await nextTick()
  return { api, state, visible }
}

afterEach(() => {
  app?.unmount()
  app = undefined
  container?.remove()
})

function form() { return container.querySelector<HTMLFormElement>('form[aria-label="Create inventory plan"]')! }
function submitButton() { return form().querySelector<HTMLButtonElement>('button[type="submit"]')! }
function result() { return container.querySelector('[aria-label="Stored inventory plan result"]') }
function button(label: string) { return Array.from(container.querySelectorAll<HTMLButtonElement>('button')).find(item => item.textContent?.includes(label))! }
async function submit() {
  form().dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await nextTick()
}
async function previousOperation(value: string) {
  const input = form().querySelector<HTMLInputElement>('input')!
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await nextTick()
}
async function settle() {
  await Promise.resolve()
  await nextTick()
  await Promise.resolve()
  await nextTick()
}

describe('stored inventory planning', () => {
  it('uses the real client POST and GET routes for the panel confirmation flow', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => new Response(JSON.stringify(fixture()), { status: 200 }))
    await mount(new ControllerApi('/api/v1', fetcher))
    await previousOperation('applied-8')
    await submit()
    await vi.waitFor(() => expect(result()?.textContent).toContain('Stored plan readback confirmed'))
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(fetcher).toHaveBeenNthCalledWith(1, '/api/v1/deployments/plan', expect.objectContaining({
      method: 'POST', credentials: 'include', headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ gateway_id: gateway.id, previous_operation_id: 'applied-8' }),
    }))
    expect(fetcher).toHaveBeenNthCalledWith(2, `/api/v1/deployments/plans/${checksum}`, expect.objectContaining({ credentials: 'include' }))
    expect(fetcher.mock.calls[1]?.[1]?.method ?? 'GET').toBe('GET')
    expect(fetcher.mock.calls[1]?.[1]?.body).toBeUndefined()
  })

  it('confirms only GET readback, sends a narrow request, and keeps deployment disabled', async () => {
    const { api } = await mount()
    const readback = deferred<InventoryPlan>()
    api.inventoryPlan.mockReturnValueOnce(readback.promise)
    await previousOperation('  applied-operation-7  ')
    await submit()
    await vi.waitFor(() => expect(api.inventoryPlan).toHaveBeenCalledWith(checksum))
    expect(api.createInventoryPlan).toHaveBeenCalledTimes(1)
    expect(api.createInventoryPlan).toHaveBeenCalledWith({ gateway_id: gateway.id, previous_operation_id: 'applied-operation-7' })
    expect(container.textContent).toContain('stored readback is not confirmed')
    expect(result()).toBeNull()
    expect(submitButton().disabled).toBe(true)
    readback.resolve(fixture({ created_at: '2026-10-08T08:00:00Z', deployable: true, blockers: [] }))
    await vi.waitFor(() => expect(result()?.textContent).toContain('Stored plan readback confirmed'))
    expect(result()?.textContent).toContain('2026-10-08T08:00:00Z')
    expect(result()?.textContent).not.toContain('2026-10-08T09:00:00Z')
    expect(result()?.textContent).toContain('revision_rechecked')
    expect(result()?.textContent).toContain('does not establish applied or verified traffic state')
    expect(result()?.textContent).toContain('Later inventory changes require a new plan')
    expect(result()?.textContent).toContain('Routing fragment')
    expect(container.querySelector('tbody tr')?.textContent).toContain(gateway.id)
    expect(button('Deploy plan unavailable').disabled).toBe(true)
  })

  it('retries failed readback without another POST and allows readback after downgrade to viewer', async () => {
    const { api, state } = await mount()
    api.inventoryPlan.mockRejectedValueOnce(new ControllerApiError('Stored plan not found', 404, 'not_found'))
    await submit()
    await vi.waitFor(() => expect(container.querySelector('[role="alert"]')?.textContent).toContain('Stored plan not found'))
    expect(result()).toBeNull()
    state.session.value = { subject: 'administrator', roles: ['viewer'] }
    await nextTick()
    expect(submitButton().disabled).toBe(true)
    await submit()
    expect(api.createInventoryPlan).toHaveBeenCalledTimes(1)
    const retry = button('Retry stored plan readback')
    expect(retry.disabled).toBe(false)
    retry.click()
    await vi.waitFor(() => expect(result()?.textContent).toContain('Stored plan readback confirmed'))
    expect(api.createInventoryPlan).toHaveBeenCalledTimes(1)
    expect(api.inventoryPlan).toHaveBeenCalledTimes(2)
    expect(api.inventoryPlan).toHaveBeenLastCalledWith(checksum)
    expect(container.querySelector('[role="alert"]')).toBeNull()
  })

  it('rejects malformed POST checksums and readback for another checksum, gateway, or scope', async () => {
    const { api } = await mount()
    api.createInventoryPlan.mockResolvedValueOnce(fixture({ checksum: 'invalid-checksum' }))
    await submit()
    await vi.waitFor(() => expect(container.textContent).toContain('invalid plan checksum'))
    expect(api.inventoryPlan).not.toHaveBeenCalled()
    for (const mismatch of [
      { checksum: 'f'.repeat(64) },
      { target: { gateway_id: otherGateway.id } },
      { input: { gateway: { id: otherGateway.id } } },
      { scope: 'device_group' },
    ]) {
      api.inventoryPlan.mockResolvedValueOnce(fixture(mismatch))
      await submit()
      await vi.waitFor(() => expect(container.textContent).toContain('does not match the requested checksum and gateway'))
      expect(result()).toBeNull()
      expect(button('Retry stored plan readback').disabled).toBe(false)
    }
    expect(api.createInventoryPlan).toHaveBeenCalledTimes(5)
    expect(api.inventoryPlan).toHaveBeenCalledTimes(4)
  })

  it('renders a persisted invalid plan without compilation or a native artifact', async () => {
    const { api } = await mount()
    api.inventoryPlan.mockResolvedValueOnce(fixture({
      valid: false, compilation: undefined, native_artifact: undefined,
      diagnostics: [{ severity: 'error', code: 'strict_ipv6_unqualified', path: 'device_groups[0]', message: 'IPv6 enforcement is unavailable.' }],
      target: { ...fixture().target, observation_status: 'failed' },
    }))
    await submit()
    await vi.waitFor(() => expect(result()?.textContent).toContain('Compilation invalid'))
    expect(container.querySelector('[aria-label="Plan validation diagnostics"]')?.textContent).toContain('strict_ipv6_unqualified')
    expect(container.querySelector('[aria-label="Plan validation diagnostics"]')?.textContent).toContain('device_groups[0]')
    expect(container.querySelector('[aria-label="Deployment blockers"]')?.textContent).toContain('coverage_unqualified')
    expect(container.querySelector('[aria-label="Inventory compilation preview"]')).toBeNull()
    expect(container.textContent).not.toContain('Read-only native routing preview')
    expect(button('Deploy plan unavailable').disabled).toBe(true)
  })

  it('requires administrator authority, policy validation capability, and a registered gateway before POST', async () => {
    const { api, state } = await mount()
    for (const roles of [['viewer'], ['operator'], []]) {
      state.session.value = { subject: 'user', roles }
      await nextTick()
      expect(submitButton().disabled).toBe(true)
      await submit()
    }
    state.session.value = undefined
    await nextTick()
    await submit()
    state.session.value = { subject: 'administrator', roles: ['administrator'] }
    state.capabilities.value = { 'policy.validate': false }
    await nextTick()
    expect(submitButton().disabled).toBe(true)
    await submit()
    state.capabilities.value = { 'policy.validate': true }
    state.gateways.value = []
    await nextTick()
    expect(submitButton().disabled).toBe(true)
    await submit()
    expect(api.createInventoryPlan).not.toHaveBeenCalled()
    expect(api.inventoryPlan).not.toHaveBeenCalled()
  })

  it('ignores old creation and readback results after gateway or previous-operation changes', async () => {
    const { api, state } = await mount()
    const firstCreate = deferred<InventoryPlan>()
    const secondRead = deferred<InventoryPlan>()
    const secondPlan = fixture({ checksum: 'e'.repeat(64), target: { gateway_id: otherGateway.id, observation_status: 'unavailable' }, input: { gateway: { id: otherGateway.id } } })
    api.createInventoryPlan.mockReturnValueOnce(firstCreate.promise).mockResolvedValue(secondPlan)
    api.inventoryPlan.mockReturnValueOnce(secondRead.promise).mockResolvedValue(secondPlan)
    await submit()
    state.selectedGatewayId.value = otherGateway.id
    await nextTick()
    expect(submitButton().disabled).toBe(false)
    await submit()
    await vi.waitFor(() => expect(api.inventoryPlan).toHaveBeenCalledWith(secondPlan.checksum))
    firstCreate.resolve(fixture())
    await settle()
    expect(api.inventoryPlan).toHaveBeenCalledTimes(1)
    await previousOperation('new-applied-operation')
    secondRead.reject(new Error('Obsolete gateway readback failure'))
    await settle()
    expect(result()).toBeNull()
    expect(container.textContent).not.toContain('Obsolete gateway readback failure')
    expect(container.textContent).not.toContain('stored readback is not confirmed')
    expect(submitButton().disabled).toBe(false)
    await submit()
    await vi.waitFor(() => expect(result()?.textContent).toContain(otherGateway.id))
    expect(api.createInventoryPlan).toHaveBeenLastCalledWith({ gateway_id: otherGateway.id, previous_operation_id: 'new-applied-operation' })
  })

  it('ignores readback that completes while deactivated and supports a fresh GET after returning', async () => {
    const { api, visible } = await mount()
    const readback = deferred<InventoryPlan>()
    api.inventoryPlan.mockReturnValueOnce(readback.promise)
    await submit()
    await vi.waitFor(() => expect(api.inventoryPlan).toHaveBeenCalledTimes(1))
    visible.value = false
    await nextTick()
    readback.resolve(fixture())
    await settle()
    visible.value = true
    await nextTick()
    expect(result()).toBeNull()
    expect(container.textContent).toContain('stored readback is not confirmed')
    expect(button('Retry stored plan readback').disabled).toBe(false)
    button('Retry stored plan readback').click()
    await vi.waitFor(() => expect(result()?.textContent).toContain('Stored plan readback confirmed'))
    expect(api.createInventoryPlan).toHaveBeenCalledTimes(1)
    expect(api.inventoryPlan).toHaveBeenCalledTimes(2)
  })

  it('discards responses across principal changes and logout without exposing the prior plan', async () => {
    const { api, state } = await mount()
    const creation = deferred<InventoryPlan>()
    const readback = deferred<InventoryPlan>()
    api.createInventoryPlan.mockReturnValueOnce(creation.promise)
    api.inventoryPlan.mockReturnValueOnce(readback.promise)
    await submit()
    state.session.value = { subject: 'different-administrator', roles: ['administrator'] }
    creation.resolve(fixture())
    await settle()
    expect(api.inventoryPlan).not.toHaveBeenCalled()
    expect(result()).toBeNull()
    expect(container.textContent).not.toContain('stored readback is not confirmed')
    await submit()
    await vi.waitFor(() => expect(api.inventoryPlan).toHaveBeenCalledTimes(1))
    state.session.value = undefined
    readback.resolve(fixture())
    await settle()
    expect(result()).toBeNull()
    expect(container.textContent).not.toContain('stored readback is not confirmed')
    expect(container.textContent).not.toContain('Retry stored plan readback')
    expect(submitButton().disabled).toBe(true)
  })

  it('clears previous success on snapshot conflict or persistence failure and permits explicit retry', async () => {
    const { api } = await mount()
    await submit()
    await vi.waitFor(() => expect(result()).not.toBeNull())
    for (const failure of [
      new ControllerApiError('Inventory changed while planning', 409, 'snapshot_changed'),
      new ControllerApiError('Immutable plan could not be persisted', 503, 'plan_persistence_failed'),
    ]) {
      api.createInventoryPlan.mockRejectedValueOnce(failure)
      await submit()
      await vi.waitFor(() => expect(container.querySelector('[role="alert"]')?.textContent).toContain(failure.message))
      expect(result()).toBeNull()
      expect(container.textContent).not.toContain('Stored plan readback confirmed')
      expect(container.textContent).not.toContain('Retry stored plan readback')
      expect(submitButton().disabled).toBe(false)
      if (failure.status === 409) expect(container.textContent).toContain('Review the inventory and create a new plan')
    }
    expect(api.inventoryPlan).toHaveBeenCalledTimes(1)
    await submit()
    await vi.waitFor(() => expect(result()?.textContent).toContain('Stored plan readback confirmed'))
    expect(api.createInventoryPlan).toHaveBeenCalledTimes(4)
    expect(api.inventoryPlan).toHaveBeenCalledTimes(2)
  })

  it('labels applied and unavailable previous manifests without treating an empty baseline as live state', async () => {
    const { api } = await mount()
    for (const status of ['applied', 'unavailable', 'manifest_unavailable']) {
      api.inventoryPlan.mockResolvedValueOnce(fixture({ previous: { status, operation_id: 'previous-operation-9', ...(status === 'applied' ? { manifest_hash: 'f'.repeat(64) } : {}) } }))
      await submit()
      await vi.waitFor(() => expect(result()?.textContent).toContain(`Previous applied manifest${status}`))
      const compilation = container.querySelector('[aria-label="Inventory compilation preview"]')?.textContent
      expect(result()?.textContent).toContain('previous-operation-9')
      if (status === 'applied') {
        expect(compilation).toContain('Impact compares with the stored previous applied manifest')
        expect(compilation).not.toContain('empty baseline')
      } else {
        expect(compilation).toContain('No previous applied manifest is available; impact compares with an empty baseline')
        expect(compilation).not.toContain('Impact compares with the stored previous applied manifest')
      }
      expect(button('Deploy plan unavailable').disabled).toBe(true)
    }
  })
})
