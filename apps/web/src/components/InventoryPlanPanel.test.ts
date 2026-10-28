// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, h, KeepAlive, nextTick, ref, type App } from 'vue'
import { ControllerApi, ControllerApiError } from '../api/client'
import { useControllerState } from '../state'
import type { GatewaySummary, InventoryPlan, OperationSummary } from '../types'
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

function deployable(): InventoryPlan {
  return fixture({
    deployable: true, configuration_deployable: true, configuration_blockers: null, enrollment_ready: false,
    complete_artifact: { gateway_id: gateway.id, native_sha256: 'f'.repeat(64), content_hash: 'e'.repeat(64), base_revision: 3, expected_generation: 8, requires_guard: false },
    target: { ...fixture().target, next_policy_generation: 9 },
    enrollment_blockers: [{ severity: 'error', code: 'firewall_fence_unavailable', message: 'Firewall fencing is unavailable.' }],
  })
}
function appliedOperation(overrides: Partial<OperationSummary> = {}): OperationSummary {
  return {
    id: 'apply-plan-1', action: 'policy.apply_generation', target: `gateway:${gateway.id}`, status: 'applied', createdAt: '2026-10-08T00:00:00Z', updatedAt: '2026-10-08T00:00:01Z',
    views: {
      desired: { generation: 9, revision: checksum, at: '2026-10-08T00:00:00Z' },
      applied: { generation: 9, revision: checksum, status: 'configuration_observed', at: '2026-10-08T00:00:01Z' },
      observed: { generation: 9, revision: checksum, status: 'configuration_observed', at: '2026-10-08T00:00:01Z' },
    }, ...overrides,
  }
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
    applyInventoryPlan: vi.fn().mockResolvedValue({ operationId: 'apply-plan-1', status: 'applying' }),
    waitForOperation: vi.fn().mockResolvedValue(appliedOperation()),
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

function form() { return container.querySelector<HTMLFormElement>('form[aria-label="创建清单计划"]')! }
function submitButton() { return form().querySelector<HTMLButtonElement>('button[type="submit"]')! }
function result() { return container.querySelector('[aria-label="持久化清单计划结果"]') }
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
    await vi.waitFor(() => expect(result()?.textContent).toContain('已确认持久化计划的回读'))
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
    expect(container.textContent).toContain('尚未确认持久化回读')
    expect(result()).toBeNull()
    expect(submitButton().disabled).toBe(true)
    readback.resolve(fixture({ created_at: '2026-10-08T08:00:00Z', deployable: true, blockers: [] }))
    await vi.waitFor(() => expect(result()?.textContent).toContain('已确认持久化计划的回读'))
    expect(result()?.textContent).toContain('2026-10-08T08:00:00Z')
    expect(result()?.textContent).not.toContain('2026-10-08T09:00:00Z')
    expect(result()?.textContent).toContain('已重新检查版本')
    expect(result()?.textContent).toContain('网关能力观测不代表配置已应用或真实流量已验证')
    expect(result()?.textContent).toContain('清单变化后需创建新计划')
    expect(result()?.textContent).toContain('这里只包含路由片段')
    expect(container.querySelector('tbody tr')?.textContent).toContain(gateway.id)
    expect(button('应用网关配置').disabled).toBe(true)
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
    const retry = button('重试持久化计划回读')
    expect(retry.disabled).toBe(false)
    retry.click()
    await vi.waitFor(() => expect(result()?.textContent).toContain('已确认持久化计划的回读'))
    expect(api.createInventoryPlan).toHaveBeenCalledTimes(1)
    expect(api.inventoryPlan).toHaveBeenCalledTimes(2)
    expect(api.inventoryPlan).toHaveBeenLastCalledWith(checksum)
    expect(container.querySelector('[role="alert"]')).toBeNull()
  })

  it('rejects malformed POST checksums and readback for another checksum, gateway, or scope', async () => {
    const { api } = await mount()
    api.createInventoryPlan.mockResolvedValueOnce(fixture({ checksum: 'invalid-checksum' }))
    await submit()
    await vi.waitFor(() => expect(container.textContent).toContain('无效的计划校验和'))
    expect(api.inventoryPlan).not.toHaveBeenCalled()
    for (const mismatch of [
      { checksum: 'f'.repeat(64) },
      { target: { gateway_id: otherGateway.id } },
      { input: { gateway: { id: otherGateway.id } } },
      { scope: 'device_group' },
    ]) {
      api.inventoryPlan.mockResolvedValueOnce(fixture(mismatch))
      await submit()
      await vi.waitFor(() => expect(container.textContent).toContain('持久化计划与请求的校验和及网关不匹配'))
      expect(result()).toBeNull()
      expect(button('重试持久化计划回读').disabled).toBe(false)
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
    await vi.waitFor(() => expect(result()?.textContent).toContain('编译未通过'))
    expect(container.querySelector('[aria-label="计划校验诊断"]')?.textContent).toContain('strict_ipv6_unqualified')
    expect(container.querySelector('[aria-label="计划校验诊断"]')?.textContent).toContain('device_groups[0]')
    expect(container.querySelector('[aria-label="部署阻塞项"]')?.textContent).toContain('coverage_unqualified')
    expect(container.querySelector('[aria-label="清单编译预览"]')).toBeNull()
    expect(container.textContent).not.toContain('只读原生路由预览')
    expect(button('应用网关配置').disabled).toBe(true)
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
    expect(container.textContent).not.toContain('尚未确认持久化回读')
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
    expect(container.textContent).toContain('尚未确认持久化回读')
    expect(button('重试持久化计划回读').disabled).toBe(false)
    button('重试持久化计划回读').click()
    await vi.waitFor(() => expect(result()?.textContent).toContain('已确认持久化计划的回读'))
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
    expect(container.textContent).not.toContain('尚未确认持久化回读')
    await submit()
    await vi.waitFor(() => expect(api.inventoryPlan).toHaveBeenCalledTimes(1))
    state.session.value = undefined
    readback.resolve(fixture())
    await settle()
    expect(result()).toBeNull()
    expect(container.textContent).not.toContain('尚未确认持久化回读')
    expect(container.textContent).not.toContain('重试持久化计划回读')
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
      expect(container.textContent).not.toContain('已确认持久化计划的回读')
      expect(container.textContent).not.toContain('重试持久化计划回读')
      expect(submitButton().disabled).toBe(false)
      if (failure.status === 409) expect(container.textContent).toContain('请检查清单并创建新计划')
    }
    expect(api.inventoryPlan).toHaveBeenCalledTimes(1)
    await submit()
    await vi.waitFor(() => expect(result()?.textContent).toContain('已确认持久化计划的回读'))
    expect(api.createInventoryPlan).toHaveBeenCalledTimes(4)
    expect(api.inventoryPlan).toHaveBeenCalledTimes(2)
  })

  it('labels applied and unavailable previous manifests without treating an empty baseline as live state', async () => {
    const { api } = await mount()
    for (const status of ['applied', 'unavailable', 'manifest_unavailable']) {
      api.inventoryPlan.mockResolvedValueOnce(fixture({ previous: { status, operation_id: 'previous-operation-9', ...(status === 'applied' ? { manifest_hash: 'f'.repeat(64) } : {}) } }))
      await submit()
      await vi.waitFor(() => expect(result()?.textContent).toContain(`上次已应用清单${status === 'applied' ? '已应用' : status === 'manifest_unavailable' ? '清单不可用' : '不可用'}`))
      const compilation = container.querySelector('[aria-label="清单编译预览"]')?.textContent
      expect(result()?.textContent).toContain('previous-operation-9')
      if (status === 'applied') {
        expect(compilation).toContain('影响范围与上次持久化的已应用清单比较')
        expect(compilation).not.toContain('空基线')
      } else {
        expect(compilation).toContain('没有上次已应用清单；影响范围与空基线比较')
        expect(compilation).not.toContain('影响范围与上次持久化的已应用清单比较')
      }
      expect(button('应用网关配置').disabled).toBe(true)
    }
  })

  it('applies a complete immutable plan and confirms configuration without claiming client traffic verification', async () => {
    const { api, state } = await mount()
    api.inventoryPlan.mockResolvedValueOnce(deployable())
    const readback = deferred<OperationSummary>()
    api.waitForOperation.mockReturnValueOnce(readback.promise)
    await submit()
    await vi.waitFor(() => expect(button('应用网关配置').disabled).toBe(false))
    expect(state.lastInventoryPlanChecksum.value).toBe(checksum)
    expect(container.querySelector('[aria-label="完整网关配置预览"]')?.textContent).toContain('此预览不包含凭据')
    expect(container.querySelector('[aria-label="纳管就绪状态"]')?.textContent).toContain('firewall_fence_unavailable')
    button('应用网关配置').click()
    await vi.waitFor(() => expect(api.waitForOperation).toHaveBeenCalledWith('apply-plan-1', expect.any(AbortSignal)))
    expect(api.applyInventoryPlan).toHaveBeenCalledWith(checksum, expect.any(String))
    expect(container.textContent).not.toContain('已确认网关配置应用与回读')
    readback.resolve(appliedOperation())
    await vi.waitFor(() => expect(container.textContent).toContain('已确认网关配置应用与回读'))
    expect(container.textContent).toContain('客户端流量验证配置应用不构成流量验证')
    expect(state.lastOperation.value?.id).toBe('apply-plan-1')
    expect(button('应用网关配置').disabled).toBe(true)
  })

  it('requires explicit configuration readiness, matching complete artifact and administrator authority', async () => {
    const { api, state } = await mount()
    for (const invalid of [
      { configuration_deployable: undefined }, { configuration_deployable: false }, { complete_artifact: undefined },
      { complete_artifact: { ...deployable().complete_artifact, gateway_id: otherGateway.id } },
      { configuration_blockers: [{ code: 'unsupported', severity: 'error', message: 'Unavailable' }] },
      { target: { ...deployable().target, next_policy_generation: 0 } },
    ]) {
      api.inventoryPlan.mockResolvedValueOnce({ ...deployable(), ...invalid } as InventoryPlan)
      await submit()
      await vi.waitFor(() => expect(result()).not.toBeNull())
      expect(button('应用网关配置').disabled).toBe(true)
    }
    api.inventoryPlan.mockResolvedValueOnce(deployable())
    await submit()
    await vi.waitFor(() => expect(button('应用网关配置').disabled).toBe(false))
    state.session.value = { subject: 'administrator', roles: ['operator'] }
    await nextTick()
    expect(button('应用网关配置').disabled).toBe(true)
    expect(api.applyInventoryPlan).not.toHaveBeenCalled()
  })

  it('retains the idempotency key after acceptance is lost and reads an unresolved operation without another mutation', async () => {
    const { api } = await mount()
    api.inventoryPlan.mockResolvedValueOnce(deployable())
    api.applyInventoryPlan.mockRejectedValueOnce(new Error('Connection lost after send'))
    api.waitForOperation.mockResolvedValueOnce(appliedOperation({ status: 'outcome_unknown', views: { desired: appliedOperation().views!.desired } }))
    await submit()
    await vi.waitFor(() => expect(button('应用网关配置').disabled).toBe(false))
    button('应用网关配置').click()
    await vi.waitFor(() => expect(container.textContent).toContain('Connection lost after send'))
    expect(submitButton().disabled).toBe(true)
    await submit()
    expect(api.createInventoryPlan).toHaveBeenCalledTimes(1)
    button('重试同一应用请求').click()
    await vi.waitFor(() => expect(container.textContent).toContain('操作结果尚未确定'))
    expect(api.applyInventoryPlan.mock.calls[1]).toEqual(api.applyInventoryPlan.mock.calls[0])
    expect(button('应用网关配置').disabled).toBe(true)
    button('读取配置操作').click()
    await vi.waitFor(() => expect(container.textContent).toContain('已确认网关配置应用与回读'))
    expect(api.applyInventoryPlan).toHaveBeenCalledTimes(2)
    expect(api.waitForOperation).toHaveBeenCalledTimes(2)
  })

  it('does not confirm applied state with the wrong runtime generation and clears stale confirmation when readback fails', async () => {
    const { api } = await mount()
    api.inventoryPlan.mockResolvedValueOnce(deployable())
    api.waitForOperation.mockResolvedValueOnce(appliedOperation({ views: { ...appliedOperation().views, observed: { generation: 8, revision: checksum, status: 'configuration_observed', at: '' } } }))
    await submit()
    await vi.waitFor(() => expect(button('应用网关配置').disabled).toBe(false))
    button('应用网关配置').click()
    await vi.waitFor(() => expect(container.textContent).toContain('缺少匹配的已应用和已观测配置证据'))
    expect(container.textContent).not.toContain('已确认网关配置应用与回读')
    button('读取配置操作').click()
    await vi.waitFor(() => expect(container.textContent).toContain('已确认网关配置应用与回读'))
    api.waitForOperation.mockRejectedValueOnce(new Error('Gateway readback unavailable'))
    button('读取配置操作').click()
    await vi.waitFor(() => expect(container.textContent).toContain('Gateway readback unavailable'))
    expect(container.textContent).not.toContain('已确认网关配置应用与回读')
    expect(api.applyInventoryPlan).toHaveBeenCalledTimes(1)
  })

  it('allows a new plan after a definite preflight conflict but preserves identity after ambiguous persistence failure', async () => {
    const { api } = await mount()
    api.inventoryPlan.mockResolvedValue(deployable())
    api.applyInventoryPlan.mockRejectedValueOnce(new ControllerApiError('Runtime generation changed', 412, 'revision_conflict'))
    await submit()
    await vi.waitFor(() => expect(button('应用网关配置').disabled).toBe(false))
    button('应用网关配置').click()
    await vi.waitFor(() => expect(container.textContent).toContain('请求在应用前被拒绝'))
    expect(submitButton().disabled).toBe(false)
    expect(container.querySelector('[aria-label="配置操作回读"]')).toBeNull()
    await submit()
    await vi.waitFor(() => expect(button('应用网关配置').disabled).toBe(false))
    api.applyInventoryPlan.mockRejectedValueOnce(new ControllerApiError('Persistence uncertain', 503, 'persistence_failed'))
    button('应用网关配置').click()
    await vi.waitFor(() => expect(container.textContent).toContain('Persistence uncertain'))
    expect(submitButton().disabled).toBe(true)
    button('重试同一应用请求').click()
    await vi.waitFor(() => expect(container.textContent).toContain('已确认网关配置应用与回读'))
    expect(api.applyInventoryPlan.mock.calls[2]).toEqual(api.applyInventoryPlan.mock.calls[1])
  })

  it('rejects an operation for another plan or gateway and ignores readback across navigation and principal changes', async () => {
    const { api, state, visible } = await mount()
    api.inventoryPlan.mockResolvedValue(deployable())
    api.waitForOperation.mockResolvedValueOnce(appliedOperation({ target: `gateway:${otherGateway.id}` }))
    await submit()
    await vi.waitFor(() => expect(button('应用网关配置').disabled).toBe(false))
    button('应用网关配置').click()
    await vi.waitFor(() => expect(container.textContent).toContain('操作回读与此计划及网关不匹配'))
    expect(state.lastOperation.value).toBeUndefined()
    const delayed = deferred<OperationSummary>()
    api.waitForOperation.mockReturnValueOnce(delayed.promise)
    button('读取配置操作').click()
    await vi.waitFor(() => expect(api.waitForOperation).toHaveBeenCalledTimes(2))
    visible.value = false
    await nextTick()
    delayed.resolve(appliedOperation())
    await settle()
    visible.value = true
    await nextTick()
    expect(container.textContent).not.toContain('已确认网关配置应用与回读')
    button('读取配置操作').click()
    await vi.waitFor(() => expect(container.textContent).toContain('已确认网关配置应用与回读'))
    state.session.value = { subject: 'new-administrator', roles: ['administrator'] }
    await nextTick()
    expect(container.querySelector('[aria-label="配置操作回读"]')).toBeNull()
    expect(state.lastInventoryPlanChecksum.value).toBeUndefined()
  })

  it('uses checksum CAS and idempotency headers with an empty public request body', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response(JSON.stringify({ id: 'apply-plan-1', status: 'applying' }), { status: 202 }))
    const api = new ControllerApi('/api/v1', fetcher)
    expect(await api.applyInventoryPlan(checksum, 'once-1')).toEqual({ operationId: 'apply-plan-1', status: 'applying' })
    expect(fetcher).toHaveBeenCalledWith(`/api/v1/deployments/plans/${checksum}/apply`, expect.objectContaining({ method: 'POST', body: '{}', headers: expect.objectContaining({ 'If-Match': `"${checksum}"`, 'Idempotency-Key': 'once-1' }) }))
  })

  it('retains a late accepted operation while away and resumes readback without repeating the mutation', async () => {
    const { api, visible } = await mount()
    api.inventoryPlan.mockResolvedValueOnce(deployable())
    const accepted = deferred<{ operationId: string; status: string }>()
    api.applyInventoryPlan.mockReturnValueOnce(accepted.promise)
    await submit()
    await vi.waitFor(() => expect(button('应用网关配置').disabled).toBe(false))
    button('应用网关配置').click()
    await vi.waitFor(() => expect(api.applyInventoryPlan).toHaveBeenCalledTimes(1))
    visible.value = false
    await nextTick()
    accepted.resolve({ operationId: 'apply-plan-1', status: 'applied' })
    await settle()
    expect(api.waitForOperation).not.toHaveBeenCalled()
    visible.value = true
    await nextTick()
    expect(button('读取配置操作')).toBeDefined()
    button('读取配置操作').click()
    await vi.waitFor(() => expect(container.textContent).toContain('已确认网关配置应用与回读'))
    expect(api.applyInventoryPlan).toHaveBeenCalledTimes(1)
  })
})
