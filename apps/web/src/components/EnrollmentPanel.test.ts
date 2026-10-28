// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, h, KeepAlive, nextTick, ref, type App } from 'vue'
import { ControllerApi } from '../api/client'
import { useControllerState } from '../state'
import type { DeviceGroupSummary, DeviceSummary, InventoryPlan } from '../types'
import EnrollmentPanel from './EnrollmentPanel.vue'

const checksum = 'a'.repeat(64)
const deviceFixture: DeviceSummary = { id: 'client-1', name: 'Canary client', groupId: 'group-1', revision: 7, enrollment: 'unenrolled', coverage: 'ipv4', addresses: [{ address: '192.0.2.40', family: 'ipv4', valid: true, verifiedAt: '2026-10-08T01:00:00Z' }] }
const groupFixture: DeviceGroupSummary = { id: 'group-1', name: 'Canary group', gatewayId: 'gateway-1', revision: 3, policyId: 'policy-1', enabled: true, state: 'desired', drift: false }
function planFixture(): InventoryPlan {
  return {
    version: 1, checksum, scope: 'gateway', created_at: '2026-10-08T01:00:00Z', consistency: 'revision_rechecked', valid: true, deployable: true,
    configuration_deployable: true, enrollment_ready: true, blockers: [], enrollment_blockers: [], configuration_blockers: [],
    complete_artifact: { gateway_id: 'gateway-1', native_sha256: 'd'.repeat(64), content_hash: 'e'.repeat(64), base_revision: 2, expected_generation: 7, requires_guard: false },
    resource_revisions: [{ kind: 'device', id: deviceFixture.id, revision: 7, sha256: 'b'.repeat(64) }, { kind: 'device_group', id: groupFixture.id, revision: 3, sha256: 'c'.repeat(64) }],
    input: { gateway: { id: 'gateway-1' }, devices: [], device_groups: [], policies: [] },
    target: { gateway_id: 'gateway-1', observation_status: 'observed', capabilities: { implementation: 'test', version: '1', capabilities: [] } },
    previous: { status: 'unavailable' },
  }
}
function operationFixture(status = 'applied') {
  return { id: 'enroll-1', action: 'enable', target: { kind: 'gateway', id: 'gateway-1' }, status, requested_generation: 8, enrollment: { device_id: 'client-1', binding_id: 'binding-1', plan_checksum: checksum, previous_operation_id: '' }, created_at: '2026-10-08T01:00:00Z', updated_at: '2026-10-08T01:00:00Z', views: { desired: { generation: 8, revision: checksum, at: '2026-10-08T01:00:00Z' }, applied: { generation: 8, revision: checksum, status: 'configuration_applied', at: '2026-10-08T01:00:00Z' }, observed: { generation: 8, revision: checksum, status: 'configuration_applied', at: '2026-10-08T01:00:00Z' } } }
}
function response(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status }) }
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(fulfill => { resolve = fulfill })
  return { promise, resolve }
}

let app: App | undefined
let container: HTMLDivElement
afterEach(() => { app?.unmount(); app = undefined; container?.remove(); document.cookie = 'egressdeck_csrf=; Max-Age=0; path=/' })

async function mount() {
  const backend = {
    plan: planFixture(),
    bindings: [
      { id: 'wrong-gateway', gateway_id: 'gateway-2', alias: 'Wrong gateway', family: 'ipv4' },
      { id: 'wrong-family', gateway_id: 'gateway-1', alias: 'IPv6 binding', family: 'ipv6' },
      { id: 'binding-1', gateway_id: 'gateway-1', alias: 'Canary hosts', family: 'ipv4', interface_scope: 'lan' },
    ],
    operation: operationFixture(),
    post: vi.fn<(init?: RequestInit) => Promise<Response>>().mockImplementation(async () => response({ operation_id: 'enroll-1', status: 'applying' }, 202)),
    recoveryPost: vi.fn<(init?: RequestInit) => Promise<Response>>().mockImplementation(async () => response({ operation_id: 'recovery-1', status: 'applying' }, 202)),
    recoveryOperation: { ...operationFixture(), id: 'recovery-1', enrollment: { ...operationFixture().enrollment, previous_operation_id: 'enroll-1' } },
    getPlan: vi.fn<() => Promise<Response>>(),
    getOperation: vi.fn<() => Promise<Response>>(),
  }
  backend.getPlan.mockImplementation(async () => response(backend.plan))
  backend.getOperation.mockImplementation(async () => response(backend.operation))
  const fetcher = vi.fn<typeof fetch>().mockImplementation(async (url, init) => {
    const path = new URL(String(url), 'http://localhost').pathname
    if (path.startsWith('/api/v1/deployments/plans/')) return backend.getPlan()
    if (path === '/api/v1/firewall-bindings') return response({ items: backend.bindings })
    if (path === '/api/v1/deployments/enrollment' && init?.method === 'POST') return backend.post(init)
    if (path === '/api/v1/deployments/enrollment/recover' && init?.method === 'POST') return backend.recoveryPost(init)
    if (path === '/api/v1/operations/enroll-1') return backend.getOperation()
    if (path === '/api/v1/operations/recovery-1') return response(backend.recoveryOperation)
    throw new Error(`Unexpected route ${path}`)
  })
  const state = useControllerState(new ControllerApi('/api/v1', fetcher))
  state.session.value = { subject: 'admin', roles: ['administrator'] }
  state.lastInventoryPlanChecksum.value = checksum
  const devices = ref([structuredClone(deviceFixture)])
  const groups = ref([structuredClone(groupFixture)])
  const completed = vi.fn()
  const visible = ref(true)
  container = document.createElement('div')
  document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => visible.value ? h(EnrollmentPanel, { state, devices: devices.value, groups: groups.value, onCompleted: completed }) : null }) })
  app.mount(container)
  await nextTick()
  return { state, backend, fetcher, devices, groups, completed, visible }
}
function button(text: string) { return [...container.querySelectorAll<HTMLButtonElement>('button')].find(item => item.textContent?.trim() === text)! }
function form(label: string) { return container.querySelector<HTMLFormElement>(`form[aria-label="${label}"]`)! }
function select(label: string) { return [...container.querySelectorAll('label')].find(item => item.textContent?.startsWith(label))!.querySelector('select')! }
function input() { return form('读取纳管计划').querySelector('input')! }
async function change(control: HTMLInputElement | HTMLSelectElement, value: string) {
  control.value = value
  control.dispatchEvent(new Event('input', { bubbles: true }))
  control.dispatchEvent(new Event('change', { bubbles: true }))
  await nextTick()
}
async function submit(label: string) { form(label).dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); await nextTick() }
async function loaded() {
  await submit('读取纳管计划')
  await vi.waitFor(() => expect(container.textContent).toContain('已确认持久化纳管计划的回读'))
}
async function ready() {
  await loaded()
  await change(select('待纳管设备'), 'client-1')
  await change(select('纳管防火墙绑定'), 'binding-1')
}

describe('device enrollment', () => {
  it('loads the actual stored plan and bindings only on request, then submits narrow CAS and CSRF fields and reads the durable operation', async () => {
    const { fetcher, backend, completed } = await mount()
    document.cookie = 'egressdeck_csrf=enrollment-csrf; path=/'
    expect(fetcher).not.toHaveBeenCalled()
    expect(input().value).toBe(checksum)
    expect(button('纳管设备').disabled).toBe(true)
    await ready()
    expect(fetcher).toHaveBeenCalledWith(`/api/v1/deployments/plans/${checksum}`, expect.objectContaining({ credentials: 'include' }))
    expect([...select('纳管防火墙绑定').options].map(option => option.value)).toEqual(['', 'binding-1'])
    expect(button('纳管设备').disabled).toBe(false)
    await submit('纳管设备')
    await vi.waitFor(() => expect(completed).toHaveBeenCalledOnce())
    const request = backend.post.mock.calls[0]![0]!
    expect(new Headers(request.headers).get('If-Match')).toBe('7')
    expect(new Headers(request.headers).get('X-CSRF-Token')).toBe('enrollment-csrf')
    expect(new Headers(request.headers).get('Idempotency-Key')).toBeTruthy()
    expect(JSON.parse(String(request.body))).toEqual({ plan_checksum: checksum, device_id: 'client-1', binding_id: 'binding-1', expected_device_revision: 7 })
    expect(backend.getOperation).toHaveBeenCalledOnce()
    expect(container.querySelector('[aria-label="纳管操作"]')?.textContent).toContain('enroll-1: 已应用')
    expect(container.textContent).toContain('此操作尚未确认流量验证')
    expect([...container.querySelectorAll('.state-views dt')].map(item => item.textContent)).toEqual(['期望状态', '已应用', '已观测', '已验证'])
    expect(container.querySelector('.state-views div:last-child dd')?.textContent).toBe('尚未确认')
  })

  it('requires backend enrollment readiness independently of valid compilation, configuration readiness, deployable, and global capabilities', async () => {
    const { backend, state } = await mount()
    backend.plan.enrollment_ready = false
    backend.plan.enrollment_blockers = [{ severity: 'error', code: 'remote_firewall_fence_unavailable', message: 'Remote firewall fencing is unavailable.' }]
    state.capabilities.value = { 'policy.apply_generation': true, 'policy.validate': true }
    await ready()
    expect(container.textContent).toContain('Remote firewall fencing is unavailable')
    expect(button('纳管设备').disabled).toBe(true)
    await submit('纳管设备')
    expect(backend.post).not.toHaveBeenCalled()
  })

  it('blocks operators and viewers even for an enrollment-ready stored plan', async () => {
    const { state, backend } = await mount()
    await ready()
    for (const role of ['operator', 'viewer']) {
      state.session.value = { subject: 'admin', roles: [role] }
      await nextTick()
      expect(button('纳管设备').disabled).toBe(true)
      await submit('纳管设备')
    }
    expect(backend.post).not.toHaveBeenCalled()
  })

  it('fails closed on inconsistent readiness, blockers, or an absent or mismatched complete artifact', async () => {
    const { backend } = await mount()
    for (const mutate of [
      () => { backend.plan.valid = false },
      () => { backend.plan.enrollment_ready = undefined },
      () => { backend.plan.enrollment_blockers = [{ severity: 'error', code: 'blocked', message: 'Enrollment blocked.' }] },
      () => { backend.plan.complete_artifact = undefined },
      () => { backend.plan.complete_artifact!.gateway_id = 'gateway-2' },
      () => { backend.plan.complete_artifact!.native_sha256 = '' },
    ]) {
      backend.plan = planFixture(); mutate()
      await ready()
      expect(button('纳管设备').disabled).toBe(true)
      await submit('纳管设备')
    }
    expect(backend.post).not.toHaveBeenCalled()
  })

  it('allows qualified enrollment when standalone configuration application is blocked by guard requirements', async () => {
    const { backend } = await mount()
    backend.plan.complete_artifact!.requires_guard = true
    backend.plan.configuration_blockers = [{ severity: 'error', code: 'requires_guard', message: 'Use coordinated enrollment to apply this configuration.' }]
    for (const deployable of [false, undefined]) {
      backend.plan.configuration_deployable = deployable
      await ready()
      expect(button('纳管设备').disabled).toBe(false)
    }
  })

  it('requires current device and group revisions, enabled correct gateway group, and exactly one stored address', async () => {
    const { devices, groups, backend } = await mount()
    await ready()
    for (const mutate of [
      () => { devices.value[0]!.revision++ },
      () => { groups.value[0]!.revision++ },
      () => { groups.value[0]!.enabled = false },
      () => { groups.value[0]!.gatewayId = 'gateway-2' },
      () => { devices.value[0]!.addresses = [] },
      () => { devices.value[0]!.addresses[0]!.address = '' },
      () => { devices.value[0]!.enrollment = 'pending' },
      () => { devices.value[0]!.addresses.push({ address: '2001:db8::1', family: 'ipv6', valid: true, verifiedAt: '2026-10-08T01:00:00Z' }) },
    ]) {
      devices.value = [structuredClone(deviceFixture)]; groups.value = [structuredClone(groupFixture)]
      mutate()
      await nextTick()
      expect(button('纳管设备').disabled).toBe(true)
      await submit('纳管设备')
    }
    expect(backend.post).not.toHaveBeenCalled()
  })

  it('allows a stored address without prior enrollment verification, leaving traffic verification to the operation', async () => {
    const { devices } = await mount()
    devices.value[0]!.addresses[0]!.valid = false
    devices.value[0]!.addresses[0]!.verifiedAt = undefined
    await ready()
    expect(button('纳管设备').disabled).toBe(false)
  })

  it('ignores mismatched and stale plan readback after checksum changes', async () => {
    const { backend } = await mount()
    backend.plan.checksum = 'b'.repeat(64)
    await submit('读取纳管计划')
    await vi.waitFor(() => expect(container.textContent).toContain('持久化纳管计划与请求的校验和及网关不匹配'))
    expect(container.querySelector('[aria-label="纳管计划回读"]')).toBeNull()
    const late = deferred<Response>()
    backend.getPlan.mockReturnValueOnce(late.promise)
    await submit('读取纳管计划')
    await change(input(), 'c'.repeat(64))
    late.resolve(response(planFixture()))
    await nextTick(); await nextTick()
    expect(container.querySelector('[aria-label="纳管计划回读"]')).toBeNull()
  })

  it('discards prior plan and operation results across principal changes and deactivation', async () => {
    const { backend, state, visible, completed, fetcher } = await mount()
    await ready()
    const lateOperation = deferred<Response>()
    backend.getOperation.mockReturnValueOnce(lateOperation.promise)
    await submit('纳管设备')
    await vi.waitFor(() => expect(backend.getOperation).toHaveBeenCalledOnce())
    state.session.value = { subject: 'different-admin', roles: ['administrator'] }
    expect(fetcher.mock.calls.find(([url]) => String(url).endsWith('/operations/enroll-1'))?.[1]?.signal?.aborted).toBe(true)
    lateOperation.resolve(response(operationFixture()))
    await nextTick(); await nextTick()
    expect(input().value).toBe('')
    expect(container.querySelector('[aria-label="纳管操作"]')).toBeNull()
    expect(completed).not.toHaveBeenCalled()
    expect(state.lastOperation.value).toBeUndefined()
    await change(input(), checksum)
    const latePlan = deferred<Response>()
    backend.getPlan.mockReturnValueOnce(latePlan.promise)
    await submit('读取纳管计划')
    visible.value = false; await nextTick()
    latePlan.resolve(response(planFixture()))
    await nextTick(); await nextTick()
    visible.value = true; await nextTick()
    expect(container.querySelector('[aria-label="纳管计划回读"]')).toBeNull()
  })

  it('recovers a lost submission response using the same identity and body without automatic retries', async () => {
    const { backend, completed } = await mount()
    backend.post.mockRejectedValueOnce(new TypeError('Connection lost'))
    await ready()
    await submit('纳管设备')
    await vi.waitFor(() => expect(container.textContent).toContain('Connection lost'))
    expect(backend.post).toHaveBeenCalledOnce()
    expect(button('纳管设备').disabled).toBe(true)
    expect(button('读取纳管计划').disabled).toBe(true)
    button('恢复原纳管请求').click()
    await vi.waitFor(() => expect(completed).toHaveBeenCalledOnce())
    expect(backend.post).toHaveBeenCalledTimes(2)
    const original = backend.post.mock.calls[0]![0]!
    const retry = backend.post.mock.calls[1]![0]!
    expect(new Headers(retry.headers).get('Idempotency-Key')).toBe(new Headers(original.headers).get('Idempotency-Key'))
    expect(retry.body).toBe(original.body)
  })

  it('retains a late accepted operation across navigation and resumes with readback only', async () => {
    const { backend, visible, completed } = await mount()
    const accepted = deferred<Response>()
    backend.post.mockReturnValueOnce(accepted.promise)
    await ready(); await submit('纳管设备')
    await vi.waitFor(() => expect(backend.post).toHaveBeenCalledOnce())
    visible.value = false; await nextTick()
    accepted.resolve(response({ operation_id: 'enroll-1', status: 'applying' }, 202))
    await nextTick(); await nextTick(); await nextTick()
    expect(backend.getOperation).not.toHaveBeenCalled()
    visible.value = true; await nextTick()
    await vi.waitFor(() => expect(button('刷新纳管操作')).toBeDefined())
    button('刷新纳管操作').click()
    await vi.waitFor(() => expect(completed).toHaveBeenCalledOnce())
    expect(backend.post).toHaveBeenCalledOnce()
    expect(backend.getOperation).toHaveBeenCalledOnce()
  })

  it('refreshes an unknown durable operation with GET and never creates another enrollment request', async () => {
    const { backend, completed } = await mount()
    backend.operation = operationFixture('outcome_unknown')
    await ready(); await submit('纳管设备')
    await vi.waitFor(() => expect(container.textContent).toContain('操作结果未知'))
    expect(completed).toHaveBeenCalledOnce()
    expect(button('纳管设备').disabled).toBe(true)
    backend.operation = operationFixture()
    button('刷新纳管操作').click()
    await vi.waitFor(() => expect(completed).toHaveBeenCalledTimes(2))
    expect(backend.post).toHaveBeenCalledOnce()
    expect(backend.getOperation).toHaveBeenCalledTimes(2)
  })

  it('clears only an explicit preflight rejection with no operation identity, while preserving ambiguous failures', async () => {
    const { backend, completed } = await mount()
    await ready()
    backend.post.mockResolvedValueOnce(response({ error: { code: 'enrollment_source_invalid', message: 'source invalid' } }, 422))
    await submit('纳管设备')
    await vi.waitFor(() => expect(container.textContent).toContain('请修正输入'))
    expect(button('读取纳管计划').disabled).toBe(false)
    expect(container.querySelector('[aria-label="纳管操作"]')).toBeNull()
    backend.post.mockResolvedValueOnce(response({ error: { code: 'persistence_failed', message: 'gateway timeout' } }, 503))
    await ready()
    await submit('纳管设备')
    await vi.waitFor(() => expect(container.textContent).toContain('请先回读此请求'))
    expect(button('读取纳管计划').disabled).toBe(true)
    expect(completed).not.toHaveBeenCalled()
    const uncertain = backend.post.mock.calls[1]![0]!
    button('恢复原纳管请求').click()
    await vi.waitFor(() => expect(completed).toHaveBeenCalledOnce())
    const recovered = backend.post.mock.calls[2]![0]!
    expect(new Headers(recovered.headers).get('Idempotency-Key')).toBe(new Headers(uncertain.headers).get('Idempotency-Key'))
    expect(recovered.body).toBe(uncertain.body)
  })

  it('keeps a rejection with a durable operation identity or an idempotency conflict bound to the original request', async () => {
    const { backend } = await mount()
    backend.post.mockResolvedValueOnce(response({ error: { code: 'idempotency_conflict', message: 'Conflicting operation' } }, 409))
    await ready(); await submit('纳管设备')
    await vi.waitFor(() => expect(container.textContent).toContain('Conflicting operation'))
    expect(button('读取纳管计划').disabled).toBe(true)
    backend.post.mockResolvedValueOnce(response({ error: { code: 'revision_conflict', message: 'Operation requires readback', operation_id: 'enroll-1' } }, 412))
    button('恢复原纳管请求').click()
    await vi.waitFor(() => expect(button('刷新纳管操作')).toBeDefined())
    expect(button('读取纳管计划').disabled).toBe(true)
    expect(backend.post.mock.calls[0]![0]!.body).toBe(backend.post.mock.calls[1]![0]!.body)
  })

  it('rejects operation readback with the wrong target rather than updating shared state', async () => {
    const { backend, state, completed } = await mount()
    backend.operation.target.id = 'gateway-2'
    await ready(); await submit('纳管设备')
    await vi.waitFor(() => expect(container.textContent).toContain('纳管操作回读与已受理的操作及网关不匹配'))
    expect(state.lastOperation.value).toBeUndefined()
    expect(completed).not.toHaveBeenCalled()
    expect(button('纳管设备').disabled).toBe(true)
  })

  it('does not preserve a prior applied or verified display when fresh operation readback fails', async () => {
    const { backend, completed } = await mount()
    await ready(); await submit('纳管设备')
    await vi.waitFor(() => expect(completed).toHaveBeenCalledOnce())
    backend.getOperation.mockRejectedValueOnce(new TypeError('Readback unavailable'))
    button('刷新纳管操作').click()
    await vi.waitFor(() => expect(container.querySelector('[data-raw-diagnostic]')?.textContent).toBe('Readback unavailable'))
    expect(container.querySelector('.state-views')).toBeNull()
    expect(container.querySelector('[aria-label="纳管操作"]')?.textContent).toContain('等待回读')
    expect(button('准备下一次纳管')).toBeUndefined()
    expect(backend.post).toHaveBeenCalledOnce()
  })

  it('requires fresh plan readback after a terminal operation before preparing another enrollment', async () => {
    const { completed } = await mount()
    await ready(); await submit('纳管设备')
    await vi.waitFor(() => expect(completed).toHaveBeenCalledOnce())
    button('准备下一次纳管').click(); await nextTick()
    expect(container.querySelector('[aria-label="纳管操作"]')).toBeNull()
    expect(container.querySelector('[aria-label="纳管计划回读"]')).toBeNull()
    expect(button('纳管设备').disabled).toBe(true)
  })

  it('recovers a partial enrollment with fresh plan readback, bound targets, new identity and exact predecessor', async () => {
    const { backend, devices, completed, fetcher } = await mount()
    backend.operation = operationFixture('partially_applied')
    await ready(); await submit('纳管设备')
    await vi.waitFor(() => expect(completed).toHaveBeenCalledOnce())
    devices.value[0]!.enrollment = 'blocked'
    button('准备恢复纳管').click(); await nextTick()
    expect(button('执行纳管恢复').disabled).toBe(true)
    expect(container.textContent).toContain('上次请求代次 8')
    backend.plan.checksum = 'b'.repeat(64)
    backend.plan.target.generation = 9
    backend.plan.target.next_policy_generation = 10
    backend.recoveryOperation.enrollment.plan_checksum = backend.plan.checksum
    await change(input(), backend.plan.checksum); await loaded()
    expect(select('待纳管设备').value).toBe('client-1')
    expect(select('待纳管设备').disabled).toBe(true)
    expect(select('纳管防火墙绑定').value).toBe('binding-1')
    expect(select('纳管防火墙绑定').disabled).toBe(true)
    expect(container.textContent).toContain('请求策略代次：10')
    expect(button('执行纳管恢复').disabled).toBe(false)
    await submit('纳管设备')
    await vi.waitFor(() => expect(completed).toHaveBeenCalledTimes(2))
    expect(backend.post).toHaveBeenCalledOnce()
    expect(backend.recoveryPost).toHaveBeenCalledOnce()
    expect(fetcher.mock.calls.some(([url, init]) => url === '/api/v1/deployments/enrollment/recover' && init?.method === 'POST')).toBe(true)
    const request = backend.recoveryPost.mock.calls[0]![0]!
    expect(new Headers(request.headers).get('If-Match')).toBe('7')
    expect(new Headers(request.headers).get('Idempotency-Key')).not.toBe(new Headers(backend.post.mock.calls[0]![0]!.headers).get('Idempotency-Key'))
    expect(JSON.parse(String(request.body))).toEqual({ plan_checksum: 'b'.repeat(64), device_id: 'client-1', binding_id: 'binding-1', expected_device_revision: 7, previous_operation_id: 'enroll-1' })
  })

  it('allows recovery using unchanged checksum only after fresh stored readback and predecessor readback', async () => {
    const { backend, devices } = await mount()
    backend.operation = operationFixture('failed')
    devices.value[0]!.enrollment = 'blocked'
    const previous = () => form('读取上次纳管操作').querySelector('input')!
    await change(previous(), 'enroll-1'); await submit('读取上次纳管操作')
    await vi.waitFor(() => expect(container.textContent).toContain('正在准备恢复'))
    expect(button('执行纳管恢复').disabled).toBe(true)
    await loaded()
    expect(backend.getOperation).toHaveBeenCalledOnce()
    expect(backend.getPlan).toHaveBeenCalledOnce()
    expect(button('执行纳管恢复').disabled).toBe(false)
    await submit('纳管设备')
    await vi.waitFor(() => expect(backend.recoveryPost).toHaveBeenCalledOnce())
    expect(backend.post).not.toHaveBeenCalled()
  })

  it('rejects unsupported predecessor states and missing identity and discards stale predecessor results', async () => {
    const { backend, state } = await mount()
    const previous = () => form('读取上次纳管操作').querySelector('input')!
    await change(previous(), 'enroll-1')
    for (const status of ['applied', 'outcome_unknown', 'applying']) {
      backend.operation = operationFixture(status)
      await submit('读取上次纳管操作')
      await vi.waitFor(() => expect(container.textContent).toContain('恢复要求上次纳管操作失败或部分应用'))
      expect(container.querySelector('[aria-label="纳管恢复准备"]')).toBeNull()
    }
    backend.getOperation.mockResolvedValueOnce(response({ ...operationFixture('failed'), enrollment: undefined }))
    await submit('读取上次纳管操作')
    await vi.waitFor(() => expect(container.textContent).toContain('上次纳管回读未包含设备、绑定和计划标识'))
    const late = deferred<Response>()
    backend.getOperation.mockReturnValueOnce(late.promise)
    await submit('读取上次纳管操作')
    await change(previous(), 'another-operation')
    late.resolve(response(operationFixture('failed')))
    await nextTick(); await nextTick()
    expect(container.querySelector('[aria-label="纳管恢复准备"]')).toBeNull()
    state.session.value = { subject: 'admin', roles: ['operator'] }; await nextTick()
    expect(button('读取上次纳管操作').disabled).toBe(true)
    expect(backend.recoveryPost).not.toHaveBeenCalled()
  })

  it('refuses recovery plan gateway and operation enrollment identity mismatches', async () => {
    const { backend, completed } = await mount()
    backend.operation.enrollment.device_id = 'other-client'
    await ready(); await submit('纳管设备')
    await vi.waitFor(() => expect(container.textContent).toContain('纳管操作回读与已受理的设备、绑定和计划不匹配'))
    expect(completed).not.toHaveBeenCalled()
    backend.operation = operationFixture('failed')
    button('刷新纳管操作').click()
    await vi.waitFor(() => expect(completed).toHaveBeenCalledOnce())
    button('准备恢复纳管').click(); await nextTick()
    backend.plan.target.gateway_id = 'gateway-2'; backend.plan.input.gateway.id = 'gateway-2'
    await change(input(), checksum); await submit('读取纳管计划')
    await vi.waitFor(() => expect(container.textContent).toContain('恢复纳管需要原网关的持久化计划'))
    expect(button('执行纳管恢复').disabled).toBe(true)
    expect(backend.recoveryPost).not.toHaveBeenCalled()
  })

  it('preserves the recovery route, predecessor and key when its acknowledgement is lost', async () => {
    const { backend } = await mount()
    backend.operation = operationFixture('failed')
    await ready(); await submit('纳管设备')
    await vi.waitFor(() => expect(button('准备恢复纳管')).toBeDefined())
    button('准备恢复纳管').click(); await nextTick()
    await change(input(), checksum); await loaded()
    backend.recoveryPost.mockRejectedValueOnce(new TypeError('Recovery response lost'))
    await submit('纳管设备')
    await vi.waitFor(() => expect(container.textContent).toContain('Recovery response lost'))
    expect(button('读取纳管计划').disabled).toBe(true)
    button('恢复原纳管请求').click()
    await vi.waitFor(() => expect(backend.recoveryPost).toHaveBeenCalledTimes(2))
    expect(backend.post).toHaveBeenCalledOnce()
    const first = backend.recoveryPost.mock.calls[0]![0]!
    const replay = backend.recoveryPost.mock.calls[1]![0]!
    expect(replay.body).toBe(first.body)
    expect(new Headers(replay.headers).get('Idempotency-Key')).toBe(new Headers(first.headers).get('Idempotency-Key'))
  })
})
