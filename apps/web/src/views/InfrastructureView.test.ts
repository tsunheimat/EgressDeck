// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, h, KeepAlive, nextTick, ref, type App, type Ref } from 'vue'
import { ControllerApi } from '../api/client'
import { useControllerState } from '../state'
import type { FirewallBindingSummary, GatewaySummary } from '../types'
import InfrastructureView from './InfrastructureView.vue'

const gateway: GatewaySummary = { id: 'gateway-1', name: 'Home gateway', endpoint: 'https://gateway.example', health: 'unknown', capabilities: { supported: [] }, revision: 1, adapter: 'dae' }
const unread: FirewallBindingSummary = {
  id: 'binding-1', gatewayId: gateway.id, alias: 'HomeProxy', addressFamily: 'ipv4', interfaceScope: 'lan',
  desiredCount: 0, state: 'desired', observationStatus: 'never_read', ruleIds: ['rule-1'], verified: false,
}
const observed: FirewallBindingSummary = {
  ...unread, state: 'observed', persistedCount: 2, activeCount: 2, desiredCount: 2, drift: false,
  observationStatus: 'fresh', observedAt: '2026-10-08T08:00:00Z', lastAttemptAt: '2026-10-08T08:00:00Z',
}
let app: App | undefined
let container: HTMLDivElement

async function mount(bindings: FirewallBindingSummary[] = [unread], role = 'administrator') {
  const api = {
    gateways: vi.fn().mockResolvedValue([gateway]),
    bindings: vi.fn().mockResolvedValue(bindings),
    attachBinding: vi.fn().mockResolvedValue(unread),
    binding: vi.fn().mockResolvedValue(unread),
    readbackBinding: vi.fn().mockResolvedValue(observed),
    createGateway: vi.fn().mockResolvedValue(gateway),
  }
  const state = useControllerState(api as unknown as ControllerApi)
  state.session.value = { subject: role, roles: [role] }
  const load = vi.spyOn(state, 'load').mockResolvedValue()
  const active = ref(true)
  const otherPage = { render: () => h('div', 'Other page') }
  container = document.createElement('div')
  document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => active.value ? h(InfrastructureView, { state }) : h(otherPage) }) })
  app.mount(container)
  await vi.waitFor(() => expect(container.textContent).toContain(gateway.name))
  await nextTick()
  return { api, state, load, active }
}

afterEach(() => {
  app?.unmount()
  app = undefined
  container?.remove()
  vi.useRealTimers()
})

function button(text: string) { return [...container.querySelectorAll<HTMLButtonElement>('button')].find(item => item.textContent?.trim() === text) }
function card() { return container.querySelector<HTMLElement>('article[aria-label="防火墙绑定 HomeProxy"]')! }
function metric(label: string) { return [...card().querySelectorAll('dl > div')].find(item => item.querySelector('dt')?.textContent === label)?.querySelector('dd')?.textContent }
async function click(text: string) { const target = button(text); expect(target).toBeDefined(); target!.click(); await nextTick() }
async function fill(name: string, value: string) {
  const input = container.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(`[name="${name}"]`)!
  expect(input).not.toBeNull()
  input.value = value
  input.dispatchEvent(new Event(input.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }))
  await nextTick()
}
async function fillAttach() {
  await click('添加主机别名绑定')
  await fill('alias', '  HomeProxy  ')
  await fill('interface_scope', '  lan  ')
  await fill('rule_ids', 'rule-1, rule-2\nrule-1\n')
}
async function submitAttach() {
  container.querySelector('form[aria-label="添加主机别名绑定"]')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await nextTick()
}
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}
async function revisit(active: Ref<boolean>) {
  active.value = false
  await nextTick()
  active.value = true
  await nextTick()
}

describe('firewall binding registration and observation', () => {
  it('distinguishes unknown observations from genuine zero counts and never presents verification', async () => {
    await mount([unread, { ...observed, id: 'empty-binding', alias: 'EmptyAlias', activeCount: 0, persistedCount: 0, desiredCount: 0 }])
    expect(metric('期望地址数')).toBe('0')
    expect(metric('已持久化地址数')).toBe('未知')
    expect(metric('生效地址数')).toBe('未知')
    expect(metric('配置差异')).toBe('未知')
    expect(card().textContent).toContain('尚未读取')
    const empty = container.querySelector('article[aria-label="防火墙绑定 EmptyAlias"]')!
    expect([...empty.querySelectorAll('.binding-metrics dd')].map(item => item.textContent)).toEqual(['0', '0', '0', '尚未观测到'])
    expect(container.textContent).not.toMatch(/verified/i)
    expect([...container.querySelectorAll('button')].map(item => item.textContent).join(' ')).not.toMatch(/纳管|绕过|禁用/)
  })

  it('allows viewers to read the firewall and hides administrative registration', async () => {
    const { api, load } = await mount([unread], 'viewer')
    expect(button('添加主机别名绑定')).toBeUndefined()
    expect(button('登记网关')).toBeUndefined()
    await click('读取防火墙')
    await vi.waitFor(() => expect(api.readbackBinding).toHaveBeenCalledWith(unread.id))
    await vi.waitFor(() => expect(metric('生效地址数')).toBe('2'))
    expect(card().textContent).toContain('已观测')
    expect(card().textContent).toContain(observed.observedAt)
    expect(api.attachBinding).not.toHaveBeenCalled()
    expect(load).toHaveBeenCalledOnce()
  })

  it('confirms an administrator attachment before reporting registration', async () => {
    const { api, load } = await mount([])
    const attached = { ...unread, ruleIds: ['rule-1', 'rule-2'], aliasUUID: 'alias-uuid', addressFamily: 'ipv6' as const }
    api.attachBinding.mockResolvedValue(attached)
    let confirm!: (value: FirewallBindingSummary) => void
    api.binding.mockImplementation(() => new Promise<FirewallBindingSummary>(resolve => { confirm = resolve }))
    await fillAttach()
    await fill('alias_uuid', ' alias-uuid ')
    await fill('family', 'ipv6')
    await submitAttach()
    await vi.waitFor(() => expect(api.binding).toHaveBeenCalledWith(unread.id))
    expect(api.attachBinding).toHaveBeenCalledWith({ gateway_id: gateway.id, alias: 'HomeProxy', alias_uuid: 'alias-uuid', alias_type: 'host', family: 'ipv6', interface_scope: 'lan', rule_ids: ['rule-1', 'rule-2'] })
    expect(container.textContent).not.toContain('主机别名绑定 HomeProxy 已登记。')
    confirm(attached)
    await vi.waitFor(() => expect(container.textContent).toContain('主机别名绑定 HomeProxy 已登记。'))
    expect(card().textContent).toContain('期望状态')
    expect(card().textContent).toContain('尚未读取')
    expect(api.readbackBinding).not.toHaveBeenCalled()
    expect(load).toHaveBeenCalledOnce()
  })

  it('withholds attachment success when registration readback fails or differs', async () => {
    const { api } = await mount([])
    api.binding.mockResolvedValue({ ...unread, alias: 'OtherAlias' })
    await fillAttach()
    await submitAttach()
    await vi.waitFor(() => expect(container.textContent).toContain('无法确认登记'))
    expect(container.textContent).toContain('再次绑定前请刷新状态')
    expect(container.textContent).not.toContain('主机别名绑定 HomeProxy 已登记。')
    expect(container.querySelector('article[aria-label="防火墙绑定 OtherAlias"]')).toBeNull()
  })

  it('rejects incomplete associations before calling the attach API', async () => {
    const { api } = await mount([])
    await fillAttach()
    await fill('rule_ids', ' , \n ')
    await submitAttach()
    expect(container.textContent).toContain('至少一个流量引导规则 ID')
    expect(api.attachBinding).not.toHaveBeenCalled()
  })

  it('shows a failed read and preserves the last successful observation from cached readback', async () => {
    const { api, load } = await mount([observed])
    api.readbackBinding.mockRejectedValue(new Error('Firewall unavailable'))
    api.binding.mockResolvedValue({ ...observed, observationStatus: 'error', observationError: 'Firewall unavailable', lastAttemptAt: '2026-10-08T08:10:00Z' })
    await click('读取防火墙')
    await vi.waitFor(() => expect(container.textContent).toContain('显示上次成功的观测结果。'))
    expect(api.binding).toHaveBeenCalledWith(observed.id)
    expect(metric('已持久化地址数')).toBe('2')
    expect(metric('生效地址数')).toBe('2')
    expect(metric('最近观测')).toBe(observed.observedAt)
    expect(metric('最近尝试')).toBe('2026-10-08T08:10:00Z')
    expect(card().querySelector('.observation')?.textContent).toContain('错误')
    expect(card().textContent).toContain('Firewall unavailable')
    expect(load).toHaveBeenCalledOnce()
    expect(container.querySelector('.alert--good')).toBeNull()
  })

  it('keeps successful counts when both the firewall and cached read fail, then recovers on a later manual read', async () => {
    const { api } = await mount([observed])
    api.readbackBinding.mockRejectedValueOnce(new Error('Firewall timed out'))
    api.binding.mockRejectedValueOnce(new Error('Controller unavailable'))
    await click('读取防火墙')
    await vi.waitFor(() => expect(card().textContent).toContain('Firewall timed out'))
    expect(metric('生效地址数')).toBe('2')
    expect(metric('最近观测')).toBe(observed.observedAt)
    await click('读取防火墙')
    await vi.waitFor(() => expect(card().querySelector('[role="alert"]')).toBeNull())
    expect(metric('生效地址数')).toBe('2')
  })

  it('does not treat an unsuccessful observation returned by the controller as read success', async () => {
    const { api } = await mount([observed])
    api.readbackBinding.mockResolvedValue({ ...unread, observationStatus: 'error', observationError: 'Alias lookup failed' })
    api.binding.mockResolvedValue(unread)
    await click('读取防火墙')
    await vi.waitFor(() => expect(card().textContent).toContain('Alias lookup failed'))
    expect(metric('生效地址数')).toBe('2')
    expect(metric('最近观测')).toBe(observed.observedAt)
    expect(card().querySelector('.observation')?.textContent).toContain('错误')
  })

  it('ages freshness locally without automatically calling the firewall or controller', async () => {
    vi.useFakeTimers({ now: new Date('2026-10-08T08:00:00Z') })
    const { api, load } = await mount([observed])
    expect(card().querySelector('.observation')?.textContent).toContain('最新')
    await vi.advanceTimersByTimeAsync(5 * 60_000 + 30_000)
    await nextTick()
    expect(card().querySelector('.observation')?.textContent).toContain('已过期')
    expect(api.bindings).toHaveBeenCalledOnce()
    expect(api.gateways).toHaveBeenCalledOnce()
    expect(api.binding).not.toHaveBeenCalled()
    expect(api.readbackBinding).not.toHaveBeenCalled()
    expect(load).not.toHaveBeenCalled()
  })

  it('marks observations dated in the future as stale', async () => {
    vi.useFakeTimers({ now: new Date('2026-10-08T07:59:00Z') })
    await mount([observed])
    expect(card().querySelector('.observation')?.textContent).toContain('已过期')
  })

  it('retains a completed firewall read when an older cached list arrives after reactivation', async () => {
    const { api, active } = await mount([observed])
    const firewall = deferred<FirewallBindingSummary>()
    const cachedList = deferred<FirewallBindingSummary[]>()
    api.readbackBinding.mockReturnValueOnce(firewall.promise)
    api.bindings.mockReturnValueOnce(cachedList.promise)
    await click('读取防火墙')
    await revisit(active)
    const latest = { ...observed, activeCount: 7, persistedCount: 7, observedAt: '2026-10-08T08:10:00Z', lastAttemptAt: '2026-10-08T08:10:00Z' }
    firewall.resolve(latest)
    await vi.waitFor(() => expect(metric('生效地址数')).toBe('7'))
    cachedList.resolve([observed])
    await vi.waitFor(() => expect(button('刷新')?.disabled).toBe(false))
    expect(metric('生效地址数')).toBe('7')
    expect(metric('最近观测')).toBe(latest.observedAt)
    expect(api.bindings).toHaveBeenCalledTimes(2)
  })

  it('retains a newer failed attempt when an earlier firewall success arrives late', async () => {
    const { api, active } = await mount([observed])
    const firewall = deferred<FirewallBindingSummary>()
    api.readbackBinding.mockReturnValueOnce(firewall.promise)
    const latestError = { ...observed, observationStatus: 'error' as const, observationError: 'Newer firewall attempt failed', lastAttemptAt: '2026-10-08T08:20:00Z' }
    api.bindings.mockResolvedValueOnce([latestError])
    await click('读取防火墙')
    await revisit(active)
    await vi.waitFor(() => expect(card().textContent).toContain(latestError.observationError))
    firewall.resolve({ ...observed, activeCount: 5, observedAt: '2026-10-08T08:10:00Z', lastAttemptAt: '2026-10-08T08:10:00Z' })
    await vi.waitFor(() => expect(button('读取防火墙')?.disabled).toBe(false))
    expect(metric('生效地址数')).toBe('2')
    expect(metric('最近尝试')).toBe(latestError.lastAttemptAt)
    expect(card().textContent).toContain(latestError.observationError)
    expect(card().querySelector('.observation')?.textContent).toContain('错误')
  })

  it('shows the newest cached error after an older request fails instead of retaining the older error message', async () => {
    const { api, active } = await mount([observed])
    const firewall = deferred<FirewallBindingSummary>()
    api.readbackBinding.mockReturnValueOnce(firewall.promise)
    const latestError = { ...observed, observationStatus: 'error' as const, observationError: 'Newest alias drift failure', lastAttemptAt: '2026-10-08T08:20:00Z' }
    api.bindings.mockResolvedValueOnce([latestError])
    api.binding.mockResolvedValueOnce(latestError)
    await click('读取防火墙')
    await revisit(active)
    await vi.waitFor(() => expect(card().textContent).toContain(latestError.observationError))
    firewall.reject(new Error('Earlier request lost connection'))
    await vi.waitFor(() => expect(button('读取防火墙')?.disabled).toBe(false))
    expect(card().textContent).toContain(latestError.observationError)
    expect(card().textContent).not.toContain('Earlier request lost connection')
    expect(metric('最近尝试')).toBe(latestError.lastAttemptAt)
  })

  it('clears a local read error after explicit successful cached refresh', async () => {
    const { api } = await mount([observed])
    api.readbackBinding.mockRejectedValueOnce(new Error('Read transport failed'))
    api.binding.mockResolvedValueOnce(observed)
    await click('读取防火墙')
    await vi.waitFor(() => expect(card().textContent).toContain('Read transport failed'))
    api.bindings.mockResolvedValueOnce([observed])
    await click('刷新')
    await vi.waitFor(() => expect(card().querySelector('[role="alert"]')).toBeNull())
    expect(metric('最近尝试')).toBe(observed.lastAttemptAt)
    expect(metric('生效地址数')).toBe('2')
  })

  it('uses a newer successful cached observation if another reader recovered after this request failed', async () => {
    const { api } = await mount([observed])
    api.readbackBinding.mockRejectedValueOnce(new Error('Earlier request failed'))
    const recovered = { ...observed, activeCount: 8, observedAt: '2026-10-08T08:20:00Z', lastAttemptAt: '2026-10-08T08:20:00Z' }
    api.binding.mockResolvedValueOnce(recovered)
    await click('读取防火墙')
    await vi.waitFor(() => expect(metric('生效地址数')).toBe('8'))
    expect(metric('最近观测')).toBe(recovered.observedAt)
    expect(card().querySelector('[role="alert"]')).toBeNull()
  })

  it('preserves gateway registration and its controller readback check', async () => {
    const { api, load } = await mount()
    await click('登记网关')
    const form = container.querySelector<HTMLFormElement>('form')!
    const inputs = [...form.querySelectorAll<HTMLInputElement>('input')]
    inputs[0]!.value = gateway.name
    inputs[0]!.dispatchEvent(new Event('input', { bubbles: true }))
    const endpoint = form.querySelector<HTMLInputElement>('[aria-label="网关地址"]')!
    endpoint.value = gateway.endpoint
    endpoint.dispatchEvent(new Event('input', { bubbles: true }))
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    await vi.waitFor(() => expect(container.textContent).toContain('网关 Home gateway 已登记。'))
    expect(api.createGateway).toHaveBeenCalledWith({ name: gateway.name, endpoint: `${gateway.endpoint}/`, adapter: 'dae' })
    expect(api.gateways).toHaveBeenCalledTimes(2)
    expect(load).toHaveBeenCalledOnce()
  })
})
