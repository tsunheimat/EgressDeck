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
function card() { return container.querySelector<HTMLElement>('article[aria-label="Firewall binding HomeProxy"]')! }
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
  await click('Attach Host binding')
  await fill('alias', '  HomeProxy  ')
  await fill('interface_scope', '  lan  ')
  await fill('rule_ids', 'rule-1, rule-2\nrule-1\n')
}
async function submitAttach() {
  container.querySelector('form[aria-label="Attach Host binding"]')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
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
    expect(metric('Desired addresses')).toBe('0')
    expect(metric('Persisted addresses')).toBe('Unknown')
    expect(metric('Active addresses')).toBe('Unknown')
    expect(metric('Drift')).toBe('Unknown')
    expect(card().textContent).toContain('Never read')
    const empty = container.querySelector('article[aria-label="Firewall binding EmptyAlias"]')!
    expect([...empty.querySelectorAll('.binding-metrics dd')].map(item => item.textContent)).toEqual(['0', '0', '0', 'None observed'])
    expect(container.textContent).not.toMatch(/verified/i)
    expect([...container.querySelectorAll('button')].map(item => item.textContent).join(' ')).not.toMatch(/enroll|bypass|disable/i)
  })

  it('allows viewers to read the firewall and hides administrative registration', async () => {
    const { api, load } = await mount([unread], 'viewer')
    expect(button('Attach Host binding')).toBeUndefined()
    expect(button('Register gateway')).toBeUndefined()
    await click('Read firewall')
    await vi.waitFor(() => expect(api.readbackBinding).toHaveBeenCalledWith(unread.id))
    await vi.waitFor(() => expect(metric('Active addresses')).toBe('2'))
    expect(card().textContent).toContain('observed')
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
    expect(container.textContent).not.toContain('Host binding HomeProxy registered.')
    confirm(attached)
    await vi.waitFor(() => expect(container.textContent).toContain('Host binding HomeProxy registered.'))
    expect(card().textContent).toContain('desired')
    expect(card().textContent).toContain('Never read')
    expect(api.readbackBinding).not.toHaveBeenCalled()
    expect(load).toHaveBeenCalledOnce()
  })

  it('withholds attachment success when registration readback fails or differs', async () => {
    const { api } = await mount([])
    api.binding.mockResolvedValue({ ...unread, alias: 'OtherAlias' })
    await fillAttach()
    await submitAttach()
    await vi.waitFor(() => expect(container.textContent).toContain('registration could not be confirmed'))
    expect(container.textContent).toContain('Refresh before attaching it again')
    expect(container.textContent).not.toContain('Host binding HomeProxy registered.')
    expect(container.querySelector('article[aria-label="Firewall binding OtherAlias"]')).toBeNull()
  })

  it('rejects incomplete associations before calling the attach API', async () => {
    const { api } = await mount([])
    await fillAttach()
    await fill('rule_ids', ' , \n ')
    await submitAttach()
    expect(container.textContent).toContain('at least one steering rule ID')
    expect(api.attachBinding).not.toHaveBeenCalled()
  })

  it('shows a failed read and preserves the last successful observation from cached readback', async () => {
    const { api, load } = await mount([observed])
    api.readbackBinding.mockRejectedValue(new Error('Firewall unavailable'))
    api.binding.mockResolvedValue({ ...observed, observationStatus: 'error', observationError: 'Firewall unavailable', lastAttemptAt: '2026-10-08T08:10:00Z' })
    await click('Read firewall')
    await vi.waitFor(() => expect(container.textContent).toContain('Showing the last successful observation.'))
    expect(api.binding).toHaveBeenCalledWith(observed.id)
    expect(metric('Persisted addresses')).toBe('2')
    expect(metric('Active addresses')).toBe('2')
    expect(metric('Last observed')).toBe(observed.observedAt)
    expect(metric('Last attempt')).toBe('2026-10-08T08:10:00Z')
    expect(card().querySelector('.observation')?.textContent).toContain('Error')
    expect(card().textContent).toContain('Firewall unavailable')
    expect(load).toHaveBeenCalledOnce()
    expect(container.querySelector('.alert--good')).toBeNull()
  })

  it('keeps successful counts when both the firewall and cached read fail, then recovers on a later manual read', async () => {
    const { api } = await mount([observed])
    api.readbackBinding.mockRejectedValueOnce(new Error('Firewall timed out'))
    api.binding.mockRejectedValueOnce(new Error('Controller unavailable'))
    await click('Read firewall')
    await vi.waitFor(() => expect(card().textContent).toContain('Firewall timed out'))
    expect(metric('Active addresses')).toBe('2')
    expect(metric('Last observed')).toBe(observed.observedAt)
    await click('Read firewall')
    await vi.waitFor(() => expect(card().querySelector('[role="alert"]')).toBeNull())
    expect(metric('Active addresses')).toBe('2')
  })

  it('does not treat an unsuccessful observation returned by the controller as read success', async () => {
    const { api } = await mount([observed])
    api.readbackBinding.mockResolvedValue({ ...unread, observationStatus: 'error', observationError: 'Alias lookup failed' })
    api.binding.mockResolvedValue(unread)
    await click('Read firewall')
    await vi.waitFor(() => expect(card().textContent).toContain('Alias lookup failed'))
    expect(metric('Active addresses')).toBe('2')
    expect(metric('Last observed')).toBe(observed.observedAt)
    expect(card().querySelector('.observation')?.textContent).toContain('Error')
  })

  it('ages freshness locally without automatically calling the firewall or controller', async () => {
    vi.useFakeTimers({ now: new Date('2026-10-08T08:00:00Z') })
    const { api, load } = await mount([observed])
    expect(card().querySelector('.observation')?.textContent).toContain('Fresh')
    await vi.advanceTimersByTimeAsync(5 * 60_000 + 30_000)
    await nextTick()
    expect(card().querySelector('.observation')?.textContent).toContain('Stale')
    expect(api.bindings).toHaveBeenCalledOnce()
    expect(api.gateways).toHaveBeenCalledOnce()
    expect(api.binding).not.toHaveBeenCalled()
    expect(api.readbackBinding).not.toHaveBeenCalled()
    expect(load).not.toHaveBeenCalled()
  })

  it('marks observations dated in the future as stale', async () => {
    vi.useFakeTimers({ now: new Date('2026-10-08T07:59:00Z') })
    await mount([observed])
    expect(card().querySelector('.observation')?.textContent).toContain('Stale')
  })

  it('retains a completed firewall read when an older cached list arrives after reactivation', async () => {
    const { api, active } = await mount([observed])
    const firewall = deferred<FirewallBindingSummary>()
    const cachedList = deferred<FirewallBindingSummary[]>()
    api.readbackBinding.mockReturnValueOnce(firewall.promise)
    api.bindings.mockReturnValueOnce(cachedList.promise)
    await click('Read firewall')
    await revisit(active)
    const latest = { ...observed, activeCount: 7, persistedCount: 7, observedAt: '2026-10-08T08:10:00Z', lastAttemptAt: '2026-10-08T08:10:00Z' }
    firewall.resolve(latest)
    await vi.waitFor(() => expect(metric('Active addresses')).toBe('7'))
    cachedList.resolve([observed])
    await vi.waitFor(() => expect(button('Refresh')?.disabled).toBe(false))
    expect(metric('Active addresses')).toBe('7')
    expect(metric('Last observed')).toBe(latest.observedAt)
    expect(api.bindings).toHaveBeenCalledTimes(2)
  })

  it('retains a newer failed attempt when an earlier firewall success arrives late', async () => {
    const { api, active } = await mount([observed])
    const firewall = deferred<FirewallBindingSummary>()
    api.readbackBinding.mockReturnValueOnce(firewall.promise)
    const latestError = { ...observed, observationStatus: 'error' as const, observationError: 'Newer firewall attempt failed', lastAttemptAt: '2026-10-08T08:20:00Z' }
    api.bindings.mockResolvedValueOnce([latestError])
    await click('Read firewall')
    await revisit(active)
    await vi.waitFor(() => expect(card().textContent).toContain(latestError.observationError))
    firewall.resolve({ ...observed, activeCount: 5, observedAt: '2026-10-08T08:10:00Z', lastAttemptAt: '2026-10-08T08:10:00Z' })
    await vi.waitFor(() => expect(button('Read firewall')?.disabled).toBe(false))
    expect(metric('Active addresses')).toBe('2')
    expect(metric('Last attempt')).toBe(latestError.lastAttemptAt)
    expect(card().textContent).toContain(latestError.observationError)
    expect(card().querySelector('.observation')?.textContent).toContain('Error')
  })

  it('shows the newest cached error after an older request fails instead of retaining the older error message', async () => {
    const { api, active } = await mount([observed])
    const firewall = deferred<FirewallBindingSummary>()
    api.readbackBinding.mockReturnValueOnce(firewall.promise)
    const latestError = { ...observed, observationStatus: 'error' as const, observationError: 'Newest alias drift failure', lastAttemptAt: '2026-10-08T08:20:00Z' }
    api.bindings.mockResolvedValueOnce([latestError])
    api.binding.mockResolvedValueOnce(latestError)
    await click('Read firewall')
    await revisit(active)
    await vi.waitFor(() => expect(card().textContent).toContain(latestError.observationError))
    firewall.reject(new Error('Earlier request lost connection'))
    await vi.waitFor(() => expect(button('Read firewall')?.disabled).toBe(false))
    expect(card().textContent).toContain(latestError.observationError)
    expect(card().textContent).not.toContain('Earlier request lost connection')
    expect(metric('Last attempt')).toBe(latestError.lastAttemptAt)
  })

  it('clears a local read error after explicit successful cached refresh', async () => {
    const { api } = await mount([observed])
    api.readbackBinding.mockRejectedValueOnce(new Error('Read transport failed'))
    api.binding.mockResolvedValueOnce(observed)
    await click('Read firewall')
    await vi.waitFor(() => expect(card().textContent).toContain('Read transport failed'))
    api.bindings.mockResolvedValueOnce([observed])
    await click('Refresh')
    await vi.waitFor(() => expect(card().querySelector('[role="alert"]')).toBeNull())
    expect(metric('Last attempt')).toBe(observed.lastAttemptAt)
    expect(metric('Active addresses')).toBe('2')
  })

  it('uses a newer successful cached observation if another reader recovered after this request failed', async () => {
    const { api } = await mount([observed])
    api.readbackBinding.mockRejectedValueOnce(new Error('Earlier request failed'))
    const recovered = { ...observed, activeCount: 8, observedAt: '2026-10-08T08:20:00Z', lastAttemptAt: '2026-10-08T08:20:00Z' }
    api.binding.mockResolvedValueOnce(recovered)
    await click('Read firewall')
    await vi.waitFor(() => expect(metric('Active addresses')).toBe('8'))
    expect(metric('Last observed')).toBe(recovered.observedAt)
    expect(card().querySelector('[role="alert"]')).toBeNull()
  })

  it('preserves gateway registration and its controller readback check', async () => {
    const { api, load } = await mount()
    await click('Register gateway')
    const form = container.querySelector<HTMLFormElement>('form')!
    const inputs = [...form.querySelectorAll<HTMLInputElement>('input')]
    inputs[0]!.value = gateway.name
    inputs[0]!.dispatchEvent(new Event('input', { bubbles: true }))
    const endpoint = form.querySelector<HTMLInputElement>('[aria-label="Gateway endpoint"]')!
    endpoint.value = gateway.endpoint
    endpoint.dispatchEvent(new Event('input', { bubbles: true }))
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    await vi.waitFor(() => expect(container.textContent).toContain('Gateway Home gateway registered.'))
    expect(api.createGateway).toHaveBeenCalledWith({ name: gateway.name, endpoint: `${gateway.endpoint}/`, adapter: 'dae' })
    expect(api.gateways).toHaveBeenCalledTimes(2)
    expect(load).toHaveBeenCalledOnce()
  })
})
