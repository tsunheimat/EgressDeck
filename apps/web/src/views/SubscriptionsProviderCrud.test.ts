// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, h, KeepAlive, nextTick, type App } from 'vue'
import { ControllerApi, ControllerApiError } from '../api/client'
import { useControllerState } from '../state'
import type { ProviderSummary } from '../types'
import SubscriptionsView from './SubscriptionsView.vue'

const provider: ProviderSummary = {
  id: 'provider-1', name: 'Private subscription', revision: 7, source: '[redacted]',
  fetchRoute: 'direct', sourceKind: 'url', format: 'auto', state: 'never_fetched', gatewayStates: [],
}
let app: App | undefined
let container: HTMLDivElement

async function mount(administrator = true) {
  let inventory = [{ ...provider }]
  const api = {
    providers: vi.fn().mockImplementation(async () => inventory),
    providerRevisions: vi.fn().mockResolvedValue([]),
    providerSchedule: vi.fn().mockResolvedValue({ provider_id: provider.id, revision: 1, enabled: false, eligible: true, interval_seconds: 3600, auto_apply: false, running: false }),
    updateProvider: vi.fn().mockImplementation(async (_id: string, body: { name: string; format: string; fetch_route: string }) => {
      const updated = { ...provider, name: body.name, format: body.format, fetchRoute: body.fetch_route, revision: 8 }
      inventory = [updated]
      return updated
    }),
    deleteProvider: vi.fn().mockImplementation(async () => { inventory = [] }),
    refreshProvider: vi.fn(), stageProvider: vi.fn(), applyProvider: vi.fn(),
  }
  const state = useControllerState(api as unknown as ControllerApi)
  state.session.value = { subject: 'tester', roles: [administrator ? 'administrator' : 'viewer'] }
  state.capabilities.value = { 'provider.stage': true }
  container = document.createElement('div')
  document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => h(SubscriptionsView, { state }) }) })
  app.mount(container)
  await vi.waitFor(() => expect(container.textContent).toContain(provider.name))
  await nextTick()
  return api
}

afterEach(() => { app?.unmount(); app = undefined; container?.remove() })

function button(label: string) { return Array.from(container.querySelectorAll<HTMLButtonElement>('button')).find((item) => item.textContent?.trim() === label)! }
async function click(label: string) { button(label).click(); await nextTick() }
function settings() { return container.querySelector<HTMLFormElement>('form[aria-label="订阅设置"]')! }
async function fill(input: HTMLInputElement, value: string) { input.value = value; input.dispatchEvent(new Event('input', { bubbles: true })); await nextTick() }
async function submit(form: HTMLFormElement) { form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); await nextTick() }
async function confirmDeletion() {
  await click('删除')
  const form = container.querySelector<HTMLFormElement>('form[aria-label="删除订阅"]')!
  const checkbox = form.querySelector<HTMLInputElement>('input[type="checkbox"]')!
  checkbox.checked = true
  checkbox.dispatchEvent(new Event('change', { bubbles: true }))
  await nextTick()
  await submit(form)
}

describe('provider settings and deletion', () => {
  it('omits an empty replacement source and binds settings edits to the inventory revision without staging', async () => {
    const api = await mount()
    await click('设置')
    const source = settings().querySelector<HTMLInputElement>('input[type="password"]')!
    expect(source.value).toBe('')
    expect(settings().textContent).not.toContain('[redacted]')
    expect(settings().textContent).toContain('保存设置不会获取、暂存或应用订阅版本')
    await fill(settings().querySelector<HTMLInputElement>('input')!, 'Updated name')
    await submit(settings())
    await vi.waitFor(() => expect(container.textContent).toContain('已保存订阅设置：Updated name'))
    expect(api.updateProvider).toHaveBeenCalledWith(provider.id, { name: 'Updated name', format: 'auto', fetch_route: 'direct' }, 7)
    expect(api.refreshProvider).not.toHaveBeenCalled()
    expect(api.stageProvider).not.toHaveBeenCalled()
    expect(api.applyProvider).not.toHaveBeenCalled()
    expect(settings()).toBeNull()
  })

  it('clears replacement credentials after acceptance and retries only readback', async () => {
    const api = await mount()
    await click('设置')
    await fill(settings().querySelector<HTMLInputElement>('input[type="password"]')!, 'https://example.test/sub?token=new-secret')
    api.providers.mockRejectedValueOnce(new Error('Readback unavailable'))
    await submit(settings())
    await vi.waitFor(() => expect(container.textContent).toContain('验证已保存设置'))
    expect(api.updateProvider).toHaveBeenCalledWith(provider.id, expect.objectContaining({ source: 'https://example.test/sub?token=new-secret' }), 7)
    expect(settings().querySelector<HTMLInputElement>('input[type="password"]')?.value).toBe('')
    expect(container.textContent).not.toContain('new-secret')
    expect(container.textContent).not.toContain('已保存订阅设置：')
    await submit(settings())
    await vi.waitFor(() => expect(container.textContent).toContain('已保存订阅设置：Private subscription'))
    expect(api.updateProvider).toHaveBeenCalledTimes(1)
  })

  it('keeps a conflicted settings draft without claiming a saved revision', async () => {
    const api = await mount()
    api.updateProvider.mockRejectedValue(new ControllerApiError('Provider changed', 409, 'revision_conflict'))
    await click('设置')
    await fill(settings().querySelector<HTMLInputElement>('input')!, 'My draft')
    await submit(settings())
    await vi.waitFor(() => expect(container.textContent).toContain('Provider changed 重试前请刷新状态。'))
    expect(settings().querySelector<HTMLInputElement>('input')?.value).toBe('My draft')
    expect(container.textContent).not.toContain('已保存订阅设置：')
  })

  it('requires deletion acknowledgement and reports an in-use provider without removing its card', async () => {
    const api = await mount()
    api.deleteProvider.mockRejectedValue(new ControllerApiError('Provider has active references', 409, 'provider_in_use'))
    await click('删除')
    expect(button('永久删除订阅').disabled).toBe(true)
    expect(api.deleteProvider).not.toHaveBeenCalled()
    await click('关闭')
    await confirmDeletion()
    await vi.waitFor(() => expect(container.textContent).toContain('Provider has active references'))
    expect(api.deleteProvider).toHaveBeenCalledWith(provider.id, 7)
    expect(container.querySelector('article')?.textContent).toContain(provider.name)
    expect(container.textContent).not.toContain('控制器回读已确认其不存在')
  })

  it('verifies deletion after a readback failure without deleting twice', async () => {
    const api = await mount()
    api.providers.mockRejectedValueOnce(new Error('Readback unavailable'))
    await confirmDeletion()
    await vi.waitFor(() => expect(container.textContent).toContain('验证删除'))
    expect(container.textContent).not.toContain('控制器回读已确认其不存在')
    await submit(container.querySelector<HTMLFormElement>('form[aria-label="删除订阅"]')!)
    await vi.waitFor(() => expect(container.textContent).toContain('控制器回读已确认其不存在'))
    expect(api.deleteProvider).toHaveBeenCalledTimes(1)
    expect(container.querySelector('article')).toBeNull()
  })

  it('withholds settings and deletion controls from viewers', async () => {
    await mount(false)
    expect(button('设置')).toBeUndefined()
    expect(button('删除')).toBeUndefined()
  })
})
