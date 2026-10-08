// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApp, h, KeepAlive, nextTick, type App } from 'vue'
import { ControllerApi, ControllerApiError } from '../api/client'
import { useControllerState } from '../state'
import type { ProviderSchedule, ProviderSummary } from '../types'
import SubscriptionsView from './SubscriptionsView.vue'

const provider: ProviderSummary = {
  id: 'provider-1', name: 'Remote subscription', revision: 1, source: '[redacted]',
  fetchRoute: 'direct', sourceKind: 'manual', format: 'auto', state: 'never_fetched', gatewayStates: [],
}
const defaultSchedule: ProviderSchedule = {
  provider_id: provider.id, revision: 0, enabled: false, eligible: true,
  interval_seconds: 3600, auto_apply: false, running: false,
}
let app: App | undefined
let container: HTMLDivElement

async function mount(scheduleResult: ProviderSchedule | Error = defaultSchedule) {
  const api = {
    providers: vi.fn().mockResolvedValue([provider]),
    providerRevisions: vi.fn().mockResolvedValue([]),
    providerSchedule: vi.fn().mockImplementation(() => scheduleResult instanceof Error ? Promise.reject(scheduleResult) : Promise.resolve(scheduleResult)),
    saveProviderSchedule: vi.fn().mockResolvedValue({ ...defaultSchedule, revision: 1, enabled: true, interval_seconds: 900, next_due_at: '2026-10-08T08:15:00Z' }),
  }
  const state = useControllerState(api as unknown as ControllerApi)
  state.session.value = { subject: 'administrator', roles: ['administrator'] }
  state.capabilities.value = { 'provider.stage': true }
  container = document.createElement('div')
  document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => h(SubscriptionsView, { state }) }) })
  app.mount(container)
  await vi.waitFor(() => expect(container.textContent).toContain(provider.name))
  await nextTick()
  return api
}

afterEach(() => {
  app?.unmount()
  app = undefined
  container?.remove()
})

function scheduleForm() { return container.querySelector<HTMLFormElement>('form[aria-label="Refresh schedule for Remote subscription"]')! }
async function inputMinutes(value: string) {
  const input = scheduleForm().querySelector<HTMLInputElement>('input[type="number"]')!
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await nextTick()
}
async function submitSchedule() {
  scheduleForm().dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await nextTick()
}

describe('subscription refresh schedules', () => {
  it('uses server eligibility for a redacted URL and saves a staged-only schedule with the read revision', async () => {
    const api = await mount({ ...defaultSchedule, revision: 7 })
    expect(container.textContent).toContain('Subscription URL')
    expect(container.textContent).toContain('Refresh provider')
    expect(container.textContent).toContain('publication requires a separate action')
    const checkbox = scheduleForm().querySelector<HTMLInputElement>('input[type="checkbox"]')!
    expect(checkbox.checked).toBe(false)
    checkbox.checked = true
    checkbox.dispatchEvent(new Event('change', { bubbles: true }))
    await inputMinutes('15')
    await submitSchedule()
    await vi.waitFor(() => expect(api.saveProviderSchedule).toHaveBeenCalledWith(provider.id, { enabled: true, interval_seconds: 900, auto_apply: false }, 7))
    await vi.waitFor(() => expect(container.textContent).toContain('2026-10-08T08:15:00Z'))
    expect(container.textContent).toContain('Refresh schedule saved')
  })

  it('shows scheduler readback and blocks out-of-range intervals without a mutation', async () => {
    const api = await mount({ ...defaultSchedule, enabled: true, running: true, last_attempt_at: '2026-10-08T08:00:00Z', last_success_at: '2026-10-08T07:00:00Z', last_error: 'Fetch timed out', last_operation_id: 'refresh-9' })
    expect(container.textContent).toContain('Refresh running')
    expect(container.textContent).toContain('2026-10-08T08:00:00Z')
    expect(container.textContent).toContain('2026-10-08T07:00:00Z')
    expect(container.textContent).toContain('Fetch timed out')
    expect(container.textContent).toContain('refresh-9')
    await inputMinutes('4')
    await submitSchedule()
    expect(container.textContent).toContain('Choose an interval from 5 minutes to 7 days')
    await inputMinutes('10081')
    await submitSchedule()
    expect(api.saveProviderSchedule).not.toHaveBeenCalled()
  })

  it('keeps inventory usable when schedule readback fails and withholds unavailable source actions', async () => {
    await mount(new Error('Schedule temporarily unavailable'))
    expect(container.textContent).toContain('Refresh schedule: Schedule temporarily unavailable')
    expect(container.textContent).toContain('Source details unavailable')
    expect(container.textContent).toContain('Import new revision')
    expect(container.textContent).not.toContain('Refresh provider')
    expect(scheduleForm()).toBeNull()
  })

  it('hides URL refresh and scheduling for imported content', async () => {
    await mount({ ...defaultSchedule, eligible: false })
    expect(container.textContent).toContain('Imported content')
    expect(container.textContent).not.toContain('Refresh provider')
    expect(scheduleForm()).toBeNull()
  })

  it('reports a revision conflict without replacing the last confirmed schedule', async () => {
    const api = await mount()
    api.saveProviderSchedule.mockRejectedValue(new ControllerApiError('Schedule changed', 409, 'revision_conflict'))
    await inputMinutes('30')
    await submitSchedule()
    await vi.waitFor(() => expect(container.textContent).toContain('Schedule changed Refresh state before retrying.'))
    expect(container.textContent).not.toContain('Refresh schedule saved')
    expect(container.querySelector('.schedule-status')?.textContent).toContain('Disabled')
  })
})
