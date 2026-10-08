// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest'
import { createApp, h, KeepAlive, nextTick, type App } from 'vue'
import { ControllerApi } from '../api/client'
import { useControllerState } from '../state'
import type { DeviceSummary } from '../types'
import DevicesView from './DevicesView.vue'

let app: App | undefined
let container: HTMLDivElement | undefined
afterEach(() => { app?.unmount(); container?.remove(); window.location.hash = '' })

it('edits a verified enrolled device using only desired inventory fields and its recorded revision', async () => {
  const device: DeviceSummary = { id: 'device1', name: 'Verified client', revision: 7, groupId: 'group1', enrollment: 'enrolled', coverage: 'ipv4', addresses: [{ address: '192.0.2.40', family: 'ipv4', valid: true, provenance: 'reserved', verifiedAt: '2026-10-08T00:00:00Z' }], exceptions: [{ id: 'later', name: 'TCP exception', enabled: true, order: 9, match: { domain_sets: ['video'], destination_ip: ['192.0.2.0/24'], ports: [{ from: 443, to: 0 }], transports: ['tcp'], families: ['ipv4'] }, action: { kind: 'direct' } }, { id: 'earlier', enabled: false, order: 2, match: { domain_suffix: ['example.test'] }, action: { kind: 'block' } }] }
  const saved = { ...device, name: 'Renamed client', revision: 8 }
  const api = {
    devices: vi.fn().mockResolvedValueOnce([device]).mockResolvedValue([saved]),
    deviceGroups: vi.fn().mockResolvedValue([]), gateways: vi.fn().mockResolvedValue([]), policies: vi.fn().mockResolvedValue([]), outboundGroups: vi.fn().mockResolvedValue([]),
    updateDevice: vi.fn().mockResolvedValue(saved),
  }
  const state = useControllerState(api as unknown as ControllerApi)
  state.session.value = { subject: 'admin', roles: ['admin'] }
  container = document.createElement('div'); document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => h(DevicesView, { state }) }) }); app.mount(container)
  await vi.waitFor(() => expect(container!.querySelector('[aria-label="Edit device Verified client"]')).not.toBeNull())
  ;(container.querySelector('[aria-label="Edit device Verified client"]') as HTMLButtonElement).click()
  await nextTick()
  const input = [...container.querySelectorAll('label')].find(label => label.textContent?.startsWith('Device name'))!.querySelector('input')!
  input.value = 'Renamed client'; input.dispatchEvent(new Event('input', { bubbles: true }))
  await nextTick()
  input.closest('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await vi.waitFor(() => expect(api.updateDevice).toHaveBeenCalledWith('device1', { name: 'Renamed client', primary_group_id: 'group1', addresses: [{ address: '192.0.2.40', family: 'ipv4', provenance: 'reserved' }], exceptions: device.exceptions }, 7))
  await vi.waitFor(() => expect(container!.textContent).toContain('Device record saved'))
})

function button(label: string): HTMLButtonElement {
  return [...container!.querySelectorAll('button')].find(item => item.getAttribute('aria-label') === label || item.textContent?.trim() === label)!
}
function input(label: string): HTMLInputElement {
  return [...container!.querySelectorAll('label')].find(item => item.textContent?.startsWith(label))!.querySelector('input')!
}
function select(label: string): HTMLSelectElement {
  return [...container!.querySelectorAll('label')].find(item => item.textContent?.startsWith(label))!.querySelector('select')!
}
async function change(control: HTMLInputElement | HTMLSelectElement, value: string) {
  control.value = value
  control.dispatchEvent(new Event('input', { bubbles: true }))
  control.dispatchEvent(new Event('change', { bubbles: true }))
  await nextTick()
}

it('reads stored exceptions through the API and saves an ordered typed outbound exception without losing existing matches', async () => {
  let device = { id: 'client', name: 'Client', revision: 4, enrollment_state: 'enrolled', addresses: [{ address: '192.0.2.50', family: 'ipv4', provenance: 'reserved', verified_at: '2026-10-08T00:00:00Z' }], exceptions: [{ id: 'original', name: 'Original exception', order: 8, enabled: true, match: { domain_exact: ['keep.example'], domain_sets: ['known-domains'], destination_cidrs: ['198.51.100.0/24'], destination_ports: [{ from: 80, to: 80 }], transport: ['tcp'], address_families: ['ipv4'] }, action: { kind: 'block' } }] }
  const writes: Array<{ body: Record<string, unknown>; revision: string | null }> = []
  const fetcher = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    const path = new URL(String(url), 'http://localhost').pathname
    if (path.endsWith('/devices/client') && init?.method === 'PUT') {
      const body = JSON.parse(String(init.body))
      writes.push({ body, revision: new Headers(init.headers).get('If-Match') })
      device = { ...device, ...body, revision: device.revision + 1 }
      return new Response(JSON.stringify(device), { status: 200 })
    }
    const items = path.endsWith('/devices') ? [device] : path.endsWith('/outbound-groups') ? [{ id: 'egress', name: 'Primary egress', node_ids: ['node1'] }] : []
    return new Response(JSON.stringify({ items }), { status: 200 })
  })
  const state = useControllerState(new ControllerApi('/api/v1', fetcher))
  state.session.value = { subject: 'admin', roles: ['admin'] }
  container = document.createElement('div'); document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => h(DevicesView, { state }) }) }); app.mount(container)
  await vi.waitFor(() => expect(button('Edit device Client')).toBeDefined())
  button('Edit device Client').click(); await nextTick()
  expect(input('Exception name').value).toBe('Original exception')
  button('Add exception').click(); await nextTick()
  await change(input('Exception name'), 'Video egress')
  await change(input('Exception domain suffixes'), 'video.example, media.example')
  await change(input('Exception destination ports'), '443, 1000-1100')
  await change(select('Exception action'), 'outbound_group')
  await change(select('Exception outbound group'), 'egress')
  button('Move exception 2 up').click(); await nextTick()
  input('Device name').closest('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await vi.waitFor(() => expect(writes).toHaveLength(1))
  expect(writes[0]!.revision).toBe('4')
  expect(writes[0]!.body).toEqual({ name: 'Client', primary_group_id: '', addresses: [{ address: '192.0.2.50', family: 'ipv4', provenance: 'reserved' }], exceptions: [
    { id: expect.any(String), name: 'Video egress', enabled: true, order: 1, match: { domain_suffix: ['video.example', 'media.example'], destination_ports: [{ from: 443, to: 443 }, { from: 1000, to: 1100 }], transport: [], address_families: [] }, action: { kind: 'outbound_group', outbound_group_id: 'egress' } },
    { id: 'original', name: 'Original exception', enabled: true, order: 2, match: { domain_exact: ['keep.example'], domain_sets: ['known-domains'], destination_cidrs: ['198.51.100.0/24'], destination_ports: [{ from: 80, to: 80 }], transport: ['tcp'], address_families: ['ipv4'] }, action: { kind: 'block' } },
  ] })
  await vi.waitFor(() => expect(container!.textContent).toContain('Device record saved'))
  button('Edit device Client').click(); await nextTick()
  expect(input('Exception name').value).toBe('Video egress')
  expect(select('Exception outbound group').value).toBe('egress')
  await change(input('Exception destination ports'), '65536')
  button('Select exception 2').click(); await nextTick()
  input('Device name').closest('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await vi.waitFor(() => expect(container!.querySelector('[role="alert"]')?.textContent).toContain('invalid port range'))
  expect(writes).toHaveLength(1)
})
