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
  await vi.waitFor(() => expect(container!.querySelector('[aria-label="编辑设备 Verified client"]')).not.toBeNull())
  ;(container.querySelector('[aria-label="编辑设备 Verified client"]') as HTMLButtonElement).click()
  await nextTick()
  const input = [...container.querySelectorAll('label')].find(label => label.textContent?.startsWith('设备名称'))!.querySelector('input')!
  input.value = 'Renamed client'; input.dispatchEvent(new Event('input', { bubbles: true }))
  await nextTick()
  input.closest('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await vi.waitFor(() => expect(api.updateDevice).toHaveBeenCalledWith('device1', { name: 'Renamed client', primary_group_id: 'group1', addresses: [{ address: '192.0.2.40', family: 'ipv4', provenance: 'reserved' }], exceptions: device.exceptions }, 7))
  await vi.waitFor(() => expect(container!.textContent).toContain('设备记录已保存'))
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
async function change(control: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement, value: string) {
  control.value = value
  control.dispatchEvent(new Event('input', { bubbles: true }))
  control.dispatchEvent(new Event('change', { bubbles: true }))
  await nextTick()
}

it.each(['manual', 'static', 'reserved'])('records explicitly selected %s address assignment without inventing verification', async (provenance) => {
  const api = {
    devices: vi.fn().mockResolvedValue([]), deviceGroups: vi.fn().mockResolvedValue([]), gateways: vi.fn().mockResolvedValue([]), policies: vi.fn().mockResolvedValue([]), outboundGroups: vi.fn().mockResolvedValue([]),
    createDevice: vi.fn().mockResolvedValue({ id: 'new', revision: 1 }),
  }
  const state = useControllerState(api as unknown as ControllerApi)
  state.session.value = { subject: 'admin', roles: ['admin'] }
  container = document.createElement('div'); document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => h(DevicesView, { state }) }) }); app.mount(container)
  await vi.waitFor(() => expect(container!.textContent).toContain('尚未登记设备。'))
  await vi.waitFor(() => expect(button('添加设备').disabled).toBe(false))
  button('添加设备').click(); await nextTick()
  expect(container!.querySelector('textarea[aria-label="IP 地址"]')).not.toBeNull()
  expect(select('新地址分配方式').value).toBe('manual')
  await change(input('设备名称'), 'New client')
  await change(container.querySelector('textarea[aria-label="IP 地址"]')!, '192.0.2.55')
  if (provenance !== 'manual') await change(select('新地址分配方式'), provenance)
  input('设备名称').closest('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await vi.waitFor(() => expect(api.createDevice).toHaveBeenCalledWith({ name: 'New client', primary_group_id: '', addresses: [{ address: '192.0.2.55', family: 'ipv4', provenance }], exceptions: [] }))
})

it('preserves each existing assignment while adding a static address and allows explicit correction of a manual record', async () => {
  const device: DeviceSummary = { id: 'existing', name: 'Mixed assignments', revision: 2, enrollment: 'unenrolled', coverage: 'incomplete', addresses: [{ address: '192.0.2.10', family: 'ipv4', valid: false, provenance: 'reserved' }, { address: '192.0.2.11', family: 'ipv4', valid: false, provenance: 'manual' }] }
  const api = { devices: vi.fn().mockResolvedValue([device]), deviceGroups: vi.fn().mockResolvedValue([]), gateways: vi.fn().mockResolvedValue([]), policies: vi.fn().mockResolvedValue([]), outboundGroups: vi.fn().mockResolvedValue([]), updateDevice: vi.fn().mockResolvedValue({ id: device.id, revision: 3 }) }
  const state = useControllerState(api as unknown as ControllerApi)
  state.session.value = { subject: 'admin', roles: ['admin'] }
  container = document.createElement('div'); document.body.append(container)
  app = createApp({ render: () => h(KeepAlive, null, { default: () => h(DevicesView, { state }) }) }); app.mount(container)
  await vi.waitFor(() => expect(button('编辑设备 Mixed assignments')).toBeDefined())
  button('编辑设备 Mixed assignments').click(); await nextTick()
  await change(select('新地址分配方式'), 'static')
  await change(container.querySelector('textarea[aria-label="IP 地址"]')!, '192.0.2.10\n192.0.2.11\n192.0.2.12')
  expect(select('地址 192.0.2.10 的分配方式').value).toBe('reserved')
  expect(select('地址 192.0.2.11 的分配方式').value).toBe('manual')
  await change(select('地址 192.0.2.11 的分配方式'), 'reserved')
  input('设备名称').closest('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await vi.waitFor(() => expect(api.updateDevice).toHaveBeenCalledWith(device.id, { name: device.name, primary_group_id: '', exceptions: [], addresses: [
    { address: '192.0.2.10', family: 'ipv4', provenance: 'reserved' }, { address: '192.0.2.11', family: 'ipv4', provenance: 'reserved' }, { address: '192.0.2.12', family: 'ipv4', provenance: 'static' },
  ] }, 2))
})

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
  await vi.waitFor(() => expect(button('编辑设备 Client')).toBeDefined())
  button('编辑设备 Client').click(); await nextTick()
  expect(input('例外名称').value).toBe('Original exception')
  button('添加例外规则').click(); await nextTick()
  await change(input('例外名称'), 'Video egress')
  await change(input('例外域名后缀'), 'video.example, media.example')
  await change(input('例外目标端口'), '443, 1000-1100')
  await change(select('例外动作'), 'outbound_group')
  await change(select('例外代理组'), 'egress')
  button('移动例外规则 2上移').click(); await nextTick()
  input('设备名称').closest('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await vi.waitFor(() => expect(writes).toHaveLength(1))
  expect(writes[0]!.revision).toBe('4')
  expect(writes[0]!.body).toEqual({ name: 'Client', primary_group_id: '', addresses: [{ address: '192.0.2.50', family: 'ipv4', provenance: 'reserved' }], exceptions: [
    { id: expect.any(String), name: 'Video egress', enabled: true, order: 1, match: { domain_suffix: ['video.example', 'media.example'], destination_ports: [{ from: 443, to: 443 }, { from: 1000, to: 1100 }], transport: [], address_families: [] }, action: { kind: 'outbound_group', outbound_group_id: 'egress' } },
    { id: 'original', name: 'Original exception', enabled: true, order: 2, match: { domain_exact: ['keep.example'], domain_sets: ['known-domains'], destination_cidrs: ['198.51.100.0/24'], destination_ports: [{ from: 80, to: 80 }], transport: ['tcp'], address_families: ['ipv4'] }, action: { kind: 'block' } },
  ] })
  await vi.waitFor(() => expect(container!.textContent).toContain('设备记录已保存'))
  button('编辑设备 Client').click(); await nextTick()
  expect(input('例外名称').value).toBe('Video egress')
  expect(select('例外代理组').value).toBe('egress')
  await change(input('例外目标端口'), '65536')
  button('选择例外规则 2').click(); await nextTick()
  input('设备名称').closest('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
  await vi.waitFor(() => expect(container!.querySelector('[role="alert"]')?.textContent).toContain('无效的端口范围'))
  expect(writes).toHaveLength(1)
})
