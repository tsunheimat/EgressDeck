<script setup lang="ts">
import { computed, nextTick, onActivated, onUnmounted, reactive, ref } from 'vue'
import { ControllerApiError, randomIdempotencyKey } from '../api/client'
import StatusPill from '../components/StatusPill.vue'
import { useControllerState } from '../state'
import type { DeviceExceptionRule, DeviceGroupSummary, DeviceSummary, GatewaySummary, OutboundGroupSummary, PolicySummary } from '../types'
import { readNavigationTarget, subscribeNavigationTarget } from '../navigationTarget'

const props = defineProps<{ state: ReturnType<typeof useControllerState> }>()
const canOperate = props.state.isAdministrator
const devices = ref<DeviceSummary[]>([])
const groups = ref<DeviceGroupSummary[]>([])
const gateways = ref<GatewaySummary[]>([])
const policies = ref<PolicySummary[]>([])
const outbounds = ref<OutboundGroupSummary[]>([])
const loading = ref(false)
const saving = ref(false)
const error = ref<string>()
const notice = ref<string>()
const deviceEditorOpen = ref(false)
const groupEditorOpen = ref(false)
const editingDevice = ref<DeviceSummary>()
const editingGroup = ref<DeviceGroupSummary>()
const deletingDevice = ref<DeviceSummary>()
const deleteAcknowledged = ref(false)
const deviceForm = reactive({ name: '', groupId: '', addresses: '' })
interface ExceptionDraft { rule: DeviceExceptionRule; ports: string }
const exceptionDrafts = ref<ExceptionDraft[]>([])
const selectedExceptionIndex = ref(0)
const activeException = computed(() => exceptionDrafts.value[selectedExceptionIndex.value])
let initialExceptions = ''
const exceptionActions: DeviceExceptionRule['action']['kind'][] = ['direct', 'proxy', 'block', 'outbound_group']
const exceptionListMatches = [
  { key: 'domain_exact', label: 'Exception exact domains', placeholder: 'example.com' },
  { key: 'domain_suffix', label: 'Exception domain suffixes', placeholder: 'example.com, media.example' },
  { key: 'domain_sets', label: 'Exception domain set IDs', placeholder: 'streaming-domains' },
  { key: 'destination_cidrs', label: 'Exception destination CIDRs', placeholder: '192.0.2.0/24' },
] as const
const groupForm = reactive({ name: '', gatewayId: '', policyId: '', enabled: true })
const linkedGroupId = ref<string>()
async function focusLinkedGroup() {
  const target = readNavigationTarget()
  if (target.page !== 'devices' || target.resource !== 'device_group' || !target.id) return
  linkedGroupId.value = target.id
  await nextTick()
  document.getElementById(`device-group-${target.id}`)?.scrollIntoView({ block: 'center', behavior: 'smooth' })
}
const stopNavigation = subscribeNavigationTarget(target => { if (target.page === 'devices') void focusLinkedGroup() })
onUnmounted(stopNavigation)

function failureMessage(cause: unknown): string {
  const message = cause instanceof Error ? cause.message : 'The controller request failed'
  return cause instanceof ControllerApiError && (cause.status === 412 || cause.code === 'revision_conflict')
    ? `${message}. Cancel editing and refresh to load the current revision before retrying.` : message
}

async function load() {
  loading.value = true
  error.value = undefined
  try {
    const results = await Promise.allSettled([props.state.api.devices(), props.state.api.deviceGroups(), props.state.api.gateways(), props.state.api.policies(), props.state.api.outboundGroups()])
    const [deviceResult, groupResult, gatewayResult, policyResult, outboundResult] = results
    if (deviceResult.status === 'fulfilled') devices.value = deviceResult.value
    if (groupResult.status === 'fulfilled') groups.value = groupResult.value
    if (gatewayResult.status === 'fulfilled') gateways.value = gatewayResult.value
    if (policyResult.status === 'fulfilled') policies.value = policyResult.value
    if (outboundResult.status === 'fulfilled') outbounds.value = outboundResult.value
    const failures = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected')
    if (failures.length) error.value = failures.map((result) => failureMessage(result.reason)).join('; ')
    return { devicesLoaded: deviceResult.status === 'fulfilled', groupsLoaded: groupResult.status === 'fulfilled' }
  } finally { loading.value = false }
}

function editDevice(device?: DeviceSummary) {
  error.value = undefined
  notice.value = undefined
  editingDevice.value = device
  deviceForm.name = device?.name ?? ''
  deviceForm.groupId = device?.groupId ?? ''
  deviceForm.addresses = device?.addresses.map((address) => address.address).join('\n') ?? ''
  exceptionDrafts.value = (device?.exceptions ?? []).map((original, index) => {
    const rule = JSON.parse(JSON.stringify(original)) as DeviceExceptionRule
    const match = rule.match
    match.destination_cidrs = [...(match.destination_cidrs ?? []), ...(match.destination_ip ?? [])]
    match.destination_ports = [...(match.destination_ports ?? []), ...(match.ports ?? [])]
    match.transport = [...(match.transport ?? []), ...(match.transports ?? [])]
    match.address_families = [...(match.address_families ?? []), ...(match.families ?? [])]
    delete match.destination_ip; delete match.ports; delete match.transports; delete match.families
    return { rule, index, ports: match.destination_ports.map(port => !port.to || port.from === port.to ? String(port.from) : `${port.from}-${port.to}`).join(', ') }
  }).sort((a, b) => (a.rule.order || a.index + 1) - (b.rule.order || b.index + 1)).map(({ rule, ports }) => ({ rule, ports }))
  initialExceptions = JSON.stringify(exceptionDrafts.value)
  selectedExceptionIndex.value = 0
  deviceEditorOpen.value = true
  deletingDevice.value = undefined
}

function csv(value: string): string[] { return value.split(/[\n,]+/).map(item => item.trim()).filter(Boolean) }
function addException() {
  exceptionDrafts.value.push({ rule: { id: `exception-${randomIdempotencyKey()}`, name: '', match: { transport: [], address_families: [] }, action: { kind: 'direct' }, enabled: true }, ports: '' })
  selectedExceptionIndex.value = exceptionDrafts.value.length - 1
}
function moveException(index: number, offset: number) {
  const target = index + offset
  if (!exceptionDrafts.value[index] || !exceptionDrafts.value[target]) return
  const current = exceptionDrafts.value[index]!
  exceptionDrafts.value[index] = exceptionDrafts.value[target]!
  exceptionDrafts.value[target] = current
  selectedExceptionIndex.value = target
}
function removeException() {
  exceptionDrafts.value.splice(selectedExceptionIndex.value, 1)
  selectedExceptionIndex.value = Math.max(0, selectedExceptionIndex.value - 1)
}
function setExceptionAction(kind: DeviceExceptionRule['action']['kind']) {
  if (activeException.value) activeException.value.rule.action = kind === 'outbound_group' ? { kind, outbound_group_id: '' } : { kind }
}
function deviceExceptions(): DeviceExceptionRule[] {
  if (JSON.stringify(exceptionDrafts.value) === initialExceptions) return JSON.parse(JSON.stringify(editingDevice.value?.exceptions ?? [])) as DeviceExceptionRule[]
  return exceptionDrafts.value.map(({ rule, ports }, index) => {
    const destination_ports = csv(ports).map(token => {
      const match = /^(\d+)(?:-(\d+))?$/.exec(token)
      const from = Number(match?.[1]); const to = Number(match?.[2] ?? match?.[1])
      if (!match || from < 1 || to < from || to > 65535) throw new Error(`Exception ${index + 1}: invalid port range "${token}". Use ports 1–65535, for example 443 or 1000-1100.`)
      return { from, to }
    })
    if (rule.action.kind === 'outbound_group' && !outbounds.value.some(group => group.id === rule.action.outbound_group_id)) throw new Error(`Exception ${index + 1}: select an available outbound group.`)
    return { ...rule, order: index + 1, match: { ...rule.match, destination_ports }, action: { ...rule.action } }
  })
}

async function saveDevice() {
  if (saving.value || !canOperate.value) return
  saving.value = true
  error.value = undefined
  notice.value = undefined
  try {
    const addresses = deviceForm.addresses.split(/[\s,]+/).filter(Boolean).map((address) => {
      const previous = editingDevice.value?.addresses.find((item) => item.address === address)
      return { address, family: previous?.family ?? (address.includes(':') ? 'ipv6' as const : 'ipv4' as const), provenance: previous?.provenance ?? 'manual' }
    })
    const payload = { name: deviceForm.name.trim(), primary_group_id: deviceForm.groupId, addresses, exceptions: deviceExceptions() }
    if (editingDevice.value && !editingDevice.value.revision) throw new Error('Refresh this device to obtain its revision before editing')
    const saved = editingDevice.value
      ? await props.state.api.updateDevice(editingDevice.value.id, payload, editingDevice.value.revision)
      : await props.state.api.createDevice(payload)
    deviceEditorOpen.value = false
    editingDevice.value = undefined
    const readback = await load()
    if (!readback.devicesLoaded || !devices.value.some((device) => device.id === saved.id && device.revision === saved.revision)) {
      error.value = 'The controller accepted the save, but its device revision could not be read back. Refresh before making further changes.'
      return
    }
    notice.value = 'Device record saved. Address verification and traffic deployment are separate operations.'
  } catch (cause) { error.value = failureMessage(cause) } finally { saving.value = false }
}

function confirmDelete(device: DeviceSummary) {
  deletingDevice.value = device
  deleteAcknowledged.value = false
  error.value = undefined
  notice.value = undefined
}

async function deleteDevice() {
  const device = deletingDevice.value
  if (!device || !deleteAcknowledged.value || saving.value || !canOperate.value) return
  saving.value = true
  error.value = undefined
  try {
    if (device.enrollment !== 'unenrolled') throw new Error('Only unenrolled device records can be deleted here')
    if (!device.revision) throw new Error('Refresh this device to obtain its revision before deleting')
    await props.state.api.deleteDevice(device.id, device.revision)
    deletingDevice.value = undefined
    if (editingDevice.value?.id === device.id) deviceEditorOpen.value = false
    const readback = await load()
    if (!readback.devicesLoaded || devices.value.some((item) => item.id === device.id)) {
      error.value = 'The controller accepted deletion, but removal could not be read back. Refresh before retrying.'
      return
    }
    notice.value = 'Device record deleted and its recorded addresses released.'
  } catch (cause) { error.value = failureMessage(cause) } finally { saving.value = false }
}

function editGroup(group?: DeviceGroupSummary) {
  error.value = undefined
  notice.value = undefined
  editingGroup.value = group
  groupForm.name = group?.name ?? ''
  groupForm.gatewayId = group?.gatewayId ?? gateways.value[0]?.id ?? ''
  groupForm.policyId = group?.policyId ?? policies.value[0]?.id ?? ''
  groupForm.enabled = group?.enabled ?? true
  groupEditorOpen.value = true
}

async function saveGroup() {
  if (saving.value || !canOperate.value) return
  saving.value = true
  error.value = undefined
  notice.value = undefined
  try {
    const payload = { name: groupForm.name.trim(), gateway_id: groupForm.gatewayId, policy_id: groupForm.policyId, enabled: groupForm.enabled }
    if (editingGroup.value && !editingGroup.value.revision) throw new Error('Refresh this group to obtain its revision before editing')
    const saved = editingGroup.value
      ? await props.state.api.updateDeviceGroup(editingGroup.value.id, payload, editingGroup.value.revision)
      : await props.state.api.createDeviceGroup(payload)
    groupEditorOpen.value = false
    editingGroup.value = undefined
    const readback = await load()
    if (!readback.groupsLoaded || !groups.value.some((group) => group.id === saved.id && group.revision === saved.revision)) {
      error.value = 'The controller accepted the save, but its group revision could not be read back. Refresh before making further changes.'
      return
    }
    notice.value = 'Desired group configuration saved. Preview and deploy the policy to change traffic.'
  } catch (cause) { error.value = failureMessage(cause) } finally { saving.value = false }
}

function memberCount(groupId: string) { return devices.value.filter((device) => device.groupId === groupId).length }
onActivated(async () => { await load(); await focusLinkedGroup() })
</script>

<template>
  <div class="page-grid"><section class="page-heading"><div><p class="eyebrow">Source identity</p><h1>Devices &amp; Groups</h1><p class="lede">Register addresses and assign one primary routing group. Saving inventory does not verify addresses or apply traffic policy.</p></div><button class="button button--secondary" :disabled="loading || saving" @click="load">{{ loading ? 'Refreshing…' : 'Refresh' }}</button></section>
    <section v-if="error" class="alert alert--bad" role="alert">{{ error }}</section>
    <section v-if="notice" class="alert alert--good" role="status">{{ notice }}</section>
    <section class="panel"><div class="panel__heading"><h2>Traffic enrollment</h2><button class="button" disabled>Enroll selected devices</button></div><p class="muted">Enrollment is unavailable until a gateway and OPNsense deployment adapter can apply policy, verify steering, and read back the result. Saving device records only changes controller intent.</p></section>
    <section class="panel">
      <div class="panel__heading"><h2>Device groups</h2><div class="actions"><span class="muted">{{ groups.length }} groups</span><button v-if="canOperate" class="button" :disabled="loading || saving" @click="editGroup()">Add group</button></div></div>
      <form v-if="groupEditorOpen && canOperate" class="editor" @submit.prevent="saveGroup">
        <h3>{{ editingGroup ? `Edit ${editingGroup.name}` : 'Create device group' }}</h3><p class="muted">{{ editingGroup ? `Editing revision ${editingGroup.revision ?? 'unavailable'}.` : 'Register a gateway on Infrastructure and create a policy on Rules before assigning a group. Your group form remains available while you choose its references.' }}</p><p v-if="!gateways.length || !policies.length" class="muted">{{ !gateways.length ? 'No gateways are registered. Open Infrastructure in the navigation and select Register gateway.' : '' }} {{ !policies.length ? 'No policies exist. Open Rules and select New policy.' : '' }}</p>
        <fieldset :disabled="saving"><div class="form-grid">
          <label>Group name<input v-model="groupForm.name" required maxlength="200" autocomplete="off" /></label>
          <label>Group gateway<select v-model="groupForm.gatewayId" required><option disabled value="">Select gateway</option><option v-if="groupForm.gatewayId && !gateways.some((gateway) => gateway.id === groupForm.gatewayId)" :value="groupForm.gatewayId">{{ groupForm.gatewayId }} (unavailable)</option><option v-for="gateway in gateways" :key="gateway.id" :value="gateway.id">{{ gateway.name }}</option></select></label>
          <label>Group policy<select v-model="groupForm.policyId" required><option disabled value="">Select policy</option><option v-if="groupForm.policyId && !policies.some((policy) => policy.id === groupForm.policyId)" :value="groupForm.policyId">{{ groupForm.policyId }} (unavailable)</option><option v-for="policy in policies" :key="policy.id" :value="policy.id">{{ policy.name }}</option></select></label>
          <label class="checkbox"><input v-model="groupForm.enabled" type="checkbox" />Enabled in desired configuration</label>
        </div><div class="actions"><button class="button" type="submit" :disabled="!groupForm.gatewayId || !groupForm.policyId">{{ saving ? 'Saving…' : 'Save group' }}</button><button class="button button--secondary" type="button" @click="groupEditorOpen = false">Cancel</button></div></fieldset>
      </form>
      <div v-if="!groups.length && !loading" class="empty-state">No device groups are configured.</div>
      <article v-for="group in groups" :id="`device-group-${group.id}`" :key="group.id" class="row-card" :class="{ 'row-card--linked': linkedGroupId === group.id }"><div><strong>{{ group.name }}</strong><p>{{ memberCount(group.id) }} members · {{ gateways.find((gateway) => gateway.id === group.gatewayId)?.name ?? group.gatewayId }}</p><p>Policy: {{ policies.find((policy) => policy.id === group.policyId)?.name ?? group.policyId }} · revision {{ group.revision ?? 'unknown' }}</p></div><div class="row-card__right"><StatusPill :label="group.drift ? 'Drift' : group.state" :tone="group.drift ? 'warn' : group.state === 'verified' ? 'good' : 'neutral'" /><span class="muted">{{ group.enabled ? 'Enabled' : 'Disabled' }}</span><button v-if="canOperate" class="button button--secondary" :disabled="saving || loading || !group.revision" :aria-label="`Edit group ${group.name}`" @click="editGroup(group)">Edit</button></div></article>
    </section>
    <section class="panel">
      <div class="panel__heading"><h2>Devices</h2><div class="actions"><span class="muted">{{ devices.length }} records</span><button v-if="canOperate" class="button" :disabled="loading || saving" @click="editDevice()">Add device</button></div></div>
      <form v-if="deviceEditorOpen && canOperate" class="editor" @submit.prevent="saveDevice">
        <h3>{{ editingDevice ? `Edit ${editingDevice.name}` : 'Register device' }}</h3><p class="muted">{{ editingDevice ? `Editing revision ${editingDevice.revision ?? 'unavailable'}.` : 'New devices start unenrolled.' }} Addresses are checked for ownership conflicts by the controller.</p>
        <fieldset :disabled="saving"><div class="form-grid">
          <label>Device name<input v-model="deviceForm.name" required maxlength="200" autocomplete="off" /></label>
          <label>Primary routing group<select v-model="deviceForm.groupId"><option value="">Unassigned</option><option v-if="deviceForm.groupId && !groups.some((group) => group.id === deviceForm.groupId)" :value="deviceForm.groupId">{{ deviceForm.groupId }} (unavailable)</option><option v-for="group in groups" :key="group.id" :value="group.id">{{ group.name }}</option></select></label>
          <label class="full-width">IP addresses<textarea aria-label="IP addresses" v-model="deviceForm.addresses" rows="3" spellcheck="false" aria-describedby="device-address-help" placeholder="192.0.2.10&#10;2001:db8::10" /><span id="device-address-help" class="muted">Enter reserved or static addresses, one per line. New addresses remain unverified.</span></label>
        </div>
        <section class="exceptions-editor" aria-label="Per-device exceptions">
          <div class="panel__heading"><h3>Per-device exceptions</h3><button class="button button--secondary" type="button" @click="addException">Add exception</button></div>
          <p class="muted">These rules apply only to this device, after mandatory rules and policy exceptions, before ordinary policy rules. The first enabled match wins. Values within a field are alternatives; populated fields must all match. An empty match applies to all this device’s traffic.</p>
          <p v-if="!exceptionDrafts.length" class="muted">No per-device exceptions.</p>
          <div v-for="(entry, index) in exceptionDrafts" :key="index" class="exception-row" :class="{ 'exception-row--selected': selectedExceptionIndex === index }">
            <button class="exception-select" type="button" :aria-pressed="selectedExceptionIndex === index" :aria-label="`Select exception ${index + 1}`" @click="selectedExceptionIndex = index"><strong>{{ index + 1 }}. {{ entry.rule.name || 'Unnamed exception' }}</strong><span class="muted">{{ entry.rule.action.kind === 'outbound_group' ? `Outbound group: ${outbounds.find(group => group.id === entry.rule.action.outbound_group_id)?.name || entry.rule.action.outbound_group_id || 'not selected'}` : entry.rule.action.kind }} · {{ entry.rule.enabled ? 'enabled' : 'disabled' }}</span></button>
            <button class="button button--secondary" type="button" :disabled="index === 0" :aria-label="`Move exception ${index + 1} up`" @click="moveException(index, -1)">↑</button>
            <button class="button button--secondary" type="button" :disabled="index === exceptionDrafts.length - 1" :aria-label="`Move exception ${index + 1} down`" @click="moveException(index, 1)">↓</button>
          </div>
          <div v-if="activeException" class="form-grid">
            <label>Exception name<input v-model="activeException.rule.name" maxlength="200" autocomplete="off" /></label>
            <label class="checkbox"><input v-model="activeException.rule.enabled" type="checkbox" />Exception enabled</label>
            <label>Exception action<select :value="activeException.rule.action.kind" @change="setExceptionAction(($event.target as HTMLSelectElement).value as DeviceExceptionRule['action']['kind'])"><option v-for="action in exceptionActions" :key="action" :value="action">{{ action }}</option></select></label>
            <label v-if="activeException.rule.action.kind === 'outbound_group'">Exception outbound group<select v-model="activeException.rule.action.outbound_group_id" required><option disabled value="">Select outbound group</option><option v-if="activeException.rule.action.outbound_group_id && !outbounds.some(group => group.id === activeException!.rule.action.outbound_group_id)" :value="activeException.rule.action.outbound_group_id" disabled>{{ activeException.rule.action.outbound_group_id }} (unavailable)</option><option v-for="group in outbounds" :key="group.id" :value="group.id">{{ group.name }}</option></select></label>
            <label v-for="field in exceptionListMatches" :key="field.key">{{ field.label }}<input :value="activeException.rule.match[field.key]?.join(', ')" :placeholder="field.placeholder" @change="activeException.rule.match[field.key] = csv(($event.target as HTMLInputElement).value)" /></label>
            <label>Exception destination ports<input v-model="activeException.ports" placeholder="443, 1000-1100" /><span class="muted">Comma-separated ports or inclusive ranges, 1–65535.</span></label>
            <label>Exception transports<select v-model="activeException.rule.match.transport" multiple><option value="tcp">TCP</option><option value="udp">UDP</option><option value="quic">QUIC</option></select><span class="muted">No selection matches any transport.</span></label>
            <label>Exception address families<select v-model="activeException.rule.match.address_families" multiple><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select><span class="muted">No selection matches either family.</span></label>
            <div class="full-width"><button class="button button--danger" type="button" @click="removeException">Remove selected exception</button></div>
          </div>
        </section>
        <div class="actions"><button class="button" type="submit">{{ saving ? 'Saving…' : 'Save device' }}</button><button class="button button--secondary" type="button" @click="deviceEditorOpen = false">Cancel</button></div></fieldset>
      </form>
      <form v-if="deletingDevice && canOperate" class="editor" @submit.prevent="deleteDevice"><h3>Delete {{ deletingDevice.name }}?</h3><p class="muted">This removes the unenrolled device record and releases its recorded address ownership.</p><label class="checkbox"><input v-model="deleteAcknowledged" :disabled="saving" type="checkbox" required />I confirm this device is unenrolled and its record can be removed.</label><div class="actions"><button class="button button--danger" type="submit" :disabled="saving || !deleteAcknowledged">{{ saving ? 'Deleting…' : 'Delete device record' }}</button><button class="button button--secondary" type="button" :disabled="saving" @click="deletingDevice = undefined">Cancel</button></div></form>
      <div v-if="!devices.length && !loading" class="empty-state">No devices have been registered.</div>
      <article v-for="device in devices" :key="device.id" class="row-card"><div><strong>{{ device.name }}</strong><p>{{ device.addresses.map((address) => address.address).join(', ') || 'No addresses recorded' }}</p><p>Group: {{ groups.find((group) => group.id === device.groupId)?.name ?? (device.groupId || 'Unassigned') }} · revision {{ device.revision ?? 'unknown' }}</p></div><div class="row-card__right"><StatusPill :label="device.enrollment" :tone="device.enrollment === 'enrolled' ? 'good' : device.enrollment === 'blocked' ? 'bad' : 'warn'" /><span class="coverage">{{ device.coverage }}</span><button v-if="canOperate" class="button button--secondary" :disabled="saving || loading || !device.revision" :aria-label="`Edit device ${device.name}`" @click="editDevice(device)">Edit</button><button v-if="canOperate" class="button button--secondary" :disabled="saving || loading || !device.revision || device.enrollment !== 'unenrolled'" :title="device.enrollment !== 'unenrolled' ? 'Resolve enrollment before removing this device record' : 'Delete unenrolled device record'" :aria-label="`Delete device ${device.name}`" @click="confirmDelete(device)">Delete</button></div></article>
    </section>
  </div>
</template>

<style scoped>
.page-grid { display: grid; gap: 1rem; } .page-heading, .panel__heading, .row-card { display: flex; align-items: center; justify-content: space-between; gap: 1rem; } h1 { margin: .25rem 0 .4rem; font-size: 2rem; } h2 { margin: 0; font-size: 1.1rem; }
.eyebrow { margin: 0; color: #78b8ff; font-size: .7rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; } .lede, .row-card p { margin: 0; color: var(--muted); } .row-card p { margin-top: .25rem; font-size: .78rem; }
.panel { display: grid; gap: .7rem; padding: 1rem; border: 1px solid var(--border); border-radius: .65rem; background: var(--surface); } .row-card { padding: .7rem; border-radius: .45rem; background: var(--surface-alt); } .row-card__right { display: flex; align-items: center; gap: .65rem; } .muted, .coverage { color: var(--muted); font-size: .78rem; }
.button { cursor: pointer; padding: .5rem .7rem; border: 1px solid var(--border); border-radius: .4rem; background: var(--accent); color: #07111f; font-weight: 700; } .button:disabled { cursor: wait; opacity: .55; } .button--secondary { background: transparent; color: var(--text); }
.row-card--linked { outline: 1px solid var(--accent); outline-offset: 2px; }
.exceptions-editor { display: grid; gap: .75rem; border-top: 1px solid var(--border); padding-top: 1rem; min-width: 0; } .exception-row { display: flex; align-items: center; gap: .5rem; padding: .45rem; border: 1px solid var(--border); border-radius: .4rem; min-width: 0; } .exception-row--selected { border-color: var(--accent); } .exception-select { display: grid; gap: .25rem; flex: 1; min-width: 0; text-align: left; border: 0; padding: .25rem; background: transparent; color: var(--text); cursor: pointer; overflow-wrap: anywhere; } select[multiple] { min-height: 5rem; }
.empty-state { padding: 1.5rem; color: var(--muted); text-align: center; } .alert { padding: .75rem 1rem; border-radius: .5rem; } .alert--bad { border: 1px solid #713847; background: #301c29; color: #ffbeca; }
.editor { display: grid; gap: .75rem; padding: 1rem; border: 1px solid var(--border); border-radius: .45rem; background: var(--surface-alt); } .editor p, h3 { margin: 0; } h3 { font-size: 1rem; } fieldset { display: grid; gap: 1rem; padding: 0; margin: 0; border: 0; min-width: 0; } .form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .8rem; } label { display: grid; gap: .35rem; color: var(--text); font-size: .82rem; } .full-width { grid-column: 1 / -1; } input, select, textarea { box-sizing: border-box; width: 100%; min-width: 0; padding: .55rem; border: 1px solid var(--border); border-radius: .35rem; background: var(--surface); color: var(--text); font: inherit; } textarea { resize: vertical; } .checkbox { display: flex; align-items: center; gap: .5rem; } .checkbox input { width: auto; } .actions { display: flex; align-items: center; flex-wrap: wrap; gap: .65rem; } .row-card__right { flex-wrap: wrap; } .row-card p, .alert { overflow-wrap: anywhere; } .button--danger { border-color: #713847; background: #301c29; color: #ffbeca; } .alert--good { border: 1px solid #32634f; background: #142e25; color: #ace4c9; }
@media (max-width: 760px) { .page-heading, .row-card { align-items: stretch; flex-direction: column; } .row-card__right { justify-content: space-between; width: 100%; } }
@media (max-width: 760px) { .panel__heading { flex-wrap: wrap; } .form-grid { grid-template-columns: 1fr; } }
</style>
