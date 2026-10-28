<script setup lang="ts">
import { uiLabel } from '../localization'
import DiagnosticMessage from '../components/DiagnosticMessage.vue'
import { computed, nextTick, onActivated, onUnmounted, reactive, ref } from 'vue'
import { ControllerApiError, randomIdempotencyKey } from '../api/client'
import StatusPill from '../components/StatusPill.vue'
import EnrollmentPanel from '../components/EnrollmentPanel.vue'
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
const deviceForm = reactive({ name: '', groupId: '', addresses: '', provenance: 'manual' })
const addressProvenance = ref<Record<string, string>>({})
const existingAddresses = computed(() => editingDevice.value?.addresses.filter(address => deviceForm.addresses.split(/[\s,]+/).includes(address.address)) ?? [])
interface ExceptionDraft { rule: DeviceExceptionRule; ports: string }
const exceptionDrafts = ref<ExceptionDraft[]>([])
const selectedExceptionIndex = ref(0)
const activeException = computed(() => exceptionDrafts.value[selectedExceptionIndex.value])
let initialExceptions = ''
const exceptionActions: DeviceExceptionRule['action']['kind'][] = ['direct', 'proxy', 'block', 'outbound_group']
const exceptionListMatches = [
  { key: 'domain_exact', label: '例外精确域名', placeholder: 'example.com' },
  { key: 'domain_suffix', label: '例外域名后缀', placeholder: 'example.com, media.example' },
  { key: 'domain_sets', label: '例外域名集 ID', placeholder: 'streaming-domains' },
  { key: 'destination_cidrs', label: '例外目标 CIDR 网段', placeholder: '192.0.2.0/24' },
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
  const message = cause instanceof Error ? cause.message : '控制器请求失败'
  return cause instanceof ControllerApiError && (cause.status === 412 || cause.code === 'revision_conflict')
    ? `${message}。请取消编辑并刷新当前版本后再重试。` : message
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
  deviceForm.provenance = 'manual'
  addressProvenance.value = Object.fromEntries((device?.addresses ?? []).map(address => [address.address, address.provenance ?? 'manual']))
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
      if (!match || from < 1 || to < from || to > 65535) throw new Error(`例外规则 ${index + 1}：无效的端口范围“${token}”。请使用 1–65535 的端口，例如 443 或 1000-1100。`)
      return { from, to }
    })
    if (rule.action.kind === 'outbound_group' && !outbounds.value.some(group => group.id === rule.action.outbound_group_id)) throw new Error(`例外规则 ${index + 1}：请选择可用的代理组。`)
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
      return { address, family: previous?.family ?? (address.includes(':') ? 'ipv6' as const : 'ipv4' as const), provenance: addressProvenance.value[address] ?? deviceForm.provenance }
    })
    const payload = { name: deviceForm.name.trim(), primary_group_id: deviceForm.groupId, addresses, exceptions: deviceExceptions() }
    if (editingDevice.value && !editingDevice.value.revision) throw new Error('编辑前请刷新此设备以获取其版本')
    const saved = editingDevice.value
      ? await props.state.api.updateDevice(editingDevice.value.id, payload, editingDevice.value.revision)
      : await props.state.api.createDevice(payload)
    deviceEditorOpen.value = false
    editingDevice.value = undefined
    const readback = await load()
    if (!readback.devicesLoaded || !devices.value.some((device) => device.id === saved.id && device.revision === saved.revision)) {
      error.value = '控制器已受理保存，但无法回读设备版本。继续修改前请刷新。'
      return
    }
    notice.value = '设备记录已保存。地址验证与流量部署是独立操作。'
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
    if (device.enrollment !== 'unenrolled') throw new Error('此处只能删除尚未纳管的设备记录')
    if (!device.revision) throw new Error('删除前请刷新此设备以获取其版本')
    await props.state.api.deleteDevice(device.id, device.revision)
    deletingDevice.value = undefined
    if (editingDevice.value?.id === device.id) deviceEditorOpen.value = false
    const readback = await load()
    if (!readback.devicesLoaded || devices.value.some((item) => item.id === device.id)) {
      error.value = '控制器已受理删除，但无法回读确认移除。重试前请刷新。'
      return
    }
    notice.value = '设备记录已删除，其登记的地址归属已释放。'
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
    if (editingGroup.value && !editingGroup.value.revision) throw new Error('编辑前请刷新此组以获取其版本')
    const saved = editingGroup.value
      ? await props.state.api.updateDeviceGroup(editingGroup.value.id, payload, editingGroup.value.revision)
      : await props.state.api.createDeviceGroup(payload)
    groupEditorOpen.value = false
    editingGroup.value = undefined
    const readback = await load()
    if (!readback.groupsLoaded || !groups.value.some((group) => group.id === saved.id && group.revision === saved.revision)) {
      error.value = '控制器已受理保存，但无法回读设备组版本。继续修改前请刷新。'
      return
    }
    notice.value = '期望组配置已保存。需预览并部署策略才能改变流量。'
  } catch (cause) { error.value = failureMessage(cause) } finally { saving.value = false }
}

function memberCount(groupId: string) { return devices.value.filter((device) => device.groupId === groupId).length }
onActivated(async () => { await load(); await focusLinkedGroup() })
</script>

<template>
  <div class="page-grid"><section class="page-heading"><div><p class="eyebrow">设备管理</p><h1>设备与分组</h1><p class="lede">管理家庭网络中的设备，按场景分组并配置策略。保存清单不代表地址已验证或代理已生效。</p></div><button class="button button--secondary" :disabled="loading || saving" @click="load">{{ loading ? '正在刷新…' : '刷新' }}</button></section>
    <section v-if="error" class="alert alert--bad" role="alert"><DiagnosticMessage :message="error" /></section>
    <section v-if="notice" class="alert alert--good" role="status">{{ notice }}</section>
    <EnrollmentPanel :state="state" :devices="devices" :groups="groups" @completed="load" />
    <section class="panel">
      <div class="panel__heading"><h2>设备组</h2><div class="actions"><span class="muted">{{ groups.length }} 个设备组</span><button v-if="canOperate" class="button" :disabled="loading || saving" @click="editGroup()">添加设备组</button></div></div>
      <form v-if="groupEditorOpen && canOperate" class="editor" @submit.prevent="saveGroup">
        <h3>{{ editingGroup ? `编辑 ${editingGroup.name}` : '创建设备组' }}</h3><p class="muted">{{ editingGroup ? `正在编辑版本 ${editingGroup.revision ?? '不可用'}.` : '分配设备组前，请先在“基础设施”中登记网关，并在“规则策略”中创建策略。选择引用时，设备组表单会保留。' }}</p><p v-if="!gateways.length || !policies.length" class="muted">{{ !gateways.length ? '尚未登记网关。请打开“基础设施”并选择“登记网关”。' : '' }} {{ !policies.length ? '尚无策略。请打开“规则策略”并选择“新建策略”。' : '' }}</p>
        <fieldset :disabled="saving"><div class="form-grid">
          <label>设备组名称<input v-model="groupForm.name" required maxlength="200" autocomplete="off" /></label>
          <label>所属网关<select v-model="groupForm.gatewayId" required><option disabled value="">选择网关</option><option v-if="groupForm.gatewayId && !gateways.some((gateway) => gateway.id === groupForm.gatewayId)" :value="groupForm.gatewayId">{{ groupForm.gatewayId }}（不可用）</option><option v-for="gateway in gateways" :key="gateway.id" :value="gateway.id">{{ gateway.name }}</option></select></label>
          <label>设备组策略<select v-model="groupForm.policyId" required><option disabled value="">选择策略</option><option v-if="groupForm.policyId && !policies.some((policy) => policy.id === groupForm.policyId)" :value="groupForm.policyId">{{ groupForm.policyId }}（不可用）</option><option v-for="policy in policies" :key="policy.id" :value="policy.id">{{ policy.name }}</option></select></label>
          <label class="checkbox"><input v-model="groupForm.enabled" type="checkbox" />在期望配置中启用</label>
        </div><div class="actions"><button class="button" type="submit" :disabled="!groupForm.gatewayId || !groupForm.policyId">{{ saving ? '正在保存…' : '保存设备组' }}</button><button class="button button--secondary" type="button" @click="groupEditorOpen = false">取消</button></div></fieldset>
      </form>
      <div v-if="!groups.length && !loading" class="empty-state">尚未配置设备组。</div>
      <article v-for="group in groups" :id="`device-group-${group.id}`" :key="group.id" class="row-card" :class="{ 'row-card--linked': linkedGroupId === group.id }"><div><strong>{{ group.name }}</strong><p>{{ memberCount(group.id) }} 个成员 · {{ gateways.find((gateway) => gateway.id === group.gatewayId)?.name ?? group.gatewayId }}</p><p>策略：{{ policies.find((policy) => policy.id === group.policyId)?.name ?? group.policyId }} · 版本 {{ group.revision ?? '未知' }}</p></div><div class="row-card__right"><StatusPill :label="group.drift ? '配置差异' : uiLabel(group.state)" :tone="group.drift ? 'warn' : group.state === 'verified' ? 'good' : 'neutral'" /><span class="muted">{{ group.enabled ? '已启用' : '已禁用' }}</span><button v-if="canOperate" class="button button--secondary" :disabled="saving || loading || !group.revision" :aria-label="`编辑设备组 ${group.name}`" @click="editGroup(group)">编辑</button></div></article>
    </section>
    <section class="panel">
      <div class="panel__heading"><h2>设备清单</h2><div class="actions"><span class="muted">{{ devices.length }} 条记录</span><button v-if="canOperate" class="button" :disabled="loading || saving" @click="editDevice()">添加设备</button></div></div>
      <form v-if="deviceEditorOpen && canOperate" class="editor" @submit.prevent="saveDevice">
        <h3>{{ editingDevice ? `编辑 ${editingDevice.name}` : '登记设备' }}</h3><p class="muted">{{ editingDevice ? `正在编辑版本 ${editingDevice.revision ?? '不可用'}.` : '新设备默认未纳管。' }} 控制器会检查地址归属冲突。</p>
        <fieldset :disabled="saving"><div class="form-grid">
          <label>设备名称<input v-model="deviceForm.name" required maxlength="200" autocomplete="off" /></label>
          <label>主要路由组<select v-model="deviceForm.groupId"><option value="">未分配</option><option v-if="deviceForm.groupId && !groups.some((group) => group.id === deviceForm.groupId)" :value="deviceForm.groupId">{{ deviceForm.groupId }}（不可用）</option><option v-for="group in groups" :key="group.id" :value="group.id">{{ group.name }}</option></select></label>
          <label class="full-width">IP 地址<textarea aria-label="IP 地址" v-model="deviceForm.addresses" rows="3" spellcheck="false" aria-describedby="device-address-help" placeholder="192.0.2.10&#10;2001:db8::10" /><span id="device-address-help" class="muted">每行输入一个保留或静态地址。新增地址仍为未验证状态。</span></label>
          <label>新地址分配方式<select v-model="deviceForm.provenance"><option value="manual">手动登记</option><option value="static">静态地址</option><option value="reserved">DHCP 保留地址</option></select><span class="muted">记录新地址的分配方式。此声明不代表地址归属或客户端流量已验证。</span></label>
          <label v-for="address in existingAddresses" :key="address.address">地址 {{ address.address }} 的分配方式<select v-model="addressProvenance[address.address]"><option v-if="addressProvenance[address.address] && !['manual', 'static', 'reserved'].includes(addressProvenance[address.address]!)" :value="addressProvenance[address.address]">{{ uiLabel(addressProvenance[address.address]) }}（已记录）</option><option value="manual">手动登记</option><option value="static">静态地址</option><option value="reserved">DHCP 保留地址</option></select><span class="muted">仅在实际分配方式改变时修改此记录。</span></label>
        </div>
        <section class="exceptions-editor" aria-label="设备例外规则">
          <div class="panel__heading"><h3>设备例外规则</h3><button class="button button--secondary" type="button" @click="addException">添加例外规则</button></div>
          <p class="muted">这些规则仅用于此设备，在强制规则和策略例外之后、普通策略规则之前执行。首条启用且匹配的规则生效。同一字段中的值满足任一即可，不同已填写字段必须同时匹配。空匹配条件适用于此设备的所有流量。</p>
          <p v-if="!exceptionDrafts.length" class="muted">此设备暂无例外规则。</p>
          <div v-for="(entry, index) in exceptionDrafts" :key="index" class="exception-row" :class="{ 'exception-row--selected': selectedExceptionIndex === index }">
            <button class="exception-select" type="button" :aria-pressed="selectedExceptionIndex === index" :aria-label="`选择例外规则 ${index + 1}`" @click="selectedExceptionIndex = index"><strong>{{ index + 1 }}. {{ entry.rule.name || '未命名例外规则' }}</strong><span class="muted">{{ entry.rule.action.kind === 'outbound_group' ? `代理组：${outbounds.find(group => group.id === entry.rule.action.outbound_group_id)?.name || entry.rule.action.outbound_group_id || '未选择'}` : uiLabel(entry.rule.action.kind) }} · {{ entry.rule.enabled ? '已启用' : '已禁用' }}</span></button>
            <button class="button button--secondary" type="button" :disabled="index === 0" :aria-label="`移动例外规则 ${index + 1}上移`" @click="moveException(index, -1)">↑</button>
            <button class="button button--secondary" type="button" :disabled="index === exceptionDrafts.length - 1" :aria-label="`移动例外规则 ${index + 1}下移`" @click="moveException(index, 1)">↓</button>
          </div>
          <div v-if="activeException" class="form-grid">
            <label>例外名称<input v-model="activeException.rule.name" maxlength="200" autocomplete="off" /></label>
            <label class="checkbox"><input v-model="activeException.rule.enabled" type="checkbox" />启用例外规则</label>
            <label>例外动作<select :value="activeException.rule.action.kind" @change="setExceptionAction(($event.target as HTMLSelectElement).value as DeviceExceptionRule['action']['kind'])"><option v-for="action in exceptionActions" :key="action" :value="action">{{ uiLabel(action) }}</option></select></label>
            <label v-if="activeException.rule.action.kind === 'outbound_group'">例外代理组<select v-model="activeException.rule.action.outbound_group_id" required><option disabled value="">选择代理组</option><option v-if="activeException.rule.action.outbound_group_id && !outbounds.some(group => group.id === activeException!.rule.action.outbound_group_id)" :value="activeException.rule.action.outbound_group_id" disabled>{{ activeException.rule.action.outbound_group_id }}（不可用）</option><option v-for="group in outbounds" :key="group.id" :value="group.id">{{ group.name }}</option></select></label>
            <label v-for="field in exceptionListMatches" :key="field.key">{{ field.label }}<input :value="activeException.rule.match[field.key]?.join(', ')" :placeholder="field.placeholder" @change="activeException.rule.match[field.key] = csv(($event.target as HTMLInputElement).value)" /></label>
            <label>例外目标端口<input v-model="activeException.ports" placeholder="443, 1000-1100" /><span class="muted">使用逗号分隔端口或闭区间，范围为 1–65535。</span></label>
            <label>例外传输协议<select v-model="activeException.rule.match.transport" multiple><option value="tcp">TCP</option><option value="udp">UDP</option><option value="quic">QUIC</option></select><span class="muted">未选择时匹配任意传输协议。</span></label>
            <label>例外地址族<select v-model="activeException.rule.match.address_families" multiple><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select><span class="muted">未选择时匹配任意地址族。</span></label>
            <div class="full-width"><button class="button button--danger" type="button" @click="removeException">移除所选例外</button></div>
          </div>
        </section>
        <div class="actions"><button class="button" type="submit">{{ saving ? '正在保存…' : '保存设备' }}</button><button class="button button--secondary" type="button" @click="deviceEditorOpen = false">取消</button></div></fieldset>
      </form>
      <form v-if="deletingDevice && canOperate" class="editor" @submit.prevent="deleteDevice"><h3>删除 {{ deletingDevice.name }}？</h3><p class="muted">此操作会删除未纳管设备的记录，并释放其已登记的地址归属。</p><label class="checkbox"><input v-model="deleteAcknowledged" :disabled="saving" type="checkbox" required />我确认此设备未被纳管，可以删除其记录。</label><div class="actions"><button class="button button--danger" type="submit" :disabled="saving || !deleteAcknowledged">{{ saving ? '正在删除…' : '删除设备记录' }}</button><button class="button button--secondary" type="button" :disabled="saving" @click="deletingDevice = undefined">取消</button></div></form>
      <div v-if="!devices.length && !loading" class="empty-state">尚未登记设备。</div>
      <article v-for="device in devices" :key="device.id" class="row-card"><div><strong>{{ device.name }}</strong><p>{{ device.addresses.map((address) => address.address).join(', ') || '尚未记录地址' }}</p><p>设备组：{{ groups.find((group) => group.id === device.groupId)?.name ?? (device.groupId || '未分配') }} · 版本 {{ device.revision ?? '未知' }}</p></div><div class="row-card__right"><StatusPill :label="uiLabel(device.enrollment)" :tone="device.enrollment === 'enrolled' ? 'good' : device.enrollment === 'blocked' ? 'bad' : 'warn'" /><span class="coverage">{{ uiLabel(device.coverage) }}</span><button v-if="canOperate" class="button button--secondary" :disabled="saving || loading || !device.revision" :aria-label="`编辑设备 ${device.name}`" @click="editDevice(device)">编辑</button><button v-if="canOperate" class="button button--secondary" :disabled="saving || loading || !device.revision || device.enrollment !== 'unenrolled'" :title="device.enrollment !== 'unenrolled' ? '移除此设备记录前请先处理纳管状态' : '删除未纳管设备记录'" :aria-label="`删除设备 ${device.name}`" @click="confirmDelete(device)">删除</button></div></article>
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
