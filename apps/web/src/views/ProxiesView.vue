<script setup lang="ts">
import { uiLabel } from '../localization'
import DiagnosticMessage from '../components/DiagnosticMessage.vue'
import { computed, onActivated, ref } from 'vue'
import StatusPill from '../components/StatusPill.vue'
import UiIcon from '../components/UiIcon.vue'
import StateStrip from '../components/StateStrip.vue'
import { randomIdempotencyKey } from '../api/client'
import { useControllerState } from '../state'
import type { GatewayProbeResponse, NodeSummary, OutboundGroupSummary, OutboundSourceFilters, SelectionSummary } from '../types'
import { outboundUsage, type UsageDeviceGroup, type UsagePolicy, type UsageRuleSet } from '../outboundUsage'
import { filterLines, previewCandidates } from '../outboundFilters'

const props = defineProps<{ state: ReturnType<typeof useControllerState> }>()
const nodes = ref<NodeSummary[]>([])
const groups = ref<OutboundGroupSummary[]>([])
const selections = ref<Record<string, SelectionSummary[]>>({})
const readbackErrors = ref<Record<string, string>>({})
const usagePolicies = ref<UsagePolicy[]>([])
const usageRuleSets = ref<UsageRuleSet[]>([])
const usageDeviceGroups = ref<UsageDeviceGroup[]>([])
const usageError = ref<string>()
const usageLoaded = ref(false)
const probeResults = ref<Record<string, GatewayProbeResponse>>({})
const probeErrors = ref<Record<string, string>>({})
const probing = ref<string>()
const selectedTransports = ref<Record<string, string>>({})
const search = ref('')
const protocolFilter = ref('')
const nodeSort = ref<'name' | 'protocol' | 'health'>('name')
const loading = ref(false)
const loadError = ref<string>()
const actionError = ref<string>()
const notice = ref<string>()
const pendingGroup = ref<string>()
const saving = ref(false)
const editorOpen = ref(false)
const editing = ref<{ id: string; revision: number }>()
const form = ref({ name: '', gatewayId: '', mode: 'manual' as OutboundGroupSummary['mode'], replacementPolicy: 'block' as OutboundGroupSummary['replacementPolicy'], nodeIds: [] as string[] })
const candidateMode = ref<'explicit' | 'filters'>('explicit')
const filterForm = ref<Record<keyof OutboundSourceFilters, string>>({ provider_ids: '', protocols: '', exclude_provider_ids: '', exclude_protocols: '', include_node_ids: '', exclude_node_ids: '', include_names: '', exclude_names: '' })
const filterFields: Array<{ key: keyof OutboundSourceFilters; label: string }> = [{ key: 'provider_ids', label: '包含的订阅 ID' }, { key: 'protocols', label: '包含的协议' }, { key: 'include_names', label: '包含的精确节点名称' }, { key: 'exclude_names', label: '排除的精确节点名称' }, { key: 'include_node_ids', label: '包含的节点 ID' }, { key: 'exclude_node_ids', label: '排除的节点 ID' }, { key: 'exclude_provider_ids', label: '排除的订阅 ID' }, { key: 'exclude_protocols', label: '排除的协议' }]
const sourceFilters = computed<OutboundSourceFilters>(() => Object.fromEntries(filterFields.map(field => [field.key, filterLines(filterForm.value[field.key]).map(value => field.key.includes('protocols') ? value.toLowerCase() : value)]).filter(([, values]) => (values as string[]).length)))
const filterPreview = computed(() => previewCandidates(sourceFilters.value, nodes.value))
const canAdminister = computed(() => props.state.isAdministrator.value)
const busy = computed(() => loading.value || saving.value || !!pendingGroup.value)
const protocols = computed(() => [...new Set(nodes.value.map(node => node.protocol))].sort())
const filteredNodes = computed(() => nodes.value.filter(matchesSearch).sort((a, b) => a[nodeSort.value].localeCompare(b[nodeSort.value]) || a.name.localeCompare(b.name) || a.id.localeCompare(b.id)))
const missingFormNodes = computed(() => form.value.nodeIds.filter(id => !nodes.value.some(node => node.id === id)))
const references = computed(() => Object.fromEntries(groups.value.map(group => [group.id, outboundUsage(group.id, usagePolicies.value, usageRuleSets.value, usageDeviceGroups.value)])))

function matchesSearch(node: NodeSummary) {
  return (!protocolFilter.value || node.protocol === protocolFilter.value) && `${node.name} ${node.protocol} ${node.id}`.toLowerCase().includes(search.value.toLowerCase())
}
function nodesForGroup(group: OutboundGroupSummary) {
  return filteredNodes.value.filter(node => group.nodeIds.includes(node.id))
}
function missingCandidates(group: OutboundGroupSummary) {
  return group.nodeIds.filter(id => !nodes.value.some(node => node.id === id))
}
function nodeName(id?: string) {
  return id ? nodes.value.find(node => node.id === id)?.name ?? id : undefined
}
function activeTransport(group: OutboundGroupSummary) {
  return selectedTransports.value[group.id] ?? 'tcp'
}
function sharedSelection(group: OutboundGroupSummary) { return group.selectionScope === 'shared_tcp_udp' }
function selectionTransports(group: OutboundGroupSummary) { return sharedSelection(group) ? ['tcp', 'udp'] : [activeTransport(group)] }
function selectionLabel(group: OutboundGroupSummary) { return selectionTransports(group).map(transport => transport.toUpperCase()).join(' + ') }
function transports(group: OutboundGroupSummary) {
  return [...new Set(['tcp', 'udp', ...group.transportScopes, ...(selections.value[group.id] ?? []).filter(item => item.scope.gateway_id === group.gatewayId).map(item => item.scope.transport)])]
}
function selectionFor(group: OutboundGroupSummary, transport = activeTransport(group)) {
  return selections.value[group.id]?.find(item => item.scope.gateway_id === group.gatewayId && item.scope.transport === transport)
}
function selectionStates(group: OutboundGroupSummary) {
  const records = selectionTransports(group).map(transport => selectionFor(group, transport))
  const state = (field: 'desired_node_id' | 'applied_node_id' | 'observed_node_id') => {
    const ids = records.map(record => record?.[field])
    return ids.every(id => id === ids[0]) ? nodeName(ids[0]) : 'TCP / UDP 不一致，请检查回读'
  }
  return { desired: state('desired_node_id'), applied: state('applied_node_id'), observed: state('observed_node_id') }
}
function observedForSelection(group: OutboundGroupSummary, nodeID: string) { return selectionTransports(group).every(transport => selectionFor(group, transport)?.observed_node_id === nodeID) }
function gatewayName(id: string) { return props.state.gateways.value.find(gateway => gateway.id === id)?.name ?? id }
function selectionNeedsAttention(group: OutboundGroupSummary) {
  if (readbackErrors.value[group.id] || groupConfigurationPending(group)) return true
  const records = selectionTransports(group).map(transport => selectionFor(group, transport))
  if (records.some(record => !record?.observed_node_id || record.desired_node_id !== record.applied_node_id || record.applied_node_id !== record.observed_node_id)) return true
  return sharedSelection(group) && records.some(record => record?.observed_node_id !== records[0]?.observed_node_id)
}
function groupConfigurationPending(group: OutboundGroupSummary) { return group.appliedRevision !== undefined && (group.appliedRevision !== group.revision || group.observedRevision !== group.revision) }
function groupApplyUnavailable(group: OutboundGroupSummary) {
  if (!canAdminister.value) return '应用组配置需要管理员会话。'
  if (!props.state.capabilities.value['group.publish_hot']) return '此控制器未报告组发布能力。'
  if (!group.nodeIds.length) return '应用组配置前请先添加候选节点。'
  return undefined
}
function selectionUnavailable(group: OutboundGroupSummary) {
  if (!props.state.canOperate.value) return '更改节点选择需要操作员或管理员会话。'
  if (!props.state.capabilities.value['selection.set_runtime']) return '此控制器不支持运行时节点选择。'
  if (group.mode !== 'manual') return '请使用手动选择模式选择节点。'
  if (groupConfigurationPending(group)) return '组配置尚未应用。选择节点前请先应用已保存的组版本。'
  if (readbackErrors.value[group.id]) return '节点选择回读不可用，更改选择前请刷新。'
  if (!Object.prototype.hasOwnProperty.call(selections.value, group.id)) return '正在等待节点选择回读。'
  if (!group.nodeIds.length) return '更改选择前请先添加候选节点。'
  return undefined
}
function errorMessage(cause: unknown, fallback: string) {
  return cause instanceof Error ? cause.message : fallback
}
function probeKey(group: OutboundGroupSummary, node?: NodeSummary) { return `${group.gatewayId}:${node ? `node:${node.id}` : `group:${group.id}`}` }
function probeUnavailable(group: OutboundGroupSummary, node?: NodeSummary) {
  if (!props.state.canOperate.value) return '网关探测需要操作员会话。'
  const gateway = props.state.gateways.value.find(item => item.id === group.gatewayId)
  if (!gateway?.capabilities.supported.includes(node ? 'probe.node' : 'probe.group')) return '此网关未报告所需的探测能力。'
  if (node && (!node.supported || !group.nodeIds.includes(node.id))) return '节点必须是分配给此网关且受支持的候选节点。'
  return undefined
}
async function runProbe(group: OutboundGroupSummary, node?: NodeSummary) {
  const key = probeKey(group, node)
  const unavailable = probeUnavailable(group, node)
  if (unavailable || probing.value) { if (unavailable) probeErrors.value[key] = unavailable; return }
  probing.value = key
  delete probeErrors.value[key]
  delete probeResults.value[key]
  try {
    const result = node ? await props.state.api.gatewayProbeNode(group.gatewayId, node.id) : await props.state.api.gatewayProbeGroup(group.gatewayId, group.id)
    if (result.gateway_id !== group.gatewayId || result.target_id !== (node?.id ?? group.id) || result.target_kind !== (node ? 'node' : 'group')) throw new Error('网关探测返回了不同的目标，结果已丢弃。')
    probeResults.value[key] = result
  } catch (cause) { probeErrors.value[key] = errorMessage(cause, '网关探测失败') }
  finally { probing.value = undefined }
}
function probeLabel(result: GatewayProbeResponse) {
  return `${result.gateway_name || result.gateway_id}: ${result.probe.ok ? `${result.probe.latency_ms} 毫秒（网关测量）` : '探测失败'} · ${result.observed_at}`
}

async function load() {
  if (loading.value) return
  loading.value = true
  loadError.value = undefined
  try {
    const [inventory, outboundGroups] = await Promise.all([props.state.api.nodes(), props.state.api.outboundGroups()])
    nodes.value = inventory
    groups.value = outboundGroups
    const [results, policyResult, ruleSetResult, deviceGroupResult] = await Promise.all([
      Promise.allSettled(outboundGroups.map(group => props.state.api.selections(group.id))),
      props.state.api.policyDocuments<UsagePolicy>().then(value => ({ ok: true as const, value }), cause => ({ ok: false as const, cause })),
      props.state.api.ruleSetDocuments<UsageRuleSet>().then(value => ({ ok: true as const, value }), cause => ({ ok: false as const, cause })),
      props.state.api.deviceGroups().then(value => ({ ok: true as const, value }), cause => ({ ok: false as const, cause })),
    ])
    if (policyResult.ok && ruleSetResult.ok && deviceGroupResult.ok) {
      usagePolicies.value = policyResult.value
      usageRuleSets.value = ruleSetResult.value
      usageDeviceGroups.value = deviceGroupResult.value
      usageLoaded.value = true
      usageError.value = undefined
    } else {
      const failures = [policyResult, ruleSetResult, deviceGroupResult].filter(result => !result.ok)
      usageError.value = failures.map(result => !result.ok ? errorMessage(result.cause, '引用清单不可用') : '').join('; ')
    }
    const nextErrors: Record<string, string> = {}
    const nextSelections: Record<string, SelectionSummary[]> = {}
    results.forEach((result, index) => {
      const group = outboundGroups[index]!
      if (result.status === 'fulfilled') nextSelections[group.id] = result.value
      else {
        nextErrors[group.id] = errorMessage(result.reason, '无法读取节点选择')
        if (selections.value[group.id]) nextSelections[group.id] = selections.value[group.id]!
      }
    })
    selections.value = nextSelections
    readbackErrors.value = nextErrors
  } catch (cause) {
    loadError.value = errorMessage(cause, '无法读取代理清单')
    usageError.value = '引用清单未刷新，之前读取的引用可能已过期。'
    for (const group of groups.value) readbackErrors.value[group.id] = '清单刷新失败，节点选择回读可能已过期。'
  } finally {
    loading.value = false
  }
}

function openEditor(group?: OutboundGroupSummary) {
  if (!canAdminister.value || busy.value) return
  editing.value = group ? { id: group.id, revision: group.revision } : undefined
  form.value = group
    ? { name: group.name, gatewayId: group.gatewayId, mode: group.mode, replacementPolicy: group.replacementPolicy, nodeIds: [...group.nodeIds] }
    : { name: '', gatewayId: props.state.selectedGatewayId.value ?? props.state.gateways.value[0]?.id ?? '', mode: 'manual', replacementPolicy: 'block', nodeIds: [] }
  candidateMode.value = group?.sourceFilters ? 'filters' : 'explicit'
  for (const field of filterFields) filterForm.value[field.key] = group?.sourceFilters?.[field.key]?.join('\n') ?? ''
  actionError.value = undefined
  notice.value = undefined
  editorOpen.value = true
}

async function saveGroup() {
  if (!canAdminister.value || busy.value) return
  if (!form.value.name.trim() || !form.value.gatewayId) {
    actionError.value = '请输入代理组名称并选择网关。'
    return
  }
  if (form.value.mode === 'automatic') { actionError.value = '网关适配器报告经过验证的自动选择能力前，自动模式不可用。'; return }
  if (candidateMode.value === 'filters' && !['provider_ids', 'protocols', 'include_node_ids', 'include_names'].some(key => sourceFilters.value[key as keyof OutboundSourceFilters]?.length)) { actionError.value = '来源筛选至少需要包含一个订阅、协议、节点 ID 或精确名称。'; return }
  saving.value = true
  actionError.value = undefined
  notice.value = undefined
  try {
    const body = { name: form.value.name.trim(), gateway_id: form.value.gatewayId, mode: form.value.mode, replacement_policy: form.value.replacementPolicy, node_ids: candidateMode.value === 'filters' ? filterPreview.value.map(node => node.id) : [...form.value.nodeIds], ...(candidateMode.value === 'filters' ? { source_filters: sourceFilters.value } : {}) }
    const saved = editing.value
      ? await props.state.api.updateOutboundGroup(editing.value.id, body, editing.value.revision)
      : await props.state.api.createOutboundGroup(body)
    editorOpen.value = false
    await load()
    const readback = groups.value.find(group => group.id === saved.id)
    if (!readback || readback.revision !== saved.revision) {
      actionError.value = '控制器已受理组变更，但回读尚未确认保存版本。重试前请刷新。'
      return
    }
    notice.value = `代理组配置已保存，版本为 ${readback.revision}.`
  } catch (cause) {
    actionError.value = errorMessage(cause, '无法保存代理组')
  } finally {
    saving.value = false
  }
}

async function select(group: OutboundGroupSummary, node: NodeSummary) {
  if (busy.value) return
  const unavailable = selectionUnavailable(group)
  if (unavailable || !node.supported || !group.nodeIds.includes(node.id)) {
    actionError.value = unavailable ?? '此节点不是组内受支持的候选节点。'
    return
  }
  const transportScopes = selectionTransports(group)
  const expectedRevisions = Object.fromEntries(transportScopes.map(transport => [transport, selectionFor(group, transport)?.revision ?? 0]))
  const expectedRevision = String(expectedRevisions[transportScopes[0]!])
  pendingGroup.value = group.id
  actionError.value = undefined
  notice.value = undefined
  try {
    const result = await props.state.api.setSelection(group.id, { nodeId: node.id, gatewayId: group.gatewayId, transportScopes, expectedRevision, ...(sharedSelection(group) ? { expectedRevisions } : {}) }, randomIdempotencyKey())
    if (!result.operationId) throw new Error('控制器未返回操作标识。重试前请刷新节点选择回读。')
    const operation = await props.state.api.waitForOperation(result.operationId)
    props.state.recordOperation(operation)
    if (['failed', 'outcome_unknown', 'partially_applied'].includes(operation.status)) actionError.value = operation.error ?? `节点选择操作状态为 ${uiLabel(operation.status)}.`
    else notice.value = `节点选择操作 ${uiLabel(operation.status)}。请检查下方的 ${selectionLabel(group)} 回读。`
  } catch (cause) {
    actionError.value = errorMessage(cause, '节点选择失败')
  } finally {
    await load()
    pendingGroup.value = undefined
  }
}

async function applyGroup(group: OutboundGroupSummary) {
  if (busy.value) return
  const unavailable = groupApplyUnavailable(group)
  if (unavailable) { actionError.value = unavailable; return }
  pendingGroup.value = group.id
  actionError.value = undefined
  notice.value = undefined
  try {
    const accepted = await props.state.api.applyOutboundGroup(group.id, group.revision, randomIdempotencyKey())
    const operation = await props.state.api.waitForOperation(accepted.operationId)
    props.state.recordOperation(operation)
    await load()
    const readback = groups.value.find(item => item.id === group.id)
    if (operation.status !== 'applied') actionError.value = operation.error ?? `组配置操作状态为 ${uiLabel(operation.status)}.`
    else if (!readback || readback.revision !== group.revision || readback.appliedRevision !== group.revision || readback.observedRevision !== group.revision) actionError.value = '控制器已受理组发布，但回读尚未确认请求版本。'
    else notice.value = `组配置版本 ${group.revision} 已在网关上应用并观测确认。`
  } catch (cause) {
    actionError.value = errorMessage(cause, '无法应用组配置')
    await load()
  } finally { pendingGroup.value = undefined }
}

onActivated(load)
</script>

<template>
  <div class="page-grid">
    <section class="page-heading">
      <div><p class="eyebrow">代理出口</p><h1>代理</h1><p class="lede">选择出口节点并管理代理组，为不同设备或场景配置合适的网络出口。</p></div>
      <div class="node-filters"><input v-model="search" class="search" type="search" placeholder="搜索节点" aria-label="搜索节点" /><label>协议<select v-model="protocolFilter" aria-label="按协议筛选节点"><option value="">全部协议</option><option v-for="protocol in protocols" :key="protocol" :value="protocol">{{ protocol }}</option></select></label><label>排序<select v-model="nodeSort" aria-label="节点排序"><option value="name">名称</option><option value="protocol">协议</option><option value="health">健康状态</option></select></label></div>
    </section>
    <section v-if="loadError" class="alert alert--bad" role="alert"><DiagnosticMessage :message="loadError" /></section>
    <section v-if="actionError" class="alert alert--bad" role="alert"><DiagnosticMessage :message="actionError" /></section>
    <section v-if="notice" class="alert alert--info" role="status">{{ notice }}</section>
    <section v-if="editorOpen" class="panel">
      <div class="panel__heading"><h2>{{ editing ? '编辑代理组' : '新建代理组' }}</h2><button class="button button--secondary" :disabled="saving" @click="editorOpen = false">取消</button></div>
      <form class="group-form" @submit.prevent="saveGroup">
        <fieldset :disabled="busy || !canAdminister">
          <div class="form-grid">
            <label>代理组名称<input v-model="form.name" required maxlength="200" /></label>
            <label>出口网关<select v-model="form.gatewayId" required><option value="" disabled>选择网关</option><option v-for="gateway in state.gateways.value" :key="gateway.id" :value="gateway.id">{{ gateway.name }}</option><option v-if="form.gatewayId && !state.gateways.value.some(gateway => gateway.id === form.gatewayId)" :value="form.gatewayId">{{ form.gatewayId }}（不可用）</option></select></label>
            <label>选择模式<select v-model="form.mode"><option value="manual">手动选择</option><option value="automatic" disabled>自动选择（暂不可用）</option></select></label>
            <label>节点替换行为<select v-model="form.replacementPolicy"><option value="block">所选节点消失时阻断流量</option><option value="none">保留未确定的选择状态</option></select></label>
            <label>候选节点来源<select v-model="candidateMode"><option value="explicit">逐个选择节点</option><option value="filters">筛选订阅清单</option></select></label>
          </div>
          <template v-if="candidateMode === 'filters'"><p class="help">筛选条件在订阅更新后仍保留。每行输入一个值。订阅与协议条件需同时满足；包含的节点标识或名称匹配任一列表即可。名称精确匹配且区分大小写，排除条件优先。</p><div class="form-grid"><label v-for="field in filterFields" :key="field.key">{{ field.label }}<textarea v-model="filterForm[field.key]" rows="2" spellcheck="false" /></label></div><p class="help">已加载清单的本地预览：{{ filterPreview.length }} 个受支持的候选节点。控制器将校验保存后的成员。</p><ul class="filter-preview"><li v-for="node in filterPreview" :key="node.id">{{ node.name }} · {{ node.protocol }} · 订阅 {{ node.providerId }}</li></ul></template>
          <template v-else>
          <div class="candidate-heading"><h3>候选节点</h3><span>已选择 {{ form.nodeIds.length }} 个</span></div>
          <p class="help">候选节点使用订阅清单中的稳定标识。不支持的节点不能加入。</p>
          <div class="candidate-grid">
            <label v-for="node in filteredNodes" :key="node.id" class="candidate-choice"><input v-model="form.nodeIds" type="checkbox" :value="node.id" :disabled="!node.supported && !form.nodeIds.includes(node.id)" :aria-label="`候选节点 ${node.name}`" /><span><strong>{{ node.name }}</strong><small>{{ node.protocol }}<span v-if="!node.supported"> · 不支持</span></small></span></label>
          </div>
          <p v-if="!nodes.length" class="help">暂存一个订阅版本后，即可选择候选节点。</p>
          <p v-else-if="!filteredNodes.length" class="help">没有匹配搜索条件的节点。</p>
          <label v-for="id in missingFormNodes" :key="id" class="candidate-choice"><input v-model="form.nodeIds" type="checkbox" :value="id" :aria-label="`候选节点 ${id}`" /><span>{{ id }} · 当前清单中不存在；取消勾选可移除。</span></label>
          </template>
          <p v-if="editing" class="help">正在编辑配置版本 {{ editing.revision }}。其他管理员修改此组后，请刷新并重新打开编辑器。</p>
          <button class="button" type="submit" :disabled="!form.name.trim() || !form.gatewayId">{{ saving ? '正在保存…' : editing ? '保存代理组' : '创建代理组' }}</button>
        </fieldset>
      </form>
    </section>
    <section class="panel proxy-groups">
      <div class="panel__heading"><h2>代理组</h2><div class="actions"><button class="button button--secondary" :disabled="busy" @click="load">刷新</button><button class="button" :disabled="busy || !canAdminister" @click="openEditor()">新建代理组</button></div></div>
      <p v-if="!canAdminister" class="help">创建或编辑代理组需要管理员会话。</p>
      <div v-if="loading && !groups.length" class="empty-state" role="status">正在读取代理清单…</div>
      <div v-else-if="!groups.length" class="empty-state">尚未配置代理组。</div>
      <article v-for="group in groups" :key="group.id" class="group-card" :aria-label="`代理组 ${group.name}`">
        <div class="group-card__heading">
          <div><h3>{{ group.name }}</h3><p>{{ group.nodeIds.length }} 个候选节点 · {{ group.mode === 'manual' ? '手动选择' : '自动选择' }} · {{ gatewayName(group.gatewayId) }}</p></div>
          <div class="actions"><StatusPill :label="pendingGroup === group.id ? '正在应用' : readbackErrors[group.id] ? '回读不可用' : groupConfigurationPending(group) ? '配置待确认' : '已配置'" :tone="pendingGroup === group.id || readbackErrors[group.id] || groupConfigurationPending(group) ? 'warn' : 'neutral'" /><button v-if="groupConfigurationPending(group)" class="button" :aria-label="`应用组配置：${group.name}`" :title="groupApplyUnavailable(group)" :disabled="busy || !!groupApplyUnavailable(group)" @click="applyGroup(group)">应用配置</button><button class="button button--secondary" :aria-label="`测试代理组 ${group.name}（从网关测试）`" :title="probeUnavailable(group)" :disabled="!!probing || !!probeUnavailable(group)" @click="runProbe(group)">{{ probing === probeKey(group) ? '正在测试…' : '测试代理组' }}</button><button class="button button--secondary" :aria-label="`编辑 ${group.name}`" :disabled="busy || !canAdminister" @click="openEditor(group)">编辑</button></div>
        </div>
        <p v-if="group.appliedRevision !== undefined" class="help">组配置：期望版本 {{ group.revision }} · 已应用 {{ group.appliedRevision || '尚未应用' }} · 已观测 {{ group.observedRevision || '尚未观测' }}<span v-if="group.appliedGeneration"> · 网关代次 {{ group.appliedGeneration }}</span></p>
        <p v-if="group.sourceFilters" class="help">候选节点遵循已保存的来源筛选条件。以下 {{ group.nodeIds.length }} 个节点是控制器当前解析的成员。</p>
        <p v-if="readbackErrors[group.id]" class="alert alert--bad" role="alert"><DiagnosticMessage :message="readbackErrors[group.id]" /> 之前读取的数值可能已过期。</p>
        <p v-if="probeResults[probeKey(group)]" class="help" role="status">{{ probeLabel(probeResults[probeKey(group)]!) }}<span v-if="probeResults[probeKey(group)]?.probe.error"> · <DiagnosticMessage :message="probeResults[probeKey(group)]?.probe.error" /></span></p>
        <p v-if="probeErrors[probeKey(group)]" class="help warning" role="alert"><DiagnosticMessage :message="probeErrors[probeKey(group)]" /></p>

        <p v-if="sharedSelection(group)" class="help">TCP 与 UDP 共用选择。选择节点会同时更改两种传输协议的出口。</p>
        <label v-else class="transport-control">选择传输协议<select :value="activeTransport(group)" :aria-label="`节点选择传输协议：${group.name}`" :disabled="busy" @change="selectedTransports[group.id] = ($event.target as HTMLSelectElement).value"><option v-for="transport in transports(group)" :key="transport" :value="transport">{{ transport.toUpperCase() }}</option></select></label>
        <StateStrip :states="selectionStates(group)" :pending="pendingGroup === group.id" />
        <p v-if="selectionUnavailable(group)" class="help warning">{{ selectionUnavailable(group) }}</p>
        <p v-else-if="!state.capabilities.value['selection.persist_restart']" class="help warning">此适配器未报告网关重启后保留节点选择的能力。</p>
        <div class="node-grid">
          <div v-for="node in nodesForGroup(group)" :key="node.id" class="node-entry"><button class="node-card" :class="{ 'node-card--selected': observedForSelection(group, node.id) }" :aria-label="`选择 ${node.name}，用于 ${group.name} (${selectionLabel(group)})`" :aria-pressed="observedForSelection(group, node.id)" :disabled="busy || !!selectionUnavailable(group) || !node.supported" @click="select(group, node)">
            <span class="node-card__name"><UiIcon name="globe" :size="19" />{{ node.name }}<UiIcon v-if="observedForSelection(group, node.id)" class="node-check" name="check" :size="17" /></span><span class="node-card__meta">{{ node.protocol }} · {{ uiLabel(node.health) }}</span><span v-if="!node.supported" class="node-card__warning">不支持</span><span v-if="observedForSelection(group, node.id)" class="node-card__meta">已观测用于 {{ selectionLabel(group) }}</span>
          </button><button class="button button--secondary" :aria-label="`测试节点 ${node.name}（从网关测试），用于 ${group.name}`" :title="probeUnavailable(group, node)" :disabled="!!probing || !!probeUnavailable(group, node)" @click="runProbe(group, node)">{{ probing === probeKey(group, node) ? '正在测试…' : '测试节点' }}</button><p v-if="probeResults[probeKey(group, node)]" class="help" role="status">{{ probeLabel(probeResults[probeKey(group, node)]!) }}<span v-if="probeResults[probeKey(group, node)]?.probe.error"> · <DiagnosticMessage :message="probeResults[probeKey(group, node)]?.probe.error" /></span></p><p v-if="probeErrors[probeKey(group, node)]" class="help warning" role="alert"><DiagnosticMessage :message="probeErrors[probeKey(group, node)]" /></p></div>
        </div>
        <p v-if="group.nodeIds.length && !nodesForGroup(group).length && !missingCandidates(group).length" class="help">没有匹配搜索条件的候选节点。</p>
        <p v-if="missingCandidates(group).length" class="help warning">当前清单中不可用的候选节点：{{ missingCandidates(group).join(', ') }}</p>
        <details class="readback-details" :open="selectionNeedsAttention(group)">
          <summary><span>部署与传输详情</span><span>{{ selectionNeedsAttention(group) ? '需要检查回读' : '查看 TCP / UDP 配置回读' }}</span></summary>
          <p class="help">以下是配置版本与传输选择的回读，不代表客户端流量已通过验证。</p>
        <div class="table-scroll"><table :aria-label="`节点选择回读：${group.name}`"><thead><tr><th>传输协议</th><th>期望状态</th><th>已应用</th><th>已观测</th><th>版本</th></tr></thead><tbody><tr v-for="transport in transports(group)" :key="transport"><th scope="row">{{ transport.toUpperCase() }}</th><td>{{ nodeName(selectionFor(group, transport)?.desired_node_id) ?? '—' }}</td><td>{{ nodeName(selectionFor(group, transport)?.applied_node_id) ?? '—' }}</td><td>{{ nodeName(selectionFor(group, transport)?.observed_node_id) ?? '—' }}</td><td>{{ selectionFor(group, transport)?.revision ?? '尚未选择' }}</td></tr></tbody></table></div>
        </details>
        <section class="usage-panel" :aria-label="`引用位置：${group.name}`">
          <h4>引用位置</h4>
          <p class="help">这些是已保存控制器配置中的引用，已禁用的引用仍会列出；实际部署流量可能不同。</p>
          <p v-if="usageError" class="help warning" role="status">引用回读不完整：<DiagnosticMessage :message="usageError" /> {{ usageLoaded ? '显示上次完整的引用快照。' : '' }}</p>
          <p v-else-if="loading && !usageLoaded" class="help">正在读取策略和设备组引用…</p>
          <p v-else-if="usageLoaded && !references[group.id]?.length" class="help">已保存的策略、规则集和设备组均未引用此代理组。</p>
          <ul v-if="references[group.id]?.length" class="usage-list">
            <li v-for="reference in references[group.id]" :key="`${reference.kind}:${reference.id}:${reference.detail}`">
              <a :href="reference.href">{{ reference.kind === 'device_group' ? '设备组' : reference.kind === 'rule_set' ? '规则集' : '策略' }}: {{ reference.name }}</a>
              <span>{{ reference.detail }}<strong v-if="reference.disabled"> · 已禁用的引用</strong></span>
            </li>
          </ul>
        </section>
      </article>
    </section>
  </div>
</template>

<style scoped>
.page-grid { display: grid; gap: 1rem; }
.page-heading { display: flex; align-items: end; justify-content: space-between; gap: 1rem; }
h1 { margin: .25rem 0 .4rem; font-size: 2rem; }
.lede { margin: 0; color: var(--muted); }
.eyebrow { margin: 0; color: #78b8ff; font-size: .7rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; }
input:not([type="checkbox"]), select { min-width: 0; padding: .65rem .75rem; border: 1px solid var(--border); border-radius: .4rem; background: var(--surface); color: var(--text); }
textarea { min-width: 0; width: 100%; padding: .6rem; resize: vertical; border: 1px solid var(--border); border-radius: .4rem; background: var(--surface); color: var(--text); font: inherit; } .filter-preview { margin: 0; padding-left: 1.2rem; color: var(--muted); font-size: .8rem; }
.search { width: 15rem; }
.node-filters { display: flex; align-items: end; flex-wrap: wrap; gap: .5rem; } .node-filters label { display: grid; gap: .2rem; font-size: .75rem; color: var(--muted); }
.panel { padding: 1rem; border: 1px solid var(--border); border-radius: .65rem; background: var(--surface); }
.panel__heading, .group-card__heading { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
h2, h3 { margin: 0; }
.actions { display: flex; align-items: center; flex-wrap: wrap; gap: .5rem; }
.button { cursor: pointer; padding: .5rem .7rem; border: 1px solid var(--border); border-radius: .4rem; background: var(--accent); color: #07111f; font-weight: 700; }
.button:disabled { cursor: not-allowed; opacity: .55; }
.button--secondary { background: transparent; color: var(--text); }
.group-card { display: grid; gap: .75rem; padding: .9rem; margin-top: .75rem; border-radius: .5rem; background: var(--surface-alt); min-width: 0; }
.group-card__heading p { margin: .3rem 0 0; color: var(--muted); font-size: .78rem; overflow-wrap: anywhere; }
.node-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(12rem, 1fr)); gap: .5rem; }
.node-entry { display: grid; align-content: start; gap: .4rem; min-width: 0; }
.node-card { display: grid; gap: .25rem; padding: .7rem; border: 1px solid var(--border); border-radius: .4rem; background: var(--surface); color: var(--text); text-align: left; cursor: pointer; overflow-wrap: anywhere; }
.node-card:hover:not(:disabled), .node-card--selected { border-color: var(--accent); }
.node-card:disabled { cursor: not-allowed; opacity: .55; }
.node-card__name { font-weight: 700; }
.node-card__meta, .node-card__warning { color: var(--muted); font-size: .75rem; }
.node-card__warning, .warning { color: var(--warn); }
.empty-state { padding: 1.5rem; color: var(--muted); text-align: center; }
.alert { padding: .75rem 1rem; border-radius: .5rem; margin: 0; overflow-wrap: anywhere; }
.alert--bad { border: 1px solid #713847; background: #301c29; color: #ffbeca; }
.alert--info { border: 1px solid var(--border); background: var(--surface); }
.group-form { margin-top: 1rem; }
fieldset { display: grid; gap: .8rem; border: 0; padding: 0; margin: 0; min-width: 0; }
.form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .75rem; }
.form-grid label { display: grid; gap: .35rem; font-size: .8rem; }
.candidate-heading { display: flex; align-items: center; justify-content: space-between; gap: .5rem; font-size: .85rem; }
.candidate-heading span, .help { color: var(--muted); font-size: .8rem; }
.help { margin: 0; line-height: 1.5; overflow-wrap: anywhere; }
.help.warning { color: var(--warn); }
.candidate-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(12rem, 1fr)); gap: .5rem; }
.candidate-choice { display: flex; gap: .5rem; align-items: flex-start; padding: .55rem; border: 1px solid var(--border); border-radius: .4rem; font-size: .8rem; overflow-wrap: anywhere; }
.candidate-choice small { display: block; color: var(--muted); margin-top: .2rem; }
.table-scroll { max-width: 100%; overflow-x: auto; overscroll-behavior-inline: contain; }
.usage-panel { display: grid; gap: .45rem; border-top: 1px solid var(--border); padding-top: .8rem; } .usage-panel h4 { margin: 0; font-size: .85rem; } .usage-list { display: grid; gap: .45rem; list-style: none; padding: 0; margin: 0; } .usage-list li { display: grid; gap: .15rem; font-size: .8rem; overflow-wrap: anywhere; } .usage-list a { color: var(--accent); } .usage-list span { color: var(--muted); } .usage-list strong { color: var(--warn); font-weight: 500; }
.table-scroll table { min-width: 35rem; width: 100%; border-collapse: collapse; }
.table-scroll th, .table-scroll td { min-width: 7rem; padding: .45rem .5rem; text-align: left; white-space: nowrap; }
table { width: 100%; border-collapse: collapse; font-size: .78rem; text-align: left; }
th, td { padding: .55rem .45rem; border-bottom: 1px solid var(--border); overflow-wrap: anywhere; }
thead th { color: var(--muted); font-weight: 500; }
.transport-control { display: flex; gap: .65rem; align-items: center; font-size: .8rem; }
.transport-control select { padding: .4rem .65rem; }
@media (max-width: 760px) { .page-heading, .group-card__heading { display: grid; } .search { width: 100%; } .form-grid { grid-template-columns: 1fr; } .panel__heading { flex-wrap: wrap; } }

.proxy-groups { background: transparent !important; border: 0; padding: 0; }
.group-card { border: 1px solid var(--border); background: linear-gradient(120deg, #0d2238, #091b2b); padding: 1rem; border-radius: 10px; }
.group-card__heading h3 { font-size: 1.1rem; }
.node-card { min-height: 85px; border-radius: 8px; background: #081a2c; }
.node-card--selected { border-color: var(--good); box-shadow: inset 0 0 0 1px var(--good), 0 0 14px #22e3ad0d; }
.node-card__name { display: flex; align-items: center; gap: 8px; font-size: .84rem; }
.node-card__name > .ui-icon { color: var(--accent); }
.node-card__name > .node-check { color: var(--good); margin-left: auto; }
.readback-details { min-width: 0; padding: .7rem .8rem; border: 1px solid var(--border); border-radius: 7px; background: #081a2b; }
.readback-details summary { color: var(--muted); font-size: .78rem; cursor: pointer; }
.readback-details summary > span:first-child { color: #c9dcf2; margin-right: 1rem; }
.readback-details[open] > .help { margin: .75rem 0; }
.usage-list { grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); }
.usage-list li { padding: .7rem; border: 1px solid #1c3854; border-radius: 7px; background: #0b2137; }
</style>
