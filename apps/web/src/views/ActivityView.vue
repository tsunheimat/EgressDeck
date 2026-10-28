<script setup lang="ts">
import { uiLabel, actionName, auditActionName, auditOutcomeName } from '../localization'
import DiagnosticMessage from '../components/DiagnosticMessage.vue'
import { formatTimestamp } from '../uiPresentation'
import { computed, onActivated, onDeactivated, ref, watch } from 'vue'
import StatusPill from '../components/StatusPill.vue'
import StateStrip from '../components/StateStrip.vue'
import { useControllerState } from '../state'
import type { GatewayConnectionsResponse, GatewayCounterValue, GatewayCountersResponse, OperationSummary } from '../types'

const props = defineProps<{ state: ReturnType<typeof useControllerState> }>()
const operations = ref<OperationSummary[]>([])
const loading = ref(false)
const error = ref<string>()
const audits = ref<Array<{ id: string; actor: string; action: string; object_type: string; object_id: string; outcome: string; created_at: string }>>([])
const selectedOperation = ref<OperationSummary>()
const connections = ref<GatewayConnectionsResponse>()
const counters = ref<GatewayCountersResponse>()
const diagnosticError = ref<string>()
const diagnosticLoading = ref(false)
const selectedGateway = computed(() => props.state.selectedGateway.value)
const supportsConnections = computed(() => selectedGateway.value?.capabilities.supported.includes('connections.observe') ?? false)
const supportsCounters = computed(() => selectedGateway.value?.capabilities.supported.some(capability => capability === 'traffic.proxy_counters' || capability === 'traffic.direct_counters') ?? false)
let diagnosticRequest = 0
let active = false
let diagnosticAbort: AbortController | undefined

async function loadDiagnostics() {
  const request = ++diagnosticRequest
  diagnosticAbort?.abort()
  connections.value = undefined
  counters.value = undefined
  diagnosticError.value = undefined
  diagnosticLoading.value = false
  const gateway = selectedGateway.value
  if (!active || !gateway || (!supportsConnections.value && !supportsCounters.value)) return
  diagnosticAbort = new AbortController()
  const signal = diagnosticAbort.signal
  diagnosticLoading.value = true
  try {
    const results = await Promise.allSettled([
      supportsConnections.value ? props.state.api.gatewayConnections(gateway.id, signal) : Promise.resolve(undefined),
      supportsCounters.value ? props.state.api.gatewayCounters(gateway.id, signal) : Promise.resolve(undefined),
    ])
    if (request !== diagnosticRequest || signal.aborted) return
    const errors: string[] = []
    if (results[0].status === 'fulfilled' && results[0].value) {
      if (results[0].value.gateway_id === gateway.id) connections.value = results[0].value
      else errors.push('连接回读与所选网关不匹配')
    } else if (results[0].status === 'rejected') errors.push(results[0].reason instanceof Error ? results[0].reason.message : '连接信息不可用')
    if (results[1].status === 'fulfilled' && results[1].value) {
      if (results[1].value.gateway_id === gateway.id) counters.value = results[1].value
      else errors.push('计数器回读与所选网关不匹配')
    } else if (results[1].status === 'rejected') errors.push(results[1].reason instanceof Error ? results[1].reason.message : '计数器不可用')
    if (errors.length) diagnosticError.value = errors.join('; ')
  } finally { if (request === diagnosticRequest) diagnosticLoading.value = false }
}

function counterText(counter: GatewayCounterValue | undefined, unit: 'bytes' | 'packets') {
  return counter?.available && counter[unit] !== undefined ? `${counter[unit]} ${unit === 'bytes' ? '字节' : '数据包'}` : '不可用'
}

async function load() {
  loading.value = true
  error.value = undefined
  try {
    void loadDiagnostics()
    const results = await Promise.allSettled([props.state.api.operations(), props.state.api.auditEvents<typeof audits.value[number]>()])
    if (results[0].status === 'fulfilled') operations.value = results[0].value
    if (results[1].status === 'fulfilled') audits.value = results[1].value
    const failures = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected')
    if (failures.length) error.value = failures.map(r => r.reason instanceof Error ? r.reason.message : '无法读取活动记录').join('; ')
  } finally { loading.value = false }
}
async function inspect(id: string) {
  try { selectedOperation.value = await props.state.api.operation(id) } catch (cause) { error.value = cause instanceof Error ? cause.message : '回读不可用' }
}
function views(operation: OperationSummary) {
  return Object.fromEntries(Object.entries(operation.views ?? {}).map(([kind, value]) => [kind, value?.revision ?? (value?.status ? uiLabel(value.status) : `代次 ${value?.generation}`)]))
}
watch(() => [selectedGateway.value?.id, supportsConnections.value, supportsCounters.value], () => { if (active) void loadDiagnostics() })
onActivated(() => { active = true; void load() })
onDeactivated(() => { active = false; diagnosticRequest++; diagnosticAbort?.abort(); diagnosticLoading.value = false })
</script>

<template>
  <div class="page-grid"><section class="page-heading"><div><p class="eyebrow">操作与证据</p><h1>活动与诊断</h1><p class="lede">追踪操作结果、排查失败原因。配置请求成功不等于网关上的真实流量已验证。</p></div><button class="button button--secondary" :disabled="loading" @click="load">刷新</button></section>
    <section v-if="error" class="alert alert--bad" role="alert"><DiagnosticMessage :message="error" /></section>
    <section class="panel" aria-label="网关诊断">
      <div class="panel__heading"><div><h2>网关流量</h2><p class="muted">{{ selectedGateway ? `测量来源：${selectedGateway.name}` : '选择网关以检查流量' }}</p></div><button class="button button--secondary" :disabled="diagnosticLoading || !selectedGateway || (!supportsConnections && !supportsCounters)" @click="loadDiagnostics">{{ diagnosticLoading ? '正在读取网关…' : '读取网关' }}</button></div>
      <p v-if="selectedGateway && !supportsConnections && !supportsCounters" class="muted">此网关未报告连接观测或流量计数器能力。</p>
      <p v-if="diagnosticError" class="alert alert--bad" role="alert"><DiagnosticMessage :message="diagnosticError" /></p>
      <div class="counter-grid">
        <div class="counter"><strong>代理流量</strong><span>{{ counterText(counters?.proxy, 'bytes') }}</span><small>{{ counterText(counters?.proxy, 'packets') }}</small></div>
        <div class="counter"><strong>直连流量</strong><span>{{ counterText(counters?.direct, 'bytes') }}</span><small>{{ counterText(counters?.direct, 'packets') }}</small></div>
        <div class="counter"><strong>订阅额度</strong><span>不可用</span><small>网关流量计数器不代表订阅套餐额度。</small></div>
      </div>
      <p v-if="counters" class="muted">计数器回读：{{ counters.gateway_name }} · {{ counters.observed_at }}。数值为网关累计值，引擎重启后可能归零。</p>
      <div class="panel__heading"><h3>连接列表</h3><span class="muted">{{ connections ? `${connections.items.length} 个已观测` : '不可用' }}</span></div>
      <p class="muted">此网关的观测接口不提供来源、目标、命中规则、路由链或策略代次。</p>
      <p v-if="!supportsConnections" class="muted">此网关不支持连接观测。</p>
      <p v-else-if="connections && !connections.items.length" class="empty-state">未在 {{ connections.gateway_name }} 上观测到连接。</p>
      <div v-if="connections?.items.length" class="table-scroll"><table><thead><tr><th>连接</th><th>代理组</th><th>节点</th><th>传输协议</th><th>状态</th><th>建立时间</th></tr></thead><tbody><tr v-for="connection in connections.items" :key="connection.id"><td>{{ connection.id }}</td><td>{{ connection.group_id || '未知' }}</td><td>{{ connection.node_id || '未知' }}</td><td>{{ uiLabel(connection.transport) }}</td><td>{{ uiLabel(connection.state) }}</td><td>{{ connection.opened_at }}</td></tr></tbody></table></div>
      <p v-if="connections" class="muted">连接回读：{{ connections.gateway_name }} · {{ connections.observed_at }}</p>
    </section>
    <section class="panel"><div class="panel__heading"><h2>操作记录</h2><span class="muted">{{ operations.length }} 条已记录</span></div><div v-if="!operations.length && !loading" class="empty-state">暂无操作记录。</div><div v-for="operation in operations" :key="operation.id" class="operation-row"><span><strong>{{ actionName(operation.action) }}</strong><small>{{ operation.target }} · {{ operation.updatedAt }}</small><small>{{ operation.id }}</small></span><StatusPill :label="uiLabel(operation.status)" :tone="operation.status === 'applied' ? 'good' : ['failed', 'outcome_unknown'].includes(operation.status) ? 'bad' : 'warn'" /><button class="button button--secondary" @click="inspect(operation.id)">读取操作</button><p v-if="operation.error" class="operation-error"><DiagnosticMessage :message="operation.error" /></p></div></section>
    <section v-if="selectedOperation" class="panel"><h2>操作回读</h2><p>{{ selectedOperation.id }} · {{ uiLabel(selectedOperation.status) }}</p><StateStrip :states="views(selectedOperation)" /><p class="muted">没有已验证状态，表示尚未记录验证证据。</p></section>
    <section class="panel"><h2>审计记录</h2><div v-if="!audits.length" class="empty-state">暂无审计事件。</div><div v-for="event in audits" :key="event.id" class="operation-row"><span><strong :title="event.action">{{ auditActionName(event.action) }} · {{ uiLabel(event.object_type) }}</strong><small>{{ event.actor }} · <time :datetime="event.created_at" :title="event.created_at">{{ formatTimestamp(event.created_at) }}</time></small></span><span>{{ auditOutcomeName(event.outcome) }}</span></div></section>
  </div>
</template>

<style scoped>
.page-grid { display: grid; gap: 1rem; } .page-heading, .panel__heading, .operation-row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; } h1 { margin: .25rem 0 .4rem; font-size: 2rem; } h2 { margin: 0; font-size: 1.1rem; }
.eyebrow { margin: 0; color: #78b8ff; font-size: .7rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; } .lede { margin: 0; color: var(--muted); }
.panel { display: grid; gap: .7rem; padding: 1rem; border: 1px solid var(--border); border-radius: .65rem; background: var(--surface); } .operation-row { position: relative; padding: .8rem; border-radius: .45rem; background: var(--surface-alt); } .operation-row > span:first-child { display: grid; gap: .2rem; } .operation-row small, .muted { color: var(--muted); font-size: .78rem; } .operation-error { flex-basis: 100%; margin: .3rem 0 0; color: var(--bad); font-size: .78rem; }
.button { cursor: pointer; padding: .5rem .7rem; border: 1px solid var(--border); border-radius: .4rem; background: var(--accent); color: #07111f; font-weight: 700; } .button:disabled { cursor: wait; opacity: .55; } .button--secondary { background: transparent; color: var(--text); }
.empty-state { padding: 1.5rem; color: var(--muted); text-align: center; } .alert { padding: .75rem 1rem; border-radius: .5rem; } .alert--bad { border: 1px solid #713847; background: #301c29; color: #ffbeca; }
.panel { min-width: 0; } .panel__heading > div { min-width: 0; } .counter-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .7rem; } .counter { display: grid; gap: .4rem; background: var(--surface-alt); padding: .8rem; border-radius: .45rem; overflow-wrap: anywhere; } .counter small { color: var(--muted); font-size: .78rem; } h3 { font-size: .95rem; margin: .3rem 0; } .table-scroll { max-width: 100%; overflow: auto; } table { width: 100%; border-collapse: collapse; text-align: left; font-size: .8rem; } th, td { padding: .6rem; border-bottom: 1px solid var(--border); } th { color: var(--muted); } td { overflow-wrap: anywhere; }
@media (max-width: 760px) { .page-heading, .operation-row { align-items: flex-start; flex-direction: column; } }
@media (max-width: 620px) { .counter-grid { grid-template-columns: 1fr; } .panel__heading { align-items: flex-start; flex-wrap: wrap; } }
.operation-row, .operation-row > span, .panel p { min-width: 0; max-width: 100%; overflow-wrap: anywhere; }
.operation-row > span:first-child { flex: 1 1 auto; }
.operation-row strong, .operation-row small { min-width: 0; overflow-wrap: anywhere; }
</style>
