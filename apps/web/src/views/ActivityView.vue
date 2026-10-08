<script setup lang="ts">
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
      else errors.push('Connection readback did not match the selected gateway')
    } else if (results[0].status === 'rejected') errors.push(results[0].reason instanceof Error ? results[0].reason.message : 'Connections unavailable')
    if (results[1].status === 'fulfilled' && results[1].value) {
      if (results[1].value.gateway_id === gateway.id) counters.value = results[1].value
      else errors.push('Counter readback did not match the selected gateway')
    } else if (results[1].status === 'rejected') errors.push(results[1].reason instanceof Error ? results[1].reason.message : 'Counters unavailable')
    if (errors.length) diagnosticError.value = errors.join('; ')
  } finally { if (request === diagnosticRequest) diagnosticLoading.value = false }
}

function counterText(counter: GatewayCounterValue | undefined, unit: 'bytes' | 'packets') {
  return counter?.available && counter[unit] !== undefined ? `${counter[unit]} ${unit}` : 'Unavailable'
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
    if (failures.length) error.value = failures.map(r => r.reason instanceof Error ? r.reason.message : 'Unable to load activity').join('; ')
  } finally { loading.value = false }
}
async function inspect(id: string) {
  try { selectedOperation.value = await props.state.api.operation(id) } catch (cause) { error.value = cause instanceof Error ? cause.message : 'Readback unavailable' }
}
function views(operation: OperationSummary) {
  return Object.fromEntries(Object.entries(operation.views ?? {}).map(([kind, value]) => [kind, value?.revision ?? value?.status ?? `generation ${value?.generation}`]))
}
watch(() => [selectedGateway.value?.id, supportsConnections.value, supportsCounters.value], () => { if (active) void loadDiagnostics() })
onActivated(() => { active = true; void load() })
onDeactivated(() => { active = false; diagnosticRequest++; diagnosticAbort?.abort(); diagnosticLoading.value = false })
</script>

<template>
  <div class="page-grid"><section class="page-heading"><div><p class="eyebrow">Operations and evidence</p><h1>Activity &amp; Diagnostics</h1><p class="lede">Operation acceptance comes from durable readback. A browser-to-controller request is not a gateway traffic verification.</p></div><button class="button button--secondary" :disabled="loading" @click="load">Refresh</button></section>
    <section v-if="error" class="alert alert--bad" role="alert">{{ error }}</section>
    <section class="panel" aria-label="Gateway diagnostics">
      <div class="panel__heading"><div><h2>Gateway traffic</h2><p class="muted">{{ selectedGateway ? `Measurements from ${selectedGateway.name}` : 'Select a gateway to inspect traffic' }}</p></div><button class="button button--secondary" :disabled="diagnosticLoading || !selectedGateway || (!supportsConnections && !supportsCounters)" @click="loadDiagnostics">{{ diagnosticLoading ? 'Reading gateway…' : 'Read gateway' }}</button></div>
      <p v-if="selectedGateway && !supportsConnections && !supportsCounters" class="muted">This gateway does not advertise connection or traffic counter support.</p>
      <p v-if="diagnosticError" class="alert alert--bad" role="alert">{{ diagnosticError }}</p>
      <div class="counter-grid">
        <div class="counter"><strong>Proxy traffic</strong><span>{{ counterText(counters?.proxy, 'bytes') }}</span><small>{{ counterText(counters?.proxy, 'packets') }}</small></div>
        <div class="counter"><strong>Direct traffic</strong><span>{{ counterText(counters?.direct, 'bytes') }}</span><small>{{ counterText(counters?.direct, 'packets') }}</small></div>
        <div class="counter"><strong>Provider quota</strong><span>Unavailable</span><small>Gateway traffic counters do not measure subscription allowance.</small></div>
      </div>
      <p v-if="counters" class="muted">Counter readback: {{ counters.gateway_name }} · {{ counters.observed_at }}. Values are gateway totals; they may reset when the engine restarts.</p>
      <div class="panel__heading"><h3>Connections</h3><span class="muted">{{ connections ? `${connections.items.length} observed` : 'Unavailable' }}</span></div>
      <p class="muted">Source, destination, matched rule, route chain, and policy generation are unavailable in this gateway observation contract.</p>
      <p v-if="!supportsConnections" class="muted">Connection observation is unavailable on this gateway.</p>
      <p v-else-if="connections && !connections.items.length" class="empty-state">No connections were observed on {{ connections.gateway_name }}.</p>
      <div v-if="connections?.items.length" class="table-scroll"><table><thead><tr><th>Connection</th><th>Outbound group</th><th>Node</th><th>Transport</th><th>State</th><th>Opened</th></tr></thead><tbody><tr v-for="connection in connections.items" :key="connection.id"><td>{{ connection.id }}</td><td>{{ connection.group_id || 'Unknown' }}</td><td>{{ connection.node_id || 'Unknown' }}</td><td>{{ connection.transport || 'Unknown' }}</td><td>{{ connection.state || 'Unknown' }}</td><td>{{ connection.opened_at }}</td></tr></tbody></table></div>
      <p v-if="connections" class="muted">Connection readback: {{ connections.gateway_name }} · {{ connections.observed_at }}</p>
    </section>
    <section class="panel"><div class="panel__heading"><h2>Operations</h2><span class="muted">{{ operations.length }} recorded</span></div><div v-if="!operations.length && !loading" class="empty-state">No operations are available.</div><div v-for="operation in operations" :key="operation.id" class="operation-row"><span><strong>{{ operation.action }}</strong><small>{{ operation.target }} · {{ operation.updatedAt }}</small><small>{{ operation.id }}</small></span><StatusPill :label="operation.status" :tone="operation.status === 'applied' ? 'good' : ['failed', 'outcome_unknown'].includes(operation.status) ? 'bad' : 'warn'" /><button class="button button--secondary" @click="inspect(operation.id)">Read operation</button><p v-if="operation.error" class="operation-error">{{ operation.error }}</p></div></section>
    <section v-if="selectedOperation" class="panel"><h2>Operation readback</h2><p>{{ selectedOperation.id }} · {{ selectedOperation.status }}</p><StateStrip :states="views(selectedOperation)" /><p class="muted">An absent verified state means no verification evidence was recorded.</p></section>
    <section class="panel"><h2>Audit history</h2><div v-if="!audits.length" class="empty-state">No audit events are available.</div><div v-for="event in audits" :key="event.id" class="operation-row"><span><strong>{{ event.action }} · {{ event.object_type }}</strong><small>{{ event.actor }} · {{ event.created_at }}</small></span><span>{{ event.outcome }}</span></div></section>
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
</style>
