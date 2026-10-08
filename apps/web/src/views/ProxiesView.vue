<script setup lang="ts">
import { computed, onActivated, ref } from 'vue'
import StatusPill from '../components/StatusPill.vue'
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
const filterFields: Array<{ key: keyof OutboundSourceFilters; label: string }> = [{ key: 'provider_ids', label: 'Included provider IDs' }, { key: 'protocols', label: 'Included protocols' }, { key: 'include_names', label: 'Included exact node names' }, { key: 'exclude_names', label: 'Excluded exact node names' }, { key: 'include_node_ids', label: 'Included node IDs' }, { key: 'exclude_node_ids', label: 'Excluded node IDs' }, { key: 'exclude_provider_ids', label: 'Excluded provider IDs' }, { key: 'exclude_protocols', label: 'Excluded protocols' }]
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
function transports(group: OutboundGroupSummary) {
  return [...new Set(['tcp', 'udp', ...group.transportScopes, ...(selections.value[group.id] ?? []).filter(item => item.scope.gateway_id === group.gatewayId).map(item => item.scope.transport)])]
}
function selectionFor(group: OutboundGroupSummary, transport = activeTransport(group)) {
  return selections.value[group.id]?.find(item => item.scope.gateway_id === group.gatewayId && item.scope.transport === transport)
}
function selectionStates(group: OutboundGroupSummary) {
  const current = selectionFor(group)
  return { desired: nodeName(current?.desired_node_id), applied: nodeName(current?.applied_node_id), observed: nodeName(current?.observed_node_id) }
}
function selectionUnavailable(group: OutboundGroupSummary) {
  if (!props.state.canOperate.value) return 'An operator or administrator session is required to change selection.'
  if (!props.state.capabilities.value['selection.set_runtime']) return 'Runtime selection is unavailable on this controller.'
  if (group.mode !== 'manual') return 'Use manual selection mode to choose a node.'
  if (readbackErrors.value[group.id]) return 'Selection readback is unavailable. Refresh before changing selection.'
  if (!Object.prototype.hasOwnProperty.call(selections.value, group.id)) return 'Selection readback is pending.'
  if (!group.nodeIds.length) return 'Add candidate nodes before changing selection.'
  return undefined
}
function errorMessage(cause: unknown, fallback: string) {
  return cause instanceof Error ? cause.message : fallback
}
function probeKey(group: OutboundGroupSummary, node?: NodeSummary) { return `${group.gatewayId}:${node ? `node:${node.id}` : `group:${group.id}`}` }
function probeUnavailable(group: OutboundGroupSummary, node?: NodeSummary) {
  if (!props.state.canOperate.value) return 'An operator session is required for gateway probes.'
  const gateway = props.state.gateways.value.find(item => item.id === group.gatewayId)
  if (!gateway?.capabilities.supported.includes(node ? 'probe.node' : 'probe.group')) return 'This gateway does not report the required probe capability.'
  if (node && (!node.supported || !group.nodeIds.includes(node.id))) return 'The node must be a supported candidate assigned to this gateway.'
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
    if (result.gateway_id !== group.gatewayId || result.target_id !== (node?.id ?? group.id) || result.target_kind !== (node ? 'node' : 'group')) throw new Error('Gateway probe returned a different target. Result was discarded.')
    probeResults.value[key] = result
  } catch (cause) { probeErrors.value[key] = errorMessage(cause, 'Gateway probe failed') }
  finally { probing.value = undefined }
}
function probeLabel(result: GatewayProbeResponse) {
  return `${result.gateway_name || result.gateway_id}: ${result.probe.ok ? `${result.probe.latency_ms} ms gateway measurement` : 'probe failed'} · ${result.observed_at}`
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
      usageError.value = failures.map(result => !result.ok ? errorMessage(result.cause, 'Reference inventory unavailable') : '').join('; ')
    }
    const nextErrors: Record<string, string> = {}
    const nextSelections: Record<string, SelectionSummary[]> = {}
    results.forEach((result, index) => {
      const group = outboundGroups[index]!
      if (result.status === 'fulfilled') nextSelections[group.id] = result.value
      else {
        nextErrors[group.id] = errorMessage(result.reason, 'Unable to read selection')
        if (selections.value[group.id]) nextSelections[group.id] = selections.value[group.id]!
      }
    })
    selections.value = nextSelections
    readbackErrors.value = nextErrors
  } catch (cause) {
    loadError.value = errorMessage(cause, 'Unable to load proxy inventory')
    usageError.value = 'Reference inventory was not refreshed; previously loaded references may be stale.'
    for (const group of groups.value) readbackErrors.value[group.id] = 'Inventory refresh failed. Selection readback may be stale.'
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
    actionError.value = 'Enter a group name and choose a gateway.'
    return
  }
  if (form.value.mode === 'automatic') { actionError.value = 'Automatic selection is unavailable until a gateway adapter reports a qualified automatic chooser.'; return }
  if (candidateMode.value === 'filters' && !['provider_ids', 'protocols', 'include_node_ids', 'include_names'].some(key => sourceFilters.value[key as keyof OutboundSourceFilters]?.length)) { actionError.value = 'Source filters need at least one included provider, protocol, node ID, or exact name.'; return }
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
      actionError.value = 'The controller accepted the group change, but readback did not confirm the saved revision. Refresh before retrying.'
      return
    }
    notice.value = `Outbound group configuration saved at revision ${readback.revision}.`
  } catch (cause) {
    actionError.value = errorMessage(cause, 'Unable to save outbound group')
  } finally {
    saving.value = false
  }
}

async function select(group: OutboundGroupSummary, node: NodeSummary) {
  if (busy.value) return
  const unavailable = selectionUnavailable(group)
  if (unavailable || !node.supported || !group.nodeIds.includes(node.id)) {
    actionError.value = unavailable ?? 'This node is not a supported candidate in the group.'
    return
  }
  const transport = activeTransport(group)
  const expectedRevision = String(selectionFor(group, transport)?.revision ?? 0)
  pendingGroup.value = group.id
  actionError.value = undefined
  notice.value = undefined
  try {
    const result = await props.state.api.setSelection(group.id, { nodeId: node.id, gatewayId: group.gatewayId, transportScopes: [transport], expectedRevision }, randomIdempotencyKey())
    if (!result.operationId) throw new Error('The controller did not return an operation identifier. Refresh selection readback before retrying.')
    const operation = await props.state.api.waitForOperation(result.operationId)
    props.state.recordOperation(operation)
    if (['failed', 'outcome_unknown', 'partially_applied'].includes(operation.status)) actionError.value = operation.error ?? `Selection operation is ${operation.status}.`
    else notice.value = `Selection operation ${operation.status}. Review the ${transport.toUpperCase()} readback below.`
  } catch (cause) {
    actionError.value = errorMessage(cause, 'Selection failed')
  } finally {
    await load()
    pendingGroup.value = undefined
  }
}

onActivated(load)
</script>

<template>
  <div class="page-grid">
    <section class="page-heading">
      <div><p class="eyebrow">Proxy inventory</p><h1>Proxies</h1><p class="lede">Organize candidate nodes and choose a node independently for each transport.</p></div>
      <div class="node-filters"><input v-model="search" class="search" type="search" placeholder="Search nodes" aria-label="Search nodes" /><label>Protocol<select v-model="protocolFilter" aria-label="Filter nodes by protocol"><option value="">All protocols</option><option v-for="protocol in protocols" :key="protocol" :value="protocol">{{ protocol }}</option></select></label><label>Sort<select v-model="nodeSort" aria-label="Sort nodes"><option value="name">Name</option><option value="protocol">Protocol</option><option value="health">Health</option></select></label></div>
    </section>
    <section v-if="loadError" class="alert alert--bad" role="alert">{{ loadError }}</section>
    <section v-if="actionError" class="alert alert--bad" role="alert">{{ actionError }}</section>
    <section v-if="notice" class="alert alert--info" role="status">{{ notice }}</section>
    <section v-if="editorOpen" class="panel">
      <div class="panel__heading"><h2>{{ editing ? 'Edit outbound group' : 'New outbound group' }}</h2><button class="button button--secondary" :disabled="saving" @click="editorOpen = false">Cancel</button></div>
      <form class="group-form" @submit.prevent="saveGroup">
        <fieldset :disabled="busy || !canAdminister">
          <div class="form-grid">
            <label>Outbound group name<input v-model="form.name" required maxlength="200" /></label>
            <label>Outbound gateway<select v-model="form.gatewayId" required><option value="" disabled>Choose a gateway</option><option v-for="gateway in state.gateways.value" :key="gateway.id" :value="gateway.id">{{ gateway.name }}</option><option v-if="form.gatewayId && !state.gateways.value.some(gateway => gateway.id === form.gatewayId)" :value="form.gatewayId">{{ form.gatewayId }} (unavailable)</option></select></label>
            <label>Selection mode<select v-model="form.mode"><option value="manual">Manual</option><option value="automatic" disabled>Automatic — unavailable</option></select></label>
            <label>Replacement behavior<select v-model="form.replacementPolicy"><option value="block">Block when the selected node disappears</option><option value="none">Leave selection unresolved</option></select></label>
            <label>Candidate source<select v-model="candidateMode"><option value="explicit">Choose individual nodes</option><option value="filters">Filter provider inventory</option></select></label>
          </div>
          <template v-if="candidateMode === 'filters'"><p class="help">Filters persist across provider updates. Enter one value per line. Provider and protocol constraints both apply; included IDs or names match either list. Names are exact and case-sensitive. Exclusions always win.</p><div class="form-grid"><label v-for="field in filterFields" :key="field.key">{{ field.label }}<textarea v-model="filterForm[field.key]" rows="2" spellcheck="false" /></label></div><p class="help">Local preview from the loaded inventory: {{ filterPreview.length }} supported candidates. The controller validates the saved membership.</p><ul class="filter-preview"><li v-for="node in filterPreview" :key="node.id">{{ node.name }} · {{ node.protocol }} · provider {{ node.providerId }}</li></ul></template>
          <template v-else>
          <div class="candidate-heading"><h3>Candidates</h3><span>{{ form.nodeIds.length }} selected</span></div>
          <p class="help">Candidates use stable node identities from provider inventory. Unsupported nodes cannot be added.</p>
          <div class="candidate-grid">
            <label v-for="node in filteredNodes" :key="node.id" class="candidate-choice"><input v-model="form.nodeIds" type="checkbox" :value="node.id" :disabled="!node.supported && !form.nodeIds.includes(node.id)" :aria-label="`Candidate ${node.name}`" /><span><strong>{{ node.name }}</strong><small>{{ node.protocol }}<span v-if="!node.supported"> · Unsupported</span></small></span></label>
          </div>
          <p v-if="!nodes.length" class="help">Stage a subscription revision to make candidate nodes available.</p>
          <p v-else-if="!filteredNodes.length" class="help">No nodes match the search.</p>
          <label v-for="id in missingFormNodes" :key="id" class="candidate-choice"><input v-model="form.nodeIds" type="checkbox" :value="id" :aria-label="`Candidate ${id}`" /><span>{{ id }} · Missing from current inventory; uncheck to remove.</span></label>
          </template>
          <p v-if="editing" class="help">Editing configuration revision {{ editing.revision }}. If another administrator changes this group, reopen the editor after refreshing.</p>
          <button class="button" type="submit" :disabled="!form.name.trim() || !form.gatewayId">{{ saving ? 'Saving…' : editing ? 'Save outbound group' : 'Create outbound group' }}</button>
        </fieldset>
      </form>
    </section>
    <section class="panel">
      <div class="panel__heading"><h2>Outbound groups</h2><div class="actions"><button class="button button--secondary" :disabled="busy" @click="load">Refresh</button><button class="button" :disabled="busy || !canAdminister" @click="openEditor()">New outbound group</button></div></div>
      <p v-if="!canAdminister" class="help">An administrator session is required to create or edit outbound groups.</p>
      <div v-if="loading && !groups.length" class="empty-state" role="status">Loading proxy inventory…</div>
      <div v-else-if="!groups.length" class="empty-state">No outbound groups are configured.</div>
      <article v-for="group in groups" :key="group.id" class="group-card" :aria-label="`Outbound group ${group.name}`">
        <div class="group-card__heading">
          <div><h3>{{ group.name }}</h3><p>{{ group.nodeIds.length }} candidates · {{ group.mode }} · gateway {{ group.gatewayId }} · configuration revision {{ group.revision }}</p></div>
          <div class="actions"><StatusPill :label="pendingGroup === group.id ? 'Applying' : readbackErrors[group.id] ? 'Readback unavailable' : 'Configured'" :tone="pendingGroup === group.id || readbackErrors[group.id] ? 'warn' : 'neutral'" /><button class="button button--secondary" :aria-label="`Test group ${group.name} from gateway`" :title="probeUnavailable(group)" :disabled="!!probing || !!probeUnavailable(group)" @click="runProbe(group)">{{ probing === probeKey(group) ? 'Testing…' : 'Test group' }}</button><button class="button button--secondary" :aria-label="`Edit ${group.name}`" :disabled="busy || !canAdminister" @click="openEditor(group)">Edit</button></div>
        </div>
        <p v-if="group.sourceFilters" class="help">Candidates follow saved source filters. The {{ group.nodeIds.length }} nodes below are the controller’s current resolved membership.</p>
        <p v-if="readbackErrors[group.id]" class="alert alert--bad" role="alert">{{ readbackErrors[group.id] }} Previously loaded values may be stale.</p>
        <p v-if="probeResults[probeKey(group)]" class="help" role="status">{{ probeLabel(probeResults[probeKey(group)]!) }}<span v-if="probeResults[probeKey(group)]?.probe.error"> · {{ probeResults[probeKey(group)]?.probe.error }}</span></p>
        <p v-if="probeErrors[probeKey(group)]" class="help warning" role="alert">{{ probeErrors[probeKey(group)] }}</p>
        <div class="table-scroll"><table :aria-label="`Selection readback for ${group.name}`"><thead><tr><th>Transport</th><th>Desired</th><th>Applied</th><th>Observed</th><th>Revision</th></tr></thead><tbody><tr v-for="transport in transports(group)" :key="transport"><th scope="row">{{ transport.toUpperCase() }}</th><td>{{ nodeName(selectionFor(group, transport)?.desired_node_id) ?? '—' }}</td><td>{{ nodeName(selectionFor(group, transport)?.applied_node_id) ?? '—' }}</td><td>{{ nodeName(selectionFor(group, transport)?.observed_node_id) ?? '—' }}</td><td>{{ selectionFor(group, transport)?.revision ?? 'No selection' }}</td></tr></tbody></table></div>
        <label class="transport-control">Selection transport<select :value="activeTransport(group)" :aria-label="`Selection transport for ${group.name}`" :disabled="busy" @change="selectedTransports[group.id] = ($event.target as HTMLSelectElement).value"><option v-for="transport in transports(group)" :key="transport" :value="transport">{{ transport.toUpperCase() }}</option></select></label>
        <StateStrip :states="selectionStates(group)" :pending="pendingGroup === group.id" />
        <p v-if="selectionUnavailable(group)" class="help warning">{{ selectionUnavailable(group) }}</p>
        <p v-else-if="!state.capabilities.value['selection.persist_restart']" class="help warning">This adapter does not report durable selection across gateway restarts.</p>
        <div class="node-grid">
          <div v-for="node in nodesForGroup(group)" :key="node.id" class="node-entry"><button class="node-card" :class="{ 'node-card--selected': node.id === selectionFor(group)?.observed_node_id }" :aria-label="`Select ${node.name} for ${group.name} (${activeTransport(group).toUpperCase()})`" :aria-pressed="node.id === selectionFor(group)?.observed_node_id" :disabled="busy || !!selectionUnavailable(group) || !node.supported" @click="select(group, node)">
            <span class="node-card__name">{{ node.name }}</span><span class="node-card__meta">{{ node.protocol }} · {{ node.health }}</span><span v-if="!node.supported" class="node-card__warning">Unsupported</span><span v-if="node.id === selectionFor(group)?.observed_node_id" class="node-card__meta">Observed for {{ activeTransport(group).toUpperCase() }}</span>
          </button><button class="button button--secondary" :aria-label="`Test node ${node.name} from gateway for ${group.name}`" :title="probeUnavailable(group, node)" :disabled="!!probing || !!probeUnavailable(group, node)" @click="runProbe(group, node)">{{ probing === probeKey(group, node) ? 'Testing…' : 'Test node' }}</button><p v-if="probeResults[probeKey(group, node)]" class="help" role="status">{{ probeLabel(probeResults[probeKey(group, node)]!) }}<span v-if="probeResults[probeKey(group, node)]?.probe.error"> · {{ probeResults[probeKey(group, node)]?.probe.error }}</span></p><p v-if="probeErrors[probeKey(group, node)]" class="help warning" role="alert">{{ probeErrors[probeKey(group, node)] }}</p></div>
        </div>
        <p v-if="group.nodeIds.length && !nodesForGroup(group).length && !missingCandidates(group).length" class="help">No candidate nodes match the search.</p>
        <p v-if="missingCandidates(group).length" class="help warning">Candidates unavailable in current inventory: {{ missingCandidates(group).join(', ') }}</p>
        <section class="usage-panel" :aria-label="`Used by ${group.name}`">
          <h4>Used by</h4>
          <p class="help">References in saved controller configuration. Disabled references remain listed; deployed traffic may differ.</p>
          <p v-if="usageError" class="help warning" role="status">Usage readback incomplete: {{ usageError }} {{ usageLoaded ? 'Showing the previous complete reference snapshot.' : '' }}</p>
          <p v-else-if="loading && !usageLoaded" class="help">Reading policy and device-group references…</p>
          <p v-else-if="usageLoaded && !references[group.id]?.length" class="help">No saved policies, rule sets, or device groups reference this outbound group.</p>
          <ul v-if="references[group.id]?.length" class="usage-list">
            <li v-for="reference in references[group.id]" :key="`${reference.kind}:${reference.id}:${reference.detail}`">
              <a :href="reference.href">{{ reference.kind === 'device_group' ? 'Device group' : reference.kind === 'rule_set' ? 'Rule set' : 'Policy' }}: {{ reference.name }}</a>
              <span>{{ reference.detail }}<strong v-if="reference.disabled"> · Disabled reference</strong></span>
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
</style>
