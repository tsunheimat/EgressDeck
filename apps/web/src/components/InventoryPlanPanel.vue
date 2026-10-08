<script setup lang="ts">
import { computed, onActivated, onDeactivated, onUnmounted, ref, watch } from 'vue'
import { ControllerApiError } from '../api/client'
import type { useControllerState } from '../state'
import type { InventoryPlan } from '../types'
import StatusPill from './StatusPill.vue'

const props = defineProps<{ state: ReturnType<typeof useControllerState> }>()
const gatewayId = ref(props.state.selectedGateway.value?.id ?? '')
const previousOperationId = ref('')
const plan = ref<InventoryPlan>()
const pending = ref<{ checksum: string; gatewayId: string }>()
const creating = ref(false)
const reading = ref(false)
const error = ref('')
const canCreate = computed(() => props.state.isAdministrator.value && props.state.capabilities.value['policy.validate'] === true && props.state.gateways.value.some(gateway => gateway.id === gatewayId.value))
const busy = computed(() => creating.value || reading.value)
let sequence = 0
let active = true

function invalidate() {
  sequence++
  creating.value = false
  reading.value = false
  error.value = ''
  pending.value = undefined
  plan.value = undefined
}
watch([gatewayId, previousOperationId], invalidate, { flush: 'sync' })
watch(() => props.state.selectedGateway.value?.id, id => { gatewayId.value = id ?? '' })
watch(() => props.state.session.value?.subject, invalidate, { flush: 'sync' })

function message(cause: unknown): string {
  if (cause instanceof ControllerApiError && (cause.status === 409 || cause.status === 412)) return `${cause.message}. Review the inventory and create a new plan.`
  return cause instanceof Error ? cause.message : 'Unable to read the inventory plan.'
}

async function readStored(currentSequence: number, target: { checksum: string; gatewayId: string }) {
  reading.value = true
  const stored = await props.state.api.inventoryPlan(target.checksum)
  if (currentSequence !== sequence || !active) return
  if (stored.checksum !== target.checksum || stored.target.gateway_id !== target.gatewayId || stored.input.gateway.id !== target.gatewayId || stored.scope !== 'gateway') {
    throw new Error('Stored plan does not match the requested checksum and gateway. Readback remains unconfirmed.')
  }
  plan.value = stored
  pending.value = undefined
}

async function createPlan() {
  if (busy.value || !canCreate.value || !active) return
  const currentSequence = ++sequence
  const targetGateway = gatewayId.value
  creating.value = true
  error.value = ''
  pending.value = undefined
  plan.value = undefined
  try {
    const created = await props.state.api.createInventoryPlan({ gateway_id: targetGateway, ...(previousOperationId.value.trim() ? { previous_operation_id: previousOperationId.value.trim() } : {}) })
    if (currentSequence !== sequence || !active) return
    if (!/^[a-f0-9]{64}$/.test(created.checksum)) throw new Error('The controller returned an invalid plan checksum. Stored readback remains unconfirmed.')
    pending.value = { checksum: created.checksum, gatewayId: targetGateway }
    creating.value = false
    await readStored(currentSequence, pending.value)
  } catch (cause) {
    if (currentSequence === sequence && active) error.value = message(cause)
  } finally {
    if (currentSequence === sequence) { creating.value = false; reading.value = false }
  }
}

async function retryReadback() {
  if (busy.value || !pending.value || !active) return
  const currentSequence = ++sequence
  error.value = ''
  try {
    await readStored(currentSequence, pending.value)
  } catch (cause) {
    if (currentSequence === sequence && active) error.value = message(cause)
  } finally {
    if (currentSequence === sequence) reading.value = false
  }
}

function deactivate() { active = false; sequence++; creating.value = false; reading.value = false }
onActivated(() => { active = true })
onDeactivated(deactivate)
onUnmounted(deactivate)
</script>

<template>
  <section class="inventory-plan panel" aria-labelledby="inventory-plan-title">
    <div class="panel-heading"><div><h2 id="inventory-plan-title">Stored inventory plan</h2><p class="muted">Compile the saved devices, device groups, policies, rule sets, and outbound groups for one gateway. Save editor changes before planning.</p></div></div>
    <form aria-label="Create inventory plan" @submit.prevent="createPlan">
      <fieldset class="form-grid" :disabled="busy">
        <label>Plan gateway<select v-model="gatewayId" required><option value="" disabled>Select a registered gateway</option><option v-for="gateway in state.gateways.value" :key="gateway.id" :value="gateway.id">{{ gateway.name }} ({{ gateway.id }})</option></select></label>
        <label>Previous applied operation ID (optional)<input v-model="previousOperationId" placeholder="Use the latest applied operation" autocomplete="off" /><small>Only a recorded applied manifest for this gateway can serve as the comparison baseline.</small></label>
      </fieldset>
      <div class="actions"><button class="button" type="submit" :disabled="busy || !canCreate">{{ creating ? 'Capturing inventory…' : reading ? 'Reading stored plan…' : 'Create inventory plan' }}</button><small v-if="!state.isAdministrator.value" class="muted">Administrator access is required to create a stored plan.</small><small v-else-if="state.capabilities.value['policy.validate'] !== true" class="muted">The controller has not advertised policy validation.</small><small v-else-if="!state.gateways.value.length" class="muted">Register a gateway before planning.</small></div>
    </form>
    <p v-if="error" class="alert alert--bad" role="alert">{{ error }}</p>
    <div v-if="pending" class="result" role="status"><p>Plan created; stored readback is not confirmed.</p><p class="hash">Requested checksum: {{ pending.checksum }}</p><button class="button button--secondary" type="button" :disabled="busy" @click="retryReadback">{{ reading ? 'Reading stored plan…' : 'Retry stored plan readback' }}</button></div>
    <div v-if="plan" class="result" aria-label="Stored inventory plan result">
      <p class="confirmed" role="status">Stored plan readback confirmed.</p>
      <div class="statuses"><StatusPill :label="plan.valid ? 'Compilation valid' : 'Compilation invalid'" :tone="plan.valid ? 'good' : 'bad'" /><StatusPill :label="plan.deployable ? 'Controller reports deployable' : 'Deployment blocked'" :tone="plan.deployable ? 'neutral' : 'warn'" /></div>
      <dl class="facts"><div><dt>Stored checksum</dt><dd class="hash">{{ plan.checksum }}</dd></div><div><dt>Scope</dt><dd>{{ plan.scope }} · {{ plan.target.gateway_id }}</dd></div><div><dt>Captured at</dt><dd>{{ plan.created_at }}</dd></div><div><dt>Inventory consistency</dt><dd>{{ plan.consistency }}</dd></div><div><dt>Gateway capability observation</dt><dd>{{ plan.target.observation_status }}</dd></div><div><dt>Previous applied manifest</dt><dd>{{ plan.previous.status }}<span v-if="plan.previous.operation_id"> · {{ plan.previous.operation_id }}</span><span v-if="plan.previous.manifest_hash" class="hash"> · {{ plan.previous.manifest_hash }}</span></dd></div></dl>
      <p class="muted">This immutable snapshot records saved intent at capture time. Later inventory changes require a new plan. Gateway capability observation does not establish applied or verified traffic state.</p>
      <section v-if="plan.diagnostics?.length" aria-label="Plan validation diagnostics"><h3>Validation diagnostics</h3><ul><li v-for="(diagnostic, index) in plan.diagnostics" :key="index"><strong>{{ diagnostic.code }}</strong> · {{ diagnostic.severity }}<span v-if="diagnostic.path"> · {{ diagnostic.path }}</span>: {{ diagnostic.message }}</li></ul></section>
      <section aria-label="Deployment blockers"><h3>Deployment blockers</h3><ul v-if="plan.blockers?.length"><li v-for="(blocker, index) in plan.blockers" :key="index"><strong>{{ blocker.code }}</strong><span v-if="blocker.path"> · {{ blocker.path }}</span>: {{ blocker.message }}</li></ul><p v-else class="muted">The stored plan reports no blockers.</p><button class="button" type="button" disabled>Deploy plan unavailable</button><p class="muted">Deployment and client enrollment require qualified gateway, firewall, transport, and IPv6 checks.</p></section>
      <details><summary>Captured resource revisions ({{ plan.resource_revisions?.length ?? 0 }})</summary><div class="table-scroll"><table><thead><tr><th>Resource</th><th>ID</th><th>Revision</th><th>Content SHA-256</th></tr></thead><tbody><tr v-for="resource in plan.resource_revisions ?? []" :key="`${resource.kind}/${resource.id}`"><td>{{ resource.kind }}</td><td>{{ resource.id }}</td><td>{{ resource.revision }}</td><td class="hash">{{ resource.sha256 }}</td></tr></tbody></table></div></details>
      <section v-if="plan.compilation" aria-label="Inventory compilation preview">
        <h3>Inventory compilation preview</h3><p class="hash">Manifest: {{ plan.compilation.manifest.content_hash }}</p>
        <p>{{ plan.compilation.manifest.groups?.length ?? 0 }} compiled groups · {{ plan.compilation.impact.changed_groups?.length ?? 0 }} changed · {{ plan.compilation.impact.unchanged_groups?.length ?? 0 }} unchanged.</p>
        <p class="muted">{{ plan.previous.status === 'applied' ? 'Impact compares with the stored previous applied manifest.' : 'No previous applied manifest is available; impact compares with an empty baseline.' }} Enrollment changes: {{ plan.compilation.impact.enrollment_changed ? 'yes' : 'no' }}. Policy application required: {{ plan.compilation.impact.requires_policy_apply ? 'yes' : 'no' }}.</p>
        <ul v-if="plan.compilation.diagnostics?.length"><li v-for="(diagnostic, index) in plan.compilation.diagnostics" :key="index">{{ diagnostic.severity }} · {{ diagnostic.code }}<span v-if="diagnostic.path"> · {{ diagnostic.path }}</span>: {{ diagnostic.message }}</li></ul>
        <details><summary>Read-only compiled manifest</summary><pre>{{ JSON.stringify(plan.compilation.manifest, null, 2) }}</pre></details>
      </section>
      <details v-if="plan.native_artifact"><summary>Read-only native routing preview</summary><p class="muted">Routing fragment; gateway globals, DNS, outbound credentials, and native validation are required before application.</p><pre>{{ plan.native_artifact.routing_config }}</pre><p class="hash">Routing SHA-256: {{ plan.native_artifact.routing_sha256 }}</p></details>
      <details><summary>Captured compiler input</summary><pre>{{ JSON.stringify(plan.input, null, 2) }}</pre></details>
    </div>
  </section>
</template>

<style scoped>
.panel,.result,form,section[aria-label] { display:grid; gap:.85rem; min-width:0; }
.panel { padding:1rem; border:1px solid var(--border); border-radius:.65rem; background:var(--surface); }
.panel-heading,.actions,.statuses { display:flex; align-items:center; flex-wrap:wrap; gap:.75rem; }
h2,h3,p { margin:0; } h2 { font-size:1.1rem; } h3 { font-size:.9rem; }
.muted,small,dt { color:var(--muted); font-size:.78rem; }.panel-heading p { margin-top:.4rem; }
.form-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:.75rem; min-width:0; margin:0; padding:0; border:0; }
label { display:grid; align-content:start; gap:.35rem; color:var(--muted); font-size:.78rem; min-width:0; }
input,select { width:100%; box-sizing:border-box; padding:.5rem .6rem; border:1px solid var(--border); border-radius:.35rem; background:var(--surface-alt); color:var(--text); font:inherit; }
.button { justify-self:start; cursor:pointer; padding:.5rem .7rem; border:1px solid var(--border); border-radius:.4rem; background:var(--accent); color:#07111f; font-weight:700; }.button--secondary { background:transparent; color:var(--text); }
button:disabled,fieldset:disabled { opacity:.6; } button:disabled { cursor:not-allowed; }
.result { padding:.8rem; border-radius:.45rem; background:var(--surface-alt); }.confirmed { color:var(--good); font-size:.85rem; }
.facts { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:.75rem; margin:0; }.facts div { min-width:0; }dt { margin-bottom:.25rem; }dd { margin:0; font-size:.82rem; overflow-wrap:anywhere; }
.hash { overflow-wrap:anywhere; font-family:monospace; font-size:.75rem; }.alert { padding:.75rem 1rem; border-radius:.5rem; overflow-wrap:anywhere; }.alert--bad { border:1px solid #713847; background:#301c29; color:#ffbeca; }
ul { margin:.25rem 0; padding-left:1.25rem; font-size:.82rem; overflow-wrap:anywhere; }li+li { margin-top:.35rem; }summary { cursor:pointer; font-size:.85rem; }pre { max-height:24rem; overflow:auto; font-size:.75rem; white-space:pre-wrap; overflow-wrap:anywhere; }
.table-scroll { overflow:auto; max-width:100%; }table { width:100%; border-collapse:collapse; font-size:.78rem; margin-top:.6rem; }th,td { text-align:left; padding:.5rem; border-bottom:1px solid var(--border); }th { color:var(--muted); }td { overflow-wrap:anywhere; }td.hash { min-width:9rem; }
@media(max-width:580px) { .form-grid,.facts { grid-template-columns:1fr; } }
</style>
