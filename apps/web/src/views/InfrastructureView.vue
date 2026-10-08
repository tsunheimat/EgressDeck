<script setup lang="ts">
import { onActivated, onDeactivated, onUnmounted, reactive, ref } from 'vue'
import StatusPill from '../components/StatusPill.vue'
import { useControllerState } from '../state'
import type { FirewallAttachRequest, FirewallBindingSummary, GatewaySummary } from '../types'

const props = defineProps<{ state: ReturnType<typeof useControllerState> }>()
const isAdministrator = props.state.isAdministrator
const gateways = ref<GatewaySummary[]>([])
const bindings = ref<FirewallBindingSummary[]>([])
const loading = ref(false)
const saving = ref(false)
const error = ref<string>()
const bindingError = ref<string>()
const notice = ref<string>()
const editorOpen = ref(false)
const form = reactive({ name: '', endpoint: '', adapter: 'dae' })
const attachOpen = ref(false)
const attaching = ref(false)
const attachError = ref<string>()
const attachForm = reactive({ gatewayId: '', alias: '', aliasUUID: '', family: 'ipv4' as 'ipv4' | 'ipv6', interfaceScope: '', ruleIds: '' })
const readingBindings = reactive(new Set<string>())
const clock = ref(Date.now())
let freshnessTimer: ReturnType<typeof setInterval> | undefined
let requestSequence = 0
let latestLoad = 0
let bindingChange = 0
const bindingOrder = new Map<string, { request: number; serverTime: number; change: number }>()

function observationStatus(binding: FirewallBindingSummary): FirewallBindingSummary['observationStatus'] {
  if (binding.observationStatus !== 'fresh') return binding.observationStatus
  const observedAt = Date.parse(binding.observedAt ?? '')
  return !Number.isFinite(observedAt) || observedAt > clock.value || clock.value - observedAt > 5 * 60_000 ? 'stale' : 'fresh'
}

const observationLabels = { never_read: 'Never read', fresh: 'Fresh', stale: 'Stale', error: 'Error' }

function timestamp(value?: string) { return Date.parse(value ?? '') || 0 }
function serverTime(binding: FirewallBindingSummary) { return Math.max(timestamp(binding.lastAttemptAt), timestamp(binding.observedAt)) }

function replaceBinding(binding: FirewallBindingSummary, request: number, observedServerTime = serverTime(binding)) {
  const index = bindings.value.findIndex(item => item.id === binding.id)
  const previous = bindings.value[index]
  const order = bindingOrder.get(binding.id)
  if (order && (observedServerTime < order.serverTime || (observedServerTime === order.serverTime && request < order.request))) return
  // A newer failed attempt may still carry an older successful observation.
  if (previous && timestamp(previous.observedAt) > timestamp(binding.observedAt)) {
    binding = { ...binding, observedAt: previous.observedAt, activeCount: previous.activeCount, persistedCount: previous.persistedCount, drift: previous.drift, state: previous.state }
  }
  bindingOrder.set(binding.id, { request, serverTime: observedServerTime, change: ++bindingChange })
  if (index < 0) bindings.value.push(binding)
  else bindings.value[index] = binding
}

function openAttach() {
  Object.assign(attachForm, { gatewayId: gateways.value[0]?.id ?? '', alias: '', aliasUUID: '', family: 'ipv4', interfaceScope: '', ruleIds: '' })
  attachError.value = undefined
  notice.value = undefined
  attachOpen.value = true
}

async function attachBinding() {
  if (attaching.value || !isAdministrator.value) return
  attaching.value = true
  attachError.value = undefined
  notice.value = undefined
  let accepted = false
  const requestNumber = ++requestSequence
  try {
    const request: FirewallAttachRequest = {
      gateway_id: attachForm.gatewayId,
      alias: attachForm.alias.trim(),
      alias_type: 'host',
      family: attachForm.family,
      interface_scope: attachForm.interfaceScope.trim(),
      rule_ids: [...new Set(attachForm.ruleIds.split(/[,\n]/).map(id => id.trim()).filter(Boolean))],
      ...(attachForm.aliasUUID.trim() ? { alias_uuid: attachForm.aliasUUID.trim() } : {}),
    }
    if (!gateways.value.some(gateway => gateway.id === request.gateway_id) || !request.alias || !request.interface_scope || !request.rule_ids.length) {
      throw new Error('Choose a registered gateway and enter the Host alias, interface scope, and at least one steering rule ID.')
    }
    const attached = await props.state.api.attachBinding(request)
    accepted = true
    attachOpen.value = false
    const confirmed = await props.state.api.binding(attached.id)
    if (confirmed.id !== attached.id || confirmed.gatewayId !== request.gateway_id || confirmed.alias !== request.alias || confirmed.addressFamily !== request.family || confirmed.interfaceScope !== request.interface_scope || (request.alias_uuid && confirmed.aliasUUID !== request.alias_uuid) || confirmed.ruleIds.length !== request.rule_ids.length || request.rule_ids.some(id => !confirmed.ruleIds.includes(id))) {
      throw new Error('The registered binding does not match the requested association.')
    }
    replaceBinding(confirmed, requestNumber)
    await props.state.load()
    notice.value = `Host binding ${confirmed.alias} registered. Use Read firewall to inspect the current firewall state.`
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : 'Unable to attach Host binding'
    attachError.value = accepted ? `The controller accepted the binding, but registration could not be confirmed: ${message} Refresh before attaching it again.` : message
  } finally { attaching.value = false }
}

async function readFirewall(binding: FirewallBindingSummary) {
  if (readingBindings.has(binding.id)) return
  readingBindings.add(binding.id)
  notice.value = undefined
  const attemptedAt = new Date().toISOString()
  const request = ++requestSequence
  const startedServerTime = bindingOrder.get(binding.id)?.serverTime ?? serverTime(binding)
  try {
    const observed = await props.state.api.readbackBinding(binding.id)
    if (observed.id !== binding.id || !observed.observedAt || !['fresh', 'stale'].includes(observed.observationStatus)) {
      throw new Error(observed.observationError ?? 'The firewall did not return a successful observation.')
    }
    replaceBinding(observed, request)
    clock.value = Date.now()
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : 'Unable to read firewall'
    let cached = binding
    let cachedReadSucceeded = false
    try { cached = await props.state.api.binding(binding.id); cachedReadSucceeded = cached.id === binding.id } catch { /* Keep the last successful observation when cached state is also unavailable. */ }
    if (cached.id !== binding.id) cached = binding
    if (cachedReadSucceeded && serverTime(cached) > startedServerTime) {
      // Another reader may have completed a newer attempt while this request failed.
      replaceBinding(cached, request)
    } else {
      if (!cachedReadSucceeded || serverTime(cached) < startedServerTime) cached = binding
      // Keep local transport failures ordered by the underlying server state,
      // so the browser clock cannot prevent a later server refresh from winning.
      replaceBinding({ ...cached, observationStatus: 'error', observationError: message, lastAttemptAt: attemptedAt }, request, startedServerTime)
    }
  } finally {
    readingBindings.delete(binding.id)
    await props.state.load()
  }
}

async function load() {
  const request = ++requestSequence
  latestLoad = request
  const startedChange = bindingChange
  loading.value = true
  error.value = undefined
  bindingError.value = undefined
  try {
    const [gatewayResult, bindingResult] = await Promise.allSettled([props.state.api.gateways(), props.state.api.bindings()])
    if (latestLoad !== request) return gatewayResult.status === 'fulfilled'
    if (gatewayResult.status === 'fulfilled') gateways.value = gatewayResult.value
    else error.value = gatewayResult.reason instanceof Error ? gatewayResult.reason.message : 'Unable to load gateways'
    if (bindingResult.status === 'fulfilled') {
      const returnedIds = new Set(bindingResult.value.map(binding => binding.id))
      bindings.value = bindings.value.filter(binding => returnedIds.has(binding.id) || (bindingOrder.get(binding.id)?.change ?? 0) > startedChange)
      for (const binding of bindingResult.value) replaceBinding(binding, request)
      clock.value = Date.now()
    }
    else bindingError.value = bindingResult.reason instanceof Error ? bindingResult.reason.message : 'Unable to load firewall bindings'
    return gatewayResult.status === 'fulfilled'
  } finally { if (latestLoad === request) loading.value = false }
}

function registerGateway() {
  Object.assign(form, { name: '', endpoint: '', adapter: 'dae' })
  error.value = undefined
  notice.value = undefined
  editorOpen.value = true
}

async function saveGateway() {
  if (saving.value || !isAdministrator.value) return
  saving.value = true
  error.value = undefined
  notice.value = undefined
  try {
    const endpoint = new URL(form.endpoint.trim())
    if (!['https:', 'http:'].includes(endpoint.protocol) || endpoint.username || endpoint.password) throw new Error('Use an HTTP or HTTPS gateway endpoint without embedded credentials')
    const gateway = await props.state.api.createGateway({ name: form.name.trim(), endpoint: endpoint.toString(), adapter: form.adapter.trim() })
    editorOpen.value = false
    const gatewayReadbackAvailable = await load()
    await props.state.load()
    if (!gatewayReadbackAvailable || !gateways.value.some((item) => item.id === gateway.id && item.revision === gateway.revision)) {
      error.value = 'The controller accepted registration, but the gateway could not be read back. Refresh before registering it again.'
      return
    }
    notice.value = `Gateway ${gateway.name} registered. Health and capabilities are shown when reported by the gateway.`
  } catch (cause) { error.value = cause instanceof Error ? cause.message : 'Unable to register gateway' } finally { saving.value = false }
}
function stopFreshnessTimer() {
  if (freshnessTimer) clearInterval(freshnessTimer)
  freshnessTimer = undefined
}
onActivated(() => {
  clock.value = Date.now()
  stopFreshnessTimer()
  freshnessTimer = setInterval(() => { clock.value = Date.now() }, 30_000)
  void load()
})
onDeactivated(stopFreshnessTimer)
onUnmounted(stopFreshnessTimer)
</script>

<template>
  <div class="page-grid"><section class="page-heading"><div><p class="eyebrow">Capability and topology</p><h1>Infrastructure</h1><p class="lede">Register gateways and inspect their reported capabilities, health, and firewall bindings.</p></div><button class="button button--secondary" :disabled="loading || saving || attaching || readingBindings.size > 0" @click="load">{{ loading ? 'Refreshing…' : 'Refresh' }}</button></section>
    <section v-if="error" class="alert alert--bad" role="alert">{{ error }}</section>
    <section v-if="notice" class="alert alert--good" role="status">{{ notice }}</section>
    <section class="panel"><div class="panel__heading"><h2>Gateways</h2><div class="actions"><span class="muted">{{ gateways.length }} registered</span><button v-if="isAdministrator" class="button" :disabled="loading || saving" @click="registerGateway">Register gateway</button></div></div>
      <form v-if="editorOpen && isAdministrator" class="editor" @submit.prevent="saveGateway"><h3>Register gateway</h3><p class="muted">Registration stores the endpoint. Connection health remains unknown until observed.</p><fieldset :disabled="saving"><div class="form-grid"><label>Gateway name<input v-model="form.name" required maxlength="200" autocomplete="off" /></label><label>Adapter<input aria-label="Adapter" v-model="form.adapter" required autocomplete="off" /><span class="muted">Use the configured adapter, such as dae.</span></label><label class="full-width">Gateway endpoint<input aria-label="Gateway endpoint" v-model="form.endpoint" type="url" required placeholder="https://gateway.example:8443" autocomplete="off" spellcheck="false" /><span class="muted">Use the gateway agent URL. Keep credentials in controller configuration.</span></label></div><div class="actions"><button class="button" type="submit">{{ saving ? 'Registering…' : 'Save gateway' }}</button><button class="button button--secondary" type="button" @click="editorOpen = false">Cancel</button></div></fieldset></form>
      <div v-if="!gateways.length && !loading" class="empty-state">No gateways are registered.</div><article v-for="gateway in gateways" :key="gateway.id" class="gateway-card"><div class="gateway-card__heading"><div><h3>{{ gateway.name }}</h3><p>{{ gateway.endpoint }}</p><p>{{ gateway.adapter ?? 'dae' }} · {{ gateway.version ?? 'version unknown' }} · revision {{ gateway.revision ?? 'unknown' }}</p></div><StatusPill :label="gateway.health" :tone="gateway.health === 'healthy' ? 'good' : gateway.health === 'offline' ? 'bad' : 'warn'" /></div><div v-if="gateway.capabilities.supported.length" class="capability-list"><span v-for="capability in gateway.capabilities.supported" :key="capability" class="capability">{{ capability }}</span></div><p v-else class="muted">No runtime capabilities reported.</p><ul v-if="gateway.capabilities.restrictions && Object.keys(gateway.capabilities.restrictions).length" class="restriction"><li v-for="(reason, capability) in gateway.capabilities.restrictions" :key="capability">{{ capability }}: {{ reason }}</li></ul></article><p v-if="gateways.length" class="muted">Gateway editing is unavailable on this controller.</p></section>
    <section class="panel" aria-label="Firewall bindings">
      <div class="panel__heading"><h2>Firewall bindings</h2><div class="actions"><span class="muted">{{ bindings.length }} bindings</span><button v-if="isAdministrator" class="button" :disabled="loading || attaching" @click="openAttach">Attach Host binding</button></div></div>
      <p class="muted">Register an existing Host alias and its steering rules. Observations describe saved and active alias contents; traffic-path validation is separate.</p>
      <p v-if="bindingError" class="alert alert--bad" role="status">Firewall bindings unavailable: {{ bindingError }}</p>
      <p v-if="attachError" class="alert alert--bad" role="alert">{{ attachError }}</p>
      <form v-if="attachOpen && isAdministrator" class="editor" aria-label="Attach Host binding" @submit.prevent="attachBinding">
        <h3>Attach existing Host binding</h3>
        <p class="muted">Use an existing persistent Host alias and the IDs of its steering rules.</p>
        <fieldset :disabled="attaching">
          <div class="form-grid">
            <label>Gateway<select v-model="attachForm.gatewayId" name="gateway_id" required><option disabled value="">Choose a gateway</option><option v-for="gateway in gateways" :key="gateway.id" :value="gateway.id">{{ gateway.name }}</option></select></label>
            <label>Host alias<input v-model="attachForm.alias" name="alias" required autocomplete="off" /></label>
            <label>Alias UUID (optional)<input v-model="attachForm.aliasUUID" name="alias_uuid" autocomplete="off" /></label>
            <label>Address family<select v-model="attachForm.family" name="family"><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></label>
            <label>Interface scope<input v-model="attachForm.interfaceScope" name="interface_scope" required placeholder="lan" autocomplete="off" /></label>
            <label>Steering rule IDs<textarea v-model="attachForm.ruleIds" name="rule_ids" rows="3" required placeholder="Separate IDs with commas or new lines" /></label>
          </div>
          <div class="actions"><button class="button" type="submit">{{ attaching ? 'Attaching…' : 'Save Host binding' }}</button><button class="button button--secondary" type="button" @click="attachOpen = false">Cancel</button></div>
        </fieldset>
      </form>
      <div v-if="!bindingError && !bindings.length && !loading" class="empty-state">No firewall bindings are configured.</div>
      <article v-for="binding in bindings" :key="binding.id" class="binding-card" :aria-label="`Firewall binding ${binding.alias}`">
        <div class="binding-row"><span><strong>{{ binding.alias }}</strong><small>{{ binding.interfaceScope }} · {{ binding.addressFamily }}</small><small>Gateway: {{ gateways.find(gateway => gateway.id === binding.gatewayId)?.name ?? binding.gatewayId }}</small></span><div class="actions"><StatusPill :label="binding.state === 'observed' ? 'observed' : 'desired'" tone="neutral" /><button class="button button--secondary" :disabled="readingBindings.has(binding.id) || loading" @click="readFirewall(binding)">{{ readingBindings.has(binding.id) ? 'Reading firewall…' : 'Read firewall' }}</button></div></div>
        <dl class="binding-metrics"><div><dt>Desired addresses</dt><dd>{{ binding.desiredCount }}</dd></div><div><dt>Persisted addresses</dt><dd>{{ binding.persistedCount ?? 'Unknown' }}</dd></div><div><dt>Active addresses</dt><dd>{{ binding.activeCount ?? 'Unknown' }}</dd></div><div><dt>Drift</dt><dd>{{ binding.drift === undefined ? 'Unknown' : binding.drift ? 'Detected' : 'None observed' }}</dd></div></dl>
        <div class="actions observation"><span>Observation</span><StatusPill :label="observationLabels[observationStatus(binding)]" :tone="observationStatus(binding) === 'error' ? 'bad' : observationStatus(binding) === 'stale' ? 'warn' : 'neutral'" /></div>
        <dl class="binding-details"><div><dt>Last observed</dt><dd><time v-if="binding.observedAt" :datetime="binding.observedAt">{{ binding.observedAt }}</time><span v-else>Never</span></dd></div><div><dt>Last attempt</dt><dd><time v-if="binding.lastAttemptAt" :datetime="binding.lastAttemptAt">{{ binding.lastAttemptAt }}</time><span v-else>Never</span></dd></div><div><dt>Steering rules</dt><dd>{{ binding.ruleIds.join(', ') || 'Unknown' }}</dd></div><div v-if="binding.aliasUUID"><dt>Alias UUID</dt><dd>{{ binding.aliasUUID }}</dd></div></dl>
        <p v-if="binding.observationError" class="alert alert--bad" role="alert">Firewall read failed: {{ binding.observationError }}<span v-if="binding.observedAt"> Showing the last successful observation.</span></p>
      </article>
    </section>
  </div>
</template>

<style scoped>
.page-grid { display: grid; gap: 1rem; } .page-heading, .panel__heading, .gateway-card__heading, .binding-row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; } h1 { margin: .25rem 0 .4rem; font-size: 2rem; } h2, h3 { margin: 0; } h2 { font-size: 1.1rem; } h3 { font-size: 1rem; }
.eyebrow { margin: 0; color: #78b8ff; font-size: .7rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; } .lede, .gateway-card p { margin: 0; color: var(--muted); } .gateway-card p { margin-top: .25rem; font-size: .78rem; }
.panel { display: grid; gap: .7rem; padding: 1rem; border: 1px solid var(--border); border-radius: .65rem; background: var(--surface); } .gateway-card, .binding-row { padding: .8rem; border-radius: .45rem; background: var(--surface-alt); } .gateway-card { display: grid; gap: .65rem; } .capability-list { display: flex; flex-wrap: wrap; gap: .35rem; } .capability { padding: .25rem .4rem; border: 1px solid var(--border); border-radius: .3rem; color: var(--muted); font-size: .7rem; } .restriction { color: var(--warn) !important; } .binding-row span:first-child { display: grid; gap: .2rem; } .binding-row small, .muted, .binding-count { color: var(--muted); font-size: .78rem; }
.button { cursor: pointer; padding: .5rem .7rem; border: 1px solid var(--border); border-radius: .4rem; background: var(--accent); color: #07111f; font-weight: 700; } .button:disabled { cursor: wait; opacity: .55; } .button--secondary { background: transparent; color: var(--text); }
.editor { display: grid; gap: .75rem; padding: 1rem; border: 1px solid var(--border); border-radius: .45rem; background: var(--surface-alt); } .editor p, h3 { margin: 0; } fieldset { display: grid; gap: 1rem; padding: 0; margin: 0; border: 0; min-width: 0; } .form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .8rem; } label { display: grid; gap: .35rem; color: var(--text); font-size: .82rem; } .full-width { grid-column: 1 / -1; } input { box-sizing: border-box; width: 100%; min-width: 0; padding: .55rem; border: 1px solid var(--border); border-radius: .35rem; background: var(--surface); color: var(--text); font: inherit; } .actions { display: flex; align-items: center; flex-wrap: wrap; gap: .65rem; } .alert--good { border: 1px solid #32634f; background: #142e25; color: #ace4c9; }
.empty-state { padding: 1.5rem; color: var(--muted); text-align: center; } .alert { padding: .75rem 1rem; border-radius: .5rem; } .alert--bad { border: 1px solid #713847; background: #301c29; color: #ffbeca; }
.binding-card { display: grid; gap: .8rem; padding: .8rem; border-radius: .45rem; background: var(--surface-alt); min-width: 0; } .binding-card .binding-row { padding: 0; } .binding-metrics, .binding-details { display: flex; flex-wrap: wrap; gap: .8rem 1.5rem; margin: 0; } .binding-metrics dt, .binding-details dt, .observation { color: var(--muted); font-size: .75rem; } .binding-metrics dd, .binding-details dd { margin: .25rem 0 0; } .binding-details dd { font-size: .78rem; overflow-wrap: anywhere; } .binding-card .alert { margin: 0; } select, textarea { box-sizing: border-box; width: 100%; min-width: 0; padding: .55rem; border: 1px solid var(--border); border-radius: .35rem; background: var(--surface); color: var(--text); font: inherit; } textarea { resize: vertical; }
@media (max-width: 760px) { .page-heading, .gateway-card__heading, .binding-row { align-items: stretch; flex-direction: column; } .binding-row { align-items: flex-start; } .panel__heading { flex-wrap: wrap; } .form-grid { grid-template-columns: 1fr; } }
</style>
