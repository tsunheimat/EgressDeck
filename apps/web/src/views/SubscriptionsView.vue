<script setup lang="ts">
import { computed, onActivated, reactive, ref } from 'vue'
import StatusPill from '../components/StatusPill.vue'
import StateStrip from '../components/StateStrip.vue'
import { ControllerApiError, randomIdempotencyKey } from '../api/client'
import { useControllerState } from '../state'
import type { OperationSummary, ProviderRevision, ProviderSchedule, ProviderSummary } from '../types'

const props = defineProps<{ state: ReturnType<typeof useControllerState> }>()
const providers = ref<ProviderSummary[]>([])
const revisions = ref<Record<string, ProviderRevision[]>>({})
const revisionErrors = ref<Record<string, string>>({})
const schedules = ref<Record<string, ProviderSchedule>>({})
const scheduleErrors = ref<Record<string, string>>({})
const scheduleDrafts = ref<Record<string, { enabled: boolean; intervalMinutes: number | string }>>({})
const operations = ref<Record<string, OperationSummary>>({})
const loading = ref(false)
const error = ref<string>()
const notice = ref<string>()
const pending = ref<string>()
const addOpen = ref(false)
const savedProvider = ref<ProviderSummary>()
const form = reactive({ name: '', mode: 'url', source: '', content: '', format: 'auto' })
const importProviderId = ref<string>()
const importContent = ref('')
const importFormat = ref('auto')
const inventoryReadbackFailed = ref(false)
const settingsTarget = ref<{ id: string; revision: number }>()
const settingsDraft = reactive({ name: '', source: '', format: 'auto', fetchRoute: 'direct' })
const settingsAccepted = ref<ProviderSummary>()
const deleteTarget = ref<{ id: string; name: string; revision: number; accepted: boolean }>()
const deleteAcknowledged = ref(false)
const maxContentBytes = 1024 * 1024
const formats = [
  { value: 'auto', label: 'Auto detect' }, { value: 'links', label: 'Node links' },
  { value: 'base64', label: 'Base64 node list' }, { value: 'sip008', label: 'SIP008' },
  { value: 'clash', label: 'Clash YAML (nodes only)' }, { value: 'json', label: 'JSON' },
]
const canManage = computed(() => props.state.isAdministrator.value)
const canStage = computed(() => canManage.value && props.state.capabilities.value['provider.stage'] === true)
const canPublish = computed(() => props.state.canOperate.value && props.state.capabilities.value['provider.publish_hot'] === true)
const busy = computed(() => !!pending.value || loading.value)

function message(cause: unknown, fallback: string): string {
  if (cause instanceof ControllerApiError && cause.code === 'provider_in_use') return `${cause.message} Remove its references and resolve active publication or pending operations before deleting.`
  if (cause instanceof ControllerApiError && cause.status === 409) return `${cause.message} Refresh state before retrying.`
  return cause instanceof Error ? cause.message : fallback
}
function latestRevision(provider: ProviderSummary): ProviderRevision | undefined {
  const items = revisions.value[provider.id] ?? []
  return items.find((revision) => revision.state === 'staged') ?? items.find((revision) => revision.state === 'active') ?? items[0]
}
function isRemote(provider: ProviderSummary): boolean { return schedules.value[provider.id]?.eligible === true }
function sourceLabel(provider: ProviderSummary): string {
  if (!schedules.value[provider.id]) return 'Source details unavailable'
  return isRemote(provider) ? 'Subscription URL' : 'Imported content'
}
function setSchedule(schedule: ProviderSchedule) {
  schedules.value[schedule.provider_id] = schedule
  scheduleDrafts.value[schedule.provider_id] = { enabled: schedule.enabled, intervalMinutes: schedule.interval_seconds / 60 }
}

async function load(clearError = true): Promise<boolean> {
  loading.value = true
  if (clearError) error.value = undefined
  try {
    const items = await props.state.api.providers()
    const [results, scheduleResults] = await Promise.all([
      Promise.allSettled(items.map((provider) => props.state.api.providerRevisions(provider.id))),
      Promise.allSettled(items.map((provider) => props.state.api.providerSchedule(provider.id))),
    ])
    const nextRevisions: Record<string, ProviderRevision[]> = {}
    const nextErrors: Record<string, string> = {}
    schedules.value = {}
    scheduleDrafts.value = {}
    scheduleErrors.value = {}
    providers.value = items.map((provider, index) => {
      const scheduleResult = scheduleResults[index]
      if (scheduleResult?.status === 'fulfilled') setSchedule(scheduleResult.value)
      else scheduleErrors.value[provider.id] = scheduleResult?.status === 'rejected' ? message(scheduleResult.reason, 'Schedule readback failed') : 'Schedule readback failed'
      const result = results[index]
      if (!result || result.status === 'rejected') {
        nextErrors[provider.id] = result?.status === 'rejected' ? message(result.reason, 'Revision readback failed') : 'Revision readback failed'
        return provider
      }
      const ordered = [...result.value].sort((a, b) => b.number - a.number)
      nextRevisions[provider.id] = ordered
      const active = ordered.find((revision) => revision.state === 'active')
      const staged = ordered.find((revision) => revision.state === 'staged')
      const latest = staged ?? active ?? ordered[0]
      return {
        ...provider,
        activeRevision: active ? String(active.number) : undefined,
        stagedRevision: staged ? String(staged.number) : undefined,
        state: staged ? 'staged' as const : active ? 'active' as const : provider.state,
        nodeCount: latest?.nodes?.length ?? 0,
        unsupportedCount: latest?.parse_report?.unsupported?.length ?? 0,
      }
    })
    revisions.value = nextRevisions
    revisionErrors.value = nextErrors
    inventoryReadbackFailed.value = false
    return true
  } catch (cause) {
    inventoryReadbackFailed.value = true
    const readbackError = message(cause, 'Unable to load providers')
    error.value = error.value ? `${error.value} Provider readback also failed: ${readbackError}` : readbackError
    revisionErrors.value = Object.fromEntries(providers.value.map((provider) => [provider.id, 'Inventory refresh failed; revision values may be stale']))
    schedules.value = {}
    scheduleDrafts.value = {}
    scheduleErrors.value = Object.fromEntries(providers.value.map((provider) => [provider.id, 'Inventory refresh failed; refresh the list before changing the schedule']))
    return false
  } finally { loading.value = false }
}

function editProvider(provider: ProviderSummary) {
  if (!canManage.value || inventoryReadbackFailed.value || !provider.revision) return
  settingsTarget.value = { id: provider.id, revision: provider.revision }
  settingsAccepted.value = undefined
  Object.assign(settingsDraft, { name: provider.name, source: '', format: provider.format, fetchRoute: provider.fetchRoute })
  deleteTarget.value = undefined
  error.value = undefined
  notice.value = undefined
}
function closeSettings() {
  settingsTarget.value = undefined
  settingsAccepted.value = undefined
  settingsDraft.source = ''
}
async function saveSettings() {
  const target = settingsTarget.value
  if (!canManage.value || !target) return
  error.value = undefined
  notice.value = undefined
  pending.value = `settings:${target.id}`
  try {
    if (!settingsAccepted.value) {
      const name = settingsDraft.name.trim()
      if (!name) throw new Error('Enter a provider name.')
      const source = settingsDraft.source.trim()
      settingsAccepted.value = await props.state.api.updateProvider(target.id, {
        name, format: settingsDraft.format, fetch_route: settingsDraft.fetchRoute.trim() || 'direct',
        ...(source ? { source } : {}),
      }, target.revision)
      settingsDraft.source = ''
    }
    if (!await load(false)) throw new Error('Settings were saved, but inventory readback failed. Select Verify saved settings to retry readback.')
    const expected = settingsAccepted.value
    const current = providers.value.find((provider) => provider.id === target.id)
    if (!current || current.revision !== expected.revision || current.name !== expected.name || current.format !== expected.format || current.fetchRoute !== expected.fetchRoute) {
      throw new Error('Settings were saved, but current inventory does not match the saved revision. Close this editor and reload the latest settings before editing again.')
    }
    notice.value = `Settings saved for ${current.name}. Refresh or import a revision to stage source changes, then review and apply separately.`
    closeSettings()
  } catch (cause) { error.value = message(cause, 'Unable to save provider settings') }
  finally { pending.value = undefined }
}
function confirmDelete(provider: ProviderSummary) {
  if (!canManage.value || inventoryReadbackFailed.value || !provider.revision) return
  closeSettings()
  deleteTarget.value = { id: provider.id, name: provider.name, revision: provider.revision, accepted: false }
  deleteAcknowledged.value = false
  error.value = undefined
  notice.value = undefined
}
async function deleteProvider() {
  const target = deleteTarget.value
  if (!canManage.value || !target || !deleteAcknowledged.value) return
  error.value = undefined
  notice.value = undefined
  pending.value = `delete:${target.id}`
  try {
    if (!target.accepted) {
      await props.state.api.deleteProvider(target.id, target.revision)
      target.accepted = true
    }
    if (!await load(false) || providers.value.some((provider) => provider.id === target.id)) {
      throw new Error('Deletion was accepted, but inventory readback has not confirmed removal. Select Verify deletion to retry readback.')
    }
    notice.value = `Provider ${target.name} deleted. Removal is confirmed by controller readback.`
    delete operations.value[target.id]
    if (importProviderId.value === target.id) { importProviderId.value = undefined; importContent.value = '' }
    deleteTarget.value = undefined
  } catch (cause) { error.value = message(cause, 'Unable to delete provider') }
  finally { pending.value = undefined }
}

async function saveSchedule(provider: ProviderSummary) {
  const schedule = schedules.value[provider.id]
  const draft = scheduleDrafts.value[provider.id]
  if (!canStage.value || !schedule?.eligible || !draft) return
  scheduleErrors.value[provider.id] = ''
  notice.value = undefined
  const intervalSeconds = Number(draft.intervalMinutes) * 60
  if (!Number.isInteger(intervalSeconds) || intervalSeconds < 300 || intervalSeconds > 604800) {
    scheduleErrors.value[provider.id] = 'Choose an interval from 5 minutes to 7 days (10080 minutes).'
    return
  }
  pending.value = `schedule:${provider.id}`
  try {
    setSchedule(await props.state.api.saveProviderSchedule(provider.id, { enabled: draft.enabled, interval_seconds: intervalSeconds, auto_apply: false }, schedule.revision))
    notice.value = `Refresh schedule saved for ${provider.name}. Scheduled refreshes stage revisions for review.`
  } catch (cause) { scheduleErrors.value[provider.id] = message(cause, 'Unable to save refresh schedule') }
  finally { pending.value = undefined }
}

async function readOperation(providerId: string, operationId: string): Promise<OperationSummary> {
  const operation = await props.state.api.waitForOperation(operationId)
  props.state.recordOperation(operation)
  operations.value[providerId] = operation
  if (['failed', 'partially_applied', 'outcome_unknown'].includes(operation.status)) throw new Error(operation.error ?? `Operation ${operation.id} is ${operation.status}. Refresh state before retrying.`)
  return operation
}
async function refreshOperation(provider: ProviderSummary) {
  const operation = operations.value[provider.id]
  if (!operation) return
  pending.value = provider.id
  error.value = undefined
  try { await readOperation(provider.id, operation.id) } catch (cause) { error.value = message(cause, 'Operation readback failed') }
  finally { await load(false); pending.value = undefined }
}
function resetForm() {
  Object.assign(form, { name: '', mode: 'url', source: '', content: '', format: 'auto' })
  savedProvider.value = undefined
  addOpen.value = false
}
function validateContent(content: string) {
  if (!content.trim()) throw new Error('Enter subscription content before staging.')
  if (new TextEncoder().encode(content).length > maxContentBytes) throw new Error('Import content must be 1 MiB or smaller.')
}
async function readFile(event: Event, target: 'new' | 'revision') {
  error.value = undefined
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    if (file.size > maxContentBytes) throw new Error('Import file must be 1 MiB or smaller.')
    const content = await file.text()
    validateContent(content)
    if (target === 'new') form.content = content
    else importContent.value = content
  } catch (cause) { error.value = message(cause, 'Unable to read the import file') }
  finally { input.value = '' }
}

async function addProvider() {
  if (!canStage.value) return
  error.value = undefined
  notice.value = undefined
  pending.value = 'new'
  try {
    if (form.mode === 'paste') validateContent(form.content)
    if (!savedProvider.value) {
      savedProvider.value = await props.state.api.createProvider({
        name: form.name.trim(), source: form.mode === 'url' ? form.source.trim() : 'inline',
        format: form.mode === 'url' ? form.format : 'local', fetch_route: 'direct',
      })
    }
    const provider = savedProvider.value
    notice.value = `Provider ${provider.name} is saved. Staging requires controller readback.`
    const accepted = form.mode === 'url'
      ? await props.state.api.refreshProvider(provider.id, randomIdempotencyKey())
      : await props.state.api.stageProvider(provider.id, { content: form.content, format: form.format }, randomIdempotencyKey())
    const operation = await readOperation(provider.id, accepted.operationId)
    notice.value = `Operation ${operation.id}: ${operation.status}. Review the revision before publishing.`
    resetForm()
  } catch (cause) { error.value = message(cause, 'Unable to add and stage provider') }
  finally { await load(false); pending.value = undefined }
}
async function refresh(provider: ProviderSummary) {
  if (!canStage.value || !isRemote(provider)) return
  error.value = undefined
  notice.value = undefined
  pending.value = provider.id
  try {
    const accepted = await props.state.api.refreshProvider(provider.id, randomIdempotencyKey())
    await readOperation(provider.id, accepted.operationId)
  } catch (cause) { error.value = message(cause, 'Provider refresh failed') }
  finally { await load(false); pending.value = undefined }
}
function openImport(provider: ProviderSummary) {
  importProviderId.value = provider.id
  importContent.value = ''
  importFormat.value = provider.format === 'local' ? 'auto' : provider.format
}
async function stage(provider: ProviderSummary) {
  if (!canStage.value) return
  error.value = undefined
  pending.value = provider.id
  try {
    validateContent(importContent.value)
    const accepted = await props.state.api.stageProvider(provider.id, { content: importContent.value, format: importFormat.value }, randomIdempotencyKey())
    await readOperation(provider.id, accepted.operationId)
    importProviderId.value = undefined
    importContent.value = ''
  } catch (cause) { error.value = message(cause, 'Unable to stage provider revision') }
  finally { await load(false); pending.value = undefined }
}
async function apply(provider: ProviderSummary) {
  if (!canPublish.value || !provider.stagedRevision || !revisions.value[provider.id] || revisionErrors.value[provider.id]) return
  error.value = undefined
  notice.value = undefined
  pending.value = provider.id
  const revision = provider.stagedRevision
  let operation: OperationSummary | undefined
  try {
    const accepted = await props.state.api.applyProvider(provider.id, revision, randomIdempotencyKey(), Number(provider.activeRevision ?? 0))
    operation = await readOperation(provider.id, accepted.operationId)
  } catch (cause) { error.value = message(cause, 'Provider publication failed') }
  finally {
    const readBack = await load(false)
    if (readBack && operation?.status === 'applied' && providers.value.find((item) => item.id === provider.id)?.activeRevision !== revision) {
      error.value = 'Publication was accepted, but active revision readback does not match. Refresh state before retrying.'
    }
    pending.value = undefined
  }
}
onActivated(() => load())
</script>

<template>
  <div class="page-grid">
    <section class="page-heading">
      <div><p class="eyebrow">Provider lifecycle</p><h1>Subscriptions</h1><p class="lede">Import, stage, review, then publish a provider revision. Parser reports show which nodes were accepted.</p></div>
      <div class="actions"><button class="button button--secondary" :disabled="busy" @click="load()">Refresh list</button><button class="button" :disabled="busy || !canStage" @click="addOpen = !addOpen">Add subscription</button></div>
    </section>
    <p v-if="!canManage" class="notice">Administrator access is required to manage subscription settings, deletion, and staging.</p>
    <p v-else-if="!canStage" class="notice">Provider staging is unavailable. The controller must enable provider.stage to import or refresh subscriptions.</p>
    <section v-if="error" class="alert alert--bad" role="alert">{{ error }}</section>
    <section v-if="notice" class="alert alert--info" role="status">{{ notice }}</section>

    <form v-if="addOpen" class="panel form-grid" aria-label="Add subscription" @submit.prevent="addProvider">
      <h2>Add subscription</h2>
      <p v-if="savedProvider" class="notice">{{ savedProvider.name }} is already saved. Retry staging to use this provider.</p>
      <label>Provider name<input v-model="form.name" required maxlength="200" autocomplete="off" :disabled="busy || !!savedProvider" /></label>
      <label>Source type<select v-model="form.mode" :disabled="busy || !!savedProvider"><option value="url">Subscription URL</option><option value="paste">Paste or upload content</option></select></label>
      <label v-if="form.mode === 'url'">Subscription URL<input v-model="form.source" type="url" required placeholder="https://…" autocomplete="off" :disabled="busy || !!savedProvider" /></label>
      <template v-else>
        <label>Import file<input type="file" :disabled="busy" @change="readFile($event, 'new')" /></label>
        <label>Subscription content<textarea v-model="form.content" required rows="7" spellcheck="false" autocomplete="off" :disabled="busy" /></label>
        <p class="muted">Maximum 1 MiB. Clash import extracts node inventory.</p>
      </template>
      <label>Import format<select v-model="form.format" :disabled="busy || (!!savedProvider && form.mode === 'url')"><option v-for="format in formats" :key="format.value" :value="format.value">{{ format.label }}</option></select></label>
      <div class="actions"><button class="button" type="submit" :disabled="busy || !canStage">{{ pending === 'new' ? 'Staging…' : savedProvider ? 'Retry staging provider' : 'Add and stage provider' }}</button><button class="button button--secondary" type="button" :disabled="busy" @click="resetForm">Close</button></div>
    </form>

    <form v-if="settingsTarget" class="panel form-grid provider-settings" aria-label="Provider settings" @submit.prevent="saveSettings">
      <h2>Provider settings</h2>
      <p class="muted">Editing inventory revision {{ settingsTarget.revision }}. Saving settings does not refresh, stage, or apply a provider revision.</p>
      <fieldset class="form-grid" :disabled="busy || !canManage || !!settingsAccepted">
        <label>Provider name<input v-model="settingsDraft.name" required maxlength="200" autocomplete="off" /></label>
        <label>Replacement subscription URL (optional)<input v-model="settingsDraft.source" type="password" placeholder="Leave empty to keep the current source" autocomplete="new-password" spellcheck="false" /></label>
        <p class="muted">The stored source is private and is never loaded into this form. Leave this field empty to preserve it.</p>
        <label>Source format<select v-model="settingsDraft.format"><option v-for="format in formats" :key="format.value" :value="format.value">{{ format.label }}</option><option value="local">Local import</option></select></label>
        <label>Fetch route<input v-model="settingsDraft.fetchRoute" required autocomplete="off" placeholder="direct" /></label>
        <p class="muted">Use direct or a route verified by the controller. For imported content, use Local import and import a new revision separately.</p>
      </fieldset>
      <div class="actions"><button class="button" type="submit" :disabled="busy || !canManage">{{ pending?.startsWith('settings:') ? 'Saving…' : settingsAccepted ? 'Verify saved settings' : 'Save provider settings' }}</button><button class="button button--secondary" type="button" :disabled="busy" @click="closeSettings">Close</button></div>
    </form>

    <form v-if="deleteTarget" class="panel form-grid" aria-label="Delete provider" @submit.prevent="deleteProvider">
      <h2>Delete {{ deleteTarget.name }}?</h2>
      <p class="muted">This removes the provider and its stored source and revisions. Providers with active publication, outbound references, selections, or pending operations cannot be deleted.</p>
      <label class="checkbox-label"><input v-model="deleteAcknowledged" type="checkbox" required :disabled="busy || deleteTarget.accepted" />I confirm deletion of {{ deleteTarget.name }} ({{ deleteTarget.id }}), inventory revision {{ deleteTarget.revision }}.</label>
      <div class="actions"><button class="button button--danger" type="submit" :disabled="busy || !canManage || !deleteAcknowledged">{{ pending?.startsWith('delete:') ? 'Deleting…' : deleteTarget.accepted ? 'Verify deletion' : 'Delete provider permanently' }}</button><button class="button button--secondary" type="button" :disabled="busy" @click="deleteTarget = undefined">Close</button></div>
    </form>

    <section class="provider-list" :aria-busy="loading">
      <article v-for="provider in providers" :key="provider.id" class="panel provider-card" :aria-label="`Provider ${provider.name}`">
        <div class="provider-card__heading"><div><h2>{{ provider.name }}</h2><p>{{ sourceLabel(provider) }} · {{ provider.format === 'local' ? 'auto / selected format' : provider.format }} · {{ provider.nodeCount ?? 'unknown' }} nodes</p></div><StatusPill :label="pending === provider.id ? 'Working' : provider.state" :tone="provider.state === 'active' ? 'good' : provider.state === 'error' ? 'bad' : 'warn'" /></div>
        <div class="provider-meta"><span>Unsupported: <strong>{{ provider.unsupportedCount ?? 'unknown' }}</strong></span><span>Last fetch: <strong>{{ provider.lastAttemptAt ?? 'unreported' }}</strong></span><span>Last successful fetch: <strong>{{ provider.lastSuccessAt ?? 'unreported' }}</strong></span></div>
        <div v-if="provider.gatewayStates.length" class="gateway-states"><span v-for="gateway in provider.gatewayStates" :key="gateway.gatewayId" class="gateway-state"><strong>{{ gateway.gatewayId }}</strong> {{ gateway.state }}<small v-if="gateway.observedRevision"> · {{ gateway.observedRevision }}</small></span></div>
        <StateStrip :states="{ desired: provider.stagedRevision, applied: provider.activeRevision }" :pending="pending === provider.id" />
        <p v-if="revisionErrors[provider.id]" class="notice" role="alert">Revision readback failed: {{ revisionErrors[provider.id] }}. Publication is disabled.</p>
        <div v-if="operations[provider.id]" class="operation" role="status"><span>Operation <code>{{ operations[provider.id]?.id }}</code>: {{ operations[provider.id]?.status }}</span><button class="button button--secondary" :disabled="busy" @click="refreshOperation(provider)">Refresh operation</button></div>
        <details v-if="latestRevision(provider)" class="revision-report" open>
          <summary>Review revision {{ latestRevision(provider)?.number }}</summary>
          <template v-for="revision in [latestRevision(provider)!]" :key="revision.number">
            <p class="muted">{{ revision.nodes?.length ?? 0 }} accepted · {{ revision.parse_report?.unsupported?.length ?? 0 }} unsupported · {{ revision.created_at }}</p>
            <p v-if="revision.changes?.noop" class="muted">No content changes.</p>
            <p v-else class="muted">{{ revision.changes?.added?.length ?? 0 }} added · {{ revision.changes?.removed?.length ?? 0 }} removed · {{ revision.changes?.changed?.length ?? 0 }} changed · {{ revision.changes?.renamed?.length ?? 0 }} renamed</p>
            <ul v-if="revision.parse_report?.warnings?.length" class="report-list"><li v-for="warning in revision.parse_report.warnings" :key="warning">{{ warning }}</li></ul>
            <ul v-if="revision.parse_report?.errors?.length" class="report-list report-list--bad"><li v-for="problem in revision.parse_report.errors" :key="problem">{{ problem }}</li></ul>
            <ul v-if="revision.parse_report?.unsupported?.length" class="report-list"><li v-for="(unsupported, index) in revision.parse_report.unsupported" :key="index">{{ unsupported.name || `Entry ${index + 1}` }}: {{ unsupported.reason || 'Unsupported node' }}</li></ul>
            <details><summary>Accepted nodes</summary><ul class="node-list"><li v-for="node in revision.nodes" :key="node.id">{{ node.name || node.id }} <span class="muted">{{ node.definition?.protocol ?? 'unknown protocol' }}</span></li></ul></details>
          </template>
        </details>
        <details v-if="(revisions[provider.id]?.length ?? 0) > 1"><summary>Revision history</summary><ul class="node-list"><li v-for="revision in revisions[provider.id]" :key="revision.number">Revision {{ revision.number }} · {{ revision.state }} · {{ revision.created_at }}</li></ul></details>
        <p v-if="provider.stagedRevision && !canPublish" class="notice">Hot publication is unavailable. This revision remains staged until a gateway adapter reports provider.publish_hot.</p>
        <p v-if="scheduleErrors[provider.id]" class="notice" role="alert">Refresh schedule: {{ scheduleErrors[provider.id] }}</p>
        <form v-if="isRemote(provider) && scheduleDrafts[provider.id]" class="form-grid refresh-schedule" :aria-label="`Refresh schedule for ${provider.name}`" @submit.prevent="saveSchedule(provider)">
          <h3>Scheduled refresh</h3>
          <p class="muted">Schedules start disabled. Each refresh stages a revision for review; publication requires a separate action.</p>
          <label class="checkbox-label"><input v-model="scheduleDrafts[provider.id]!.enabled" type="checkbox" :disabled="busy || !canStage" />Enable scheduled refresh</label>
          <label>Refresh interval (minutes)<input v-model.number="scheduleDrafts[provider.id]!.intervalMinutes" type="number" required min="5" max="10080" step="1" :disabled="busy || !canStage" /></label>
          <p class="muted">Between 5 minutes and 7 days (10080 minutes).</p>
          <dl class="schedule-status">
            <div><dt>Schedule</dt><dd>{{ schedules[provider.id]?.running ? 'Refresh running' : schedules[provider.id]?.enabled ? 'Enabled' : 'Disabled' }}</dd></div>
            <div><dt>Next due</dt><dd>{{ schedules[provider.id]?.next_due_at ?? 'Not scheduled' }}</dd></div>
            <div><dt>Last attempt</dt><dd>{{ schedules[provider.id]?.last_attempt_at ?? 'Never' }}</dd></div>
            <div><dt>Last successful refresh</dt><dd>{{ schedules[provider.id]?.last_success_at ?? 'Never' }}</dd></div>
            <div v-if="schedules[provider.id]?.last_operation_id"><dt>Last operation</dt><dd><code>{{ schedules[provider.id]?.last_operation_id }}</code></dd></div>
          </dl>
          <p v-if="schedules[provider.id]?.last_error" class="notice" role="alert">Last scheduled refresh failed: {{ schedules[provider.id]?.last_error }}</p>
          <div class="actions"><button class="button button--secondary" type="submit" :disabled="busy || !canStage">{{ pending === `schedule:${provider.id}` ? 'Saving schedule…' : 'Save refresh schedule' }}</button></div>
        </form>
        <div class="actions">
          <button v-if="isRemote(provider)" class="button button--secondary" :disabled="busy || !canStage" @click="refresh(provider)">Refresh provider</button>
          <button class="button button--secondary" :disabled="busy || !canStage" @click="openImport(provider)">Import new revision</button>
          <button class="button" :disabled="busy || !canPublish || !provider.stagedRevision || !!revisionErrors[provider.id]" @click="apply(provider)">Apply staged revision</button>
          <button v-if="canManage" class="button button--secondary" :disabled="busy || inventoryReadbackFailed || !provider.revision" :aria-label="`Edit settings for ${provider.name}`" @click="editProvider(provider)">Settings</button>
          <button v-if="canManage" class="button button--secondary" :disabled="busy || inventoryReadbackFailed || !provider.revision" :aria-label="`Delete provider ${provider.name}`" @click="confirmDelete(provider)">Delete</button>
        </div>
        <form v-if="importProviderId === provider.id" class="form-grid revision-import" aria-label="Import new revision" @submit.prevent="stage(provider)">
          <label>Revision file<input type="file" :disabled="busy" @change="readFile($event, 'revision')" /></label>
          <label>Revision content<textarea v-model="importContent" required rows="6" spellcheck="false" autocomplete="off" :disabled="busy" /></label>
          <label>Revision format<select v-model="importFormat" :disabled="busy"><option v-for="format in formats" :key="format.value" :value="format.value">{{ format.label }}</option></select></label>
          <div class="actions"><button class="button" :disabled="busy || !canStage">Stage revision</button><button class="button button--secondary" type="button" :disabled="busy" @click="importProviderId = undefined; importContent = ''">Cancel</button></div>
        </form>
      </article>
      <div v-if="!providers.length && !loading" class="panel empty-state">No subscription providers have been configured.</div>
    </section>
  </div>
</template>

<style scoped>
.page-grid, .provider-list, .provider-card, .form-grid { display: grid; gap: 1rem; }
.page-heading, .provider-card__heading, .provider-meta, .actions, .operation { display: flex; align-items: center; justify-content: space-between; gap: .75rem; }
h1 { margin: .25rem 0 .4rem; font-size: 2rem; } h2 { margin: 0; font-size: 1.1rem; }
.eyebrow { margin: 0; color: var(--accent); font-size: .7rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; }
.lede, .provider-card p { margin: 0; color: var(--muted); } .provider-card__heading p { margin-top: .3rem; font-size: .8rem; }
.panel { padding: 1rem; border: 1px solid var(--border); border-radius: .65rem; background: var(--surface); }
.provider-meta, .actions { justify-content: flex-start; flex-wrap: wrap; } .provider-meta, .muted { color: var(--muted); font-size: .78rem; } .provider-meta strong { color: var(--text); }
.form-grid label { display: grid; gap: .4rem; font-size: .85rem; } input, select, textarea { width: 100%; padding: .55rem .65rem; border: 1px solid var(--border); border-radius: .4rem; background: var(--surface-alt); color: var(--text); }
.provider-settings fieldset { min-width: 0; margin: 0; padding: 0; border: 0; }
textarea { resize: vertical; font: .8rem ui-monospace, monospace; } .revision-import { padding-top: 1rem; border-top: 1px solid var(--border); }
.refresh-schedule { border-top: 1px solid var(--border); padding-top: 1rem; } .refresh-schedule h3 { margin: 0; font-size: .95rem; } .refresh-schedule label { max-width: 22rem; }
.form-grid .checkbox-label { display: flex; align-items: center; gap: .5rem; } .checkbox-label input { width: auto; }
.schedule-status { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 15rem), 1fr)); gap: .6rem 1rem; margin: 0; font-size: .78rem; } .schedule-status dt { color: var(--muted); } .schedule-status dd { margin: .2rem 0 0; overflow-wrap: anywhere; }
.gateway-states { display: flex; flex-wrap: wrap; gap: .45rem; } .gateway-state { padding: .35rem .5rem; border-radius: .35rem; background: var(--surface-alt); color: var(--muted); font-size: .75rem; }
.button { cursor: pointer; padding: .5rem .7rem; border: 1px solid var(--border); border-radius: .4rem; background: var(--accent); color: #07111f; font-weight: 700; } .button:disabled { cursor: not-allowed; opacity: .55; } .button--secondary { background: transparent; color: var(--text); }
.button--danger { background: #301c29; border-color: #713847; color: #ffbeca; }
.revision-report { display: grid; gap: .5rem; padding: .75rem; border: 1px solid var(--border); border-radius: .45rem; } summary { cursor: pointer; font-size: .85rem; } details p, details details, details ul { margin-top: .65rem !important; }
.report-list, .node-list { padding-left: 1.25rem; font-size: .8rem; } .report-list, .notice { color: var(--warn) !important; } .report-list--bad { color: var(--bad); } .notice { margin: 0; font-size: .85rem; }
.operation { flex-wrap: wrap; font-size: .78rem; } code { overflow-wrap: anywhere; } .empty-state { padding: 1.5rem; color: var(--muted); text-align: center; }
.alert { padding: .75rem 1rem; border-radius: .5rem; overflow-wrap: anywhere; } .alert--bad { border: 1px solid #713847; background: #301c29; color: #ffbeca; } .alert--info { border: 1px solid var(--border); color: var(--text); background: var(--surface-alt); }
@media (max-width: 760px) { .page-heading, .provider-card__heading { align-items: stretch; flex-direction: column; } .actions .button { flex: 1; } }
</style>
