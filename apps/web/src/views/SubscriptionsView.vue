<script setup lang="ts">
import { uiLabel } from '../localization'
import DiagnosticMessage from '../components/DiagnosticMessage.vue'
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
  { value: 'auto', label: '自动检测' }, { value: 'links', label: '节点链接' },
  { value: 'base64', label: 'Base64 节点列表' }, { value: 'sip008', label: 'SIP008' },
  { value: 'clash', label: 'Clash YAML（仅节点）' }, { value: 'json', label: 'JSON' },
]
const canManage = computed(() => props.state.isAdministrator.value)
const canStage = computed(() => canManage.value && props.state.capabilities.value['provider.stage'] === true)
const canPublish = computed(() => props.state.canOperate.value && props.state.capabilities.value['provider.publish_hot'] === true)
const busy = computed(() => !!pending.value || loading.value)

function message(cause: unknown, fallback: string): string {
  if (cause instanceof ControllerApiError && cause.code === 'provider_in_use') return `${cause.message} 删除前请先移除引用，并处理生效发布或待处理操作。`
  if (cause instanceof ControllerApiError && cause.status === 409) return `${cause.message} 重试前请刷新状态。`
  return cause instanceof Error ? cause.message : fallback
}
function latestRevision(provider: ProviderSummary): ProviderRevision | undefined {
  const items = revisions.value[provider.id] ?? []
  return items.find((revision) => revision.state === 'staged') ?? items.find((revision) => revision.state === 'active') ?? items[0]
}
function isRemote(provider: ProviderSummary): boolean { return schedules.value[provider.id]?.eligible === true }
function sourceLabel(provider: ProviderSummary): string {
  if (!schedules.value[provider.id]) return '来源详情不可用'
  return isRemote(provider) ? '订阅 URL' : '导入内容'
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
      else scheduleErrors.value[provider.id] = scheduleResult?.status === 'rejected' ? message(scheduleResult.reason, '定时计划回读失败') : '定时计划回读失败'
      const result = results[index]
      if (!result || result.status === 'rejected') {
        nextErrors[provider.id] = result?.status === 'rejected' ? message(result.reason, '版本回读失败') : '版本回读失败'
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
    const readbackError = message(cause, '无法读取订阅清单')
    error.value = error.value ? `${error.value} 订阅回读也失败了：${readbackError}` : readbackError
    revisionErrors.value = Object.fromEntries(providers.value.map((provider) => [provider.id, '清单刷新失败；版本数值可能已过期']))
    schedules.value = {}
    scheduleDrafts.value = {}
    scheduleErrors.value = Object.fromEntries(providers.value.map((provider) => [provider.id, '清单刷新失败；修改定时计划前请先刷新列表']))
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
      if (!name) throw new Error('请输入订阅名称。')
      const source = settingsDraft.source.trim()
      settingsAccepted.value = await props.state.api.updateProvider(target.id, {
        name, format: settingsDraft.format, fetch_route: settingsDraft.fetchRoute.trim() || 'direct',
        ...(source ? { source } : {}),
      }, target.revision)
      settingsDraft.source = ''
    }
    if (!await load(false)) throw new Error('设置已保存，但清单回读失败。请选择“验证已保存设置”重试回读。')
    const expected = settingsAccepted.value
    const current = providers.value.find((provider) => provider.id === target.id)
    if (!current || current.revision !== expected.revision || current.name !== expected.name || current.format !== expected.format || current.fetchRoute !== expected.fetchRoute) {
      throw new Error('设置已保存，但当前清单与保存版本不匹配。请关闭编辑器并重新读取最新设置后再编辑。')
    }
    notice.value = `已保存订阅设置：${current.name}。请刷新或导入版本以暂存来源变化，再单独审查和应用。`
    closeSettings()
  } catch (cause) { error.value = message(cause, '无法保存订阅设置') }
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
      throw new Error('删除请求已受理，但清单回读尚未确认移除。请选择“验证删除”重试回读。')
    }
    notice.value = `订阅 ${target.name} 已删除，控制器回读已确认其不存在。`
    delete operations.value[target.id]
    if (importProviderId.value === target.id) { importProviderId.value = undefined; importContent.value = '' }
    deleteTarget.value = undefined
  } catch (cause) { error.value = message(cause, '无法删除订阅') }
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
    scheduleErrors.value[provider.id] = '请选择 5 分钟至 7 天（10080 分钟）的间隔。'
    return
  }
  pending.value = `schedule:${provider.id}`
  try {
    setSchedule(await props.state.api.saveProviderSchedule(provider.id, { enabled: draft.enabled, interval_seconds: intervalSeconds, auto_apply: false }, schedule.revision))
    notice.value = `已保存刷新计划，订阅为 ${provider.name}。定时刷新只暂存待审查版本。`
  } catch (cause) { scheduleErrors.value[provider.id] = message(cause, '无法保存刷新计划') }
  finally { pending.value = undefined }
}

async function readOperation(providerId: string, operationId: string): Promise<OperationSummary> {
  const operation = await props.state.api.waitForOperation(operationId)
  props.state.recordOperation(operation)
  operations.value[providerId] = operation
  if (['failed', 'partially_applied', 'outcome_unknown'].includes(operation.status)) throw new Error(operation.error ?? `操作 ${operation.id} 的状态为 ${uiLabel(operation.status)}。重试前请刷新状态。`)
  return operation
}
async function refreshOperation(provider: ProviderSummary) {
  const operation = operations.value[provider.id]
  if (!operation) return
  pending.value = provider.id
  error.value = undefined
  try { await readOperation(provider.id, operation.id) } catch (cause) { error.value = message(cause, '操作回读失败') }
  finally { await load(false); pending.value = undefined }
}
function resetForm() {
  Object.assign(form, { name: '', mode: 'url', source: '', content: '', format: 'auto' })
  savedProvider.value = undefined
  addOpen.value = false
}
function validateContent(content: string) {
  if (!content.trim()) throw new Error('暂存前请先输入订阅内容。')
  if (new TextEncoder().encode(content).length > maxContentBytes) throw new Error('导入内容不能超过 1 MiB。')
}
async function readFile(event: Event, target: 'new' | 'revision') {
  error.value = undefined
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    if (file.size > maxContentBytes) throw new Error('导入文件不能超过 1 MiB。')
    const content = await file.text()
    validateContent(content)
    if (target === 'new') form.content = content
    else importContent.value = content
  } catch (cause) { error.value = message(cause, '无法读取导入文件') }
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
    notice.value = `订阅 ${provider.name} 已保存。暂存前需要控制器回读。`
    const accepted = form.mode === 'url'
      ? await props.state.api.refreshProvider(provider.id, randomIdempotencyKey())
      : await props.state.api.stageProvider(provider.id, { content: form.content, format: form.format }, randomIdempotencyKey())
    const operation = await readOperation(provider.id, accepted.operationId)
    notice.value = `操作 ${operation.id}: ${uiLabel(operation.status)}。发布前请审查版本。`
    resetForm()
  } catch (cause) { error.value = message(cause, '无法添加并暂存订阅') }
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
  } catch (cause) { error.value = message(cause, '订阅刷新失败') }
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
  } catch (cause) { error.value = message(cause, '无法暂存订阅版本') }
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
  } catch (cause) { error.value = message(cause, '订阅发布失败') }
  finally {
    const readBack = await load(false)
    if (readBack && operation?.status === 'applied' && providers.value.find((item) => item.id === provider.id)?.activeRevision !== revision) {
      error.value = '发布请求已受理，但生效版本回读不匹配。重试前请刷新状态。'
    }
    pending.value = undefined
  }
}
onActivated(() => load())
</script>

<template>
  <div class="page-grid">
    <section class="page-heading">
      <div><p class="eyebrow">订阅管理</p><h1>订阅</h1><p class="lede">导入、检查并审查节点更新，再将确认的版本应用到网关。</p></div>
      <div class="actions"><button class="button button--secondary" :disabled="busy" @click="load()">刷新列表</button><button class="button" :disabled="busy || !canStage" @click="addOpen = !addOpen">添加订阅</button></div>
    </section>
    <p v-if="!canManage" class="notice">管理订阅设置、删除订阅和暂存版本需要管理员权限。</p>
    <p v-else-if="!canStage" class="notice">订阅暂存不可用。控制器需启用 provider.stage 才能导入或刷新订阅。</p>
    <section v-if="error" class="alert alert--bad" role="alert"><DiagnosticMessage :message="error" /></section>
    <section v-if="notice" class="alert alert--info" role="status">{{ notice }}</section>

    <form v-if="addOpen" class="panel form-grid" aria-label="添加订阅" @submit.prevent="addProvider">
      <h2>添加订阅</h2>
      <p v-if="savedProvider" class="notice">{{ savedProvider.name }} 已保存。重试暂存以使用此订阅。</p>
      <label>订阅名称<input v-model="form.name" required maxlength="200" autocomplete="off" :disabled="busy || !!savedProvider" /></label>
      <label>来源类型<select v-model="form.mode" :disabled="busy || !!savedProvider"><option value="url">订阅 URL</option><option value="paste">粘贴或上传内容</option></select></label>
      <label v-if="form.mode === 'url'">订阅 URL<input v-model="form.source" type="url" required placeholder="https://…" autocomplete="off" :disabled="busy || !!savedProvider" /></label>
      <template v-else>
        <label>导入文件<input type="file" :disabled="busy" @change="readFile($event, 'new')" /></label>
        <label>订阅内容<textarea v-model="form.content" required rows="7" spellcheck="false" autocomplete="off" :disabled="busy" /></label>
        <p class="muted">最大 1 MiB。导入 Clash 文件时仅提取节点清单。</p>
      </template>
      <label>导入格式<select v-model="form.format" :disabled="busy || (!!savedProvider && form.mode === 'url')"><option v-for="format in formats" :key="format.value" :value="format.value">{{ format.label }}</option></select></label>
      <div class="actions"><button class="button" type="submit" :disabled="busy || !canStage">{{ pending === 'new' ? '正在暂存…' : savedProvider ? '重试暂存订阅' : '添加并暂存订阅' }}</button><button class="button button--secondary" type="button" :disabled="busy" @click="resetForm">关闭</button></div>
    </form>

    <form v-if="settingsTarget" class="panel form-grid provider-settings" aria-label="订阅设置" @submit.prevent="saveSettings">
      <h2>订阅设置</h2>
      <p class="muted">正在编辑清单版本 {{ settingsTarget.revision }}。保存设置不会获取、暂存或应用订阅版本。</p>
      <fieldset class="form-grid" :disabled="busy || !canManage || !!settingsAccepted">
        <label>订阅名称<input v-model="settingsDraft.name" required maxlength="200" autocomplete="off" /></label>
        <label>替换订阅 URL（可选）<input v-model="settingsDraft.source" type="password" placeholder="留空以保留当前来源" autocomplete="new-password" spellcheck="false" /></label>
        <p class="muted">已保存的来源属于私密信息，不会载入此表单。留空可保留现有来源。</p>
        <label>来源格式<select v-model="settingsDraft.format"><option v-for="format in formats" :key="format.value" :value="format.value">{{ format.label }}</option><option value="local">本地导入</option></select></label>
        <label>获取路由<input v-model="settingsDraft.fetchRoute" required autocomplete="off" placeholder="direct（直连）" /></label>
        <p class="muted">使用直连或控制器已验证的路由。导入内容时请选择“本地导入”，并单独导入新版本。</p>
      </fieldset>
      <div class="actions"><button class="button" type="submit" :disabled="busy || !canManage">{{ pending?.startsWith('settings:') ? '正在保存…' : settingsAccepted ? '验证已保存设置' : '保存订阅设置' }}</button><button class="button button--secondary" type="button" :disabled="busy" @click="closeSettings">关闭</button></div>
    </form>

    <form v-if="deleteTarget" class="panel form-grid" aria-label="删除订阅" @submit.prevent="deleteProvider">
      <h2>删除 {{ deleteTarget.name }}？</h2>
      <p class="muted">此操作会删除订阅及其已保存的来源和版本。存在生效发布、代理组引用、节点选择或待处理操作时，不能删除订阅。</p>
      <label class="checkbox-label"><input v-model="deleteAcknowledged" type="checkbox" required :disabled="busy || deleteTarget.accepted" />我确认删除 {{ deleteTarget.name }}（{{ deleteTarget.id }}），清单版本 {{ deleteTarget.revision }}。</label>
      <div class="actions"><button class="button button--danger" type="submit" :disabled="busy || !canManage || !deleteAcknowledged">{{ pending?.startsWith('delete:') ? '正在删除…' : deleteTarget.accepted ? '验证删除' : '永久删除订阅' }}</button><button class="button button--secondary" type="button" :disabled="busy" @click="deleteTarget = undefined">关闭</button></div>
    </form>

    <section class="provider-list" :aria-busy="loading">
      <article v-for="provider in providers" :key="provider.id" class="panel provider-card" :aria-label="`订阅 ${provider.name}`">
        <div class="provider-card__heading"><div><h2>{{ provider.name }}</h2><p>{{ sourceLabel(provider) }} · {{ provider.format === 'local' ? '自动检测或所选格式' : uiLabel(provider.format) }} · {{ provider.nodeCount ?? '未知' }} 个节点</p></div><StatusPill :label="pending === provider.id ? '处理中' : uiLabel(provider.state)" :tone="provider.state === 'active' ? 'good' : provider.state === 'error' ? 'bad' : 'warn'" /></div>
        <div class="provider-meta"><span>不支持： <strong>{{ provider.unsupportedCount ?? '未知' }}</strong></span><span>最近获取： <strong>{{ provider.lastAttemptAt ?? '未报告' }}</strong></span><span>最近成功获取： <strong>{{ provider.lastSuccessAt ?? '未报告' }}</strong></span></div>
        <div v-if="provider.gatewayStates.length" class="gateway-states"><span v-for="gateway in provider.gatewayStates" :key="gateway.gatewayId" class="gateway-state"><strong>{{ gateway.gatewayId }}</strong> {{ uiLabel(gateway.state) }}<small v-if="gateway.observedRevision"> · {{ gateway.observedRevision }}</small></span></div>
        <StateStrip :states="{ desired: provider.stagedRevision, applied: provider.activeRevision }" :pending="pending === provider.id" />
        <p v-if="revisionErrors[provider.id]" class="notice" role="alert">版本回读失败：<DiagnosticMessage :message="revisionErrors[provider.id]" />。发布已禁用。</p>
        <div v-if="operations[provider.id]" class="operation" role="status"><span>操作 <code>{{ operations[provider.id]?.id }}</code>: {{ uiLabel(operations[provider.id]?.status) }}</span><button class="button button--secondary" :disabled="busy" @click="refreshOperation(provider)">刷新操作</button></div>
        <details v-if="latestRevision(provider)" class="revision-report" open>
          <summary>审查版本 {{ latestRevision(provider)?.number }}</summary>
          <template v-for="revision in [latestRevision(provider)!]" :key="revision.number">
            <p class="muted">{{ revision.nodes?.length ?? 0 }} 个已接受 · {{ revision.parse_report?.unsupported?.length ?? 0 }} 个不支持 · {{ revision.created_at }}</p>
            <p v-if="revision.changes?.noop" class="muted">内容没有变化。</p>
            <p v-else class="muted">{{ revision.changes?.added?.length ?? 0 }} 个新增 · {{ revision.changes?.removed?.length ?? 0 }} 个移除 · {{ revision.changes?.changed?.length ?? 0 }} 个变更 · {{ revision.changes?.renamed?.length ?? 0 }} 个重命名</p>
            <ul v-if="revision.parse_report?.warnings?.length" class="report-list"><li v-for="warning in revision.parse_report.warnings" :key="warning"><DiagnosticMessage :message="warning" /></li></ul>
            <ul v-if="revision.parse_report?.errors?.length" class="report-list report-list--bad"><li v-for="problem in revision.parse_report.errors" :key="problem"><DiagnosticMessage :message="problem" /></li></ul>
            <ul v-if="revision.parse_report?.unsupported?.length" class="report-list"><li v-for="(unsupported, index) in revision.parse_report.unsupported" :key="index">{{ unsupported.name || `条目 ${index + 1}` }}: <DiagnosticMessage :message="unsupported.reason || '不支持的节点'" /></li></ul>
            <details><summary>已接受的节点</summary><ul class="node-list"><li v-for="node in revision.nodes" :key="node.id">{{ node.name || node.id }} <span class="muted">{{ node.definition?.protocol ?? '未知协议' }}</span></li></ul></details>
          </template>
        </details>
        <details v-if="(revisions[provider.id]?.length ?? 0) > 1"><summary>版本历史</summary><ul class="node-list"><li v-for="revision in revisions[provider.id]" :key="revision.number">版本 {{ revision.number }} · {{ uiLabel(revision.state) }} · {{ revision.created_at }}</li></ul></details>
        <p v-if="provider.stagedRevision && !canPublish" class="notice">热发布不可用。网关适配器报告 provider.publish_hot 能力前，此版本将保持暂存。</p>
        <p v-if="scheduleErrors[provider.id]" class="notice" role="alert">刷新计划：<DiagnosticMessage :message="scheduleErrors[provider.id]" /></p>
        <form v-if="isRemote(provider) && scheduleDrafts[provider.id]" class="form-grid refresh-schedule" :aria-label="`订阅刷新计划：${provider.name}`" @submit.prevent="saveSchedule(provider)">
          <h3>定时刷新</h3>
          <p class="muted">定时计划默认禁用。每次刷新只会暂存待审查版本，发布需单独执行。</p>
          <label class="checkbox-label"><input v-model="scheduleDrafts[provider.id]!.enabled" type="checkbox" :disabled="busy || !canStage" />启用定时刷新</label>
          <label>刷新间隔（分钟）<input v-model.number="scheduleDrafts[provider.id]!.intervalMinutes" type="number" required min="5" max="10080" step="1" :disabled="busy || !canStage" /></label>
          <p class="muted">允许范围：5 分钟至 7 天（10080 分钟）。</p>
          <dl class="schedule-status">
            <div><dt>定时计划</dt><dd>{{ schedules[provider.id]?.running ? '正在刷新' : schedules[provider.id]?.enabled ? '已启用' : '已禁用' }}</dd></div>
            <div><dt>下次执行时间</dt><dd>{{ schedules[provider.id]?.next_due_at ?? '未安排' }}</dd></div>
            <div><dt>最近尝试</dt><dd>{{ schedules[provider.id]?.last_attempt_at ?? '尚无记录' }}</dd></div>
            <div><dt>最近成功刷新</dt><dd>{{ schedules[provider.id]?.last_success_at ?? '尚无记录' }}</dd></div>
            <div v-if="schedules[provider.id]?.last_operation_id"><dt>最近操作</dt><dd><code>{{ schedules[provider.id]?.last_operation_id }}</code></dd></div>
          </dl>
          <p v-if="schedules[provider.id]?.last_error" class="notice" role="alert">最近一次定时刷新失败：<DiagnosticMessage :message="schedules[provider.id]?.last_error" /></p>
          <div class="actions"><button class="button button--secondary" type="submit" :disabled="busy || !canStage">{{ pending === `schedule:${provider.id}` ? '正在保存计划…' : '保存刷新计划' }}</button></div>
        </form>
        <div class="actions">
          <button v-if="isRemote(provider)" class="button button--secondary" :disabled="busy || !canStage" @click="refresh(provider)">刷新订阅</button>
          <button class="button button--secondary" :disabled="busy || !canStage" @click="openImport(provider)">导入新版本</button>
          <button class="button" :disabled="busy || !canPublish || !provider.stagedRevision || !!revisionErrors[provider.id]" @click="apply(provider)">应用暂存版本</button>
          <button v-if="canManage" class="button button--secondary" :disabled="busy || inventoryReadbackFailed || !provider.revision" :aria-label="`编辑订阅设置：${provider.name}`" @click="editProvider(provider)">设置</button>
          <button v-if="canManage" class="button button--secondary" :disabled="busy || inventoryReadbackFailed || !provider.revision" :aria-label="`删除订阅 ${provider.name}`" @click="confirmDelete(provider)">删除</button>
        </div>
        <form v-if="importProviderId === provider.id" class="form-grid revision-import" aria-label="导入新版本" @submit.prevent="stage(provider)">
          <label>版本文件<input type="file" :disabled="busy" @change="readFile($event, 'revision')" /></label>
          <label>版本内容<textarea v-model="importContent" required rows="6" spellcheck="false" autocomplete="off" :disabled="busy" /></label>
          <label>版本格式<select v-model="importFormat" :disabled="busy"><option v-for="format in formats" :key="format.value" :value="format.value">{{ format.label }}</option></select></label>
          <div class="actions"><button class="button" :disabled="busy || !canStage">暂存版本</button><button class="button button--secondary" type="button" :disabled="busy" @click="importProviderId = undefined; importContent = ''">取消</button></div>
        </form>
      </article>
      <div v-if="!providers.length && !loading" class="panel empty-state">尚未配置订阅。</div>
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
