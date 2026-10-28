<script setup lang="ts">
import { uiLabel } from '../localization'
import DiagnosticMessage from '../components/DiagnosticMessage.vue'
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

const observationLabels = { never_read: '尚未读取', fresh: '最新', stale: '已过期', error: '错误' }

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
      throw new Error('请选择已登记的网关，并填写主机别名、接口范围及至少一个流量引导规则 ID。')
    }
    const attached = await props.state.api.attachBinding(request)
    accepted = true
    attachOpen.value = false
    const confirmed = await props.state.api.binding(attached.id)
    if (confirmed.id !== attached.id || confirmed.gatewayId !== request.gateway_id || confirmed.alias !== request.alias || confirmed.addressFamily !== request.family || confirmed.interfaceScope !== request.interface_scope || (request.alias_uuid && confirmed.aliasUUID !== request.alias_uuid) || confirmed.ruleIds.length !== request.rule_ids.length || request.rule_ids.some(id => !confirmed.ruleIds.includes(id))) {
      throw new Error('已登记绑定与请求的关联不匹配。')
    }
    replaceBinding(confirmed, requestNumber)
    await props.state.load()
    notice.value = `主机别名绑定 ${confirmed.alias} 已登记。请使用“读取防火墙”检查当前状态。`
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : '无法添加主机别名绑定'
    attachError.value = accepted ? `控制器已受理绑定，但无法确认登记：${message} 再次绑定前请刷新状态。` : message
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
      throw new Error(observed.observationError ?? '防火墙未返回成功的观测结果。')
    }
    replaceBinding(observed, request)
    clock.value = Date.now()
  } catch (cause) {
    const message = cause instanceof Error ? cause.message : '无法读取防火墙'
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
    else error.value = gatewayResult.reason instanceof Error ? gatewayResult.reason.message : '无法读取网关清单'
    if (bindingResult.status === 'fulfilled') {
      const returnedIds = new Set(bindingResult.value.map(binding => binding.id))
      bindings.value = bindings.value.filter(binding => returnedIds.has(binding.id) || (bindingOrder.get(binding.id)?.change ?? 0) > startedChange)
      for (const binding of bindingResult.value) replaceBinding(binding, request)
      clock.value = Date.now()
    }
    else bindingError.value = bindingResult.reason instanceof Error ? bindingResult.reason.message : '无法读取防火墙绑定'
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
    if (!['https:', 'http:'].includes(endpoint.protocol) || endpoint.username || endpoint.password) throw new Error('请使用不包含内嵌凭据的 HTTP 或 HTTPS 网关地址')
    const gateway = await props.state.api.createGateway({ name: form.name.trim(), endpoint: endpoint.toString(), adapter: form.adapter.trim() })
    editorOpen.value = false
    const gatewayReadbackAvailable = await load()
    await props.state.load()
    if (!gatewayReadbackAvailable || !gateways.value.some((item) => item.id === gateway.id && item.revision === gateway.revision)) {
      error.value = '控制器已受理登记，但无法回读网关。再次登记前请刷新。'
      return
    }
    notice.value = `网关 ${gateway.name} 已登记。网关报告后才会显示健康状态和能力。`
  } catch (cause) { error.value = cause instanceof Error ? cause.message : '无法登记网关' } finally { saving.value = false }
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
  <div class="page-grid"><section class="page-heading"><div><p class="eyebrow">网关与防火墙</p><h1>基础设施</h1><p class="lede">管理网关与 OPNsense 绑定，检查组件报告的能力、健康状态与配置回读。</p></div><button class="button button--secondary" :disabled="loading || saving || attaching || readingBindings.size > 0" @click="load">{{ loading ? '正在刷新…' : '刷新' }}</button></section>
    <section v-if="error" class="alert alert--bad" role="alert"><DiagnosticMessage :message="error" /></section>
    <section v-if="notice" class="alert alert--good" role="status">{{ notice }}</section>
    <section class="panel"><div class="panel__heading"><h2>网关清单</h2><div class="actions"><span class="muted">{{ gateways.length }} 个已登记</span><button v-if="isAdministrator" class="button" :disabled="loading || saving" @click="registerGateway">登记网关</button></div></div>
      <form v-if="editorOpen && isAdministrator" class="editor" @submit.prevent="saveGateway"><h3>登记网关</h3><p class="muted">登记只会保存网关地址；观测完成前，连接健康状态仍为未知。</p><fieldset :disabled="saving"><div class="form-grid"><label>网关名称<input v-model="form.name" required maxlength="200" autocomplete="off" /></label><label>适配器<input aria-label="适配器" v-model="form.adapter" required autocomplete="off" /><span class="muted">使用已配置的适配器，例如 dae。</span></label><label class="full-width">网关地址<input aria-label="网关地址" v-model="form.endpoint" type="url" required placeholder="https://gateway.example:8443" autocomplete="off" spellcheck="false" /><span class="muted">使用网关代理服务的 URL。凭据应保存在控制器配置中。</span></label></div><div class="actions"><button class="button" type="submit">{{ saving ? '正在登记…' : '保存网关' }}</button><button class="button button--secondary" type="button" @click="editorOpen = false">取消</button></div></fieldset></form>
      <div v-if="!gateways.length && !loading" class="empty-state">尚未登记网关。</div><article v-for="gateway in gateways" :key="gateway.id" class="gateway-card"><div class="gateway-card__heading"><div><h3>{{ gateway.name }}</h3><p>{{ gateway.endpoint }}</p><p>{{ gateway.adapter ?? 'dae' }} · {{ gateway.version ?? '版本未知' }} · 版本 {{ gateway.revision ?? '未知' }}</p></div><StatusPill :label="uiLabel(gateway.health)" :tone="gateway.health === 'healthy' ? 'good' : gateway.health === 'offline' ? 'bad' : 'warn'" /></div><div v-if="gateway.capabilities.supported.length" class="capability-list"><span v-for="capability in gateway.capabilities.supported" :key="capability" class="capability">{{ uiLabel(capability) }}</span></div><p v-else class="muted">尚未报告运行时能力。</p><ul v-if="gateway.capabilities.restrictions && Object.keys(gateway.capabilities.restrictions).length" class="restriction"><li v-for="(reason, capability) in gateway.capabilities.restrictions" :key="capability">{{ uiLabel(capability) }}: <DiagnosticMessage :message="reason" /></li></ul></article><p v-if="gateways.length" class="muted">此控制器不支持编辑网关。</p></section>
    <section class="panel" aria-label="防火墙绑定">
      <div class="panel__heading"><h2>防火墙绑定</h2><div class="actions"><span class="muted">{{ bindings.length }} 个绑定</span><button v-if="isAdministrator" class="button" :disabled="loading || attaching" @click="openAttach">添加主机别名绑定</button></div></div>
      <p class="muted">登记现有主机别名及其流量引导规则。观测结果表示已保存和生效的别名内容；流量路径验证需单独进行。</p>
      <p v-if="bindingError" class="alert alert--bad" role="status">防火墙绑定不可用：<DiagnosticMessage :message="bindingError" /></p>
      <p v-if="attachError" class="alert alert--bad" role="alert"><DiagnosticMessage :message="attachError" /></p>
      <form v-if="attachOpen && isAdministrator" class="editor" aria-label="添加主机别名绑定" @submit.prevent="attachBinding">
        <h3>绑定现有主机别名</h3>
        <p class="muted">使用现有持久化主机别名及其流量引导规则 ID。</p>
        <fieldset :disabled="attaching">
          <div class="form-grid">
            <label>网关<select v-model="attachForm.gatewayId" name="gateway_id" required><option disabled value="">选择网关</option><option v-for="gateway in gateways" :key="gateway.id" :value="gateway.id">{{ gateway.name }}</option></select></label>
            <label>主机别名<input v-model="attachForm.alias" name="alias" required autocomplete="off" /></label>
            <label>别名 UUID（可选）<input v-model="attachForm.aliasUUID" name="alias_uuid" autocomplete="off" /></label>
            <label>地址族<select v-model="attachForm.family" name="family"><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></label>
            <label>接口范围<input v-model="attachForm.interfaceScope" name="interface_scope" required placeholder="例如：lan" autocomplete="off" /></label>
            <label>流量引导规则 ID<textarea v-model="attachForm.ruleIds" name="rule_ids" rows="3" required placeholder="使用逗号或换行分隔 ID" /></label>
          </div>
          <div class="actions"><button class="button" type="submit">{{ attaching ? '正在绑定…' : '保存主机别名绑定' }}</button><button class="button button--secondary" type="button" @click="attachOpen = false">取消</button></div>
        </fieldset>
      </form>
      <div v-if="!bindingError && !bindings.length && !loading" class="empty-state">尚未配置防火墙绑定。</div>
      <article v-for="binding in bindings" :key="binding.id" class="binding-card" :aria-label="`防火墙绑定 ${binding.alias}`">
        <div class="binding-row"><span><strong>{{ binding.alias }}</strong><small>{{ binding.interfaceScope }} · {{ uiLabel(binding.addressFamily) }}</small><small>网关：{{ gateways.find(gateway => gateway.id === binding.gatewayId)?.name ?? binding.gatewayId }}</small></span><div class="actions"><StatusPill :label="binding.state === 'observed' ? '已观测' : '期望状态'" tone="neutral" /><button class="button button--secondary" :disabled="readingBindings.has(binding.id) || loading" @click="readFirewall(binding)">{{ readingBindings.has(binding.id) ? '正在读取防火墙…' : '读取防火墙' }}</button></div></div>
        <dl class="binding-metrics"><div><dt>期望地址数</dt><dd>{{ binding.desiredCount }}</dd></div><div><dt>已持久化地址数</dt><dd>{{ binding.persistedCount ?? '未知' }}</dd></div><div><dt>生效地址数</dt><dd>{{ binding.activeCount ?? '未知' }}</dd></div><div><dt>配置差异</dt><dd>{{ binding.drift === undefined ? '未知' : binding.drift ? '已检测到' : '尚未观测到' }}</dd></div></dl>
        <div class="actions observation"><span>观测状态</span><StatusPill :label="observationLabels[observationStatus(binding)]" :tone="observationStatus(binding) === 'error' ? 'bad' : observationStatus(binding) === 'stale' ? 'warn' : 'neutral'" /></div>
        <dl class="binding-details"><div><dt>最近观测</dt><dd><time v-if="binding.observedAt" :datetime="binding.observedAt">{{ binding.observedAt }}</time><span v-else>尚无记录</span></dd></div><div><dt>最近尝试</dt><dd><time v-if="binding.lastAttemptAt" :datetime="binding.lastAttemptAt">{{ binding.lastAttemptAt }}</time><span v-else>尚无记录</span></dd></div><div><dt>流量引导规则</dt><dd>{{ binding.ruleIds.join(', ') || '未知' }}</dd></div><div v-if="binding.aliasUUID"><dt>别名 UUID</dt><dd>{{ binding.aliasUUID }}</dd></div></dl>
        <p v-if="binding.observationError" class="alert alert--bad" role="alert">防火墙读取失败：<DiagnosticMessage :message="binding.observationError" /><span v-if="binding.observedAt"> 显示上次成功的观测结果。</span></p>
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
