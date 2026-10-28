<script setup lang="ts">
import { uiLabel } from '../localization'
import DiagnosticMessage from './DiagnosticMessage.vue'
import { computed, onActivated, onDeactivated, onUnmounted, ref, watch } from 'vue'
import { ControllerApiError, randomIdempotencyKey } from '../api/client'
import type { useControllerState } from '../state'
import type { InventoryPlan, OperationSummary } from '../types'
import StatusPill from './StatusPill.vue'

const props = defineProps<{ state: ReturnType<typeof useControllerState> }>()
const gatewayId = ref(props.state.selectedGateway.value?.id ?? '')
const previousOperationId = ref('')
const plan = ref<InventoryPlan>()
const pending = ref<{ checksum: string; gatewayId: string }>()
const creating = ref(false)
const reading = ref(false)
const error = ref('')
interface ApplyRequest { checksum: string; gatewayId: string; key: string; operationId?: string; generation: number; runtimeGeneration: number }
const applyRequest = ref<ApplyRequest>()
const operation = ref<OperationSummary>()
const applying = ref(false)
const operationError = ref('')
let operationAbort: AbortController | undefined
const canCreate = computed(() => props.state.isAdministrator.value && props.state.capabilities.value['policy.validate'] === true && props.state.gateways.value.some(gateway => gateway.id === gatewayId.value))
const busy = computed(() => creating.value || reading.value || applying.value)
const unresolvedApply = computed(() => !!applyRequest.value && !['applied', 'failed'].includes(operation.value?.status ?? ''))
const configurationBlockers = computed(() => plan.value?.configuration_deployable !== undefined ? plan.value.configuration_blockers ?? [] : plan.value?.blockers ?? [])
const canApply = computed(() => props.state.isAdministrator.value && plan.value?.valid === true && plan.value.configuration_deployable === true && configurationBlockers.value.length === 0 && plan.value.complete_artifact?.gateway_id === plan.value.target.gateway_id && Number.isSafeInteger(plan.value.target.next_policy_generation) && (plan.value.target.next_policy_generation ?? 0) > 0 && Number.isSafeInteger(plan.value.complete_artifact?.expected_generation) && (plan.value.complete_artifact?.expected_generation ?? -1) >= 0)
const configurationObserved = computed(() => operation.value?.status === 'applied' && operation.value.views?.applied?.revision === applyRequest.value?.checksum && operation.value.views?.observed?.revision === applyRequest.value?.checksum && operation.value.views?.applied?.generation === applyRequest.value?.runtimeGeneration && operation.value.views?.observed?.generation === applyRequest.value?.runtimeGeneration && operation.value.views?.observed?.status === 'configuration_observed')
let sequence = 0
let active = true

function invalidate() {
  sequence++
  creating.value = false
  reading.value = false
  error.value = ''
  pending.value = undefined
  plan.value = undefined
  operationAbort?.abort()
  applyRequest.value = undefined
  operation.value = undefined
  operationError.value = ''
  applying.value = false
}
watch([gatewayId, previousOperationId], invalidate, { flush: 'sync' })
watch(() => props.state.selectedGateway.value?.id, id => { gatewayId.value = id ?? '' })
watch(() => props.state.session.value?.subject, invalidate, { flush: 'sync' })

function message(cause: unknown): string {
  if (cause instanceof ControllerApiError && (cause.status === 409 || cause.status === 412)) return `${cause.message}。请检查清单并创建新计划。`
  return cause instanceof Error ? cause.message : '无法读取清单计划。'
}

async function readStored(currentSequence: number, target: { checksum: string; gatewayId: string }) {
  reading.value = true
  const stored = await props.state.api.inventoryPlan(target.checksum)
  if (currentSequence !== sequence || !active) return
  if (stored.checksum !== target.checksum || stored.target.gateway_id !== target.gatewayId || stored.input.gateway.id !== target.gatewayId || stored.scope !== 'gateway') {
    throw new Error('持久化计划与请求的校验和及网关不匹配，回读仍未确认。')
  }
  plan.value = stored
  props.state.lastInventoryPlanChecksum.value = stored.checksum
  pending.value = undefined
}

async function createPlan() {
  if (busy.value || unresolvedApply.value || !canCreate.value || !active) return
  const currentSequence = ++sequence
  const targetGateway = gatewayId.value
  creating.value = true
  error.value = ''
  pending.value = undefined
  plan.value = undefined
  operationAbort?.abort()
  applyRequest.value = undefined
  operation.value = undefined
  operationError.value = ''
  try {
    const created = await props.state.api.createInventoryPlan({ gateway_id: targetGateway, ...(previousOperationId.value.trim() ? { previous_operation_id: previousOperationId.value.trim() } : {}) })
    if (currentSequence !== sequence || !active) return
    if (!/^[a-f0-9]{64}$/.test(created.checksum)) throw new Error('控制器返回了无效的计划校验和，持久化回读仍未确认。')
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

async function readOperation(currentSequence: number, request: ApplyRequest) {
  if (!request.operationId) return
  const observed = await props.state.api.waitForOperation(request.operationId, operationAbort?.signal)
  if (currentSequence !== sequence || !active) return
  if (observed.id !== request.operationId || observed.target !== `gateway:${request.gatewayId}` || observed.action !== 'policy.apply_generation' || observed.views?.desired?.revision !== request.checksum || observed.views.desired.generation !== request.generation) {
    throw new Error('操作回读与此计划及网关不匹配，配置仍未确认。')
  }
  operation.value = observed
  props.state.recordOperation(observed)
  if (observed.status === 'failed' || observed.status === 'partially_applied') operationError.value = observed.error || '配置应用失败。创建新计划前请先检查“活动与诊断”。'
  else if (observed.status === 'outcome_unknown') operationError.value = '操作结果尚未确定。恢复后请继续读取同一操作，不要提交替代请求。'
  else if (observed.status === 'applied' && !configurationObserved.value) operationError.value = '操作已完成，但缺少匹配的已应用和已观测配置证据。回读仍未确认。'
}

async function applyPlan() {
  if (busy.value || !canApply.value || !active || !plan.value || applyRequest.value?.operationId) return
  const request = applyRequest.value ?? { checksum: plan.value.checksum, gatewayId: plan.value.target.gateway_id, generation: plan.value.target.next_policy_generation!, runtimeGeneration: plan.value.complete_artifact!.expected_generation + 1, key: randomIdempotencyKey() }
  applyRequest.value = request
  const currentSequence = ++sequence
  applying.value = true
  operationError.value = ''
  operationAbort = new AbortController()
  try {
    const accepted = await props.state.api.applyInventoryPlan(request.checksum, request.key)
    if (applyRequest.value?.key === request.key) applyRequest.value.operationId = accepted.operationId
    if (currentSequence !== sequence || !active) return
    await readOperation(currentSequence, request)
  } catch (cause) {
    if (cause instanceof ControllerApiError && cause.operationId && applyRequest.value?.key === request.key) applyRequest.value.operationId = cause.operationId
    if (currentSequence === sequence && active) {
      if (cause instanceof ControllerApiError && !cause.operationId && !request.operationId && ((cause.status === 412 && cause.code === 'revision_conflict') || (cause.status === 422 && cause.code === 'validation_error'))) {
        applyRequest.value = undefined
        error.value = `${cause.message}。请求在应用前被拒绝。请创建新的清单计划。`
        return
      }
      operationError.value = cause instanceof Error ? cause.message : '配置应用回读不可用。'
    }
  } finally { if (currentSequence === sequence) applying.value = false }
}

async function refreshOperation() {
  if (busy.value || !active || !applyRequest.value?.operationId) return
  const currentSequence = ++sequence
  applying.value = true
  operation.value = undefined
  operationError.value = ''
  operationAbort = new AbortController()
  try { await readOperation(currentSequence, applyRequest.value) }
  catch (cause) { if (currentSequence === sequence && active) operationError.value = cause instanceof Error ? cause.message : '操作回读不可用。' }
  finally { if (currentSequence === sequence) applying.value = false }
}

function deactivate() { active = false; sequence++; creating.value = false; reading.value = false; applying.value = false; operationAbort?.abort() }
onActivated(() => { active = true })
onDeactivated(deactivate)
onUnmounted(deactivate)
</script>

<template>
  <section class="inventory-plan panel" aria-labelledby="inventory-plan-title">
    <div class="panel-heading"><div><h2 id="inventory-plan-title">持久化清单计划</h2><p class="muted">为一个网关编译已保存的设备、设备组、策略、规则集和代理组。创建计划前请先保存编辑内容。</p></div></div>
    <form aria-label="创建清单计划" @submit.prevent="createPlan">
      <fieldset class="form-grid" :disabled="busy || unresolvedApply">
        <label>计划网关<select v-model="gatewayId" required><option value="" disabled>选择已登记的网关</option><option v-for="gateway in state.gateways.value" :key="gateway.id" :value="gateway.id">{{ gateway.name }} ({{ gateway.id }})</option></select></label>
        <label>上次已应用操作 ID（可选）<input v-model="previousOperationId" placeholder="使用最近一次已应用操作" autocomplete="off" /><small>只有此网关已记录的已应用清单才可用作比较基线。</small></label>
      </fieldset>
      <div class="actions"><button class="button" type="submit" :disabled="busy || unresolvedApply || !canCreate">{{ creating ? '正在生成清单快照…' : reading ? '正在读取持久化计划…' : '创建清单计划' }}</button><small v-if="unresolvedApply" class="muted">准备下一次应用前，请先确认当前配置操作的结果。</small><small v-else-if="!state.isAdministrator.value" class="muted">创建持久化计划需要管理员权限。</small><small v-else-if="state.capabilities.value['policy.validate'] !== true" class="muted">控制器尚未报告策略校验能力。</small><small v-else-if="!state.gateways.value.length" class="muted">创建计划前请先登记网关。</small></div>
    </form>
    <p v-if="error" class="alert alert--bad" role="alert"><DiagnosticMessage :message="error" /></p>
    <div v-if="pending" class="result" role="status"><p>计划已创建，但尚未确认持久化回读。</p><p class="hash">请求校验和：{{ pending.checksum }}</p><button class="button button--secondary" type="button" :disabled="busy" @click="retryReadback">{{ reading ? '正在读取持久化计划…' : '重试持久化计划回读' }}</button></div>
    <div v-if="plan" class="result" aria-label="持久化清单计划结果">
      <p class="confirmed" role="status">已确认持久化计划的回读。</p>
      <div class="statuses"><StatusPill :label="plan.valid ? '编译通过' : '编译未通过'" :tone="plan.valid ? 'good' : 'bad'" /><StatusPill :label="plan.configuration_deployable === true ? '配置可应用' : '配置部署被阻止'" :tone="plan.configuration_deployable === true ? 'neutral' : 'warn'" /><StatusPill :label="plan.enrollment_ready === true ? '纳管前置条件已就绪' : '纳管被阻止'" :tone="plan.enrollment_ready === true ? 'neutral' : 'warn'" /></div>
      <dl class="facts"><div><dt>持久化校验和</dt><dd class="hash">{{ plan.checksum }}</dd></div><div><dt>范围</dt><dd>{{ uiLabel(plan.scope) }} · {{ plan.target.gateway_id }}</dd></div><div><dt>生成时间</dt><dd>{{ plan.created_at }}</dd></div><div><dt>清单一致性</dt><dd>{{ uiLabel(plan.consistency) }}</dd></div><div><dt>网关能力观测</dt><dd>{{ uiLabel(plan.target.observation_status) }}</dd></div><div><dt>上次已应用清单</dt><dd>{{ uiLabel(plan.previous.status) }}<span v-if="plan.previous.operation_id"> · {{ plan.previous.operation_id }}</span><span v-if="plan.previous.manifest_hash" class="hash"> · {{ plan.previous.manifest_hash }}</span></dd></div></dl>
      <p class="muted">此不可变快照记录生成时已保存的配置意图。清单变化后需创建新计划。网关能力观测不代表配置已应用或真实流量已验证。</p>
      <section v-if="plan.diagnostics?.length" aria-label="计划校验诊断"><h3>校验诊断</h3><ul><li v-for="(diagnostic, index) in plan.diagnostics" :key="index"><strong>{{ diagnostic.code }}</strong> · {{ uiLabel(diagnostic.severity) }}<span v-if="diagnostic.path"> · {{ diagnostic.path }}</span>: <DiagnosticMessage :message="diagnostic.message" :code="diagnostic.code" /></li></ul></section>
      <section aria-label="部署阻塞项"><h3>配置部署</h3><ul v-if="configurationBlockers.length"><li v-for="(blocker, index) in configurationBlockers" :key="index"><strong>{{ blocker.code }}</strong><span v-if="blocker.path"> · {{ blocker.path }}</span>: <DiagnosticMessage :message="blocker.message" :code="blocker.code" /></li></ul><p v-else-if="!canApply" class="muted">控制器尚未确认此计划具有完整可部署配置，或当前用户没有管理员权限。</p><p v-else class="muted">将此持久化配置原样应用到 {{ plan.target.gateway_id }}。</p>
        <div v-if="plan.complete_artifact" aria-label="完整网关配置预览"><h3>完整网关配置</h3><dl class="facts"><div><dt>网关</dt><dd>{{ plan.complete_artifact.gateway_id }}</dd></div><div><dt>基础配置版本</dt><dd>{{ plan.complete_artifact.base_revision }}</dd></div><div><dt>预期运行时代次</dt><dd>{{ plan.complete_artifact.expected_generation }}</dd></div><div><dt>需要独立守护服务</dt><dd>{{ plan.complete_artifact.requires_guard ? '是' : '否' }}</dd></div><div><dt>配置 SHA-256</dt><dd class="hash">{{ plan.complete_artifact.native_sha256 }}</dd></div><div><dt>产物 SHA-256</dt><dd class="hash">{{ plan.complete_artifact.content_hash }}</dd></div></dl><p class="muted">控制器已将路由策略与网关基础配置和出口定义组装完成。此预览不包含凭据。</p></div>
        <button class="button" type="button" :disabled="busy || !canApply || !!applyRequest?.operationId" @click="applyPlan">{{ applying ? '正在读取配置操作…' : applyRequest && !applyRequest.operationId ? '重试同一应用请求' : '应用网关配置' }}</button>
        <p class="muted">应用配置只记录网关配置状态；设备纳管和流量验证是独立步骤。</p>
      </section>
      <section v-if="applyRequest" aria-label="配置操作回读"><h3>配置操作</h3><p v-if="applyRequest.operationId" class="hash">{{ applyRequest.operationId }}</p><p v-else class="muted">尚未确认请求是否已受理。重试将沿用同一请求标识。</p><p v-if="operationError" class="alert alert--bad" role="alert"><DiagnosticMessage :message="operationError" /></p><StatusPill v-if="operation" :label="uiLabel(operation.status)" :tone="configurationObserved ? 'good' : operation.status === 'failed' ? 'bad' : 'warn'" /><dl class="facts"><div><dt>期望配置</dt><dd>{{ operation?.views?.desired?.revision === applyRequest.checksum ? `已记录 · 代次 ${operation.views.desired.generation}` : '计划已保存，等待操作回读' }}</dd></div><div><dt>已应用配置</dt><dd>{{ operation?.views?.applied?.revision === applyRequest.checksum ? `已记录 · 代次 ${operation.views.applied.generation}` : '未确认' }}</dd></div><div><dt>已观测配置</dt><dd>{{ configurationObserved ? `已确认 · 代次 ${operation?.views?.observed?.generation}` : '未确认' }}</dd></div><div><dt>客户端流量验证</dt><dd>配置应用不构成流量验证</dd></div></dl><p v-if="configurationObserved" class="confirmed" role="status">已确认网关配置应用与回读。</p><button v-if="applyRequest.operationId" class="button button--secondary" :disabled="busy" type="button" @click="refreshOperation">读取配置操作</button></section>
      <section aria-label="纳管就绪状态"><h3>设备纳管就绪状态</h3><ul v-if="plan.enrollment_blockers?.length"><li v-for="(blocker, index) in plan.enrollment_blockers" :key="index"><strong>{{ blocker.code }}</strong><span v-if="blocker.path"> · {{ blocker.path }}</span>: <DiagnosticMessage :message="blocker.message" :code="blocker.code" /></li></ul><p v-else-if="plan.enrollment_ready === true" class="muted">打开“设备与分组”，选择一台设备及其防火墙绑定。执行纳管前会重新检查计划和设备版本。</p><p v-else class="muted">控制器尚未确认纳管所需的网关、独立守护服务、防火墙和客户端验证条件。</p><p v-if="configurationObserved" class="muted">纳管前请创建新的清单计划，以记录本次配置应用后的网关代次。</p></section>
      <details><summary>已记录的资源版本（{{ plan.resource_revisions?.length ?? 0 }}）</summary><div class="table-scroll"><table><thead><tr><th>资源</th><th>ID</th><th>版本</th><th>内容 SHA-256</th></tr></thead><tbody><tr v-for="resource in plan.resource_revisions ?? []" :key="`${resource.kind}/${resource.id}`"><td>{{ uiLabel(resource.kind) }}</td><td>{{ resource.id }}</td><td>{{ resource.revision }}</td><td class="hash">{{ resource.sha256 }}</td></tr></tbody></table></div></details>
      <section v-if="plan.compilation" aria-label="清单编译预览">
        <h3>清单编译预览</h3><p class="hash">清单：{{ plan.compilation.manifest.content_hash }}</p>
        <p>{{ plan.compilation.manifest.groups?.length ?? 0 }} 个已编译组 · {{ plan.compilation.impact.changed_groups?.length ?? 0 }} 个变更 · {{ plan.compilation.impact.unchanged_groups?.length ?? 0 }} 个未变更。</p>
        <p class="muted">{{ plan.previous.status === 'applied' ? '影响范围与上次持久化的已应用清单比较。' : '没有上次已应用清单；影响范围与空基线比较。' }} 纳管变化：{{ plan.compilation.impact.enrollment_changed ? '是' : '否' }}。需要应用策略：{{ plan.compilation.impact.requires_policy_apply ? '是' : '否' }}。</p>
        <ul v-if="plan.compilation.diagnostics?.length"><li v-for="(diagnostic, index) in plan.compilation.diagnostics" :key="index">{{ uiLabel(diagnostic.severity) }} · {{ diagnostic.code }}<span v-if="diagnostic.path"> · {{ diagnostic.path }}</span>: <DiagnosticMessage :message="diagnostic.message" :code="diagnostic.code" /></li></ul>
        <details><summary>只读编译清单</summary><pre>{{ JSON.stringify(plan.compilation.manifest, null, 2) }}</pre></details>
      </section>
      <details v-if="plan.native_artifact"><summary>只读原生路由预览</summary><p class="muted">这里只包含路由片段；应用前还需要网关全局设置、DNS、出口凭据和原生校验。</p><pre>{{ plan.native_artifact.routing_config }}</pre><p class="hash">路由 SHA-256：{{ plan.native_artifact.routing_sha256 }}</p></details>
      <details><summary>生成时的编译输入</summary><pre>{{ JSON.stringify(plan.input, null, 2) }}</pre></details>
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
