<script setup lang="ts">
import { uiLabel } from '../localization'
import DiagnosticMessage from './DiagnosticMessage.vue'
import { computed, onActivated, onDeactivated, onUnmounted, ref, watch } from 'vue'
import { ControllerApiError, randomIdempotencyKey } from '../api/client'
import type { useControllerState } from '../state'
import type { DeviceGroupSummary, DeviceSummary, FirewallBindingSummary, InventoryPlan, OperationSummary, StateKind } from '../types'
import StatusPill from './StatusPill.vue'

const props = defineProps<{ state: ReturnType<typeof useControllerState>; devices: DeviceSummary[]; groups: DeviceGroupSummary[] }>()
const emit = defineEmits<{ completed: [] }>()
const checksum = ref(props.state.lastInventoryPlanChecksum.value ?? '')
const deviceId = ref('')
const bindingId = ref('')
const plan = ref<InventoryPlan>()
const bindings = ref<FirewallBindingSummary[]>([])
const reading = ref(false)
const submitting = ref(false)
const error = ref('')
const operation = ref<OperationSummary>()
const previousOperationId = ref('')
interface Recovery {
  id: string
  gatewayId: string
  deviceId?: string
  bindingId?: string
  checksum?: string
  generation?: number
  status: 'failed' | 'partially_applied'
}
const recovery = ref<Recovery>()
interface Attempt {
  key: string
  subject: string
  gatewayId: string
  body: { plan_checksum: string; device_id: string; binding_id: string; expected_device_revision: number; previous_operation_id?: string }
  operationId?: string
}
const attempt = ref<Attempt>()
const device = computed(() => props.devices.find(item => item.id === deviceId.value))
const group = computed(() => props.groups.find(item => item.id === device.value?.groupId))
const busy = computed(() => reading.value || submitting.value)
const unresolved = computed(() => !!attempt.value && !['applied', 'failed'].includes(operation.value?.status ?? ''))
const preparingRecovery = computed(() => !!recovery.value && attempt.value?.operationId === recovery.value.id)
const canLoadPlan = computed(() => !unresolved.value || preparingRecovery.value)
const canPrepareRecovery = computed(() => props.state.isAdministrator.value && !!attempt.value?.operationId && ['failed', 'partially_applied'].includes(operation.value?.status ?? ''))
const compatibleBindings = computed(() => bindings.value.filter(binding => binding.gatewayId === plan.value?.target.gateway_id && device.value?.addresses.length && device.value.addresses.every(address => binding.addressFamily === 'dual' || binding.addressFamily === address.family)))
const viewKinds: StateKind[] = ['desired', 'applied', 'observed', 'verified']
let sequence = 0
let active = true
let operationRead: AbortController | undefined
let restoringTarget = false
function restoreDevice(id: string) { restoringTarget = true; deviceId.value = id; restoringTarget = false }

function captured(kind: string, id: string, revision: number) {
  return revision > 0 && plan.value?.resource_revisions?.some(item => item.kind === kind && item.id === id && item.revision === revision)
}
const unavailable = computed(() => {
  if (!props.state.isAdministrator.value) return '设备纳管需要管理员权限。'
  if (attempt.value) return preparingRecovery.value ? '请重新读取持久化计划以准备恢复纳管。' : '开始新的请求前，请先读取现有纳管操作。'
  if (!plan.value) return '请读取并确认持久化纳管计划。'
  if (plan.value.enrollment_ready !== true || plan.value.valid !== true || plan.value.enrollment_blockers?.length) return '控制器尚未确认此计划已具备纳管条件。'
  if (plan.value.complete_artifact?.gateway_id !== plan.value.target.gateway_id || !/^[a-f0-9]{64}$/.test(plan.value.complete_artifact?.native_sha256 ?? '') || !/^[a-f0-9]{64}$/.test(plan.value.complete_artifact?.content_hash ?? '')) return '纳管前需要与此计划匹配的完整网关配置。'
  if (!device.value) return '请选择包含在此计划中的设备。'
  if (recovery.value && (recovery.value.gatewayId !== plan.value.target.gateway_id || (recovery.value.deviceId && recovery.value.deviceId !== device.value.id) || (recovery.value.bindingId && recovery.value.bindingId !== bindingId.value))) return '恢复必须保留原网关、设备和防火墙绑定。'
  if (!group.value?.enabled || group.value.gatewayId !== plan.value.target.gateway_id) return '设备必须属于计划网关上已启用的设备组。'
  if (!captured('device', device.value.id, device.value.revision) || !captured('device_group', group.value.id, group.value.revision)) return '设备或组版本与计划快照不一致。请刷新清单并创建新计划。'
  if (recovery.value ? !['unenrolled', 'blocked'].includes(device.value.enrollment) : device.value.enrollment !== 'unenrolled') return recovery.value ? '恢复要求设备处于被阻止或未纳管状态，且上次操作失败或部分应用。' : '此处只能为尚未纳管的设备发起纳管。'
  if (device.value.addresses.length !== 1 || !device.value.addresses[0]?.address.trim()) return '当前纳管流程要求设备恰好有一个已保存的主机地址。'
  if (!compatibleBindings.value.some(binding => binding.id === bindingId.value)) return '请选择与网关及设备所有地址族匹配的防火墙绑定。'
  return ''
})

function invalidatePlan() {
  operationRead?.abort()
  sequence++
  reading.value = false
  plan.value = undefined
  bindings.value = []
  bindingId.value = ''
  error.value = ''
}
watch(checksum, invalidatePlan, { flush: 'sync' })
watch(deviceId, () => { if (restoringTarget) return; operationRead?.abort(); sequence++; reading.value = false; bindingId.value = ''; error.value = '' }, { flush: 'sync' })
watch(previousOperationId, () => { recovery.value = undefined; invalidatePlan() }, { flush: 'sync' })
watch(() => props.state.lastInventoryPlanChecksum.value, value => { if (!attempt.value && value) checksum.value = value })
watch(() => props.state.session.value?.subject, () => {
  invalidatePlan()
  checksum.value = ''
  deviceId.value = ''
  attempt.value = undefined
  operation.value = undefined
  recovery.value = undefined
  previousOperationId.value = ''
  submitting.value = false
}, { flush: 'sync' })

function message(cause: unknown) { return cause instanceof Error ? cause.message : '无法回读纳管请求。' }
function current(token: number) { return token === sequence && active }

async function loadPlan() {
  if (busy.value || !canLoadPlan.value || !active || !props.state.session.value || !/^[a-f0-9]{64}$/.test(checksum.value.trim())) return
  const wanted = checksum.value.trim()
  invalidatePlan()
  const token = sequence
  reading.value = true
  try {
    const [stored, available] = await Promise.all([props.state.api.inventoryPlan(wanted), props.state.api.bindings()])
    if (!current(token)) return
    if (stored.checksum !== wanted || stored.scope !== 'gateway' || !stored.target.gateway_id || stored.input.gateway.id !== stored.target.gateway_id) throw new Error('持久化纳管计划与请求的校验和及网关不匹配。')
    if (recovery.value && stored.target.gateway_id !== recovery.value.gatewayId) throw new Error('恢复纳管需要原网关的持久化计划。')
    plan.value = stored
    bindings.value = available
    if (recovery.value) {
      if (recovery.value.deviceId) restoreDevice(recovery.value.deviceId)
      if (recovery.value.bindingId) bindingId.value = recovery.value.bindingId
      if (preparingRecovery.value) { attempt.value = undefined; operation.value = undefined }
    }
  } catch (cause) { if (current(token)) error.value = message(cause) }
  finally { if (token === sequence) reading.value = false }
}

async function readOperation(target: Attempt, token: number) {
  if (!target.operationId) return
  operationRead?.abort()
  operationRead = new AbortController()
  const readback = await props.state.api.waitForOperation(target.operationId, operationRead.signal)
  if (!current(token) || attempt.value?.key !== target.key || props.state.session.value?.subject !== target.subject) return
  if (readback.id !== target.operationId || readback.target !== `gateway:${target.gatewayId}` || readback.action !== 'enable') throw new Error('纳管操作回读与已受理的操作及网关不匹配。')
  if (!readback.enrollment || readback.enrollment.device_id !== target.body.device_id || readback.enrollment.binding_id !== target.body.binding_id || readback.enrollment.plan_checksum !== target.body.plan_checksum || (readback.enrollment.previous_operation_id ?? '') !== (target.body.previous_operation_id ?? '')) throw new Error('纳管操作回读与已受理的设备、绑定和计划不匹配。')
  operation.value = readback
  props.state.recordOperation(readback)
  if (readback.error) error.value = readback.error
  if (['applied', 'failed', 'partially_applied', 'outcome_unknown'].includes(readback.status)) emit('completed')
}

function prepareRecovery() {
  if (busy.value || !canPrepareRecovery.value || !attempt.value || !operation.value) return
  const prior = attempt.value
  previousOperationId.value = prior.operationId!
  recovery.value = { id: prior.operationId!, gatewayId: prior.gatewayId, deviceId: prior.body.device_id, bindingId: prior.body.binding_id, checksum: prior.body.plan_checksum, generation: operation.value.requestedGeneration, status: operation.value.status as Recovery['status'] }
  checksum.value = ''
  invalidatePlan()
}

async function readPreviousOperation() {
  if (busy.value || attempt.value || !active || !props.state.isAdministrator.value || !previousOperationId.value.trim()) return
  invalidatePlan()
  recovery.value = undefined
  const wanted = previousOperationId.value.trim()
  const token = sequence
  reading.value = true
  operationRead = new AbortController()
  try {
    const prior = await props.state.api.operation(wanted, operationRead.signal)
    if (!current(token)) return
    if (prior.id !== wanted || prior.action !== 'enable' || !prior.target.startsWith('gateway:') || !['failed', 'partially_applied'].includes(prior.status)) throw new Error('恢复要求上次纳管操作失败或部分应用。结果未知时，必须先通过现有操作确认结果。')
    const summary = prior.enrollment
    if (!summary?.device_id || !summary.binding_id || !/^[a-f0-9]{64}$/.test(summary.plan_checksum)) throw new Error('上次纳管回读未包含设备、绑定和计划标识，恢复仍未确认。')
    recovery.value = { id: prior.id, gatewayId: prior.target.slice('gateway:'.length), deviceId: summary.device_id, bindingId: summary.binding_id, checksum: summary.plan_checksum, generation: prior.requestedGeneration, status: prior.status as Recovery['status'] }
    restoreDevice(summary.device_id)
  } catch (cause) { if (current(token)) error.value = message(cause) }
  finally { if (token === sequence) reading.value = false }
}

function cancelRecovery() {
  if (busy.value || attempt.value) return
  recovery.value = undefined
  previousOperationId.value = ''
  invalidatePlan()
}

async function submitAttempt(target: Attempt, token: number) {
  try {
    const accepted = target.body.previous_operation_id
      ? await props.state.api.recoverEnrollment({ ...target.body, previous_operation_id: target.body.previous_operation_id }, target.key)
      : await props.state.api.enrollDevice(target.body, target.key)
    if (attempt.value?.key !== target.key || props.state.session.value?.subject !== target.subject) return
    attempt.value.operationId = accepted.operationId
    if (current(token)) await readOperation(target, token)
  } catch (cause) {
    if (!current(token) || attempt.value?.key !== target.key) return
    if (cause instanceof ControllerApiError && cause.operationId) attempt.value.operationId = cause.operationId
    const rejectionStatus: Record<string, number> = { enrollment_resource_required: 422, enrollment_state_conflict: 409, enrollment_group_invalid: 422, enrollment_binding_invalid: 422, enrollment_source_invalid: 422, enrollment_recovery_reference_required: 422, enrollment_recovery_conflict: 409, enrollment_recovery_required: 409, revision_conflict: 412, validation_error: 422, unsupported_capability: 501 }
    const definitePreflight = cause instanceof ControllerApiError && !cause.operationId && !target.operationId && rejectionStatus[cause.code ?? ''] === cause.status
    if (definitePreflight) {
      attempt.value = undefined
      operation.value = undefined
      plan.value = undefined
      bindings.value = []
      bindingId.value = ''
      error.value = `${message(cause)} 请修正输入或读取新计划后再重试。`
    } else error.value = `${message(cause)} 开始下一次纳管前，请先回读此请求。`
  } finally { if (token === sequence) submitting.value = false }
}

async function enroll() {
  if (busy.value || unavailable.value || !active || !device.value || !plan.value || !props.state.session.value) return
  const target: Attempt = {
    key: randomIdempotencyKey(), subject: props.state.session.value.subject, gatewayId: plan.value.target.gateway_id,
    body: { plan_checksum: plan.value.checksum, device_id: device.value.id, binding_id: bindingId.value, expected_device_revision: device.value.revision, ...(recovery.value ? { previous_operation_id: recovery.value.id } : {}) },
  }
  attempt.value = target
  operation.value = undefined
  error.value = ''
  submitting.value = true
  await submitAttempt(target, ++sequence)
}

async function refreshOperation() {
  const target = attempt.value
  if (!target || busy.value || !active || target.subject !== props.state.session.value?.subject) return
  error.value = ''
  operation.value = undefined
  submitting.value = true
  const token = ++sequence
  if (!target.operationId) {
    if (!props.state.isAdministrator.value) { submitting.value = false; error.value = '恢复原纳管请求需要管理员权限。'; return }
    await submitAttempt(target, token)
    return
  }
  try { await readOperation(target, token) }
  catch (cause) { if (current(token)) error.value = message(cause) }
  finally { if (token === sequence) submitting.value = false }
}

function nextEnrollment() {
  if (busy.value || unresolved.value) return
  attempt.value = undefined
  operation.value = undefined
  recovery.value = undefined
  previousOperationId.value = ''
  invalidatePlan()
}
function deactivate() { active = false; operationRead?.abort(); sequence++; reading.value = false; submitting.value = false; plan.value = undefined; bindings.value = []; bindingId.value = '' }
onActivated(() => { active = true })
onDeactivated(deactivate)
onUnmounted(deactivate)
</script>

<template>
  <section class="panel enrollment-panel" aria-labelledby="enrollment-title">
    <h2 id="enrollment-title">设备流量纳管</h2>
    <p class="muted">使用持久化计划应用设备策略，并协调防火墙纳管。流量验证与配置应用分别报告。</p>
    <form v-if="!attempt && !recovery" aria-label="读取上次纳管操作" @submit.prevent="readPreviousOperation">
      <label>上次纳管操作 ID（用于恢复）<input v-model="previousOperationId" :disabled="busy" autocomplete="off" placeholder="失败或部分应用的操作 ID" /></label>
      <button class="button button--secondary" type="submit" :disabled="busy || !state.isAdministrator.value || !previousOperationId.trim()">读取上次纳管操作</button>
    </form>
    <div v-if="recovery" class="readback" aria-label="纳管恢复准备">
      <p>正在准备恢复 <code>{{ recovery.id }}</code>：{{ uiLabel(recovery.status) }} · 网关 {{ recovery.gatewayId }}<span v-if="recovery.generation"> · 上次请求代次 {{ recovery.generation }}</span>.</p>
      <p v-if="recovery.deviceId && recovery.bindingId">设备 {{ recovery.deviceId }} · 防火墙绑定 {{ recovery.bindingId }}。</p>
      <p v-else class="muted">选择原设备和绑定。控制器会对照已记录的操作检查这些信息，再受理恢复请求。</p>
      <p class="muted">重新读取持久化计划，检查当前版本和请求代次。控制器将在恢复纳管前重新检查守护服务和防火墙状态。准备此请求不代表流量已验证。</p>
      <button v-if="!attempt" class="button button--secondary" type="button" :disabled="busy" @click="cancelRecovery">取消恢复准备</button>
    </div>
    <form aria-label="读取纳管计划" @submit.prevent="loadPlan">
      <label>纳管计划校验和<input v-model="checksum" :disabled="busy || !canLoadPlan" autocomplete="off" placeholder="粘贴“规则策略”中的校验和" /></label>
      <button class="button button--secondary" type="submit" :disabled="busy || !canLoadPlan || !state.session.value || !/^[a-f0-9]{64}$/.test(checksum.trim())">{{ reading ? '正在读取纳管计划…' : '读取纳管计划' }}</button>
    </form>
    <div v-if="plan" aria-label="纳管计划回读" class="readback">
      <p>已确认持久化纳管计划的回读。</p>
      <StatusPill :label="plan.enrollment_ready === true ? '可开始纳管' : '纳管被阻止'" :tone="plan.enrollment_ready === true ? 'good' : 'warn'" />
      <p class="muted">网关：{{ plan.target.gateway_id }} · 生成时间 {{ plan.created_at }}</p>
      <p v-if="recovery" class="muted">已观测运行时代次：{{ plan.target.generation ?? '不可用' }} · 请求策略代次：{{ plan.target.next_policy_generation ?? '不可用' }}。恢复应用前会再次检查网关和防火墙状态。</p>
      <ul v-if="plan.enrollment_blockers?.length" aria-label="纳管阻塞项"><li v-for="(blocker, index) in plan.enrollment_blockers" :key="index"><strong>{{ blocker.code }}</strong>: <DiagnosticMessage :message="blocker.message" :code="blocker.code" /></li></ul>
    </div>
    <form aria-label="纳管设备" @submit.prevent="enroll">
      <fieldset class="form-grid" :disabled="busy || !!attempt">
        <label>待纳管设备<select v-model="deviceId" :disabled="!!recovery?.deviceId"><option value="">选择设备</option><option v-for="item in devices" :key="item.id" :value="item.id">{{ item.name }}（版本 {{ item.revision }}）</option></select></label>
        <label>纳管防火墙绑定<select v-model="bindingId" :disabled="!!recovery?.bindingId"><option value="">选择匹配的防火墙绑定</option><option v-for="binding in compatibleBindings" :key="binding.id" :value="binding.id">{{ binding.alias }} · {{ uiLabel(binding.addressFamily) }} · {{ binding.interfaceScope }}</option></select></label>
      </fieldset>
      <p v-if="unavailable" class="muted" aria-label="纳管要求">{{ unavailable }}</p>
      <button class="button" type="submit" :disabled="busy || !!unavailable">{{ submitting && !attempt?.operationId ? '正在提交纳管…' : recovery ? '执行纳管恢复' : '纳管设备' }}</button>
    </form>
    <p v-if="error" class="alert" role="alert"><DiagnosticMessage :message="error" /></p>
    <div v-if="attempt" class="readback" aria-label="纳管操作">
      <p>设备 {{ attempt.body.device_id }} · 网关 {{ attempt.gatewayId }}</p>
      <p v-if="attempt.operationId">操作 <code>{{ attempt.operationId }}</code>: {{ operation?.status ? uiLabel(operation.status) : '等待回读' }}</p>
      <p v-else>尚未确认提交结果。恢复时只会使用同一标识重试原请求。</p>
      <p v-if="operation?.status === 'outcome_unknown'" class="muted">操作结果未知。请继续读取此操作；新的纳管请求已被阻止。</p>
      <dl v-if="operation" class="state-views"><div v-for="kind in viewKinds" :key="kind"><dt>{{ uiLabel(kind) }}</dt><dd>{{ operation.views?.[kind]?.status ? uiLabel(operation.views[kind]!.status) : (operation.views?.[kind] ? '已记录' : '尚未确认') }}<span v-if="operation.views?.[kind]"> · 代次 {{ operation.views[kind]!.generation }}<span v-if="operation.views[kind]!.revision"> · 版本 {{ operation.views[kind]!.revision }}</span></span></dd></div></dl>
      <p v-if="operation && !operation.views?.verified" class="muted">此操作尚未确认流量验证。</p>
      <div class="actions"><button class="button button--secondary" type="button" :disabled="busy" @click="refreshOperation">{{ attempt.operationId ? '刷新纳管操作' : '恢复原纳管请求' }}</button><button v-if="canPrepareRecovery && !preparingRecovery" class="button button--secondary" type="button" :disabled="busy" @click="prepareRecovery">准备恢复纳管</button><button v-if="operation?.status === 'applied'" class="button button--secondary" type="button" :disabled="busy" @click="nextEnrollment">准备下一次纳管</button></div>
    </div>
  </section>
</template>

<style scoped>
.panel,.readback,form { display:grid; gap:.75rem; min-width:0; }.panel { padding:1rem; border:1px solid var(--border); border-radius:.65rem; background:var(--surface); }h2,p { margin:0; }h2 { font-size:1.1rem; }.muted,dt { color:var(--muted); font-size:.78rem; }
.form-grid,.state-views { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:.75rem; margin:0; padding:0; border:0; min-width:0; }label { display:grid; gap:.35rem; color:var(--muted); font-size:.78rem; }input,select { width:100%; box-sizing:border-box; padding:.5rem .6rem; border:1px solid var(--border); border-radius:.35rem; background:var(--surface-alt); color:var(--text); font:inherit; }
.button { justify-self:start; cursor:pointer; padding:.5rem .7rem; border:1px solid var(--border); border-radius:.4rem; background:var(--accent); color:#07111f; font-weight:700; }.button--secondary { background:transparent; color:var(--text); }button:disabled,fieldset:disabled { opacity:.6; }button:disabled { cursor:not-allowed; }.readback { padding:.8rem; border-radius:.45rem; background:var(--surface-alt); font-size:.85rem; }ul { margin:0; padding-left:1.25rem; }li+li { margin-top:.3rem; }.alert { padding:.75rem 1rem; border:1px solid #713847; border-radius:.5rem; background:#301c29; color:#ffbeca; }.alert,dd,code,li { overflow-wrap:anywhere; }dd { margin:.2rem 0 0; font-size:.78rem; }dt { text-transform:capitalize; }.actions { display:flex; gap:.75rem; flex-wrap:wrap; }@media(max-width:580px) { .form-grid,.state-views { grid-template-columns:1fr; } }
</style>
