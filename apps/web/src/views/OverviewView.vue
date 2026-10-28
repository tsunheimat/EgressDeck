<script setup lang="ts">
import { computed, onActivated, onBeforeUnmount, onDeactivated, onMounted, ref, watch } from 'vue'
import StatusPill from '../components/StatusPill.vue'
import DiagnosticMessage from '../components/DiagnosticMessage.vue'
import { actionName } from '../localization'
import UiIcon from '../components/UiIcon.vue'
import { useControllerState } from '../state'
import { attentionItems, coveragePercent, outboundPending, setupSteps } from '../overviewModel'
import { navigationHref, type PageName } from '../navigationTarget'
import { formatTimestamp, healthLabels, healthTone, operationLabels, operationTone } from '../uiPresentation'
import type { DeviceSummary, OutboundGroupSummary } from '../types'

const props = defineProps<{ state: ReturnType<typeof useControllerState> }>()
const devices = ref<DeviceSummary[]>()
const outbounds = ref<OutboundGroupSummary[]>()
const inventoryLoading = ref(false)
const inventoryErrors = ref<string[]>([])
const busy = computed(() => props.state.loading.value || inventoryLoading.value)
const stale = computed(() => props.state.loading.value || !!props.state.error.value || props.state.sessionUnavailable.value || !props.state.session.value)
const overview = computed(() => stale.value ? undefined : props.state.overview.value)
const snapshot = computed(() => ({ overview: overview.value, devices: devices.value, outbounds: outbounds.value, stale: stale.value }))
const steps = computed(() => setupSteps(snapshot.value, props.state.selectedGatewayId.value))
const completed = computed(() => steps.value.filter(step => step.state === 'complete').length)
const nextStep = computed(() => steps.value.findIndex(step => step.state !== 'complete'))
const attention = computed(() => attentionItems(snapshot.value))
const recent = computed(() => [...(overview.value?.operations ?? [])].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 5))
const providers = computed(() => [...(overview.value?.providers ?? [])].sort((a, b) => (b.lastSuccessAt ?? '').localeCompare(a.lastSuccessAt ?? '')).slice(0, 3))
const ipv4 = computed(() => coveragePercent(overview.value?.coverage, 'ipv4'))
const ipv6 = computed(() => coveragePercent(overview.value?.coverage, 'ipv6'))
const dualStack = computed(() => coveragePercent(overview.value?.coverage, 'dualStack'))
const metrics = computed(() => [
  { id: 'gateways', label: '网关', icon: 'infrastructure', color: '', value: overview.value?.gateways.length ?? '—', detail: overview.value ? `${overview.value.gateways.filter(g => g.health === 'healthy').length} 个健康 · ${overview.value.gateways.length} 个已登记` : '等待控制器回读', page: 'infrastructure' as PageName },
  { id: 'devices', label: '设备', icon: 'devices', color: '', value: devices.value?.length ?? '—', detail: devices.value ? `${devices.value.filter(d => d.enrollment === 'enrolled').length} 台已纳管 · 登记数量不代表在线` : '设备清单尚未读取', page: 'devices' as PageName },
  { id: 'outbounds', label: '代理组', icon: 'proxies', color: 'green', value: outbounds.value?.length ?? '—', detail: outbounds.value ? `${outbounds.value.filter(outboundPending).length} 个配置待确认应用` : '代理组清单尚未读取', page: 'proxies' as PageName },
  { id: 'attention', label: '关注事项', icon: 'warning', color: 'amber', value: overview.value && !inventoryLoading.value && !inventoryErrors.value.length ? attention.value.length : '—', detail: inventoryErrors.value.length ? '部分清单不可用，结果不完整' : '配置差异与近期异常类别', page: 'activity' as PageName },
])
const providerLabels = { active: '已有应用版本', staged: '待审查更新', error: '需要检查', never_fetched: '尚未获取' }
const href = (page: PageName) => navigationHref({ page })
const percent = (value?: number) => value === undefined ? '待验证' : `${value}%`
function targetName(target: string) {
  const separator = target.indexOf(':')
  const kind = target.slice(0, separator)
  const id = target.slice(separator + 1)
  const collections: Record<string, Array<{ id: string; name: string }> | undefined> = { gateway: overview.value?.gateways, provider: overview.value?.providers, device_group: overview.value?.deviceGroups, outbound_group: outbounds.value, device: devices.value }
  return collections[kind]?.find(item => item.id === id)?.name ?? target
}

let active = false
let activatedOnce = false
let request: AbortController | undefined
let sequence = 0
function cancelInventory() { sequence++; request?.abort(); inventoryLoading.value = false }
async function loadInventory() {
  if (!active || inventoryLoading.value) return
  if (!props.state.session.value || props.state.authRequired.value) { devices.value = undefined; outbounds.value = undefined; return }
  const current = ++sequence
  request?.abort()
  const controller = new AbortController()
  request = controller
  inventoryLoading.value = true
  devices.value = undefined
  outbounds.value = undefined
  inventoryErrors.value = []
  try {
    const [deviceResult, outboundResult] = await Promise.allSettled([props.state.api.devices(controller.signal), props.state.api.outboundGroups(controller.signal)])
    if (controller.signal.aborted || current !== sequence || !active) return
    if (deviceResult.status === 'fulfilled') devices.value = deviceResult.value
    else inventoryErrors.value.push('设备清单读取失败')
    if (outboundResult.status === 'fulfilled') outbounds.value = outboundResult.value
    else inventoryErrors.value.push('代理组清单读取失败')
  } finally { if (current === sequence) inventoryLoading.value = false }
}
async function refresh() { await Promise.all([props.state.load(), loadInventory()]) }
function activate() {
  if (active) return
  active = true
  if (activatedOnce) void props.state.load()
  activatedOnce = true
  void loadInventory()
}
onMounted(activate)
onActivated(activate)
onDeactivated(() => { active = false; cancelInventory() })
onBeforeUnmount(() => { active = false; cancelInventory() })
watch(() => props.state.session.value?.subject, () => { cancelInventory(); devices.value = undefined; outbounds.value = undefined; inventoryErrors.value = []; if (active) void loadInventory() })
</script>

<template>
  <div class="dashboard" :aria-busy="busy">
    <header class="ed-page-heading dashboard-heading">
      <div><h1>总览</h1><p>安全地管理家庭实验室的代理路由与防火墙接入，让每一次配置都清晰可查。</p></div>
      <button class="ed-button ed-button--quiet" :disabled="busy" @click="refresh"><UiIcon name="refresh" :size="17" />{{ busy ? '正在读取' : '刷新总览' }}</button>
    </header>
    <div v-if="state.error.value" class="dashboard-alert" role="alert"><UiIcon name="warning" /><span>无法确认最新控制器状态：<DiagnosticMessage :message="state.error.value" />。刷新成功前，不显示已完成或健康结论。</span></div>
    <div v-if="inventoryErrors.length" class="dashboard-alert" role="status"><UiIcon name="warning" /><span>{{ inventoryErrors.join('；') }}。不可用的清单显示为「—」，不按零计算。</span></div>

    <section class="setup-card ed-panel" aria-labelledby="setup-title">
      <div class="setup-heading">
        <span class="setup-rocket"><UiIcon name="rocket" :size="36" /></span>
        <div><h2 id="setup-title">快速开始</h2><p>按步骤准备代理路由。网关相关步骤以「{{ state.selectedGateway.value?.name ?? '未选择网关' }}」为目标。</p></div>
        <div class="setup-progress"><span>{{ completed }} / 6 项已确认</span><progress :value="completed" max="6" aria-label="设置完成进度" /></div>
      </div>
      <ol class="setup-steps">
        <li v-for="(step, index) in steps" :key="step.id" :data-step="step.id" :data-state="step.state" :class="{ 'step--complete': step.state === 'complete', 'step--current': index === nextStep }">
          <a :href="href(step.page)" :aria-current="index === nextStep ? 'step' : undefined" :aria-label="`${step.title}：${step.state === 'complete' ? '已确认' : step.state === 'unknown' ? '待确认' : '待设置'}`">
            <span class="step-marker"><UiIcon v-if="step.state === 'complete'" name="check" :size="18" /><template v-else>{{ index + 1 }}</template></span>
            <strong>{{ step.title }}</strong><small>{{ step.detail }}</small>
            <span v-if="index === nextStep" class="step-action">{{ step.id === 'verification' ? '查看诊断' : '继续设置' }}<UiIcon name="arrow" :size="14" /></span>
            <span v-else class="step-state">{{ step.state === 'complete' ? '已确认' : step.state === 'unknown' ? '待确认' : '待设置' }}</span>
          </a>
        </li>
      </ol>
    </section>

    <section class="metric-grid" aria-label="控制器资源概况">
      <a v-for="metric in metrics" :key="metric.id" :href="href(metric.page)" class="metric-card ed-panel" :data-metric="metric.id">
        <span class="ed-icon-tile" :class="metric.color ? `ed-icon-tile--${metric.color}` : ''"><UiIcon :name="metric.icon" :size="25" /></span>
        <span class="metric-copy"><span>{{ metric.label }}</span><strong>{{ metric.value }}</strong><small>{{ metric.detail }}</small></span>
        <UiIcon class="metric-arrow" name="chevron" :size="15" />
      </a>
    </section>

    <div class="middle-grid">
      <section class="ed-panel" aria-labelledby="attention-title">
        <div class="ed-panel__heading"><h2 id="attention-title"><UiIcon name="subscriptions" />待处理事项</h2><span class="panel-caption">{{ overview ? `${attention.length} 类事项` : '等待回读' }}</span></div>
        <ul v-if="attention.length" class="attention-list">
          <li v-for="item in attention.slice(0, 4)" :key="item.id"><span class="task-icon"><UiIcon :name="item.icon" /></span><span class="task-copy"><strong>{{ item.title }}</strong><small>{{ item.detail }}</small></span><a :href="href(item.page)" class="ed-button ed-button--quiet">{{ item.action }}</a></li>
        </ul>
        <div v-else-if="!overview || inventoryErrors.length || inventoryLoading" class="ed-empty">尚未完整读取资源，暂不能确认待处理事项。<br />请刷新后再检查。</div>
        <div v-else-if="!overview.gateways.length" class="ed-empty">从连接第一个网关开始。<br /><a :href="href('infrastructure')" class="empty-link">打开基础设施<UiIcon name="arrow" :size="15" /></a></div>
        <div v-else class="ed-empty">当前已读取的配置暂无待处理事项。<br />配置回读正常不代表真实流量已经验证。</div>
      </section>
      <section class="ed-panel" aria-labelledby="recent-title">
        <div class="ed-panel__heading"><h2 id="recent-title"><UiIcon name="clock" />最近操作</h2><a :href="href('activity')">查看全部<UiIcon name="arrow" :size="15" /></a></div>
        <ol v-if="recent.length" class="activity-list">
          <li v-for="operation in recent" :key="operation.id"><span class="timeline-dot" :class="`timeline-dot--${operationTone(operation.status)}`"><UiIcon :name="operation.status === 'applied' ? 'check' : operation.status === 'failed' ? 'close' : 'clock'" :size="12" /></span><span class="activity-copy"><strong>{{ actionName(operation.action) }}</strong><small :title="operation.target">{{ targetName(operation.target) }}</small></span><time :datetime="operation.createdAt">{{ formatTimestamp(operation.createdAt) }}</time><StatusPill :label="operationLabels[operation.status] ?? operation.status" :tone="operationTone(operation.status)" /></li>
        </ol>
        <div v-else class="ed-empty">{{ overview ? '尚无操作记录。完成设置后，可在这里追踪每次变更。' : '等待控制器返回操作记录。' }}</div>
      </section>
    </div>

    <div class="bottom-grid">
      <section class="ed-panel" aria-labelledby="verification-title">
        <div class="ed-panel__heading"><h2 id="verification-title"><UiIcon name="shield" />网络验证状态</h2><StatusPill :label="ipv4 === undefined && ipv6 === undefined ? '待验证' : '已报告覆盖率'" /></div>
        <p class="panel-description">配置应用与真实流量验证是两件事。</p>
        <div class="verification-body">
          <div class="coverage-ring" :class="{ 'coverage-ring--unknown': ipv4 === undefined }" :style="ipv4 === undefined ? undefined : { background: `conic-gradient(var(--good) ${ipv4}%, #20344e 0)` }"><span><strong>{{ percent(ipv4) }}</strong><small>IPv4 覆盖率</small></span></div>
          <dl class="coverage-list"><div><dt>IPv4 流量验证</dt><dd>{{ percent(ipv4) }}</dd></div><div><dt>IPv6 流量验证</dt><dd>{{ percent(ipv6) }}</dd></div><div><dt>双栈验证</dt><dd>{{ percent(dualStack) }}</dd></div><div><dt>首台设备验证</dt><dd>待确认</dd></div></dl>
        </div>
        <p class="verification-note">未提供证据时不显示通过，也不会自动开启设备纳管。</p>
      </section>
      <section class="ed-panel" aria-labelledby="providers-title">
        <div class="ed-panel__heading"><h2 id="providers-title"><UiIcon name="subscriptions" />订阅状态</h2><a :href="href('subscriptions')">管理订阅<UiIcon name="arrow" :size="15" /></a></div>
        <ul v-if="providers.length" class="provider-list"><li v-for="provider in providers" :key="provider.id"><span class="ed-icon-tile"><UiIcon name="subscriptions" :size="18" /></span><span><strong>{{ provider.name }}</strong><small>{{ provider.nodeCount ?? '—' }} 个节点 · {{ formatTimestamp(provider.lastSuccessAt) }}</small></span><StatusPill :label="providerLabels[provider.state] ?? provider.state" :tone="provider.state === 'error' ? 'bad' : provider.state === 'staged' ? 'warn' : 'neutral'" /></li></ul>
        <div v-else class="ed-empty">{{ overview ? '还没有订阅。导入后先审查节点变化，再应用到网关。' : '等待订阅状态回读。' }}</div>
      </section>
      <section class="ed-panel" aria-labelledby="health-title">
        <div class="ed-panel__heading"><h2 id="health-title"><UiIcon name="activity" />管理面状态</h2><a :href="href('infrastructure')">详情<UiIcon name="arrow" :size="15" /></a></div>
        <p class="panel-description">仅展示已读取的组件状态，不推断流量健康。</p>
        <ul class="health-list"><li><span>控制器清单</span><StatusPill :label="overview ? '已读取' : '待确认'" /></li><li v-for="gateway in overview?.gateways.slice(0, 3) ?? []" :key="gateway.id"><span :title="gateway.name">{{ gateway.name }}</span><StatusPill :label="healthLabels[gateway.health]" :tone="healthTone(gateway.health)" /></li><li><span>防火墙绑定</span><StatusPill :label="!overview ? '待确认' : !overview.bindings.length ? '未配置' : `${overview.bindings.filter(binding => binding.observationStatus === 'fresh').length} / ${overview.bindings.length} 已回读`" /></li></ul>
      </section>
    </div>
  </div>
</template>

<style scoped>
.dashboard { display: grid; gap: 16px; }.dashboard-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 2px; }.dashboard-heading .ed-button { flex: 0 0 auto; }.dashboard-alert { display: flex; align-items: flex-start; gap: 10px; padding: 12px 15px; border: 1px solid #70582d; border-radius: 8px; background: #30291d; color: #f8cf7b; font-size: .83rem; line-height: 1.7; overflow-wrap: anywhere; }
.setup-card { padding: 22px 24px 18px; border-color: #245486; background: radial-gradient(ellipse at 70% -20%, #103b72 0, transparent 65%), linear-gradient(120deg, #10233b, #0c1a2d); overflow: hidden; }.setup-heading { display: flex; align-items: center; gap: 17px; }.setup-heading h2 { margin: 0 0 5px; font-size: 1.25rem; }.setup-heading p { margin: 0; color: var(--muted); font-size: .8rem; line-height: 1.7; }.setup-rocket { color: #6ea5ff; }.setup-progress { display: grid; gap: 11px; min-width: 152px; margin-left: auto; text-align: right; color: #becfe8; font-size: .79rem; }.setup-progress progress { width: 100%; height: 8px; appearance: none; border: 0; border-radius: 20px; background: #233b5e; overflow: hidden; }.setup-progress progress::-webkit-progress-bar { background: #233b5e; }.setup-progress progress::-webkit-progress-value { background: #23cfa3; border-radius: 20px; }.setup-progress progress::-moz-progress-bar { background: #23cfa3; border-radius: 20px; }
.setup-steps { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); padding: 0; margin: 24px 0 0; list-style: none; }.setup-steps li { position: relative; min-width: 0; }.setup-steps li:not(:last-child)::after { content: ''; position: absolute; top: 15px; left: 32px; right: 0; height: 2px; background: #2a4266; }.setup-steps li.step--complete::after { background: #22cda7; }.setup-steps a { position: relative; z-index: 1; display: flex; flex-direction: column; align-items: flex-start; padding-right: 15px; color: var(--text); text-decoration: none; }.step-marker { display: grid; place-items: center; width: 32px; height: 32px; margin-bottom: 12px; border: 1.5px solid #7797bf; border-radius: 50%; background: #10233b; color: #c2d3ed; font-size: .85rem; box-shadow: 0 0 0 4px #0e2035; }.step--complete .step-marker { background: #26e2ad; border-color: #26e2ad; color: #063329; }.step--current .step-marker { background: #0877ff; border-color: #6aafff; color: #fff; box-shadow: 0 0 15px #0877ff44; }.setup-steps strong { font-size: .84rem; }.setup-steps small { display: block; margin-top: 6px; color: var(--muted); font-size: .74rem; line-height: 1.65; }.step-action, .step-state { display: inline-flex; align-items: center; gap: 6px; margin-top: 10px; font-size: .69rem; line-height: 1.4; }.step-action { padding: 5px 10px; border: 1px solid #318cff; border-radius: 5px; background: #086df1; }.step-state { color: #7d97b5; }.step--complete .step-state { color: var(--good); }
.metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; }.metric-card { position: relative; display: flex; align-items: flex-start; gap: 14px; min-height: 112px; padding: 17px; text-decoration: none; color: var(--text); }.metric-card:hover { border-color: #366d9e; }.metric-copy { display: grid; gap: 4px; min-width: 0; }.metric-copy > span { color: #bacde5; font-size: .82rem; }.metric-copy strong { font-size: 1.65rem; font-weight: 650; }.metric-copy small { color: var(--muted); font-size: .67rem; line-height: 1.6; }.metric-arrow { position: absolute; top: 17px; right: 12px; color: var(--muted); }
.middle-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }.panel-caption { color: var(--muted); font-size: .73rem; }.attention-list { list-style: none; margin: 0; padding: 0 16px 10px; }.attention-list li { display: flex; align-items: center; gap: 11px; padding: 12px 0; border-top: 1px solid #18314a; }.task-icon { display: grid; place-items: center; flex: 0 0 auto; width: 36px; height: 39px; border-radius: 8px; background: #292c22; color: var(--warn); }.task-copy { min-width: 0; flex: 1; }.task-copy strong, .task-copy small { display: block; }.task-copy strong { font-size: .79rem; font-weight: 550; }.task-copy small { margin-top: 5px; color: var(--muted); font-size: .71rem; line-height: 1.65; }.attention-list .ed-button { flex: 0 0 auto; min-height: 30px; padding: 6px 12px; font-size: .72rem; }.empty-link { display: inline-flex; align-items: center; gap: 6px; margin-top: 14px; text-decoration: none; }
.activity-list { display: grid; list-style: none; padding: 0 16px 15px; margin: 0; }.activity-list li { position: relative; display: flex; align-items: center; gap: 10px; min-height: 49px; padding: 7px 0; }.activity-list li:not(:last-child)::before { content: ''; position: absolute; left: 8px; top: 29px; bottom: -9px; width: 1px; background: #28506e; }.timeline-dot { display: grid; place-items: center; width: 18px; height: 18px; flex: 0 0 auto; border-radius: 50%; background: #325478; color: #d1e3f6; }.timeline-dot--good { background: #26dba8; color: #064438; }.timeline-dot--bad { background: #ed5773; color: #3b0b19; }.timeline-dot--warn { background: #e8b43b; color: #3e2a06; }.activity-copy { min-width: 0; flex: 1; }.activity-copy strong { display: block; font-size: .77rem; font-weight: 550; }.activity-copy small { display: block; max-width: 210px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 5px; color: var(--muted); font-size: .69rem; }.activity-list time { font-size: .66rem; color: #9bb1ce; white-space: nowrap; }.activity-list :deep(.status-pill) { font-size: .65rem; padding: 3px 6px; }
.bottom-grid { display: grid; grid-template-columns: 1.2fr 1fr 1fr; gap: 14px; }.panel-description { margin: -4px 17px 12px; color: var(--muted); font-size: .72rem; line-height: 1.7; }.verification-body { display: flex; align-items: center; gap: 20px; padding: 10px 17px; }.coverage-ring { display: grid; place-items: center; flex: 0 0 auto; width: 96px; height: 96px; border-radius: 50%; background: #253d5a; }.coverage-ring > span { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px; width: 79px; height: 79px; border-radius: 50%; background: #0b1d30; }.coverage-ring strong { font-size: 1.15rem; }.coverage-ring small { color: var(--muted); font-size: .64rem; }.coverage-ring--unknown { border: 1px dashed #516a87; background: #1a3049; }.coverage-list { display: grid; gap: 12px; flex: 1; min-width: 0; margin: 0; font-size: .7rem; }.coverage-list > div { display: flex; justify-content: space-between; gap: 10px; }.coverage-list dt { color: #b6c9e0; }.coverage-list dd { margin: 0; color: var(--muted); white-space: nowrap; }.verification-note { margin: 5px 17px 15px; font-size: .67rem; color: var(--muted); line-height: 1.7; }
.provider-list, .health-list { margin: 0; padding: 0 15px 15px; list-style: none; }.provider-list li { display: flex; align-items: center; gap: 10px; padding: 10px 0; border-top: 1px solid #18314a; }.provider-list .ed-icon-tile { width: 31px; height: 33px; border-radius: 7px; }.provider-list li > span:nth-child(2) { min-width: 0; flex: 1; }.provider-list strong, .provider-list small { display: block; overflow-wrap: anywhere; }.provider-list strong { font-size: .75rem; font-weight: 500; }.provider-list small { margin-top: 5px; font-size: .67rem; line-height: 1.6; color: var(--muted); }.provider-list :deep(.status-pill) { font-size: .62rem; padding: 3px 6px; }.health-list li { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 8px 0; border-bottom: 1px solid #17314b; font-size: .73rem; }.health-list li > span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }.health-list :deep(.status-pill) { font-size: .65rem; padding: 2px 6px; }
@media (max-width: 1250px) { .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }.bottom-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }.bottom-grid > :last-child { grid-column: 1 / -1; }.middle-grid { grid-template-columns: 1fr; }.setup-steps { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 22px 0; }.setup-steps li:nth-child(3)::after { display: none; }.activity-copy small { max-width: 100%; } }
@media (max-width: 600px) { .dashboard { gap: 12px; }.dashboard-heading { align-items: flex-start; }.dashboard-heading .ed-button { padding: 8px; font-size: .72rem; }.dashboard-heading .ed-button .ui-icon { display: none; }.setup-card { padding: 18px 15px; }.setup-heading { gap: 10px; flex-wrap: wrap; }.setup-heading > div:nth-child(2) { flex: 1; }.setup-heading h2 { font-size: 1.05rem; }.setup-rocket .ui-icon { width: 27px; height: 27px; }.setup-progress { width: 100%; display: flex; align-items: center; justify-content: space-between; gap: 15px; margin-top: 8px; }.setup-progress progress { flex: 1; max-width: 170px; }.setup-steps { grid-template-columns: repeat(2, minmax(0, 1fr)); }.setup-steps li:nth-child(3)::after { display: block; }.setup-steps li:nth-child(even)::after { display: none; }.setup-steps a { padding-right: 12px; }.setup-steps small { font-size: .69rem; }.metric-grid { gap: 10px; }.metric-card { padding: 13px; gap: 10px; }.metric-card .ed-icon-tile { width: 30px; height: 32px; border-radius: 7px; }.metric-card .ui-icon { width: 20px; }.metric-copy strong { font-size: 1.4rem; }.metric-copy small { font-size: .64rem; }.metric-arrow { display: none; }.bottom-grid { grid-template-columns: 1fr; }.bottom-grid > :last-child { grid-column: auto; }.activity-list time { display: none; }.attention-list li { flex-wrap: wrap; }.attention-list .ed-button { margin-left: 47px; }.task-copy { flex-basis: calc(100% - 50px); }.verification-body { justify-content: center; }.coverage-list { max-width: 230px; } }
</style>
