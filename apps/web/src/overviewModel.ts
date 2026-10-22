import type { DeviceSummary, OutboundGroupSummary, OverviewResponse } from './types'
import type { PageName } from './navigationTarget'

export interface DashboardSnapshot {
  overview?: OverviewResponse
  devices?: DeviceSummary[]
  outbounds?: OutboundGroupSummary[]
  stale?: boolean
}
export interface SetupStep { id: string; title: string; detail: string; page: PageName; state: 'complete' | 'pending' | 'unknown' }
export interface AttentionItem { id: string; title: string; detail: string; page: PageName; action: string; icon: string }

/** Unknown and absent coverage must never become a zero or a successful check. */
export function coveragePercent(coverage: OverviewResponse['coverage'] | undefined, family: 'ipv4' | 'ipv6' | 'dualStack'): number | undefined {
  const value = coverage?.[family]
  return coverage?.available === true && typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100 ? value : undefined
}
export function outboundPending(group: OutboundGroupSummary): boolean {
  return group.appliedRevision !== undefined && (group.appliedRevision !== group.revision || group.observedRevision !== group.revision)
}
export function setupSteps(snapshot: DashboardSnapshot, gatewayId?: string): SetupStep[] {
  const { overview, outbounds, stale } = snapshot
  const gateway = overview?.gateways.find(item => item.id === gatewayId) ?? (!gatewayId ? overview?.gateways[0] : undefined)
  const known = !!overview && !stale
  const state = (done: boolean, available = known): SetupStep['state'] => !available ? 'unknown' : done ? 'complete' : 'pending'
  const bindingReady = !!gateway && !!overview?.bindings.some(binding => binding.gatewayId === gateway.id && binding.observationStatus === 'fresh' && !!binding.observedAt && binding.drift === false && binding.persistedCount === binding.desiredCount && binding.activeCount === binding.desiredCount)
  return [
    { id: 'gateway', title: '连接网关', detail: '注册网关并读取健康状态。', page: 'infrastructure', state: state(gateway?.health === 'healthy') },
    { id: 'firewall', title: '连接 OPNsense', detail: '绑定防火墙并确认配置回读一致。', page: 'infrastructure', state: state(bindingReady) },
    { id: 'subscription', title: '导入订阅', detail: '导入节点；检查更新与应用更新分开进行。', page: 'subscriptions', state: state(!!overview?.providers.some(provider => (provider.state === 'active' || provider.state === 'staged') && (provider.nodeCount ?? 0) > 0)) },
    { id: 'outbound', title: '创建代理组', detail: '为此网关保存代理组与候选节点。', page: 'proxies', state: state(!!gateway && !!outbounds?.some(group => group.gatewayId === gateway.id && group.nodeIds.length > 0), known && outbounds !== undefined) },
    { id: 'devices', title: '创建设备组', detail: '为此网关的设备组关联路由策略。', page: 'devices', state: state(!!gateway && !!overview?.deviceGroups.some(group => group.gatewayId === gateway.id && !!group.policyId)) },
    // Neither an enrolled address nor aggregate coverage proves the first client's path.
    // The overview contract has no per-client verification receipt. Keep this explicit.
    { id: 'verification', title: '验证首台设备', detail: '需要真实客户端证据；总览尚不提供单台设备的验证结论。', page: 'activity', state: 'unknown' },
  ]
}
export function attentionItems(snapshot: DashboardSnapshot): AttentionItem[] {
  const { overview, devices, outbounds } = snapshot
  if (!overview || snapshot.stale) return []
  const items: AttentionItem[] = []
  const staged = overview.providers.filter(provider => !!provider.stagedRevision)
  if (staged.length) items.push({ id: 'subscriptions', title: `${staged.length} 个订阅有待审查的更新`, detail: '审查新增、删除和变化的节点，再决定是否应用。', page: 'subscriptions', action: '审查更新', icon: 'subscriptions' })
  const pending = outbounds?.filter(outboundPending) ?? []
  if (pending.length) items.push({ id: 'outbounds', title: `${pending.length} 个代理组配置尚未确认应用`, detail: '保存配置不代表网关已采用该版本。', page: 'proxies', action: '查看配置', icon: 'proxies' })
  const drift = overview.bindings.filter(binding => binding.drift === true).length + overview.deviceGroups.filter(group => group.drift).length
  if (drift) items.push({ id: 'drift', title: `${drift} 项配置回读不一致`, detail: '检查防火墙绑定与设备组，不自动重试变更。', page: 'infrastructure', action: '检查状态', icon: 'warning' })
  const ungrouped = devices?.filter(device => !device.groupId).length
  if (ungrouped) items.push({ id: 'ungrouped', title: `${ungrouped} 台设备尚未分组`, detail: '分配设备组与策略；保存分组不会自动开启代理。', page: 'devices', action: '管理设备', icon: 'devices' })
  const uncertain = overview.operations.filter(operation => ['failed', 'partially_applied', 'outcome_unknown'].includes(operation.status))
  if (uncertain.length) items.push({ id: 'operations', title: `${uncertain.length} 条近期操作需要检查`, detail: '历史记录不代表问题仍未恢复；请查看原操作结果。', page: 'activity', action: '查看记录', icon: 'activity' })
  return items
}
