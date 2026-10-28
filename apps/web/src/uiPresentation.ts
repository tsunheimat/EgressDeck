import type { Health, OperationSummary } from './types'

export type StatusTone = 'neutral' | 'good' | 'warn' | 'bad'
export const healthLabels: Record<Health, string> = { healthy: '健康', degraded: '状态异常', offline: '离线', unknown: '状态未知' }
export function healthTone(health?: Health): StatusTone { return health === 'healthy' ? 'good' : health === 'offline' ? 'bad' : health === 'degraded' ? 'warn' : 'neutral' }
export const operationLabels: Record<OperationSummary['status'], string> = {
  draft: '草稿', validated: '配置已校验', staged: '已暂存', applying: '正在应用', verifying: '正在验证',
  applied: '配置已应用', partially_applied: '部分应用', failed: '失败', outcome_unknown: '结果未确认',
}
export function operationTone(status: OperationSummary['status']): StatusTone {
  if (status === 'applied') return 'good'
  if (status === 'failed') return 'bad'
  return ['applying', 'verifying', 'partially_applied', 'outcome_unknown'].includes(status) ? 'warn' : 'neutral'
}
const actions: Record<string, string> = { stage: '导入订阅', refresh: '检查订阅更新', scheduled_refresh: '定时检查订阅', publish: '应用订阅更新', selection: '切换代理节点', group_apply: '应用代理组配置', apply: '应用路由策略', enroll: '纳管设备', unenroll: '移除设备纳管', verify: '验证流量路径' }
export function operationAction(action: string): string { return Object.prototype.hasOwnProperty.call(actions, action) ? actions[action]! : action }
export function formatTimestamp(value?: string): string {
  if (!value) return '尚无记录'
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '时间未知'
  return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(date)
}
