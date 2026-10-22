import type { Capability, GatewaySummary } from './types'

export interface NavigationItem {
  id: string
  label: string
  route: string
  description: string
  requiredCapabilities?: Capability[]
}

export const navigation: NavigationItem[] = [
  { id: 'overview', label: '总览', route: '/', description: '网关、防火墙、验证覆盖率与最近操作' },
  { id: 'proxies', label: '代理', route: '/proxies', description: '管理代理组、候选节点与出口选择', requiredCapabilities: ['inventory.read'] },
  { id: 'subscriptions', label: '订阅', route: '/subscriptions', description: '导入订阅、审查节点变化与应用更新', requiredCapabilities: ['provider.stage'] },
  { id: 'devices', label: '设备与分组', route: '/devices', description: '设备清单、分组策略与安全纳管', requiredCapabilities: ['inventory.read'] },
  { id: 'rules', label: '规则策略', route: '/rules', description: '有序规则、默认动作与配置影响预览', requiredCapabilities: ['policy.validate'] },
  { id: 'infrastructure', label: '基础设施', route: '/infrastructure', description: '网关能力、连接状态与防火墙绑定', requiredCapabilities: ['inventory.read'] },
  { id: 'activity', label: '活动与诊断', route: '/activity', description: '操作记录、审计与诊断证据', requiredCapabilities: ['events.resume'] },
]

export interface VisibleNavigationItem extends NavigationItem {
  disabledReason?: string
}

/**
 * Capability absence is visible in the navigation. Pages remain discoverable,
 * but mutation controls are disabled by the views when their operation is not
 * supported by the selected gateway.
 */
export function visibleNavigation(gateways: GatewaySummary[], selectedGatewayId?: string): VisibleNavigationItem[] {
  const gateway = gateways.find((item) => item.id === selectedGatewayId) ?? gateways[0]
  return navigation.map((item) => {
    const missing = item.requiredCapabilities?.filter((capability) => !gateway?.capabilities.supported.includes(capability)) ?? []
    return missing.length === 0
      ? item
      : { ...item, disabledReason: gateway ? `Gateway does not support ${missing.join(', ')}` : 'Register a gateway to inspect capabilities' }
  })
}

// Management pages stay available before a gateway is registered. Individual
// mutation controls use controller and gateway capabilities plus the session.
export function managementNavigation(): VisibleNavigationItem[] { return navigation.map(item => ({ ...item })) }
