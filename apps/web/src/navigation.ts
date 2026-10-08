import type { Capability, GatewaySummary } from './types'

export interface NavigationItem {
  id: string
  label: string
  route: string
  description: string
  requiredCapabilities?: Capability[]
}

export const navigation: NavigationItem[] = [
  { id: 'overview', label: 'Overview', route: '/', description: 'Gateway, firewall, coverage, and recent operations' },
  { id: 'proxies', label: 'Proxies', route: '/proxies', description: 'Nodes, groups, health, and manual selection', requiredCapabilities: ['inventory.read'] },
  { id: 'subscriptions', label: 'Subscriptions', route: '/subscriptions', description: 'Providers, staged revisions, and publication', requiredCapabilities: ['provider.stage'] },
  { id: 'devices', label: 'Devices & Groups', route: '/devices', description: 'Address verification and enrollment', requiredCapabilities: ['inventory.read'] },
  { id: 'rules', label: 'Rules', route: '/rules', description: 'Ordered rules, defaults, and impact preview', requiredCapabilities: ['policy.validate'] },
  { id: 'infrastructure', label: 'Infrastructure', route: '/infrastructure', description: 'Gateway capabilities and firewall bindings', requiredCapabilities: ['inventory.read'] },
  { id: 'activity', label: 'Activity & Diagnostics', route: '/activity', description: 'Durable operations, audit, and observed traffic', requiredCapabilities: ['events.resume'] },
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
