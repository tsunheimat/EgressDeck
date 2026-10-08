import { navigationHref } from './navigationTarget'

export interface UsageAction { kind: string; outbound_group_id?: string }
export interface UsageRule { id: string; name?: string; enabled?: boolean; action: UsageAction }
export interface UsageRuleSet { id: string; name?: string; rules?: UsageRule[] }
export interface UsagePolicy {
  id: string
  name?: string
  mandatory_rules?: UsageRule[]
  mandatory?: UsageRule[]
  exceptions?: UsageRule[]
  rules?: UsageRule[]
  entries?: Array<{ rule?: UsageRule; rule_set_id?: string }>
  rule_set_ids?: string[]
  default_action?: UsageAction
  unknown_domain_action?: UsageAction
  proxy_failure_action?: UsageAction
}
export interface UsageDeviceGroup { id: string; name: string; policyId?: string; enabled: boolean; gatewayId: string }
export interface OutboundUsage {
  kind: 'policy' | 'rule_set' | 'device_group'
  id: string
  name: string
  detail: string
  href: string
  disabled: boolean
}

/** Resolve configured references, including disabled rules, without claiming a deployed traffic path. */
export function outboundUsage(outboundId: string, policies: UsagePolicy[], ruleSets: UsageRuleSet[], groups: UsageDeviceGroup[]): OutboundUsage[] {
  const result: OutboundUsage[] = []
  const affectedPolicies = new Set<string>()
  const sets = new Map(ruleSets.map(set => [set.id, set]))
  const seen = new Set<string>()
  const matches = (action?: UsageAction) => action?.kind === 'outbound_group' && action.outbound_group_id === outboundId
  function add(kind: OutboundUsage['kind'], id: string, name: string | undefined, detail: string, disabled = false, ruleId?: string) {
    const href = navigationHref({ page: kind === 'device_group' ? 'devices' : 'rules', resource: kind, id, ruleId })
    const key = `${kind}\0${id}\0${detail}\0${ruleId ?? ''}`
    if (!seen.has(key)) { seen.add(key); result.push({ kind, id, name: name || id, detail, disabled, href }) }
  }
  for (const set of ruleSets) for (const rule of set.rules ?? []) {
    if (matches(rule.action)) add('rule_set', set.id, set.name, `Rule: ${rule.name || rule.id}`, rule.enabled === false, rule.id)
  }
  for (const policy of policies) {
    const inspect = (rule: UsageRule, phase: string) => {
      if (!matches(rule.action)) return
      affectedPolicies.add(policy.id)
      add('policy', policy.id, policy.name, `${phase}: ${rule.name || rule.id}`, rule.enabled === false, rule.id)
    }
    for (const rule of [...policy.mandatory_rules ?? [], ...policy.mandatory ?? []]) inspect(rule, 'Mandatory rule')
    for (const rule of policy.exceptions ?? []) inspect(rule, 'Exception')
    for (const rule of policy.rules ?? []) inspect(rule, 'Rule')
    const referencedSets = new Set(policy.rule_set_ids ?? [])
    for (const entry of policy.entries ?? []) {
      if (entry.rule) inspect(entry.rule, 'Rule')
      if (entry.rule_set_id) referencedSets.add(entry.rule_set_id)
    }
    for (const setID of referencedSets) {
      const set = sets.get(setID)
      const matchingRules = set?.rules?.filter(rule => matches(rule.action)) ?? []
      if (!matchingRules.length) continue
      affectedPolicies.add(policy.id)
      add('policy', policy.id, policy.name, `References rule set: ${set?.name || setID}`, matchingRules.every(rule => rule.enabled === false))
    }
    for (const [field, label] of [['default_action', 'Default action'], ['unknown_domain_action', 'Unknown-domain action'], ['proxy_failure_action', 'Proxy-failure action']] as const) {
      if (matches(policy[field])) { affectedPolicies.add(policy.id); add('policy', policy.id, policy.name, label) }
    }
  }
  for (const group of groups) if (group.policyId && affectedPolicies.has(group.policyId)) {
    const policy = policies.find(item => item.id === group.policyId)
    add('device_group', group.id, group.name, `Policy: ${policy?.name || group.policyId} · gateway ${group.gatewayId}`, !group.enabled)
  }
  return result.sort((left, right) => left.kind.localeCompare(right.kind) || left.name.localeCompare(right.name) || left.detail.localeCompare(right.detail))
}
