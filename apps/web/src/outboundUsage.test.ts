import { describe, expect, it } from 'vitest'
import { outboundUsage, type UsagePolicy, type UsageRuleSet } from './outboundUsage'
import { navigationHref, readNavigationTarget } from './navigationTarget'

describe('outbound references', () => {
  it('resolves ordered rules, reused rule sets, defaults and device groups by stable identity', () => {
    const sets: UsageRuleSet[] = [{ id: 'rs1', name: 'Shared', rules: [{ id: 'r1', name: 'Remote service', enabled: true, action: { kind: 'outbound_group', outbound_group_id: 'exit1' } }] }]
    const policies: UsagePolicy[] = [{ id: 'p1', name: 'Work', entries: [{ rule_set_id: 'rs1' }], rule_set_ids: ['rs1'], unknown_domain_action: { kind: 'outbound_group', outbound_group_id: 'exit1' } }, { id: 'p2', name: 'Other', default_action: { kind: 'outbound_group', outbound_group_id: 'exit2' } }]
    const references = outboundUsage('exit1', policies, sets, [{ id: 'g1', name: 'Development', policyId: 'p1', gatewayId: 'gw1', enabled: true }, { id: 'g2', name: 'Other', policyId: 'p2', gatewayId: 'gw1', enabled: true }])
    expect(references.map(item => [item.kind, item.id])).toEqual([['device_group', 'g1'], ['policy', 'p1'], ['policy', 'p1'], ['rule_set', 'rs1']])
    expect(references.find(item => item.kind === 'rule_set')?.href).toBe('#/rules?resource=rule_set&id=rs1&rule=r1')
    expect(references.some(item => item.id === 'g2')).toBe(false)
  })

  it('keeps disabled references visible and does not infer usage from names or Direct', () => {
    const refs = outboundUsage('exit1', [{ id: 'p1', mandatory: [{ id: 'r1', enabled: false, action: { kind: 'outbound_group', outbound_group_id: 'exit1' } }], exceptions: [{ id: 'r2', action: { kind: 'direct', outbound_group_id: 'exit1' } }], rules: [{ id: 'r3', name: 'exit1', action: { kind: 'block' } }] }], [], [{ id: 'g1', name: 'Disabled group', policyId: 'p1', enabled: false, gatewayId: 'gw1' }])
    expect(refs).toHaveLength(2)
    expect(refs.every(ref => ref.disabled)).toBe(true)
    expect(refs.find(ref => ref.kind === 'policy')?.detail).toBe('Mandatory rule: r1')
  })

  it('makes encoded links round-trip without letting identifiers choose a page', () => {
    const target = { page: 'rules' as const, resource: 'policy' as const, id: 'a /?&b', ruleId: 'rule#1' }
    expect(readNavigationTarget(navigationHref(target))).toEqual(target)
    expect(readNavigationTarget('#/untrusted?resource=invalid&id=1')).toEqual({ page: 'overview', resource: undefined, id: '1', ruleId: undefined })
  })
})
