import { describe, expect, it } from 'vitest'
import { attentionItems, coveragePercent, outboundPending, setupSteps } from './overviewModel'
import { formatTimestamp, operationAction, operationLabels, operationTone } from './uiPresentation'
import type { DeviceSummary, FirewallBindingSummary, GatewaySummary, OutboundGroupSummary, OverviewResponse } from './types'

const gateway: GatewaySummary = { id: 'gw1', name: 'Gateway one', endpoint: 'https://gateway.test', health: 'healthy', revision: 1, adapter: 'dae', capabilities: { supported: [] } }
const binding: FirewallBindingSummary = { id: 'fw1', gatewayId: 'gw1', alias: 'lab', addressFamily: 'ipv4', interfaceScope: 'lan', desiredCount: 2, persistedCount: 2, activeCount: 2, drift: false, state: 'observed', observationStatus: 'fresh', observedAt: '2026-10-21T12:00:00Z', ruleIds: ['rule'], verified: false }
const outbound: OutboundGroupSummary = { id: 'out1', name: 'Browser', gatewayId: 'gw1', revision: 2, appliedRevision: 1, observedRevision: 1, nodeIds: ['n1'], candidateCount: 1, mode: 'manual', replacementPolicy: 'block', selectionScope: 'shared_tcp_udp', transportScopes: ['tcp', 'udp'], usedBy: [] }
const device: DeviceSummary = { id: 'd1', name: 'Computer', revision: 1, addresses: [{ family: 'ipv4', address: '192.0.2.5', valid: true }], enrollment: 'enrolled', coverage: 'dual_stack' }
function overview(): OverviewResponse { return { gateways: [gateway], bindings: [binding], providers: [], deviceGroups: [], operations: [], coverage: { ipv4: null, ipv6: null, dualStack: null, incomplete: null, available: false } } }

describe('evidence-based overview', () => {
  it('keeps missing, disabled and malformed coverage unavailable, but preserves an explicitly reported zero', () => {
    expect(coveragePercent(undefined, 'ipv4')).toBeUndefined()
    const c = overview().coverage
    for (const value of [null, -1, 101, Infinity, NaN]) expect(coveragePercent({ ...c, available: true, ipv4: value }, 'ipv4')).toBeUndefined()
    expect(coveragePercent({ ...c, available: false, ipv4: 100 }, 'ipv4')).toBeUndefined()
    expect(coveragePercent({ ...c, available: true, ipv4: 0 }, 'ipv4')).toBe(0)
    expect(coveragePercent({ ...c, available: true, ipv4: 75 }, 'ipv4')).toBe(75)
  })

  it('does not infer client verification from enrollment, observed configuration, or aggregate coverage', () => {
    const data = overview()
    data.coverage = { available: true, ipv4: 100, ipv6: 100, dualStack: 100, incomplete: 0 }
    const steps = setupSteps({ overview: data, devices: [device], outbounds: [outbound] }, 'gw1')
    expect(steps.find(step => step.id === 'firewall')?.state).toBe('complete')
    expect(steps.find(step => step.id === 'verification')?.state).toBe('unknown')
    expect(steps.filter(step => step.state === 'complete')).toHaveLength(3)
  })

  it('requires fresh, count-consistent firewall readback with an explicit no-drift observation', () => {
    for (const change of [{ observationStatus: 'stale' }, { observationStatus: 'error' }, { activeCount: undefined }, { activeCount: 1 }, { persistedCount: 0 }, { drift: undefined }, { drift: true }, { observedAt: undefined }] as Partial<FirewallBindingSummary>[]) {
      const data = overview(); data.bindings = [{ ...binding, ...change }]
      expect(setupSteps({ overview: data }, 'gw1').find(step => step.id === 'firewall')?.state).toBe('pending')
    }
  })

  it('never combines another gateway’s binding, outbound, or policy to complete the selected gateway setup', () => {
    const data = overview()
    data.gateways.push({ ...gateway, id: 'gw2' })
    data.deviceGroups = [{ id: 'dg1', name: 'Work', revision: 1, gatewayId: 'gw1', policyId: 'p1', enabled: true, state: 'desired', drift: false }]
    const steps = setupSteps({ overview: data, outbounds: [outbound] }, 'gw2')
    for (const id of ['firewall', 'outbound', 'devices']) expect(steps.find(step => step.id === id)?.state).toBe('pending')
    expect(setupSteps({ overview: data }, 'missing').find(step => step.id === 'gateway')?.state).toBe('pending')
  })

  it('clears completion claims for a stale snapshot and distinguishes missing from empty outbound inventory', () => {
    expect(setupSteps({ overview: overview(), stale: true, outbounds: [outbound] }).every(step => step.state === 'unknown')).toBe(true)
    expect(setupSteps({ overview: overview() }).find(step => step.id === 'outbound')?.state).toBe('unknown')
    expect(setupSteps({ overview: overview(), outbounds: [] }).find(step => step.id === 'outbound')?.state).toBe('pending')
    expect(attentionItems({ overview: overview(), stale: true, outbounds: [outbound] })).toEqual([])
  })

  it('separates known configuration differences from unknown publication support', () => {
    expect(outboundPending(outbound)).toBe(true)
    expect(outboundPending({ ...outbound, appliedRevision: undefined, observedRevision: undefined })).toBe(false)
    expect(outboundPending({ ...outbound, appliedRevision: 2, observedRevision: 2 })).toBe(false)
    const data = overview()
    data.operations.push({ id: 'op', target: 'gateway:gw1', action: 'apply', status: 'failed', createdAt: '', updatedAt: '' })
    const items = attentionItems({ overview: data, devices: [device], outbounds: [outbound] })
    expect(items.map(item => item.id)).toEqual(['outbounds', 'ungrouped', 'operations'])
    expect(items.find(item => item.id === 'operations')?.detail).toContain('历史记录不代表问题仍未恢复')
  })
})

it('labels configuration success separately from verification and retains unknown action names', () => {
  expect(operationLabels.applied).toBe('配置已应用')
  expect(operationTone('outcome_unknown')).toBe('warn')
  expect(operationAction('custom_adapter_action')).toBe('custom_adapter_action')
  expect(formatTimestamp()).toBe('尚无记录')
  expect(formatTimestamp('not-a-date')).toBe('时间未知')
})
