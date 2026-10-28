import { describe, expect, it } from 'vitest'
import { actionName, auditActionName, auditOutcomeName, diagnosticLabels, diagnosticPresentation, uiLabel } from './localization'

describe('Chinese display boundary', () => {
  it('labels state, routing, health and capabilities without mutating the wire values', () => {
    const wire = { status: 'applied', action: 'outbound_group', capability: 'selection.set_runtime' }
    expect(uiLabel(wire.status)).toBe('已应用')
    expect(uiLabel(wire.action)).toBe('代理组')
    expect(uiLabel(wire.capability)).toBe('运行时节点选择')
    expect(wire).toEqual({ status: 'applied', action: 'outbound_group', capability: 'selection.set_runtime' })
    expect(uiLabel('observed')).toBe('已观测')
    expect(uiLabel('verified')).toBe('已验证')
    expect(uiLabel('outcome_unknown')).toBe('结果未确认')
    expect(uiLabel('unavailable')).toBe('不可用')
    expect(uiLabel('healthy')).toBe('健康')
    expect(uiLabel('ipv6')).toBe('IPv6')
  })
  it('never presents an unknown future state as success or translates user data', () => {
    expect(uiLabel('future_state')).toBe('未识别（future_state）')
    expect(uiLabel(undefined)).toBe('未知')
    expect(uiLabel(false)).toBe('否')
    expect(actionName('custom_action')).toBe('未识别（custom_action）')
    expect(actionName('selection')).toBe('切换代理节点')
  })
  it('keeps authoritative diagnostics intact behind Chinese summaries', () => {
    const original = 'provider has active or retained runtime references'
    expect(diagnosticPresentation(original, 'provider_in_use')).toEqual({ summary: diagnosticLabels.provider_in_use, original })
    const unknown = '<script>alert(1)</script> adapter-specific new diagnostic'
    expect(diagnosticPresentation(unknown, 'future_error').original).toBe(unknown)
    expect(diagnosticPresentation(unknown).summary).toContain('原始内容')
    expect(diagnosticPresentation('资源版本已变化。')).toEqual({ summary: '资源版本已变化。' })
    expect(diagnosticPresentation('resource changed。请刷新。').original).toBe('resource changed。请刷新。')
    expect(diagnosticPresentation('Failed to fetch').summary).toContain('无法连接控制器')
  })
  it('does not confuse acceptance, application, observation and traffic verification', () => {
    for (const status of ['accepted', 'applied', 'observed', 'outcome_unknown', 'failed_partial']) expect(uiLabel(status)).not.toContain('已验证')
    expect(diagnosticPresentation('readback unavailable', 'operation_state_unavailable').summary).toContain('不要创建替代请求')
    expect(diagnosticPresentation('wait cancelled', 'request_cancelled').summary).toContain('不代表远端操作已撤销')
  })
})

it('renders management audit routes and HTTP statuses without claiming client verification', () => {
  expect(auditActionName('POST /api/v1/policies')).toBe('提交策略请求')
  expect(auditActionName('POST /api/v1/policies/explain')).toBe('解释策略路径')
  expect(auditActionName('PUT /api/v1/outbound-groups/{id}/selection')).toBe('更改节点选择')
  expect(auditActionName('apply')).toBe('应用')
  expect(uiLabel('management_request')).toBe('管理请求')
  expect(auditOutcomeName('200')).toBe('请求成功（HTTP 200）')
  expect(auditOutcomeName('202')).toBe('请求已受理（HTTP 202）')
  expect(auditOutcomeName('403')).toBe('请求被拒绝（HTTP 403）')
  expect(auditOutcomeName('500')).toBe('服务端错误（HTTP 500）')
  expect(auditOutcomeName('verified')).toBe('操作回读已确认')
  expect(auditOutcomeName('future_status')).toBe('未识别（future_status）')
})

it('does not resolve inherited object properties as translated labels', () => {
  for (const value of ['constructor', 'toString', '__proto__']) {
    expect(uiLabel(value)).toBe(`未识别（${value}）`)
    expect(actionName(value)).toBe(`未识别（${value}）`)
    expect(typeof diagnosticPresentation('adapter diagnostic', value).summary).toBe('string')
    expect(auditActionName(`POST /api/v1/${value}`)).toBe('提交管理请求')
  }
})
