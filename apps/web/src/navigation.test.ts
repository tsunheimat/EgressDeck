import { describe, expect, it } from 'vitest'
import { visibleNavigation } from './navigation'
import type { GatewaySummary } from './types'

const gateway: GatewaySummary = {
  id: 'gw-1',
  name: 'lab-gateway',
  endpoint: 'https://gateway.example.test',
  health: 'healthy',
  revision: 1,
  adapter: 'dae',
  capabilities: { supported: ['inventory.read', 'provider.stage', 'events.resume'] },
}

describe('visibleNavigation', () => {
  it('marks capability dependent pages unavailable instead of claiming support', () => {
    const items = visibleNavigation([gateway], gateway.id)
    expect(items.find((item) => item.id === 'subscriptions')?.disabledReason).toBeUndefined()
    expect(items.find((item) => item.id === 'rules')?.disabledReason).toContain('policy.validate')
    expect(items.find((item) => item.id === 'activity')?.disabledReason).toBeUndefined()
  })

  it('explains that a gateway must be registered when there is no selection', () => {
    const items = visibleNavigation([], undefined)
    expect(items.find((item) => item.id === 'proxies')?.disabledReason).toBe('Register a gateway to inspect capabilities')
  })
})
