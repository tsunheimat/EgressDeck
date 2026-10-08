import { expect, it } from 'vitest'
import { previewCandidates } from './outboundFilters'
import type { NodeSummary } from './types'

it('previews independent provider/protocol constraints, exact-name inclusion and winning exclusions', () => {
  const node = (id: string, providerId: string, name: string, protocol = 'ss', supported = true): NodeSummary => ({ id, providerId, name, protocol, supported, health: 'unknown', usedBy: [] })
  const inventory = [node('1', 'p1', 'US'), node('2', 'p1', 'us'), node('3', 'p2', 'US'), node('4', 'p1', 'US', 'socks5'), node('5', 'p1', 'US', 'ss', false)]
  expect(previewCandidates({ provider_ids: ['p1'], protocols: ['ss'], include_names: ['US'] }, inventory).map(n => n.id)).toEqual(['1'])
  expect(previewCandidates({ provider_ids: ['p1'], include_names: ['US'], include_node_ids: ['2'], exclude_names: ['US'] }, inventory).map(n => n.id)).toEqual(['2'])
  expect(previewCandidates({ protocols: ['ss'], exclude_provider_ids: ['p2'], exclude_node_ids: ['1'] }, inventory).map(n => n.id)).toEqual(['2'])
})
