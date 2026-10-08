import type { NodeSummary, OutboundSourceFilters } from './types'

/** Local membership preview only; the controller validates the saved snapshot. */
export function previewCandidates(filters: OutboundSourceFilters, nodes: NodeSummary[]): NodeSummary[] {
  const contains = (values: string[] | undefined, value: string) => values?.includes(value) ?? false
  return nodes.filter(node => {
    if (!node.supported) return false
    if (filters.provider_ids?.length && !contains(filters.provider_ids, node.providerId)) return false
    if (filters.protocols?.length && !contains(filters.protocols, node.protocol)) return false
    if ((filters.include_node_ids?.length || filters.include_names?.length) && !contains(filters.include_node_ids, node.id) && !contains(filters.include_names, node.name)) return false
    return !contains(filters.exclude_provider_ids, node.providerId) && !contains(filters.exclude_protocols, node.protocol) && !contains(filters.exclude_node_ids, node.id) && !contains(filters.exclude_names, node.name)
  }).sort((a, b) => a.id.localeCompare(b.id))
}

export function filterLines(value: string): string[] { return [...new Set(value.split('\n').map(item => item.trim()).filter(Boolean))] }
