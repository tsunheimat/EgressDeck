import { boundedListJSON } from './pagination'
import type {
  ApiErrorBody,
  Capability,
  DeviceExceptionRule,
  DeviceGroupSummary,
  DeviceSummary,
  FirewallBindingSummary,
  FirewallAttachRequest,
  GatewaySummary,
  GatewayProbeResponse,
  GatewayConnectionsResponse,
  GatewayCountersResponse,
  InventoryPlan,
  NodeSummary,
  OperationSummary,
  OutboundGroupSummary,
  OverviewResponse,
  PolicySummary,
  ProviderSummary,
  ProviderRevision,
  ProviderSchedule,
  SelectionSummary,
  SessionSummary,
} from '../types'

export class ControllerApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
    readonly operationId?: string,
  ) {
    super(message)
    this.name = 'ControllerApiError'
  }
}

export interface SelectionRequest {
  nodeId: string
  gatewayId: string
  transportScopes?: string[]
  expectedRevision?: string
}

export interface OperationResult {
  operationId: string
  status: OperationSummary['status']
}

function csrfToken(): string | undefined {
  if (typeof document === 'undefined') return undefined
  return document.cookie.split('; ').find((cookie) => cookie.startsWith('egressdeck_csrf='))?.slice('egressdeck_csrf='.length)
}

type Wire = Record<string, unknown>
function wire(value: unknown): Wire { return value && typeof value === 'object' ? value as Wire : {} }
function text(value: unknown, fallback = ''): string { return typeof value === 'string' ? value : fallback }
function number(value: unknown, fallback = 0): number { return typeof value === 'number' ? value : fallback }
function array<T>(value: unknown): T[] { return Array.isArray(value) ? value as T[] : [] }
function normalizeGateway(value: unknown): GatewaySummary {
  const g = wire(value)
  return { id: text(g.id), name: text(g.name), endpoint: text(g.endpoint), health: (g.health ?? 'unknown') as GatewaySummary['health'], revision: number(g.revision), adapter: text(g.adapter, 'dae'), version: text(g.version) || undefined, capabilities: (g.capabilities ?? { supported: [] }) as GatewaySummary['capabilities'], observedGeneration: typeof g.observed_generation === 'number' ? g.observed_generation : undefined, lastSeenAt: text(g.last_seen_at) || undefined }
}
function normalizeDevice(value: unknown): DeviceSummary {
  const d = wire(value)
  return { id: text(d.id), name: text(d.name), revision: number(d.revision), groupId: text(d.primary_group_id) || undefined, enrollment: (d.enrollment_state ?? 'unenrolled') as DeviceSummary['enrollment'], coverage: (d.coverage ?? 'incomplete') as DeviceSummary['coverage'], exceptions: array<DeviceExceptionRule>(d.exceptions), addresses: array<Wire>(d.addresses).map(a => ({ address: text(a.address), family: a.family as 'ipv4' | 'ipv6', valid: !!a.verified_at, provenance: text(a.provenance) || undefined, verifiedAt: text(a.verified_at) || undefined })) }
}
function normalizeDeviceGroup(value: unknown): DeviceGroupSummary {
  const g = wire(value)
  return { id: text(g.id), name: text(g.name), revision: number(g.revision), gatewayId: text(g.gateway_id), policyId: text(g.policy_id), enabled: g.enabled === true, memberCount: typeof g.member_count === 'number' ? g.member_count : undefined, state: (g.state ?? 'desired') as DeviceGroupSummary['state'], drift: g.drift === true }
}
function normalizeBinding(value: unknown): FirewallBindingSummary {
  const b = wire(value)
  return { id: text(b.id), gatewayId: text(b.gateway_id), alias: typeof b.alias === 'string' ? b.alias : text(wire(b.alias).name), addressFamily: (b.address_family ?? b.family ?? 'ipv4') as FirewallBindingSummary['addressFamily'], interfaceScope: text(b.interface_scope), persistedCount: typeof b.persisted_count === 'number' ? b.persisted_count : undefined, activeCount: typeof b.active_count === 'number' ? b.active_count : undefined, drift: typeof b.drift === 'boolean' ? b.drift : undefined, desiredCount: number(b.desired_count), observedAt: text(b.observed_at) || undefined, lastAttemptAt: text(b.last_attempt_at) || undefined, observationStatus: (b.observation_status ?? 'never_read') as FirewallBindingSummary['observationStatus'], observationError: text(b.observation_error) || undefined, ruleIds: array(b.rule_ids), aliasUUID: text(b.alias_uuid) || undefined, verified: false, state: (b.state ?? 'desired') as FirewallBindingSummary['state'] }
}
function normalizeProvider(value: unknown): ProviderSummary {
  const p = wire(value)
  const active = number(p.active_revision)
  const staged = number(p.staged_revision)
  return { id: text(p.id), name: text(p.name), revision: number(p.revision), source: text(p.source), fetchRoute: text(p.fetch_route, 'direct'), sourceKind: (p.source_kind ?? 'url') as ProviderSummary['sourceKind'], format: text(p.format), state: (p.state ?? (staged ? 'staged' : active ? 'active' : 'never_fetched')) as ProviderSummary['state'], nodeCount: typeof p.node_count === 'number' ? p.node_count : undefined, unsupportedCount: typeof p.unsupported_count === 'number' ? p.unsupported_count : undefined, activeRevision: active ? String(active) : undefined, stagedRevision: staged ? String(staged) : undefined, lastAttemptAt: text(p.last_attempt_at) || undefined, lastSuccessAt: text(p.last_success_at) || undefined, gatewayStates: array(p.gateway_states) }
}
function normalizeNode(value: unknown): NodeSummary {
  const n = wire(value)
  return { id: text(n.id), name: text(n.name), providerId: text(n.provider_id), protocol: text(n.protocol, text(wire(n.definition).protocol, 'unknown')), health: (n.health ?? 'unknown') as NodeSummary['health'], supported: n.supported === true, usedBy: array(n.used_by) }
}
function normalizeOutbound(value: unknown): OutboundGroupSummary {
  const g = wire(value)
  const ids = array<string>(g.node_ids)
  return { id: text(g.id), name: text(g.name), revision: number(g.revision), mode: (g.mode ?? 'manual') as OutboundGroupSummary['mode'], gatewayId: text(g.gateway_id), nodeIds: ids, sourceFilters: g.source_filters as OutboundGroupSummary['sourceFilters'], candidateCount: ids.length, replacementPolicy: (g.replacement_policy ?? 'block') as 'block' | 'none', transportScopes: array(g.transport_scopes), desired: text(g.desired) || undefined, applied: text(g.applied) || undefined, observed: text(g.observed) || undefined, usedBy: array(g.used_by) }
}
function normalizeOperation(value: unknown): OperationSummary {
  const o = wire(value)
  const target = wire(o.target)
  return { id: text(o.id), target: typeof o.target === 'string' ? o.target : `${text(target.kind)}:${text(target.id)}`, action: text(o.action), status: o.status as OperationSummary['status'], requestedGeneration: number(o.requested_generation), createdAt: text(o.created_at), updatedAt: text(o.updated_at), error: text(o.error) || undefined, views: o.views as OperationSummary['views'] }
}
function normalizeAccepted(value: unknown): OperationResult {
  const body = wire(value)
  const id = text(body.operation_id, text(body.id))
  if (!id) throw new ControllerApiError('The controller did not return a durable operation identifier. Reload observed state before retrying.', 502, 'operation_identifier_missing')
  return { operationId: id, status: body.status as OperationSummary['status'] }
}
function normalizeOverview(value: unknown): OverviewResponse {
  const body = wire(value)
  const coverage = wire(body.coverage)
  const metric = (key: string): number | null => coverage.available === true && typeof coverage[key] === 'number' ? coverage[key] as number : null
  return { gateways: array(body.gateways).map(normalizeGateway), bindings: array(body.bindings).map(normalizeBinding), providers: array(body.providers).map(normalizeProvider), deviceGroups: array(body.device_groups).map(normalizeDeviceGroup), operations: array(body.operations).map(normalizeOperation), coverage: { ipv4: metric('ipv4'), ipv6: metric('ipv6'), dualStack: metric('dual_stack'), incomplete: metric('incomplete'), available: coverage.available === true } }
}

/**
 * The frontend talks only to the controller contract. It never calls dae or
 * OPNsense directly and never presents a successful mutation before readback.
 */
export class ControllerApi {
  constructor(private readonly baseUrl = '/api/v1', private readonly fetcher: typeof fetch = (...args) => globalThis.fetch(...args)) {}

  private async request<T>(path: string, init?: RequestInit, boundedList = false): Promise<T> {
    const csrf = init?.method && !['GET', 'HEAD', 'OPTIONS'].includes(init.method) ? csrfToken() : undefined
    const response = await this.fetcher(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
        ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
        ...init?.headers,
      },
      credentials: 'include',
    })
    if (!response.ok) {
      let body: ApiErrorBody & { error?: string | (ApiErrorBody & { operation_id?: string }) } = {}
      try {
        body = (await response.json()) as ApiErrorBody
      } catch {
        // Preserve the HTTP status when the server did not return JSON.
      }
      const detail = typeof body.error === 'object' ? body.error : body
      throw new ControllerApiError(detail.message ?? `Controller request failed (${response.status})`, response.status, detail.code ?? (typeof body.error === 'string' ? body.error : undefined), detail.operationId ?? ('operation_id' in detail ? detail.operation_id : undefined))
    }
    if (response.status === 204) return undefined as T
    return (boundedList ? await boundedListJSON(response, init?.signal ?? undefined) : await response.json()) as T
  }

  private async list<T>(path: string, signal?: AbortSignal): Promise<T[]> {
    const items: T[] = []
    const seen = new Set<string>()
    let cursor: string | undefined
    for (let page = 0; page < 100; page++) {
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError')
      const query = new URLSearchParams(path.split('?')[1] ?? '')
      query.set('limit', '100')
      if (cursor) query.set('cursor', cursor)
      const pagePath = `${path.split('?')[0]}?${query.toString()}`
      const body = await this.request<T[] | { items?: T[]; next_cursor?: string }>(pagePath, { signal }, true)
      const batch = Array.isArray(body) ? body : body.items ?? []
      if (!Array.isArray(batch) || batch.length > 500 || items.length + batch.length > 10_000) {
        throw new ControllerApiError('The collection exceeds the browser list limit. Use the paginated API to inspect all items.', 413, 'collection_limit')
      }
      items.push(...batch)
      cursor = Array.isArray(body) ? undefined : body.next_cursor
      if (!cursor) return items
      if (typeof cursor !== 'string' || cursor.length > 2048 || seen.has(cursor)) {
        throw new ControllerApiError('The controller returned an invalid or repeated collection cursor.', 502, 'invalid_cursor')
      }
      seen.add(cursor)
    }
    throw new ControllerApiError('The collection exceeds the browser page limit. Use the paginated API to inspect all items.', 413, 'collection_limit')
  }

  overview(signal?: AbortSignal): Promise<OverviewResponse> {
    return this.request<unknown>('/overview', { signal }).then(normalizeOverview)
  }

  gateways(signal?: AbortSignal): Promise<GatewaySummary[]> {
    return this.list<unknown>('/gateways', signal).then((items) => items.map(normalizeGateway))
  }

  gatewayProbeNode(gatewayId: string, nodeId: string): Promise<GatewayProbeResponse> { return this.request(`/gateways/${encodeURIComponent(gatewayId)}/probes/nodes/${encodeURIComponent(nodeId)}`, { method: 'POST', body: '{}' }) }
  gatewayProbeGroup(gatewayId: string, groupId: string): Promise<GatewayProbeResponse> { return this.request(`/gateways/${encodeURIComponent(gatewayId)}/probes/groups/${encodeURIComponent(groupId)}`, { method: 'POST', body: '{}' }) }
  gatewayConnections(gatewayId: string, signal?: AbortSignal): Promise<GatewayConnectionsResponse> { return this.request(`/gateways/${encodeURIComponent(gatewayId)}/connections`, { signal }) }
  gatewayCounters(gatewayId: string, signal?: AbortSignal): Promise<GatewayCountersResponse> { return this.request(`/gateways/${encodeURIComponent(gatewayId)}/counters`, { signal }) }

  bindings(signal?: AbortSignal): Promise<FirewallBindingSummary[]> {
    return this.list<unknown>('/firewall-bindings', signal).then(items => items.map(normalizeBinding))
  }

  providers(signal?: AbortSignal): Promise<ProviderSummary[]> {
    return this.list<unknown>('/providers', signal).then(items => items.map(normalizeProvider))
  }

  nodes(signal?: AbortSignal): Promise<NodeSummary[]> {
    return this.list<unknown>('/nodes', signal).then(items => items.map(normalizeNode))
  }

  outboundGroups(signal?: AbortSignal): Promise<OutboundGroupSummary[]> {
    return this.list<unknown>('/outbound-groups', signal).then(items => items.map(normalizeOutbound))
  }

  devices(signal?: AbortSignal): Promise<DeviceSummary[]> {
    return this.list<unknown>('/devices', signal).then(items => items.map(normalizeDevice))
  }

  deviceGroups(signal?: AbortSignal): Promise<DeviceGroupSummary[]> {
    return this.list<unknown>('/device-groups', signal).then(items => items.map(normalizeDeviceGroup))
  }

  policies(signal?: AbortSignal): Promise<PolicySummary[]> {
    return this.list<Wire>('/policies', signal).then(items => items.map(p => ({ id: text(p.id), name: text(p.name), ruleCount: array(p.entries).length, finalAction: text(wire(p.default_action).kind, text(p.default_action, 'unknown')) as PolicySummary['finalAction'], unknownDomainAction: text(wire(p.unknown_domain_action).kind, text(p.unknown_domain_action, 'unknown')) as PolicySummary['unknownDomainAction'], proxyFailure: text(p.proxy_failure, 'block_matching_traffic') as PolicySummary['proxyFailure'], validation: 'unknown' })))
  }

  capabilities(signal?: AbortSignal): Promise<{ capabilities: Partial<Record<Capability, boolean>> }> { return this.request('/capabilities', { signal }) }
  session(signal?: AbortSignal): Promise<SessionSummary> { return this.request('/auth/session', { signal }) }
  logout(): Promise<void> { return this.request('/auth/logout', { method: 'POST' }) }
  get loginURL(): string { return `${this.baseUrl}/auth/oidc/login` }

  createDevice(body: unknown): Promise<DeviceSummary> { return this.request('/devices', { method: 'POST', body: JSON.stringify(body) }).then(normalizeDevice) }
  updateDevice(id: string, body: unknown, revision: number): Promise<DeviceSummary> { return this.request(`/devices/${encodeURIComponent(id)}`, { method: 'PUT', headers: { 'If-Match': String(revision) }, body: JSON.stringify(body) }).then(normalizeDevice) }
  deleteDevice(id: string, revision: number): Promise<void> { return this.request(`/devices/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { 'If-Match': String(revision) } }) }
  createDeviceGroup(body: unknown): Promise<DeviceGroupSummary> { return this.request('/device-groups', { method: 'POST', body: JSON.stringify(body) }).then(normalizeDeviceGroup) }
  updateDeviceGroup(id: string, body: unknown, revision: number): Promise<DeviceGroupSummary> { return this.request(`/device-groups/${encodeURIComponent(id)}`, { method: 'PUT', headers: { 'If-Match': String(revision) }, body: JSON.stringify(body) }).then(normalizeDeviceGroup) }
  attachBinding(body: FirewallAttachRequest): Promise<FirewallBindingSummary> { return this.request<Wire>('/firewall-bindings', { method: 'POST', body: JSON.stringify(body) }).then(result => normalizeBinding(result.view ?? result)) }
  binding(id: string): Promise<FirewallBindingSummary> { return this.request<Wire>(`/firewall-bindings/${encodeURIComponent(id)}`).then(result => normalizeBinding(result.view ?? result)) }
  readbackBinding(id: string): Promise<FirewallBindingSummary> { return this.request<Wire>(`/firewall-bindings/${encodeURIComponent(id)}/readback`).then(result => normalizeBinding(result.view ?? result)) }
  createGateway(body: unknown): Promise<GatewaySummary> { return this.request('/gateways', { method: 'POST', body: JSON.stringify(body) }).then(normalizeGateway) }
  createProvider(body: unknown): Promise<ProviderSummary> { return this.request('/providers', { method: 'POST', body: JSON.stringify(body) }).then(normalizeProvider) }
  updateProvider(id: string, body: { name?: string; source?: string; format?: string; fetch_route?: string }, revision: number): Promise<ProviderSummary> { return this.request(`/providers/${encodeURIComponent(id)}`, { method: 'PATCH', headers: { 'If-Match': String(revision) }, body: JSON.stringify(body) }).then(normalizeProvider) }
  deleteProvider(id: string, revision: number): Promise<void> { return this.request(`/providers/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { 'If-Match': String(revision) } }) }
  providerRevisions(id: string): Promise<ProviderRevision[]> { return this.list<ProviderRevision & { report?: ProviderRevision['parse_report'] }>(`/providers/${encodeURIComponent(id)}/revisions`).then(items => items.map(item => ({ ...item, parse_report: item.parse_report ?? item.report ?? {} }))) }
  providerSchedule(id: string): Promise<ProviderSchedule> { return this.request(`/providers/${encodeURIComponent(id)}/schedule`) }
  saveProviderSchedule(id: string, body: { enabled: boolean; interval_seconds: number; auto_apply?: false }, revision: number): Promise<ProviderSchedule> { return this.request(`/providers/${encodeURIComponent(id)}/schedule`, { method: 'PUT', headers: { 'If-Match': String(revision) }, body: JSON.stringify(body) }) }
  stageProvider(id: string, body: { content: string; format: string }, key: string): Promise<OperationResult> { return this.request(`/providers/${encodeURIComponent(id)}/stage`, { method: 'POST', headers: { 'Idempotency-Key': key }, body: JSON.stringify(body) }).then(normalizeAccepted) }
  createOutboundGroup(body: unknown): Promise<OutboundGroupSummary> { return this.request('/outbound-groups', { method: 'POST', body: JSON.stringify(body) }).then(normalizeOutbound) }
  updateOutboundGroup(id: string, body: unknown, revision: number): Promise<OutboundGroupSummary> { return this.request(`/outbound-groups/${encodeURIComponent(id)}`, { method: 'PUT', headers: { 'If-Match': String(revision) }, body: JSON.stringify(body) }).then(normalizeOutbound) }
  selections(id: string): Promise<SelectionSummary[]> { return this.list(`/outbound-groups/${encodeURIComponent(id)}/selection`) }
  policyDocuments<T>(): Promise<T[]> { return this.list('/policies') }
  policy<T>(id: string): Promise<T> { return this.request(`/policies/${encodeURIComponent(id)}`) }
  createPolicy<T>(body: unknown): Promise<T> { return this.request('/policies', { method: 'POST', body: JSON.stringify(body) }) }
  updatePolicy<T>(id: string, body: unknown, revision: number): Promise<T> { return this.request(`/policies/${encodeURIComponent(id)}`, { method: 'PUT', headers: { 'If-Match': String(revision) }, body: JSON.stringify(body) }) }
  deletePolicy(id: string, revision: number): Promise<void> { return this.request(`/policies/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { 'If-Match': String(revision) } }) }
  previewPolicy<T>(body: unknown): Promise<T> { return this.request('/deployments/preview', { method: 'POST', body: JSON.stringify(body) }) }
  createInventoryPlan(body: { gateway_id: string; previous_operation_id?: string }): Promise<InventoryPlan> { return this.request('/deployments/plan', { method: 'POST', body: JSON.stringify(body) }) }
  inventoryPlan(checksum: string, signal?: AbortSignal): Promise<InventoryPlan> { return this.request(`/deployments/plans/${encodeURIComponent(checksum)}`, { signal }) }
  explainPolicy<T>(manifest: unknown, packet: unknown): Promise<T> { return this.request('/policies/explain', { method: 'POST', body: JSON.stringify({ manifest, packet }) }) }
  ruleSetDocuments<T>(): Promise<T[]> { return this.list('/rule-sets') }
  createRuleSet<T>(body: unknown): Promise<T> { return this.request('/rule-sets', { method: 'POST', body: JSON.stringify(body) }) }
  updateRuleSet<T>(id: string, body: unknown, revision: number): Promise<T> { return this.request(`/rule-sets/${encodeURIComponent(id)}`, { method: 'PUT', headers: { 'If-Match': String(revision) }, body: JSON.stringify(body) }) }
  deleteRuleSet(id: string, revision: number): Promise<void> { return this.request(`/rule-sets/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { 'If-Match': String(revision) } }) }
  outboundGroupDocuments<T>(): Promise<T[]> { return this.list('/outbound-groups') }

  operations(signal?: AbortSignal): Promise<OperationSummary[]> {
    return this.list<unknown>('/operations', signal).then(items => items.map(normalizeOperation))
  }
  auditEvents<T>(signal?: AbortSignal): Promise<T[]> { return this.list('/audit-events', signal) }

  refreshProvider(providerId: string, idempotencyKey: string): Promise<OperationResult> {
    return this.request<unknown>(`/providers/${encodeURIComponent(providerId)}/refresh`, {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: '{}',
    }).then(normalizeAccepted)
  }

  applyProvider(providerId: string, revision: string, idempotencyKey: string, expectedActiveRevision?: number): Promise<OperationResult> {
    return this.request<unknown>(`/providers/${encodeURIComponent(providerId)}/revisions/${encodeURIComponent(revision)}/apply`, {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey, ...(expectedActiveRevision !== undefined ? { 'If-Match': String(expectedActiveRevision) } : {}) },
      body: '{}',
    }).then(normalizeAccepted)
  }

  setSelection(outboundGroupId: string, request: SelectionRequest, idempotencyKey: string): Promise<OperationResult> {
    return this.request<unknown>(`/outbound-groups/${encodeURIComponent(outboundGroupId)}/selection`, {
      method: 'PUT',
      headers: { 'Idempotency-Key': idempotencyKey, ...(request.expectedRevision ? { 'If-Match': request.expectedRevision } : {}) },
      body: JSON.stringify({ node_id: request.nodeId, gateway_id: request.gatewayId, transport_scopes: request.transportScopes }),
    }).then(normalizeAccepted)
  }

  operation(operationId: string, signal?: AbortSignal): Promise<OperationSummary> {
    return this.request<unknown>(`/operations/${encodeURIComponent(operationId)}`, { signal }).then(normalizeOperation)
  }

  async waitForOperation(operationId: string, signal?: AbortSignal): Promise<OperationSummary> {
    for (let attempt = 0; attempt < 30; attempt++) {
      const operation = await this.operation(operationId, signal)
      if (['applied', 'partially_applied', 'failed', 'outcome_unknown'].includes(operation.status) || (operation.status === 'staged' && ['stage', 'refresh'].includes(operation.action))) return operation
      await new Promise<void>((resolve, reject) => {
        if (signal?.aborted) { reject(new DOMException('Aborted', 'AbortError')); return }
        const abort = () => { clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')) }
        const timer = setTimeout(() => { signal?.removeEventListener('abort', abort); resolve() }, 500)
        signal?.addEventListener('abort', abort, { once: true })
      })
    }
    throw new ControllerApiError(`Operation ${operationId} is still in progress. Refresh Activity to read its outcome before retrying.`, 202, 'operation_pending', operationId)
  }

  supports(gateway: GatewaySummary | undefined, capability: Capability): boolean {
    return gateway?.capabilities.supported.includes(capability) ?? false
  }
}

export function randomIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID()
  return `web-${Date.now()}-${Math.random().toString(16).slice(2)}`
}
