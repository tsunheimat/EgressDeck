export type Capability =
  | 'inventory.read'
  | 'provider.stage'
  | 'provider.publish_hot'
  | 'group.publish_hot'
  | 'selection.set_runtime'
  | 'selection.persist_restart'
  | 'policy.validate'
  | 'policy.apply_generation'
  | 'probe.node'
  | 'probe.group'
  | 'connections.observe'
  | 'connections.close_filtered'
  | 'traffic.proxy_counters'
  | 'traffic.direct_counters'
  | 'events.resume'

export type Health = 'healthy' | 'degraded' | 'offline' | 'unknown'
export type StateKind = 'desired' | 'applied' | 'observed' | 'verified'

export interface CapabilitySet {
  supported: Capability[]
  restrictions?: Partial<Record<Capability, string>>
}

export interface GatewaySummary {
  id: string
  name: string
  endpoint: string
  health: Health
  version?: string
  capabilities: CapabilitySet
  observedGeneration?: number
  lastSeenAt?: string
  revision: number
  adapter: string
}

export interface FirewallBindingSummary {
  id: string
  gatewayId: string
  alias: string
  addressFamily: 'ipv4' | 'ipv6' | 'dual'
  interfaceScope: string
  persistedCount?: number
  activeCount?: number
  drift?: boolean
  state: StateKind
  desiredCount: number
  observedAt?: string
  lastAttemptAt?: string
  observationStatus: 'never_read' | 'fresh' | 'stale' | 'error'
  observationError?: string
  ruleIds: string[]
  aliasUUID?: string
  verified: false
}

export interface FirewallAttachRequest {
  gateway_id: string
  alias: string
  alias_uuid?: string
  alias_type: 'host'
  family: 'ipv4' | 'ipv6'
  interface_scope: string
  rule_ids: string[]
}

export interface ProviderSummary {
  id: string
  name: string
  revision: number
  source?: string
  fetchRoute: string
  sourceKind: 'url' | 'node-link' | 'upload' | 'manual'
  format: string
  state: 'active' | 'staged' | 'error' | 'never_fetched'
  nodeCount?: number
  unsupportedCount?: number
  lastAttemptAt?: string
  lastSuccessAt?: string
  activeRevision?: string
  stagedRevision?: string
  gatewayStates: Array<{
    gatewayId: string
    state: 'published' | 'pending' | 'failed' | 'unknown'
    observedRevision?: string
  }>
}

export interface ProviderSchedule {
  provider_id: string
  revision: number
  enabled: boolean
  interval_seconds: number
  auto_apply: false
  eligible: boolean
  next_due_at?: string
  last_attempt_at?: string
  last_success_at?: string
  last_error?: string
  last_operation_id?: string
  running: boolean
}

export interface NodeSummary {
  id: string
  providerId: string
  name: string
  protocol: string
  health: Health
  supported: boolean
  usedBy: string[]
}

export interface OutboundGroupSummary {
  id: string
  name: string
  revision: number
  nodeIds: string[]
  appliedRevision?: number
  observedRevision?: number
  appliedGeneration?: number
  appliedNodeIds?: string[]
  sourceFilters?: OutboundSourceFilters
  replacementPolicy: 'block' | 'none'
  mode: 'manual' | 'automatic'
  candidateCount: number
  desired?: string
  applied?: string
  observed?: string
  gatewayId: string
  selectionScope: 'shared_tcp_udp' | 'independent_transport'
  transportScopes: string[]
  usedBy: string[]
}

export interface OutboundSourceFilters {
  provider_ids?: string[]
  protocols?: string[]
  exclude_provider_ids?: string[]
  exclude_protocols?: string[]
  include_node_ids?: string[]
  exclude_node_ids?: string[]
  include_names?: string[]
  exclude_names?: string[]
}

export interface DeviceExceptionRule {
  id: string
  name?: string
  enabled: boolean
  order?: number
  action: { kind: 'direct' | 'proxy' | 'block' | 'outbound_group'; outbound_group_id?: string }
  match: {
    domain_exact?: string[]; domain_suffix?: string[]; domain_sets?: string[]
    destination_cidrs?: string[]; destination_ip?: string[]
    destination_ports?: Array<{ from: number; to: number }>; ports?: Array<{ from: number; to: number }>
    transport?: Array<'tcp' | 'udp' | 'quic'>; transports?: Array<'tcp' | 'udp' | 'quic'>
    address_families?: Array<'ipv4' | 'ipv6'>; families?: Array<'ipv4' | 'ipv6'>
  }
}

export interface DeviceSummary {
  id: string
  name: string
  revision: number
  addresses: Array<{ family: 'ipv4' | 'ipv6'; address: string; valid: boolean; provenance?: string; verifiedAt?: string }>
  exceptions?: DeviceExceptionRule[]
  groupId?: string
  enrollment: 'enrolled' | 'pending' | 'blocked' | 'bypassed' | 'unmanaged' | 'unenrolled'
  coverage: 'ipv4' | 'ipv6' | 'dual_stack' | 'incomplete'
  lastVerifiedAt?: string
}

export interface DeviceGroupSummary {
  id: string
  name: string
  revision: number
  gatewayId: string
  memberCount?: number
  policyId?: string
  enabled: boolean
  state: StateKind
  drift: boolean
}

export interface PolicySummary {
  id: string
  name: string
  ruleCount: number
  finalAction: 'direct' | 'proxy' | 'block'
  unknownDomainAction: 'policy_default' | 'proxy' | 'block'
  proxyFailure: 'block_matching_traffic' | 'quarantine' | 'direct'
  validation: 'valid' | 'invalid' | 'unknown'
  validationMessage?: string
}

export interface OperationSummary {
  id: string
  target: string
  action: string
  status: 'draft' | 'validated' | 'staged' | 'applying' | 'verifying' | 'applied' | 'partially_applied' | 'failed' | 'outcome_unknown'
  requestedGeneration?: number
  createdAt: string
  updatedAt: string
  error?: string
  views?: Partial<Record<StateKind, { generation: number; revision?: string; status?: string; at: string; data?: unknown }>>
}

export interface OverviewResponse {
  gateways: GatewaySummary[]
  bindings: FirewallBindingSummary[]
  providers: ProviderSummary[]
  deviceGroups: DeviceGroupSummary[]
  operations: OperationSummary[]
  coverage: { ipv4: number | null; ipv6: number | null; dualStack: number | null; incomplete: number | null; available?: boolean }
}

export interface ProviderRevision {
  provider_id: string
  number: number
  state: 'staged' | 'active' | 'failed' | 'superseded'
  nodes: Array<{ id: string; name: string; supported: boolean; definition?: { protocol?: string } }>
  parse_report: { unsupported?: Array<{ name?: string; reason?: string; [key: string]: unknown }>; warnings?: string[]; errors?: string[] }
  changes: { added?: unknown[]; removed?: unknown[]; changed?: unknown[]; renamed?: unknown[]; unchanged: number; noop: boolean }
  created_at: string
}

export interface SelectionSummary {
  group_id: string
  scope: { gateway_id: string; transport: string }
  desired_node_id?: string
  applied_node_id?: string
  observed_node_id?: string
  generation: number
  revision: number
}

export interface SessionSummary {
  subject: string
  roles: string[]
  expires_at?: string
}

export interface ApiErrorBody {
  code?: string
  message?: string
  fieldErrors?: Record<string, string>
  operationId?: string
}

export interface GatewayProbeResponse {
  gateway_id: string
  gateway_name: string
  observed_at: string
  target_kind: 'node' | 'group'
  target_id: string
  probe: { target: string; ok: boolean; latency_ms: number; observed_at: string; error?: string }
}

export interface GatewayConnectionsResponse {
  gateway_id: string
  gateway_name: string
  observed_at: string
  items: Array<{ id: string; group_id?: string; provider_id?: string; node_id?: string; transport?: string; state?: string; opened_at: string }>
}

export interface GatewayCounterValue {
  available: boolean
  bytes?: string
  packets?: string
}

export interface GatewayCountersResponse {
  gateway_id: string
  gateway_name: string
  observed_at: string
  proxy: GatewayCounterValue
  direct: GatewayCounterValue
  provider_quota: GatewayCounterValue
}

export interface InventoryPlanDiagnostic {
  severity: 'error' | 'warning'
  code: string
  path?: string
  message: string
}

export interface InventoryPlanManifest {
  version: number
  gateway_id: string
  groups: unknown[] | null
  enrollments: unknown[] | null
  source_map: unknown[] | null
  domain_sets?: unknown[] | null
  content_hash: string
}

export interface InventoryPlan {
  version: number
  checksum: string
  created_at: string
  scope: string
  consistency: string
  resource_revisions: Array<{ kind: string; id: string; revision: number; sha256: string }> | null
  input: {
    gateway: { id: string; name?: string; supported_transports?: string[]; supports_ipv6?: boolean; distinguishes_networks?: boolean }
    devices: unknown[] | null
    device_groups: unknown[] | null
    policies: unknown[] | null
    rule_sets?: unknown[] | null
    domain_sets?: unknown[] | null
    outbound_groups?: unknown[] | null
    options?: Record<string, unknown>
    previous?: InventoryPlanManifest
  }
  compilation?: {
    manifest: InventoryPlanManifest
    normalized: unknown[] | null
    source_map: unknown[] | null
    impact: { changed_groups?: string[]; unchanged_groups?: string[]; enrollment_changed: boolean; requires_policy_apply: boolean }
    diagnostics?: InventoryPlanDiagnostic[]
  }
  native_artifact?: {
    format: string
    dae_base: string
    gateway_id: string
    manifest: InventoryPlanManifest
    routing_config: string
    routing_sha256: string
    content_hash: string
    requires_guard: boolean
    outbound_bindings: Array<{ outbound_group_id: string; engine_name: string }> | null
    source_map: unknown[] | null
    required_globals: { dial_mode: string; auto_sniff_punt: boolean }
  }
  valid: boolean
  deployable: boolean
  diagnostics?: InventoryPlanDiagnostic[]
  blockers: InventoryPlanDiagnostic[] | null
  target: {
    gateway_id: string
    observation_status: string
    capabilities: {
      implementation: string
      version: string
      capabilities: Array<{ name: string; supported: boolean; implementation?: string; restrictions?: string[] }> | null
    }
  }
  previous: { status: string; operation_id?: string; manifest_hash?: string }
}
