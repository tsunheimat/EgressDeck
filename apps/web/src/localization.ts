import { healthLabels, operationAction, operationLabels } from './uiPresentation'

function ownLabel(table: Readonly<Record<string, string>>, key: string): string | undefined {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined
}

/** Display-only labels. Never use translated strings in requests, comparisons, or IDs. */
const labels: Readonly<Record<string, string>> = {
  ...healthLabels, ...operationLabels,
  desired: '期望状态', applied: '已应用', observed: '已观测', verified: '已验证',
  direct: '直连', proxy: '代理', block: '阻断', outbound_group: '代理组',
  quarantine: '隔离', block_matching_traffic: '阻断匹配流量', policy_default: '策略默认值',
  manual: '手动', automatic: '自动', none: '无', unset: '未设置',
  enabled: '已启用', disabled: '已禁用', active: '生效中', pending: '待处理',
  enrolled: '已纳管', unenrolled: '未纳管', unmanaged: '未管理', bypassed: '已绕过', blocked: '已阻止',
  ipv4: 'IPv4', ipv6: 'IPv6', dual: '双栈', dual_stack: '双栈', incomplete: '覆盖不完整',
  fresh: '最新', stale: '已过期', never_read: '尚未读取', error: '错误', warning: '警告', info: '信息',
  manifest_unavailable: '清单不可用', unavailable: '不可用', unreported: '未报告', unknown: '未知',
  valid: '有效', invalid: '无效', published: '已发布', never_fetched: '尚未获取', superseded: '已被替代',
  shared_tcp_udp: 'TCP / UDP 共用', independent_transport: '独立传输协议',
  static: '静态地址', reserved: 'DHCP 保留地址', url: '订阅 URL', 'node-link': '节点链接', upload: '文件导入',
  auto: '自动检测', local: '本地导入', links: '节点链接', base64: 'Base64', json: 'JSON', clash: 'Clash YAML', sip008: 'SIP008',
  tcp: 'TCP', udp: 'UDP', quic: 'QUIC',
  policy: '策略', policies: '策略', rule: '规则', rule_set: '规则集', rule_sets: '规则集',
  management_request: '管理请求', device: '设备', device_group: '设备组', gateway: '网关', provider: '订阅',
  domain_set: '域名集', firewall_binding: '防火墙绑定', selection: '节点选择', schedule: '定时计划',
  create: '创建', update: '更新', delete: '删除', attach: '绑定', read: '读取',
  stage: '暂存', refresh: '刷新', publish: '发布', apply: '应用', group_apply: '应用组配置',
  scheduled_refresh: '定时刷新', enroll: '纳管设备', enrollment: '设备纳管', recover: '恢复',
  unenroll: '移除纳管', verify: '验证', registered: '已登记', requested: '已请求',
  success: '成功', succeeded: '成功', failure: '失败', denied: '已拒绝', accepted: '已受理',
  running: '运行中', complete: '已完成', completed: '已完成', cancelled: '已取消',
  committed: '已提交', failed_partial: '部分失败', prepared: '已准备', quarantined: '已隔离', released: '已释放',
  open: '已建立', closed: '已关闭', established: '已建立', connecting: '连接中',
  revision_rechecked: '已重新检查版本', gateway_inventory: '网关清单', snapshot: '快照', atomic: '原子快照', best_effort: '尽力读取', stored_inventory: '持久化清单',
  yes: '是', no: '否', mandatory_rules: '强制规则', exceptions: '例外规则', entries: '策略条目',
  'inventory.read': '读取清单', 'provider.stage': '暂存订阅', 'provider.publish_hot': '热发布订阅',
  'group.publish_hot': '热发布代理组', 'selection.set_runtime': '运行时节点选择',
  'selection.persist_restart': '重启后保留节点选择', 'policy.validate': '策略校验',
  'policy.apply_generation': '应用策略代次', 'probe.node': '节点探测', 'probe.group': '代理组探测',
  'connections.observe': '连接观测', 'connections.close_filtered': '按条件关闭连接',
  'traffic.proxy_counters': '代理流量计数', 'traffic.direct_counters': '直连流量计数', 'events.resume': '恢复事件流',
}

/** Unknown wire values remain visible as raw identifiers, never silently become a success. */
export function uiLabel(value: unknown): string {
  if (value == null || value === '') return '未知'
  if (typeof value === 'boolean') return value ? '是' : '否'
  const text = String(value)
  if (Object.prototype.hasOwnProperty.call(labels, text)) return labels[text]!
  if (/[\u3400-\u9fff]/.test(text)) return text
  return `未识别（${text}）`
}

export function actionName(value: string): string {
  const action = operationAction(value)
  return action === value ? uiLabel(value) : action
}

/** API codes describe refusal/readback boundaries, not whether remote effects were undone. */
export const diagnosticLabels: Readonly<Record<string, string>> = {
  address_conflict: '地址归属存在冲突，请检查设备清单。',
  already_exists: '资源已存在，请读取现有记录。',
  collection_capacity: '集合超过扫描容量，请缩小范围或使用分页接口。',
  collection_item_too_large: '单个集合条目超过响应大小上限。',
  cursor_expired: '历史游标已过期，请重新读取当前状态。',
  cursor_stream_changed: '事件流已更换，请重新读取当前状态。',
  deployment_required: '此变更涉及已纳管设备，需要经过受控部署流程。',
  derived_state_read_only: '验证与纳管状态由部署结果生成，不能直接修改。',
  disposition_required: '删除已纳管设备前，需要明确保留、阻断或绕过的部署处置。',
  enrollment_binding_invalid: '防火墙绑定与批准的网关或地址范围不匹配。',
  enrollment_group_invalid: '设备必须属于批准网关上已启用的设备组。',
  enrollment_pending: '存在进行中的纳管操作，请先确认其结果。',
  enrollment_preparation_invalid: '纳管准备与批准的清单、策略或恢复操作不匹配。',
  enrollment_recovery_conflict: '恢复条件不满足，请核对原设备、绑定、失败操作和当前计划。',
  enrollment_recovery_reference_required: '恢复请求必须正确引用上次纳管操作。',
  enrollment_recovery_required: '现有纳管操作需要先协调确认或显式恢复。',
  enrollment_resource_required: '请选择设备和防火墙绑定。',
  enrollment_source_invalid: '纳管来源地址不满足要求。',
  enrollment_state_conflict: '设备当前状态不允许发起新的纳管流程。',
  enrollment_state_unavailable: '无法读取纳管操作状态，请勿重复提交新请求。',
  events_unavailable: '管理事件存储不可用。',
  firewall_binding_exists: '此防火墙别名或绑定已存在，请回读现有绑定。',
  gateway_not_registered: '请先登记所选网关。',
  gateway_required: '请选择已保存的网关。',
  gateway_unavailable: '所选网关无法完成此次诊断。',
  idempotency_conflict: '此幂等标识已用于其他请求，请检查原操作。',
  idempotency_key_required: '请求缺少幂等标识。',
  internal_error: '控制器内部处理异常，请检查原始诊断和服务日志。',
  invalid_cursor: '分页或事件游标无效，请重新读取。',
  invalid_expected_revisions: '预期版本与请求的传输协议范围不一致。',
  invalid_gateway_response: '网关返回了无效的诊断响应。',
  invalid_gateway_scope: '所选网关与代理组所属网关不一致。',
  invalid_interval: '刷新间隔必须为 5 分钟至 7 天。',
  invalid_json: '请求内容不是有效的 JSON。',
  invalid_limit: '分页数量不在允许范围内。',
  invalid_plan_id: '计划标识必须是小写 SHA-256 校验和。',
  invalid_query: '查询参数无效或重复。',
  invalid_request: '请求格式或参数不符合接口要求。',
  invalid_revision: '版本号无效。',
  invalid_transport_scope: '传输协议范围必须使用不重复的 TCP 或 UDP 条目。',
  method_not_allowed: '此接口不支持该请求方法。',
  not_found: '请求的资源不存在或不属于当前范围。',
  not_ready: '控制器存储尚未就绪。',
  operation_state_unavailable: '请求可能已受理，但无法读取操作状态。请回读原请求，不要创建替代请求。',
  outcome_unknown: '操作结果未知，请读取原操作并检查恢复状态。',
  persistence_failed: '状态持久化失败，控制器写入可能已暂停，请检查存储。',
  pinned_node_removed: '暂存版本移除了正在使用的节点，请先检查节点选择。',
  plan_checksum_required: '请求必须携带与持久化计划完全一致的校验和。',
  plan_corrupt: '计划校验和与内容不匹配，不能应用。',
  plan_persistence_failed: '无法持久化不可变计划。',
  plan_state_unavailable: '无法确认批准计划或当前运行时状态。',
  plan_storage_unavailable: '不可变计划存储不可用。',
  provider_in_use: '订阅仍被引用，请先处理引用或运行时操作。',
  provider_storage_unavailable: '无法保存订阅设置。',
  refresh_busy: '订阅刷新请求过多，请确认现有请求后再重试。',
  request_cancelled: '请求等待已取消；这不代表远端操作已撤销。',
  request_error: '请求未完成，请检查原始诊断。',
  resource_in_use: '资源仍在使用中，请先处理关联操作。',
  resource_referenced: '资源仍被引用，请先移除或重新分配引用。',
  revision_conflict: '资源版本已变化，请刷新并检查最新版本。',
  revision_required: '请求缺少匹配当前资源的版本前置条件。',
  schedule_unavailable: '定时刷新需要远程订阅及已启用的订阅暂存能力。',
  shared_transport_required: '此网关要求同时选择 TCP 与 UDP。',
  snapshot_changed: '创建计划时清单发生变化，请刷新并创建新计划。',
  stale_cursor: '集合已变化，请从第一页重新读取。',
  validation_error: '输入未通过校验，请检查字段和原始诊断。',
  forbidden: '当前会话没有执行此操作的权限。',
  unauthorized: '请先登录或重新验证会话。',
}

const commonDiagnostics: Readonly<Record<string, string>> = {
  'Failed to fetch': '无法连接控制器，请检查网络后读取最新状态。',
  'NetworkError when attempting to fetch resource.': '无法连接控制器，请检查网络后读取最新状态。',
  'Load failed': '请求加载失败，请检查连接并读取最新状态。',
}

export interface DiagnosticPresentation { summary: string; original?: string }
export function diagnosticPresentation(message: unknown, code?: string): DiagnosticPresentation {
  const original = typeof message === 'string' ? message : message instanceof Error ? message.message : ''
  if (!original.trim()) return { summary: code ? ownLabel(diagnosticLabels, code) ?? '暂无可用诊断信息。' : '' }
  // Locally authored Chinese copy is already localized. User resource names are never passed here.
  if (/[\u3400-\u9fff]/.test(original) && !/[a-z]{3,} [a-z]{3,}/i.test(original)) return { summary: original }
  const summary = (code && ownLabel(diagnosticLabels, code)) || ownLabel(commonDiagnostics, original) || '控制器或网关返回了诊断信息，请展开原始内容检查详情。'
  return { summary, original }
}

/** Audit HTTP success is management-request success, never packet-path verification. */
export function auditOutcomeName(value: unknown): string {
  const status = String(value ?? '')
  if (/^[1-5][0-9]{2}$/.test(status)) {
    const code = Number(status)
    const label = code === 202 ? '请求已受理' : code === 201 ? '资源已创建' : code < 200 ? '请求处理中' : code < 300 ? '请求成功' : code < 400 ? '请求重定向' : code < 500 ? '请求被拒绝' : '服务端错误'
    return `${label}（HTTP ${status}）`
  }
  if (status === 'verified') return '操作回读已确认'
  return uiLabel(value)
}

export function auditActionName(value: string): string {
  const request = /^(GET|HEAD|POST|PUT|PATCH|DELETE) (\/api\/v1\/[^ ?]+)$/.exec(value)
  if (!request) return uiLabel(value)
  const [, method, path] = request
  const endpoints: Readonly<Record<string, string>> = {
    explain: '解释策略路径', preview: '预览部署配置', plan: '创建清单计划',
    selection: method === 'GET' ? '读取节点选择' : '更改节点选择',
    apply: '请求应用配置', stage: '暂存订阅版本', refresh: '刷新订阅',
    enroll: '请求设备纳管', recover: '请求恢复操作',
  }
  const tail = path!.split('/').at(-1)!
  const specific = ownLabel(endpoints, tail)
  if (specific) return specific
  const resources: Readonly<Record<string, string>> = {
    policies: '策略', 'rule-sets': '规则集', providers: '订阅', devices: '设备',
    'device-groups': '设备组', 'outbound-groups': '代理组', gateways: '网关',
    operations: '操作记录', deployments: '部署配置', 'firewall-bindings': '防火墙绑定',
  }
  const verb = ({ GET: '读取', HEAD: '检查', POST: '提交', PUT: '更新', PATCH: '更新', DELETE: '删除' } as Record<string, string>)[method!]!
  return `${verb}${ownLabel(resources, path!.split('/')[3]!) ?? '管理'}请求`
}
