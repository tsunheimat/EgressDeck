<script setup lang="ts">
import { computed, onActivated, onDeactivated, onMounted, onUnmounted, ref, watch } from 'vue'
import StatusPill from '../components/StatusPill.vue'
import InventoryPlanPanel from '../components/InventoryPlanPanel.vue'
import { ControllerApiError } from '../api/client'
import { useControllerState } from '../state'
import { readNavigationTarget, subscribeNavigationTarget, type NavigationTarget } from '../navigationTarget'

type ActionKind = 'direct' | 'proxy' | 'block' | 'outbound_group'
type Transport = 'tcp' | 'udp' | 'quic'
type Family = 'ipv4' | 'ipv6'
type Phase = 'mandatory_rules' | 'exceptions' | 'entries'
type ActionField = 'default_action' | 'unknown_domain_action' | 'proxy_failure_action'
interface Action { kind: ActionKind; outbound_group_id?: string }
interface PortRange { from: number; to: number }
interface Match {
  domain_exact?: string[]; domain_suffix?: string[]; domain_sets?: string[]
  destination_cidrs?: string[]; destination_ip?: string[]; destination_ports?: PortRange[]; ports?: PortRange[]
  transport?: Transport[]; transports?: Transport[]; address_families?: Family[]; families?: Family[]
}
interface Rule { id: string; name?: string; match: Match; action: Action; enabled: boolean; order?: number }
interface Entry { rule?: Rule; rule_set_id?: string }
interface Policy {
  id: string; name?: string; revision?: number
  mandatory_rules?: Rule[]; mandatory?: Rule[]; exceptions?: Rule[]; entries?: Entry[]; rules?: Rule[]; rule_set_ids?: string[]
  default_action: Action; unknown_domain_action?: Action; proxy_failure_action?: Action
  strict?: boolean; strict_mode?: boolean; raw_config_override?: string
}
interface RuleSet { id: string; name?: string; rules: Rule[]; revision?: number }
interface DeleteTarget { mode: 'policy' | 'rule_set'; id: string; name: string; revision: number; accepted: boolean }
interface Outbound { id: string; name?: string; node_ids?: string[]; candidate_node_ids?: string[] }
interface Manifest { version: number; gateway_id: string; groups: unknown[]; enrollments: unknown[]; source_map: unknown[]; content_hash: string }
interface Preview {
  manifest: Manifest; impact: { changed_groups?: string[]; unchanged_groups?: string[]; enrollment_changed: boolean; requires_policy_apply: boolean }
  diagnostics?: Array<{ severity: string; code: string; path?: string; message: string }>
}
interface Explanation { predicted: boolean; action: Action; device_group_id?: string; matched_rule_id?: string; matched_rule_name?: string; reason: string; candidates?: string[] }
interface Packet { source_ip: string; destination_ip: string; destination_port: number; transport: Transport; family: Family; domain: string }

const props = defineProps<{ state: ReturnType<typeof useControllerState> }>()
const policies = ref<Policy[]>([])
const ruleSets = ref<RuleSet[]>([])
const outbounds = ref<Outbound[]>([])
const editingMode = ref<'policy' | 'rule_set'>('policy')
const selectedId = ref('')
const draft = ref<Policy>()
const phase = ref<Phase>('entries')
const selectedIndex = ref(0)
const loading = ref(false)
const saving = ref(false)
const deleting = ref(false)
const deleteTarget = ref<DeleteTarget>()
const deleteAcknowledged = ref(false)
const compiling = ref(false)
const explaining = ref(false)
const error = ref('')
const notice = ref('')
const portsError = ref('')
const preview = ref<Preview>()
const explanation = ref<Explanation>()
const context = ref({ gatewayId: '', sourceIP: '192.0.2.10', transports: ['tcp'] as Transport[], supportsIPv6: false, distinguishesNetworks: false, domainSets: '' })
const packet = ref<Packet>({ source_ip: '192.0.2.10', destination_ip: '203.0.113.80', destination_port: 443, transport: 'tcp', family: 'ipv4', domain: 'example.com' })
const actions: ActionKind[] = ['direct', 'proxy', 'block', 'outbound_group']
const policyActions: Array<{ key: ActionField; label: string }> = [{ key: 'default_action', label: 'Default action' }, { key: 'unknown_domain_action', label: 'Unknown domain action' }, { key: 'proxy_failure_action', label: 'Proxy failure action' }]
const listMatches: Array<{ key: 'domain_exact' | 'domain_suffix' | 'domain_sets' | 'destination_cidrs'; label: string; placeholder: string }> = [
  { key: 'domain_exact', label: 'Exact domains', placeholder: 'example.com' }, { key: 'domain_suffix', label: 'Domain suffixes', placeholder: 'example.com, media.example' },
  { key: 'domain_sets', label: 'Domain set IDs', placeholder: 'streaming-domains' }, { key: 'destination_cidrs', label: 'Destination CIDRs', placeholder: '192.0.2.0/24' },
]
const entries = computed<Entry[]>(() => !draft.value ? [] : phase.value === 'entries' ? draft.value.entries ?? [] : (draft.value[phase.value] ?? []).map((rule) => ({ rule })))
const activeEntry = computed(() => entries.value[selectedIndex.value])
const activeRule = computed(() => activeEntry.value?.rule)
const busy = computed(() => loading.value || saving.value || deleting.value || !!deleteTarget.value)
const storedSelection = computed(() => editingMode.value === 'policy' ? policies.value.find((policy) => policy.id === selectedId.value) : ruleSets.value.find((set) => set.id === selectedId.value))
const referencingPolicies = computed(() => editingMode.value === 'rule_set' ? policies.value.filter((policy) => policy.entries?.some((entry) => entry.rule_set_id?.trim() === selectedId.value) || policy.rule_set_ids?.some((id) => id.trim() === selectedId.value)) : [])
const deleteBlockedReason = computed(() => {
  if (referencingPolicies.value.length) return `Cannot delete this rule set while referenced by ${referencingPolicies.value.length === 1 ? 'policy' : 'policies'}: ${referencingPolicies.value.map((policy) => `${policy.name || policy.id} (${policy.id})`).join(', ')}.`
  if (!Number.isInteger(draft.value?.revision) || (draft.value?.revision ?? 0) < 1) return 'Reload this document to obtain its current revision before deletion.'
  return ''
})
const canPreview = computed(() => props.state.canOperate.value && props.state.capabilities.value['policy.validate'] === true)
const draftSignature = computed(() => JSON.stringify({ mode: editingMode.value, policy: draft.value, context: context.value }))
const rulesetSignature = computed(() => JSON.stringify({ ruleSets: ruleSets.value, outbounds: outbounds.value }))
let loadSequence = 0
let explainSequence = 0
let compileSequence = 0
let documentsLoaded = false
let viewActive = true
let activatedOnce = false
let unsubscribeNavigation = () => {}

function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T }
function unique(values: string[]): string[] { return [...new Set(values)] }
function csv(value: string): string[] { return value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean) }
function ordered(rules: Rule[]): Rule[] {
  return rules.map((rule, index) => ({ rule, order: rule.order || index + 1 })).sort((a, b) => a.order - b.order).map(({ rule }) => rule)
}
function normalizeRule(rule: Rule): Rule {
  const match = rule.match ?? {}
  match.destination_cidrs = [...(match.destination_cidrs ?? []), ...(match.destination_ip ?? [])]
  match.destination_ports = [...(match.destination_ports ?? []), ...(match.ports ?? [])]
  match.transport = [...(match.transport ?? []), ...(match.transports ?? [])]
  match.address_families = [...(match.address_families ?? []), ...(match.families ?? [])]
  delete match.destination_ip; delete match.ports; delete match.transports; delete match.families
  return { ...rule, match }
}
function normalizePolicy(policy: Policy): Policy {
  const next = clone(policy)
  next.mandatory_rules = ordered([...(next.mandatory_rules ?? []), ...(next.mandatory ?? [])]).map((rule, index) => ({ ...normalizeRule(rule), order: index + 1 }))
  next.exceptions = ordered(next.exceptions ?? []).map((rule, index) => ({ ...normalizeRule(rule), order: index + 1 }))
  if (!next.entries?.length) {
    next.entries = [...ordered(next.rules ?? []).map((rule) => ({ rule: normalizeRule(rule) })), ...unique(next.rule_set_ids ?? []).map((rule_set_id) => ({ rule_set_id }))]
    delete next.rules; delete next.rule_set_ids
  } else next.entries = next.entries.map((entry) => entry.rule ? { rule: normalizeRule(entry.rule) } : entry)
  next.strict = next.strict || next.strict_mode || false
  if (!next.unknown_domain_action?.kind) delete next.unknown_domain_action
  if (!next.proxy_failure_action?.kind) delete next.proxy_failure_action
  delete next.mandatory; delete next.strict_mode
  return next
}
function actionLabel(action?: Action): string { return action?.kind === 'outbound_group' ? `outbound group: ${action.outbound_group_id || 'unset'}` : action?.kind || 'policy default' }
function actionOptions(field: ActionField): ActionKind[] { return field === 'proxy_failure_action' ? ['block'] : actions }
function errorMessage(cause: unknown): string {
  if (cause instanceof ControllerApiError && (cause.status === 409 || cause.status === 412)) return `${cause.message}. Reload this document to review the latest revision before saving again.`
  return cause instanceof Error ? cause.message : 'The controller request failed.'
}
function invalidatePreview() { preview.value = undefined; explanation.value = undefined; explainSequence++; compileSequence++ }
watch([draftSignature, rulesetSignature], invalidatePreview, { flush: 'sync' })
watch(packet, () => { explanation.value = undefined; explainSequence++ }, { deep: true, flush: 'sync' })
watch(phase, () => { selectedIndex.value = 0 }, { flush: 'sync' })
watch(activeRule, () => { portsError.value = '' })
watch(props.state.isAdministrator, (administrator) => {
  if (!administrator && deleteTarget.value && !deleteTarget.value.accepted && !deleting.value) {
    deleteTarget.value = undefined; deleteAcknowledged.value = false
  }
})

function editPolicy(policy: Policy) {
  deleteTarget.value = undefined; deleteAcknowledged.value = false
  editingMode.value = 'policy'
  selectedId.value = policy.id
  draft.value = normalizePolicy(policy)
  selectedIndex.value = 0
  phase.value = 'entries'
  error.value = ''; notice.value = ''
}
function newPolicy() {
  deleteTarget.value = undefined; deleteAcknowledged.value = false
  editingMode.value = 'policy'
  selectedId.value = ''
  draft.value = { id: '', name: '', entries: [], mandatory_rules: [], exceptions: [], default_action: { kind: 'direct' }, proxy_failure_action: { kind: 'block' }, strict: false }
  selectedIndex.value = 0; phase.value = 'entries'; error.value = ''; notice.value = ''
}
function editRuleSet(ruleSet: RuleSet) {
  deleteTarget.value = undefined; deleteAcknowledged.value = false
  editingMode.value = 'rule_set'
  selectedId.value = ruleSet.id
  // A local policy-shaped shell shares the typed rule editor. Only RuleSet
  // fields are ever serialized for persistence; rule sets have no fallback.
  draft.value = { id: ruleSet.id, name: ruleSet.name, revision: ruleSet.revision, entries: ordered(clone(ruleSet.rules ?? [])).map((rule) => ({ rule: normalizeRule(rule) })), default_action: { kind: 'direct' } }
  selectedIndex.value = 0; phase.value = 'entries'; error.value = ''; notice.value = ''
}
function newRuleSet() {
  editRuleSet({ id: '', name: '', rules: [] })
}
async function load() {
  const sequence = ++loadSequence
  loading.value = true; error.value = ''
  try {
    const [policyItems, setItems, outboundItems] = await Promise.all([props.state.api.policyDocuments<Policy>(), props.state.api.ruleSetDocuments<RuleSet>(), props.state.api.outboundGroupDocuments<Outbound>()])
    if (sequence !== loadSequence) return
    policies.value = policyItems
    ruleSets.value = setItems
    outbounds.value = outboundItems
    documentsLoaded = true
    if (!draft.value && policyItems[0]) editPolicy(policyItems[0])
    else if (!draft.value && setItems[0]) editRuleSet(setItems[0])
    if (viewActive) await openNavigationTarget(readNavigationTarget())
  } catch (cause) { if (sequence === loadSequence) error.value = errorMessage(cause) } finally { if (sequence === loadSequence) loading.value = false }
}
async function reloadSelected() {
  if (!selectedId.value) return
  const id = selectedId.value
  const mode = editingMode.value
  const sequence = ++loadSequence
  loading.value = true; error.value = ''
  try {
    if (mode === 'rule_set') {
      const items = await props.state.api.ruleSetDocuments<RuleSet>()
      if (sequence !== loadSequence || !viewActive) return
      const item = items.find((set) => set.id === id)
      if (!item) throw new Error('The rule set no longer exists in the controller.')
      ruleSets.value = items; editRuleSet(item)
    } else {
      const item = await props.state.api.policy<Policy>(id)
      if (sequence !== loadSequence || !viewActive) return
      policies.value = [...policies.value.filter((policy) => policy.id !== item.id), item]
      editPolicy(item)
    }
  } catch (cause) { if (sequence === loadSequence) error.value = errorMessage(cause) } finally { if (sequence === loadSequence) loading.value = false }
}
function selectLinkedRule(ruleId?: string) {
  if (!ruleId || !draft.value) return
  const phases: Phase[] = editingMode.value === 'policy' ? ['mandatory_rules', 'exceptions', 'entries'] : ['entries']
  for (const item of phases) {
    const rules = item === 'entries' ? (draft.value.entries ?? []).map((entry) => entry.rule) : draft.value[item] ?? []
    const index = rules.findIndex((rule) => rule?.id === ruleId)
    if (index >= 0) { phase.value = item; selectedIndex.value = index; return }
  }
  error.value = `Rule ${ruleId} no longer exists in this document. The latest document is shown.`
}
async function openNavigationTarget(target: NavigationTarget) {
  if (target.page !== 'rules' || !target.id || (target.resource !== 'policy' && target.resource !== 'rule_set')) return
  if (saving.value || deleting.value || deleteTarget.value?.accepted) {
    error.value = 'Finish the current save or deletion readback before opening another document.'
    return
  }
  if (!documentsLoaded) { await load(); return }
  const sequence = ++loadSequence
  loading.value = true; error.value = ''; notice.value = ''
  try {
    if (target.resource === 'policy') {
      const policy = await props.state.api.policy<Policy>(target.id)
      if (sequence !== loadSequence || !viewActive) return
      policies.value = [...policies.value.filter((item) => item.id !== policy.id), policy]
      editPolicy(policy)
    } else {
      const items = await props.state.api.ruleSetDocuments<RuleSet>()
      if (sequence !== loadSequence || !viewActive) return
      const item = items.find((set) => set.id === target.id)
      if (!item) throw new Error('The linked rule set no longer exists in the controller.')
      ruleSets.value = items; editRuleSet(item)
    }
    selectLinkedRule(target.ruleId)
  } catch (cause) { if (sequence === loadSequence) error.value = errorMessage(cause) } finally { if (sequence === loadSequence) loading.value = false }
}
function confirmDelete() {
  if (!props.state.isAdministrator.value || busy.value || !storedSelection.value || deleteBlockedReason.value) return
  deleteTarget.value = { mode: editingMode.value, id: selectedId.value, name: storedSelection.value.name || selectedId.value, revision: draft.value!.revision!, accepted: false }
  deleteAcknowledged.value = false; error.value = ''; notice.value = ''
}
function deletionError(cause: unknown): string {
  if (!(cause instanceof ControllerApiError)) return cause instanceof Error ? cause.message : 'The controller request failed.'
  const message = `${cause.code ? `[${cause.code}] ` : ''}${cause.message}`
  if (cause.code === 'resource_referenced') return `${message}. Remove or reassign the reference, then refresh before deleting.`
  if (cause.status === 409 || cause.status === 412) return `${message}. Reload this document and confirm its latest revision before deleting.`
  return message
}
async function deleteSelected() {
  const target = deleteTarget.value
  if (!target || !deleteAcknowledged.value || loading.value || saving.value || deleting.value) return
  if (!target.accepted && !props.state.isAdministrator.value) { error.value = 'An administrator session is required to delete policies and rule sets.'; return }
  if (!Number.isInteger(target.revision) || target.revision < 1) { error.value = 'Reload this document before deleting.'; return }
  deleting.value = true; error.value = ''; notice.value = ''
  invalidatePreview()
  try {
    if (!target.accepted) {
      if (target.mode === 'rule_set') await props.state.api.deleteRuleSet(target.id, target.revision)
      else await props.state.api.deletePolicy(target.id, target.revision)
      target.accepted = true
    }
    const [policyItems, setItems] = await Promise.all([props.state.api.policyDocuments<Policy>(), props.state.api.ruleSetDocuments<RuleSet>()])
    if ((target.mode === 'policy' ? policyItems : setItems).some((item) => item.id === target.id)) throw new Error('The deleted document is still present in controller readback.')
    policies.value = policyItems; ruleSets.value = setItems
    deleteTarget.value = undefined; deleteAcknowledged.value = false
    selectedId.value = ''; draft.value = undefined
    if (policyItems[0]) editPolicy(policyItems[0])
    else if (setItems[0]) editRuleSet(setItems[0])
    notice.value = `${target.mode === 'policy' ? 'Policy' : 'Rule set'} “${target.name}” deleted and absence confirmed by controller readback.`
  } catch (cause) {
    error.value = `${target.accepted ? 'Deletion was accepted, but readback has not confirmed removal. Select Verify deletion to retry readback. ' : ''}${deletionError(cause)}`
    if (!target.accepted) { deleteTarget.value = undefined; deleteAcknowledged.value = false }
  } finally { deleting.value = false }
}
function setEntries(next: Entry[]) {
  if (!draft.value) return
  if (phase.value === 'entries') draft.value.entries = next
  else draft.value[phase.value] = next.flatMap((entry, index) => entry.rule ? [{ ...entry.rule, order: index + 1 }] : [])
}
function addRule() {
  const id = globalThis.crypto?.randomUUID?.() ?? `rule-${Date.now()}-${Math.random().toString(36).slice(2)}`
  const next = [...entries.value, { rule: { id, name: '', match: {}, action: { kind: 'direct' as const }, enabled: true } }]
  setEntries(next); selectedIndex.value = next.length - 1
}
function addRuleSet() { if (editingMode.value !== 'policy') return; const next = [...entries.value, { rule_set_id: ruleSets.value[0]?.id ?? '' }]; setEntries(next); selectedIndex.value = next.length - 1 }
function removeEntry() { setEntries(entries.value.filter((_, index) => index !== selectedIndex.value)); selectedIndex.value = Math.max(0, selectedIndex.value - 1) }
function moveEntry(index: number, offset: number) {
  const target = index + offset
  const next = [...entries.value]
  if (!next[index] || !next[target]) return
  const current = next[index]!
  next[index] = next[target]!
  next[target] = current
  setEntries(next); selectedIndex.value = target
}
function setAction(field: ActionField, kind: string) {
  if (!draft.value) return
  if (!kind && field === 'unknown_domain_action') { delete draft.value.unknown_domain_action; return }
  draft.value[field] = kind === 'outbound_group' ? { kind, outbound_group_id: '' } : { kind: kind as ActionKind }
}
function setRuleAction(kind: ActionKind) { if (activeRule.value) activeRule.value.action = kind === 'outbound_group' ? { kind, outbound_group_id: '' } : { kind } }
function updatePorts(event: Event) {
  if (!activeRule.value) return
  const value = (event.target as HTMLInputElement).value
  const result: PortRange[] = []
  for (const token of csv(value)) {
    const match = /^(\d+)(?:-(\d+))?$/.exec(token)
    const from = Number(match?.[1]); const to = Number(match?.[2] ?? match?.[1])
    if (!match || from < 1 || to < from || to > 65535) { portsError.value = `Invalid port range "${token}". Use ports 1–65535, for example 443 or 1000-1100.`; error.value = portsError.value; invalidatePreview(); return }
    result.push({ from, to })
  }
  activeRule.value.match.destination_ports = result; portsError.value = ''; error.value = ''
}
function validateDraft(requireRevision = false): Policy {
  if (!draft.value) throw new Error('Create or select a policy or rule set first.')
  if (portsError.value) throw new Error(portsError.value)
  const item = clone(draft.value)
  if (!item.name?.trim()) throw new Error(`${editingMode.value === 'rule_set' ? 'A rule set' : 'A policy'} name is required.`)
  if (item.entries?.length && (item.rules?.length || item.rule_set_ids?.length)) throw new Error('This stored policy combines entries with rules or rule_set_ids. The controller rejects this ambiguous order; create a new policy with one ordered representation.')
  if (requireRevision && selectedId.value && (!Number.isInteger(item.revision) || (item.revision ?? 0) < 1)) throw new Error('The controller did not supply a revision. Reload this policy before saving.')
  const allRules = [...(item.mandatory_rules ?? []), ...(item.exceptions ?? []), ...(item.entries ?? []).flatMap((entry) => entry.rule ? [entry.rule] : [])]
  if (allRules.some((rule) => !rule.id.trim())) throw new Error('Every rule requires an ID.')
  if ((item.entries ?? []).some((entry) => !entry.rule && !entry.rule_set_id)) throw new Error('Select a rule set for every rule-set entry.')
  for (const action of [item.default_action, item.unknown_domain_action, item.proxy_failure_action, ...allRules.map((rule) => rule.action)]) {
    if (action?.kind === 'outbound_group' && !action.outbound_group_id?.trim()) throw new Error('Every outbound-group action requires an outbound group ID.')
  }
  return item
}
async function save() {
  if (editingMode.value === 'rule_set') { await saveRuleSet(); return }
  error.value = ''; notice.value = ''
  if (!props.state.isAdministrator.value) { error.value = 'An administrator session is required to save policies.'; return }
  saving.value = true
  let accepted = false
  try {
    const item = validateDraft(true)
    const result = selectedId.value ? await props.state.api.updatePolicy<Policy>(selectedId.value, item, item.revision!) : await props.state.api.createPolicy<Policy>(item)
    accepted = true
    selectedId.value = result.id
    draft.value = normalizePolicy(result)
    const readback = await props.state.api.policy<Policy>(result.id)
    policies.value = [...policies.value.filter((policy) => policy.id !== readback.id), readback]
    draft.value = normalizePolicy(readback)
    notice.value = `Policy revision ${readback.revision ?? 'unknown'} saved and read back. Gateway deployment requires a separate apply operation.`
  } catch (cause) { error.value = `${accepted ? 'The save was accepted, but readback failed. Reload before editing again. ' : ''}${errorMessage(cause)}` } finally { saving.value = false }
}
async function saveRuleSet() {
  error.value = ''; notice.value = ''
  if (!props.state.isAdministrator.value) { error.value = 'An administrator session is required to save rule sets.'; return }
  saving.value = true
  let accepted = false
  try {
    const item = validateDraft(true)
    if (item.entries?.some((entry) => !entry.rule)) throw new Error('Reusable rule sets contain typed rules only; nested rule-set references are unsupported.')
    const payload: RuleSet = { id: item.id, name: item.name?.trim(), revision: item.revision, rules: (item.entries ?? []).flatMap((entry, index) => entry.rule ? [{ ...entry.rule, order: index + 1 }] : []) }
    const result = selectedId.value ? await props.state.api.updateRuleSet<RuleSet>(selectedId.value, payload, item.revision!) : await props.state.api.createRuleSet<RuleSet>(payload)
    accepted = true
    selectedId.value = result.id
    draft.value = { id: result.id, name: result.name, revision: result.revision, entries: (result.rules ?? []).map((rule) => ({ rule })), default_action: { kind: 'direct' } }
    const items = await props.state.api.ruleSetDocuments<RuleSet>()
    const readback = items.find((set) => set.id === result.id)
    if (!readback) throw new Error('The saved rule set was absent from controller readback.')
    ruleSets.value = items
    editRuleSet(readback)
    notice.value = `Rule set revision ${readback.revision ?? 'unknown'} saved and read back. Referencing policies use these rules when next compiled.`
  } catch (cause) { error.value = `${accepted ? 'The save was accepted, but readback failed. Reload before editing again. ' : ''}${errorMessage(cause)}` } finally { saving.value = false }
}
async function compile() {
  if (editingMode.value !== 'policy') return
  if (!canPreview.value) { error.value = 'An operator session and the controller policy validation capability are required for preview.'; return }
  compiling.value = true; error.value = ''; notice.value = ''; invalidatePreview()
  const signature = draftSignature.value
  let sequence = compileSequence
  try {
    const policy = validateDraft()
    if (!context.value.gatewayId.trim()) throw new Error('Enter the gateway ID used by this simulation.')
    if (!context.value.sourceIP.trim()) throw new Error('Enter a source IP for the simulated device.')
    if (!context.value.transports.length) throw new Error('Select at least one supported gateway transport.')
    const domainSets = context.value.domainSets.split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
      const separator = line.indexOf('=')
      if (separator < 1 || !line.slice(separator + 1).trim()) throw new Error('Use one domain set per line: set-id=example.com, another.example')
      return { id: line.slice(0, separator).trim(), domains: csv(line.slice(separator + 1)) }
    })
    const [currentOutbounds, currentRuleSets] = await Promise.all([props.state.api.outboundGroupDocuments<Outbound>(), props.state.api.ruleSetDocuments<RuleSet>()])
    if (signature !== draftSignature.value || sequence !== compileSequence || portsError.value) return
    outbounds.value = currentOutbounds
    ruleSets.value = currentRuleSets
    sequence = compileSequence
    const referencedRuleSets = new Set([
      ...(policy.entries ?? []).flatMap((entry) => entry.rule_set_id ? [entry.rule_set_id] : []),
      ...(policy.rule_set_ids ?? []),
    ])
    policy.id ||= 'preview-policy'
    const gatewayId = context.value.gatewayId.trim()
    const result = await props.state.api.previewPolicy<Preview>({
      gateway: { id: gatewayId, supported_transports: context.value.transports, supports_ipv6: context.value.supportsIPv6, distinguishes_networks: context.value.distinguishesNetworks },
      devices: [{ id: 'preview-device', addresses: [{ address: context.value.sourceIP.trim() }], enabled: true }],
      device_groups: [{ id: 'preview-group', gateway_id: gatewayId, policy_id: policy.id, device_ids: ['preview-device'], enabled: true }],
      policies: [policy], rule_sets: currentRuleSets.filter((set) => referencedRuleSets.has(set.id)), domain_sets: domainSets,
      outbound_groups: currentOutbounds.map((group) => ({ id: group.id, name: group.name, node_ids: group.node_ids ?? group.candidate_node_ids ?? [] })),
    })
    if (signature !== draftSignature.value || sequence !== compileSequence || portsError.value) return
    preview.value = result
    notice.value = 'Compiled the supplied simulation context. This result is a prediction of policy behavior.'
  } catch (cause) { if (signature === draftSignature.value && sequence === compileSequence) error.value = errorMessage(cause) } finally { compiling.value = false }
}
async function explain() {
  if (!preview.value || !canPreview.value) return
  const sequence = ++explainSequence
  explaining.value = true; error.value = ''; explanation.value = undefined
  try {
    if (!Number.isInteger(packet.value.destination_port) || packet.value.destination_port < 1 || packet.value.destination_port > 65535) throw new Error('Destination port must be an integer between 1 and 65535.')
    const result = await props.state.api.explainPolicy<Explanation>(preview.value.manifest, clone(packet.value))
    if (sequence === explainSequence) explanation.value = result
  } catch (cause) { if (sequence === explainSequence) error.value = errorMessage(cause) } finally { explaining.value = false }
}
onMounted(() => {
  context.value.gatewayId = props.state.selectedGateway.value?.id ?? ''
  unsubscribeNavigation = subscribeNavigationTarget((target) => { if (viewActive) void openNavigationTarget(target) })
  void load()
})
onActivated(() => {
  viewActive = true
  if (activatedOnce) {
    if (!documentsLoaded) void load()
    else void openNavigationTarget(readNavigationTarget())
  }
  activatedOnce = true
})
onDeactivated(() => { viewActive = false; loadSequence++; loading.value = false })
onUnmounted(() => { unsubscribeNavigation(); loadSequence++ })
</script>

<template>
  <div class="page-grid">
    <section class="page-heading"><div><p class="eyebrow">Policy compiler</p><h1>Rules</h1><p class="lede">Build typed policies, review rule order, and predict a packet’s path before applying a generation.</p></div><div class="actions"><button class="button button--secondary" :disabled="busy" @click="load">Refresh policies</button><button class="button" :disabled="busy || !state.isAdministrator.value" @click="newPolicy">New policy</button><button class="button button--secondary" :disabled="busy || !state.isAdministrator.value" @click="newRuleSet">New rule set</button></div></section>
    <p v-if="error" class="alert alert--bad" role="alert">{{ error }}</p><p v-if="notice" class="alert alert--good" role="status">{{ notice }}</p>
    <InventoryPlanPanel :state="state" />
    <div class="workspace">
      <section class="panel"><div class="panel__heading"><h2>Policies</h2><span class="muted">{{ policies.length }}</span></div><p v-if="!policies.length" class="muted">{{ loading ? 'Loading policies…' : 'No policies configured.' }}</p><button v-for="policy in policies" :key="policy.id" class="policy-choice" :class="{ selected: editingMode === 'policy' && policy.id === selectedId }" :disabled="busy" @click="editPolicy(policy)"><strong>{{ policy.name || policy.id }}</strong><small>Revision {{ policy.revision ?? 'unknown' }} · {{ actionLabel(policy.default_action) }}</small></button><div class="panel__heading"><h2>Reusable rule sets</h2><span class="muted">{{ ruleSets.length }}</span></div><p v-if="!ruleSets.length" class="muted">No rule sets configured.</p><button v-for="set in ruleSets" :key="set.id" class="policy-choice" :class="{ selected: editingMode === 'rule_set' && set.id === selectedId }" :disabled="busy" @click="editRuleSet(set)"><strong>{{ set.name || set.id }}</strong><small>{{ set.rules?.length ?? 0 }} ordered rules · revision {{ set.revision ?? 'unknown' }}</small></button></section>
      <div v-if="draft" class="editor-column">
        <section class="panel"><div class="panel__heading"><h2>{{ selectedId ? 'Edit' : 'Create' }} {{ editingMode === 'rule_set' ? 'rule set' : 'policy' }}</h2><div class="actions"><button v-if="selectedId" class="button button--secondary" :disabled="busy" @click="reloadSelected">Reload {{ editingMode === 'rule_set' ? 'rule set' : 'policy' }}</button><button class="button" :disabled="busy || !state.isAdministrator.value" @click="save">{{ saving ? 'Saving…' : editingMode === 'rule_set' ? 'Save rule set' : 'Save policy' }}</button><button v-if="selectedId && state.isAdministrator.value" class="button button--danger" :disabled="busy || !!deleteBlockedReason" :title="deleteBlockedReason || undefined" @click="confirmDelete">Delete {{ editingMode === 'rule_set' ? 'rule set' : 'policy' }}</button></div></div><fieldset :disabled="busy || !state.isAdministrator.value" class="form-grid"><label>{{ editingMode === 'rule_set' ? 'Rule set name' : 'Policy name' }}<input v-model="draft.name" autocomplete="off" required /></label><label v-if="editingMode === 'policy'" class="check-field"><input v-model="draft.strict" type="checkbox" />Strict mode</label><template v-for="field in editingMode === 'policy' ? policyActions : []" :key="field.key"><label>{{ field.label }}<select :value="draft[field.key]?.kind ?? ''" @change="setAction(field.key, ($event.target as HTMLSelectElement).value)"><option v-if="field.key === 'unknown_domain_action'" value="">Use policy default</option><option v-if="field.key === 'proxy_failure_action'" value="" disabled>Use block default</option><option v-if="field.key === 'proxy_failure_action' && draft[field.key]?.kind && draft[field.key]?.kind !== 'block'" :value="draft[field.key]?.kind" disabled>{{ draft[field.key]?.kind }} (invalid failure action)</option><option v-for="action in actionOptions(field.key)" :key="action" :value="action">{{ action }}</option></select></label><label v-if="draft[field.key]?.kind === 'outbound_group'">{{ field.label }} group ID<input v-model="draft[field.key]!.outbound_group_id" /></label></template></fieldset><p class="muted">{{ selectedId ? `Editing revision ${draft.revision ?? 'unknown'}. Saves reject concurrent changes.` : 'The controller assigns an ID and revision when this document is created.' }}</p><p v-if="editingMode === 'rule_set'" class="muted">Reusable rule sets contain ordered match/action rules. If no rule matches, evaluation continues with the next policy entry. Compile and explain by referencing this set from a policy.</p><p v-if="draft.raw_config_override" class="alert alert--warn">This policy contains a raw configuration override. The typed editor preserves it; compilation applies the controller’s safety checks.</p></section>
        <p v-if="selectedId && state.isAdministrator.value && deleteBlockedReason" class="muted">{{ deleteBlockedReason }}</p>
        <form v-if="deleteTarget && (state.isAdministrator.value || deleteTarget.accepted || deleting)" class="panel" @submit.prevent="deleteSelected">
          <h2>Delete {{ deleteTarget.mode === 'rule_set' ? 'rule set' : 'policy' }} “{{ deleteTarget.name }}”?</h2>
          <p class="muted">This removes the saved document {{ deleteTarget.id }} at revision {{ deleteTarget.revision }}. The controller rejects deletion if this document is referenced or changed.</p>
          <label class="check-field"><input v-model="deleteAcknowledged" :disabled="deleting || deleteTarget.accepted" type="checkbox" required />I confirm deletion of {{ deleteTarget.name }} ({{ deleteTarget.id }}).</label>
          <div class="actions"><button class="button button--danger" type="submit" :disabled="deleting || !deleteAcknowledged">{{ deleting ? 'Verifying deletion…' : deleteTarget.accepted ? 'Verify deletion' : `Confirm delete ${deleteTarget.mode === 'rule_set' ? 'rule set' : 'policy'}` }}</button><button class="button button--secondary" type="button" :disabled="deleting || deleteTarget.accepted" @click="deleteTarget = undefined; deleteAcknowledged = false">Cancel deletion</button></div>
        </form>
        <section class="panel"><div class="panel__heading"><h2>Ordered rules</h2><label v-if="editingMode === 'policy'">Evaluation phase<select v-model="phase" :disabled="busy"><option value="mandatory_rules">1. Mandatory rules</option><option value="exceptions">2. Policy exceptions</option><option value="entries">3. Policy rules and rule sets</option></select></label></div><p v-if="editingMode === 'policy'" class="muted">Mandatory rules run first, followed by policy and device exceptions, ordered policy entries, and the default action. Values within a match field are ORed; populated fields are ANDed. An empty match applies to all packets.</p><div class="actions"><button class="button button--secondary" :disabled="busy || !state.isAdministrator.value" @click="addRule">Add rule</button><button v-if="editingMode === 'policy' && phase === 'entries'" class="button button--secondary" :disabled="busy || !ruleSets.length || !state.isAdministrator.value" @click="addRuleSet">Add rule set</button></div><p v-if="!entries.length" class="muted">No entries in this phase.</p><div v-for="(entry, index) in entries" :key="index" class="entry-row" :class="{ selected: selectedIndex === index }"><button class="entry-select" :disabled="busy" @click="selectedIndex = index"><span>{{ index + 1 }}.</span><span><strong>{{ entry.rule?.name || entry.rule?.id || `Rule set: ${entry.rule_set_id}` }}</strong><small v-if="entry.rule">{{ actionLabel(entry.rule.action) }} · {{ entry.rule.enabled ? 'enabled' : 'disabled' }}</small></span></button><button class="icon-button" :disabled="busy || index === 0 || !state.isAdministrator.value" :aria-label="`Move entry ${index + 1} up`" @click="moveEntry(index, -1)">↑</button><button class="icon-button" :disabled="busy || index === entries.length - 1 || !state.isAdministrator.value" :aria-label="`Move entry ${index + 1} down`" @click="moveEntry(index, 1)">↓</button></div>
          <fieldset v-if="activeRule" :disabled="busy || !state.isAdministrator.value" class="form-grid rule-fields"><label>Rule name<input v-model="activeRule.name" /></label><label>Rule ID<input v-model="activeRule.id" required /></label><label class="check-field"><input v-model="activeRule.enabled" type="checkbox" />Rule enabled</label><label>Rule action<select :value="activeRule.action.kind" @change="setRuleAction(($event.target as HTMLSelectElement).value as ActionKind)"><option v-for="action in actions" :key="action" :value="action">{{ action }}</option></select></label><label v-if="activeRule.action.kind === 'outbound_group'">Rule outbound group ID<input v-model="activeRule.action.outbound_group_id" /></label><label v-for="field in listMatches" :key="field.key">{{ field.label }}<input :value="activeRule.match[field.key]?.join(', ')" :placeholder="field.placeholder" @change="activeRule.match[field.key] = csv(($event.target as HTMLInputElement).value)" /></label><label>Destination ports<input :value="activeRule.match.destination_ports?.map((port) => !port.to || port.from === port.to ? String(port.from) : `${port.from}-${port.to}`).join(', ')" placeholder="443, 1000-1100" @change="updatePorts" /></label><label>Rule transports<select v-model="activeRule.match.transport" multiple><option value="tcp">TCP</option><option value="udp">UDP</option><option value="quic">QUIC</option></select><small>No selection matches any transport.</small></label><label>Rule address families<select v-model="activeRule.match.address_families" multiple><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select><small>No selection matches either family.</small></label></fieldset>
          <label v-else-if="activeEntry">Referenced rule set<select v-model="activeEntry.rule_set_id" :disabled="busy || !state.isAdministrator.value"><option v-for="set in ruleSets" :key="set.id" :value="set.id">{{ set.name || set.id }} ({{ set.rules?.length ?? 0 }} rules)</option></select></label><button v-if="activeEntry" class="button button--danger" :disabled="busy || !state.isAdministrator.value" @click="removeEntry">Remove selected entry</button>
        </section>
      </div>
      <section v-else class="panel"><p class="muted">Select a policy or create one to begin.</p></section>
    </div>
    <section v-if="draft && editingMode === 'policy'" class="panel"><div class="panel__heading"><div><h2>Compile preview</h2><p class="muted">Simulate this draft with one device and the gateway capabilities you specify. Choose capabilities supported by your gateway.</p></div><button class="button" :disabled="busy || compiling || !canPreview" @click="compile">{{ compiling ? 'Compiling…' : 'Compile preview' }}</button></div><fieldset class="form-grid" :disabled="compiling || busy"><label>Simulation gateway ID<input v-model="context.gatewayId" required /></label><label>Simulation source IP<input v-model="context.sourceIP" required /></label><label>Supported gateway transports<select v-model="context.transports" multiple><option value="tcp">TCP</option><option value="udp">UDP</option><option value="quic">QUIC</option></select></label><div class="checks"><label class="check-field"><input v-model="context.supportsIPv6" type="checkbox" />Gateway supports IPv6</label><label class="check-field"><input v-model="context.distinguishesNetworks" type="checkbox" />Gateway distinguishes source networks</label></div><label class="wide">Domain sets for simulation<textarea v-model="context.domainSets" rows="2" placeholder="streaming=example.com, media.example" /><small>One set-id=domain, domain per line. Referenced rule sets and outbound candidates are read from the controller.</small></label></fieldset><div v-if="preview" class="result"><StatusPill label="Compiler accepted" tone="good" /><p class="hash">Manifest {{ preview.manifest.content_hash }}</p><p class="muted">{{ preview.manifest.groups?.length ?? 0 }} compiled group(s). {{ preview.impact.changed_groups?.length ?? 0 }} groups changed against an empty baseline; this preview does not compare with a live deployment.</p><ul v-if="preview.diagnostics?.length"><li v-for="(diagnostic, index) in preview.diagnostics" :key="index">{{ diagnostic.severity }} · {{ diagnostic.code }}<span v-if="diagnostic.path"> · {{ diagnostic.path }}</span>: {{ diagnostic.message }}</li></ul><details><summary>Read-only generated manifest</summary><pre>{{ JSON.stringify(preview.manifest, null, 2) }}</pre></details></div></section>
    <section v-if="draft && editingMode === 'policy'" class="panel"><div class="panel__heading"><div><h2>Explain a packet</h2><p class="muted">The prediction uses the last compiled snapshot, including its rule sets and outbound candidates. Recompile after external changes; editing this draft or context clears the snapshot.</p></div><button class="button" :disabled="!preview || explaining || busy || !canPreview" @click="explain">{{ explaining ? 'Explaining…' : 'Explain packet' }}</button></div><fieldset class="form-grid" :disabled="explaining"><label>Packet source IP<input v-model="packet.source_ip" /></label><label>Packet destination IP<input v-model="packet.destination_ip" /></label><label>Packet destination port<input v-model.number="packet.destination_port" type="number" min="1" max="65535" /></label><label>Packet transport<select v-model="packet.transport"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="quic">QUIC</option></select></label><label>Packet family<select v-model="packet.family"><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></label><label>Packet domain<input v-model="packet.domain" placeholder="Optional; blank tests unknown-domain handling" /></label></fieldset><div v-if="explanation" class="result"><StatusPill :label="explanation.predicted ? `Predicted: ${actionLabel(explanation.action)}` : 'No prediction'" tone="warn" /><p>{{ explanation.reason }}</p><p v-if="explanation.matched_rule_id">Matched rule: {{ explanation.matched_rule_name || explanation.matched_rule_id }}</p><p v-if="explanation.device_group_id">Device group: {{ explanation.device_group_id }}</p><p v-if="explanation.candidates?.length">Candidates: {{ explanation.candidates.join(', ') }}</p><small class="muted">This is a compiler prediction; traffic observation is separate.</small></div></section>
  </div>
</template>

<style scoped>
.page-grid,.editor-column { display:grid; gap:1rem; } .page-heading,.panel__heading,.actions { display:flex; align-items:center; justify-content:space-between; gap:.75rem; flex-wrap:wrap; } .page-heading { align-items:end; } h1 { margin:.25rem 0 .4rem; font-size:2rem; } h2 { margin:0; font-size:1.1rem; } p { margin:0; } .eyebrow { color:#78b8ff; font-size:.7rem; font-weight:700; letter-spacing:.1em; text-transform:uppercase; } .lede,.muted { color:var(--muted); } .lede { max-width:46rem; } .muted,small { font-size:.78rem; } .workspace { display:grid; grid-template-columns:minmax(12rem,17rem) minmax(0,1fr); gap:1rem; align-items:start; } .panel { display:grid; gap:.85rem; padding:1rem; border:1px solid var(--border); border-radius:.65rem; background:var(--surface); min-width:0; } .policy-choice { display:grid; gap:.25rem; padding:.7rem; border:1px solid var(--border); border-radius:.4rem; background:var(--surface-alt); color:var(--text); text-align:left; cursor:pointer; overflow-wrap:anywhere; } .policy-choice small { color:var(--muted); } .selected { border-color:#4a93d7!important; background:#1b314b!important; } .form-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:.75rem; min-width:0; margin:0; padding:0; border:0; } label { display:grid; gap:.35rem; color:var(--muted); font-size:.78rem; min-width:0; } input,select,textarea { width:100%; box-sizing:border-box; padding:.5rem .6rem; border:1px solid var(--border); border-radius:.35rem; background:var(--surface-alt); color:var(--text); font:inherit; } select[multiple] { min-height:4.5rem; } textarea { resize:vertical; } .wide { grid-column:1/-1; } .check-field { display:flex; gap:.5rem; align-items:center; } .check-field input { width:auto; } .checks { display:grid; gap:.7rem; align-content:center; } .entry-row { display:flex; gap:.5rem; align-items:center; padding:.3rem; border:1px solid var(--border); border-radius:.4rem; background:var(--surface-alt); } .entry-select { display:flex; gap:.6rem; flex:1; min-width:0; padding:.3rem; border:0; background:transparent; color:var(--text); text-align:left; cursor:pointer; } .entry-select span:last-child { display:grid; gap:.2rem; overflow-wrap:anywhere; } .entry-select small { color:var(--muted); } .rule-fields { padding-top:.6rem; border-top:1px solid var(--border); } .button,.icon-button { cursor:pointer; padding:.5rem .7rem; border:1px solid var(--border); border-radius:.4rem; background:var(--accent); color:#07111f; font-weight:700; } .button--secondary,.icon-button { background:transparent; color:var(--text); } .button--danger { justify-self:start; border-color:#713847; background:transparent; color:#ffbeca; } button:disabled,fieldset:disabled { opacity:.6; } button:disabled { cursor:not-allowed; } .alert { padding:.75rem 1rem; border-radius:.5rem; overflow-wrap:anywhere; } .alert--bad { border:1px solid #713847; background:#301c29; color:#ffbeca; } .alert--good { border:1px solid #2b6a58; background:#15352e; color:#a7f3d0; } .alert--warn { border:1px solid #6b542b; background:#332b1b; color:#ffcf92; } .result { display:grid; gap:.65rem; padding:.8rem; border-radius:.45rem; background:var(--surface-alt); min-width:0; } .hash { overflow-wrap:anywhere; font-size:.75rem; } pre { max-height:24rem; overflow:auto; font-size:.75rem; white-space:pre-wrap; overflow-wrap:anywhere; } summary { cursor:pointer; } @media(max-width:900px) { .workspace { grid-template-columns:1fr; } } @media(max-width:580px) { .form-grid { grid-template-columns:1fr; } .wide { grid-column:auto; } }
</style>
