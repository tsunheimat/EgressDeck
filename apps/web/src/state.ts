import { computed, ref } from 'vue'
import { ControllerApi, ControllerApiError } from './api/client'
import type { Capability, GatewaySummary, OverviewResponse, OperationSummary, SessionSummary } from './types'

export function useControllerState(api = new ControllerApi()) {
  const loading = ref(false)
  const error = ref<string | undefined>()
  const overview = ref<OverviewResponse>()
  const gateways = ref<GatewaySummary[]>([])
  const selectedGatewayId = ref<string>()
  const lastOperation = ref<OperationSummary>()
  const capabilities = ref<Partial<Record<Capability, boolean>>>({})
  const session = ref<SessionSummary>()
  const authRequired = ref(false)
  const sessionUnavailable = ref(false)
  const canOperate = computed(() => !!session.value?.roles.some(role => ['operator', 'administrator', 'admin'].includes(role)))
  const isAdministrator = computed(() => !!session.value?.roles.some(role => ['administrator', 'admin'].includes(role)))

  const selectedGateway = computed(() => gateways.value.find((gateway) => gateway.id === selectedGatewayId.value) ?? gateways.value[0])
  const hasDrift = computed(() => overview.value?.bindings.some((binding) => binding.drift) || overview.value?.deviceGroups.some((group) => group.drift) || false)

  async function load(signal?: AbortSignal) {
    loading.value = true
    error.value = undefined
    try {
      const [overviewResult, gatewayResult, capabilityResult, sessionResult] = await Promise.allSettled([api.overview(signal), api.gateways(signal), api.capabilities(signal), api.session(signal)])
      if (capabilityResult.status === 'fulfilled') capabilities.value = capabilityResult.value.capabilities
      if (sessionResult.status === 'fulfilled') { session.value = sessionResult.value; authRequired.value = false; sessionUnavailable.value = false }
      else { session.value = undefined; authRequired.value = sessionResult.reason instanceof ControllerApiError && sessionResult.reason.status === 401; sessionUnavailable.value = !authRequired.value }
      if (overviewResult.status === 'fulfilled') overview.value = overviewResult.value
      if (gatewayResult.status === 'fulfilled') {
        gateways.value = gatewayResult.value
        if (!selectedGatewayId.value && gatewayResult.value[0]) selectedGatewayId.value = gatewayResult.value[0].id
      }
      const failures = [overviewResult, gatewayResult].filter((result): result is PromiseRejectedResult => result.status === 'rejected')
      if (failures.length === 2) throw failures[0]?.reason
      if (failures.length === 1) error.value = failures[0]?.reason instanceof ControllerApiError ? failures[0].reason.message : 'Some controller state is unavailable'
    } catch (cause) {
      if (cause instanceof DOMException && cause.name === 'AbortError') return
      error.value = cause instanceof ControllerApiError ? cause.message : 'Unable to load controller state'
    } finally {
      loading.value = false
    }
  }

  function recordOperation(operation: OperationSummary) {
    lastOperation.value = operation
  }

  return { api, loading, error, overview, gateways, selectedGatewayId, selectedGateway, lastOperation, hasDrift, capabilities, session, authRequired, sessionUnavailable, canOperate, isAdministrator, load, recordOperation }
}
