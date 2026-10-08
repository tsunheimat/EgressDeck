<script setup lang="ts">
import StatusPill from '../components/StatusPill.vue'
import { useControllerState } from '../state'

const props = defineProps<{ state: ReturnType<typeof useControllerState> }>()
</script>

<template>
  <div class="page-grid">
    <section class="hero-card">
      <div>
        <p class="eyebrow">Controller overview</p>
        <h1>Know what is intended, applied, and verified.</h1>
        <p class="lede">Traffic policy remains on the gateway when the controller is unavailable. This view reports readback state instead of assuming a request succeeded.</p>
      </div>
      <StatusPill v-if="props.state.hasDrift.value" label="Drift detected" tone="warn" />
      <StatusPill v-else-if="props.state.loading.value" label="Loading" />
      <StatusPill v-else-if="props.state.error.value || !props.state.overview.value" label="Readback unavailable" tone="warn" />
      <StatusPill v-else label="Controller inventory loaded" />
    </section>

    <section v-if="props.state.error.value" class="alert alert--bad" role="alert">{{ props.state.error.value }}</section>

    <section class="metric-grid">
      <article class="metric-card"><span>Gateways</span><strong>{{ props.state.overview.value?.gateways.length ?? '—' }}</strong><small>registered data-plane hosts</small></article>
      <article class="metric-card"><span>Device groups</span><strong>{{ props.state.overview.value?.deviceGroups.length ?? '—' }}</strong><small>policy scopes</small></article>
      <article class="metric-card"><span>IPv4 coverage</span><strong>{{ props.state.overview.value?.coverage.ipv4 == null ? 'Unavailable' : `${props.state.overview.value.coverage.ipv4}%` }}</strong><small>Requires traffic verification</small></article>
      <article class="metric-card"><span>IPv6 coverage</span><strong>{{ props.state.overview.value?.coverage.ipv6 == null ? 'Unavailable' : `${props.state.overview.value.coverage.ipv6}%` }}</strong><small>Strict mode requires verified coverage</small></article>
    </section>

    <section class="panel">
      <div class="panel__heading"><div><p class="eyebrow">Recent operations</p><h2>Durable activity</h2></div><span class="muted">{{ props.state.overview.value?.operations.length ?? 0 }} recorded</span></div>
      <div v-if="!props.state.overview.value?.operations.length" class="empty-state">No controller operations have been recorded.</div>
      <ul v-else class="operation-list">
        <li v-for="operation in props.state.overview.value.operations" :key="operation.id"><span><strong>{{ operation.action }}</strong><small>{{ operation.target }}</small></span><StatusPill :label="operation.status" :tone="operation.status === 'applied' ? 'good' : operation.status.includes('failed') ? 'bad' : 'warn'" /></li>
      </ul>
    </section>
  </div>
</template>

<style scoped>
.page-grid { display: grid; gap: 1rem; }
.hero-card { display: flex; justify-content: space-between; align-items: flex-start; gap: 1.5rem; padding: 1.5rem; border: 1px solid var(--border); border-radius: .75rem; background: linear-gradient(135deg, #14263d, #101c30); }
.hero-card h1 { max-width: 34rem; margin: .35rem 0 .65rem; font-size: clamp(1.55rem, 3vw, 2.25rem); line-height: 1.1; }
.lede { max-width: 42rem; margin: 0; color: #a9bad0; }
.eyebrow { margin: 0; color: #78b8ff; font-size: .7rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; }
.metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .75rem; }
.metric-card, .panel { border: 1px solid var(--border); border-radius: .65rem; background: var(--surface); }
.metric-card { display: grid; gap: .25rem; padding: 1rem; }
.metric-card span, .metric-card small, .muted { color: var(--muted); }
.metric-card strong { font-size: 1.6rem; }
.metric-card small { font-size: .72rem; }
.panel { padding: 1rem; }
.panel__heading { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: .8rem; }
.panel h2 { margin: .2rem 0 0; font-size: 1.15rem; }
.operation-list { display: grid; gap: .5rem; padding: 0; margin: 0; list-style: none; }
.operation-list li { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: .65rem; border-radius: .45rem; background: var(--surface-alt); }
.operation-list span:first-child { display: grid; gap: .15rem; }
.operation-list small { color: var(--muted); }
.empty-state { padding: 1.5rem; color: var(--muted); text-align: center; }
.alert { padding: .75rem 1rem; border-radius: .5rem; }
.alert--bad { border: 1px solid #713847; background: #301c29; color: #ffbeca; }
@media (max-width: 760px) { .hero-card { display: grid; } .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
</style>
