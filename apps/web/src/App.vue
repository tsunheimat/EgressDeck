<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ControllerApi } from './api/client'
import { managementNavigation } from './navigation'
import { navigationHref, readNavigationTarget, subscribeNavigationTarget, type PageName } from './navigationTarget'
import { useControllerState } from './state'
import ActivityView from './views/ActivityView.vue'
import DevicesView from './views/DevicesView.vue'
import InfrastructureView from './views/InfrastructureView.vue'
import OverviewView from './views/OverviewView.vue'
import ProxiesView from './views/ProxiesView.vue'
import RulesView from './views/RulesView.vue'
import SubscriptionsView from './views/SubscriptionsView.vue'

const api = new ControllerApi()
const state = useControllerState(api)
const currentPage = ref(readNavigationTarget().page)
const sidebarOpen = ref(false)
const gateways = state.gateways
const selectedGatewayId = state.selectedGatewayId
const selectedGateway = state.selectedGateway
const loading = state.loading
const error = state.error
const hasDrift = state.hasDrift
const session = state.session
const authRequired = state.authRequired
const sessionUnavailable = state.sessionUnavailable
const navItems = managementNavigation()
const loggingOut = ref(false)
async function logout() {
  loggingOut.value = true
  try { await api.logout(); await state.load() } catch (cause) { error.value = cause instanceof Error ? cause.message : 'Logout failed' } finally { loggingOut.value = false }
}

const pageComponents = { overview: OverviewView, proxies: ProxiesView, subscriptions: SubscriptionsView, devices: DevicesView, rules: RulesView, infrastructure: InfrastructureView, activity: ActivityView } as const
const currentComponent = computed(() => pageComponents[currentPage.value as keyof typeof pageComponents] ?? OverviewView)

function navigate(itemId: string) {
  currentPage.value = itemId as PageName
  window.location.hash = navigationHref({ page: itemId as PageName }).slice(1)
  sidebarOpen.value = false
}

let abortController: AbortController | undefined
let stopNavigation: (() => void) | undefined
onMounted(() => {
  abortController = new AbortController()
  void state.load(abortController.signal)
  stopNavigation = subscribeNavigationTarget(target => { currentPage.value = target.page; sidebarOpen.value = false })
})
onUnmounted(() => { abortController?.abort(); stopNavigation?.() })
</script>

<template>
  <div class="app-shell">
    <header class="topbar">
      <button class="menu-button" aria-label="Toggle navigation" @click="sidebarOpen = !sidebarOpen">☰</button>
      <div class="brand"><span class="brand__mark">◇</span><span><strong>EgressDeck</strong><small>Homelab proxy controller</small></span></div>
      <div class="topbar__tools">
        <label class="gateway-select"><span>Gateway</span><select v-model="selectedGatewayId"><option :value="undefined">Select gateway</option><option v-for="gateway in gateways" :key="gateway.id" :value="gateway.id">{{ gateway.name }}</option></select></label>
        <span v-if="selectedGateway" class="topbar__health" :class="`topbar__health--${selectedGateway.health}`">● {{ selectedGateway.health }}</span>
        <div v-if="session" class="session"><span>{{ session.subject }} · {{ session.roles.join(', ') }}</span><button :disabled="loggingOut" @click="logout">Sign out</button></div>
        <a v-else :href="api.loginURL" class="login-link">Sign in with SSO</a>
      </div>
    </header>
    <div class="body-shell">
      <aside class="sidebar" :class="{ 'sidebar--open': sidebarOpen }">
        <nav aria-label="Main navigation">
          <button v-for="item in navItems" :key="item.id" class="nav-item" :class="{ 'nav-item--active': currentPage === item.id, 'nav-item--disabled': item.disabledReason }" :disabled="!!item.disabledReason" :title="item.disabledReason ?? item.description" @click="navigate(item.id)"><span class="nav-item__icon" aria-hidden="true">{{ item.label.slice(0, 1) }}</span><span>{{ item.label }}</span><span v-if="item.disabledReason" class="nav-item__lock" aria-label="Unavailable">⌁</span></button>
        </nav>
        <div class="sidebar__footer"><small>Controller state</small><strong>{{ error ? 'Unavailable' : loading ? 'Loading…' : hasDrift ? 'Drift detected' : 'Readback current' }}</strong><button class="refresh-link" @click="state.load()">↻ Refresh</button></div>
      </aside>
      <main class="main-content"><section v-if="authRequired" class="auth-panel"><h1>Sign in to EgressDeck</h1><p>Use your identity provider to access device policies and gateway management.</p><a :href="api.loginURL">Sign in with SSO</a></section><template v-else><p v-if="sessionUnavailable" class="session-warning" role="status">Session details are unavailable. Administrative controls require a verified session.</p><KeepAlive><component :is="currentComponent" :state="state" /></KeepAlive></template></main>
    </div>
  </div>
</template>

<style scoped>
.app-shell { min-height: 100vh; background: var(--page); color: var(--text); }
.session { display: flex; gap: .5rem; align-items: center; font-size: .7rem; } .session button { background: none; border: 1px solid var(--border); color: var(--text); padding: .35rem; border-radius: .3rem; } .login-link, .auth-panel a { color: var(--accent); } .session-warning { padding: .75rem; color: var(--warn); background: var(--surface); border-radius: .4rem; font-size: .8rem; } .auth-panel { padding: 2rem; border: 1px solid var(--border); border-radius: .7rem; }
.topbar { position: sticky; z-index: 3; top: 0; display: flex; align-items: center; justify-content: space-between; gap: 1rem; height: 4rem; padding: 0 1.25rem; border-bottom: 1px solid var(--border); background: rgba(13, 24, 41, .94); backdrop-filter: blur(12px); }
.brand { display: flex; align-items: center; gap: .55rem; min-width: 13rem; } .brand__mark { display: grid; width: 1.8rem; height: 1.8rem; place-items: center; border: 1px solid #4a93d7; border-radius: .45rem; color: #78b8ff; font-size: 1.2rem; } .brand strong, .brand small { display: block; } .brand small { color: var(--muted); font-size: .7rem; }
.topbar__tools { display: flex; align-items: center; gap: 1rem; } .gateway-select { display: flex; align-items: center; gap: .5rem; color: var(--muted); font-size: .75rem; } .gateway-select select { min-width: 10rem; padding: .45rem .6rem; border: 1px solid var(--border); border-radius: .35rem; background: var(--surface); color: var(--text); } .topbar__health { font-size: .75rem; } .topbar__health--healthy { color: var(--good); } .topbar__health--offline { color: var(--bad); } .topbar__health--degraded, .topbar__health--unknown { color: var(--warn); }
.body-shell { display: flex; min-height: calc(100vh - 4rem); } .sidebar { display: flex; width: 15rem; flex: 0 0 15rem; flex-direction: column; justify-content: space-between; padding: 1rem .65rem; border-right: 1px solid var(--border); background: var(--surface); } .sidebar nav { display: grid; gap: .25rem; }
.nav-item { display: flex; align-items: center; gap: .6rem; width: 100%; padding: .65rem .7rem; border: 0; border-radius: .4rem; background: transparent; color: var(--muted); text-align: left; cursor: pointer; } .nav-item:hover:not(:disabled), .nav-item--active { background: #1b314b; color: var(--text); } .nav-item--active { box-shadow: inset 2px 0 #78b8ff; } .nav-item--disabled { cursor: not-allowed; opacity: .5; } .nav-item__icon { display: inline-grid; width: 1.25rem; height: 1.25rem; place-items: center; border: 1px solid currentColor; border-radius: .25rem; font-size: .65rem; } .nav-item__lock { margin-left: auto; }
.sidebar__footer { display: grid; gap: .3rem; padding: .7rem; border-radius: .45rem; background: var(--surface-alt); } .sidebar__footer small, .refresh-link { color: var(--muted); font-size: .7rem; } .refresh-link { width: fit-content; padding: 0; border: 0; background: none; cursor: pointer; } .refresh-link:hover { color: var(--text); }
.main-content { width: 100%; max-width: 1280px; padding: 1.5rem; margin: 0 auto; }
.menu-button { display: none; padding: .35rem; border: 0; background: transparent; color: var(--text); font-size: 1.2rem; }
@media (max-width: 760px) { .topbar { padding: 0 .75rem; gap: .5rem; overflow: hidden; } .menu-button { display: block; flex: 0 0 auto; } .brand { min-width: 0; flex: 0 1 auto; font-size: .8rem; white-space: nowrap; } .brand__mark, .gateway-select span, .topbar__health, .session > span { display: none; } .topbar__tools { min-width: 0; flex: 1 1 auto; justify-content: flex-end; gap: .35rem; overflow: hidden; } .gateway-select { min-width: 0; } .gateway-select select { min-width: 0; max-width: 7rem; } .session { min-width: 0; flex: 0 0 auto; } .session button { white-space: nowrap; } .sidebar { position: fixed; z-index: 2; top: 4rem; bottom: 0; left: 0; transform: translateX(-100%); transition: transform .2s ease; } .sidebar--open { transform: translateX(0); } .main-content { padding: 1rem; min-width: 0; overflow-x: hidden; } }
</style>
