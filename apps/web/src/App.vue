<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ControllerApi } from './api/client'
import { installChineseValidation } from './formValidation'
import { managementNavigation } from './navigation'
import { navigationHref, readNavigationTarget, subscribeNavigationTarget, type PageName } from './navigationTarget'
import { useControllerState } from './state'
import { healthLabels, healthTone } from './uiPresentation'
import StatusPill from './components/StatusPill.vue'
import UiIcon from './components/UiIcon.vue'
import ActivityView from './views/ActivityView.vue'
import DevicesView from './views/DevicesView.vue'
import InfrastructureView from './views/InfrastructureView.vue'
import OverviewView from './views/OverviewView.vue'
import ProxiesView from './views/ProxiesView.vue'
import RulesView from './views/RulesView.vue'
import SubscriptionsView from './views/SubscriptionsView.vue'

const uiBuild = __EGRESSDECK_UI_BUILD__
const api = new ControllerApi()
const state = useControllerState(api)
const currentPage = ref(readNavigationTarget().page)
const sidebarOpen = ref(false)
const compact = ref(false)
const sidebar = ref<HTMLElement>()
const menuButton = ref<HTMLButtonElement>()
const mainContent = ref<HTMLElement>()
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
const roleLabel = computed(() => state.isAdministrator.value ? '管理员' : state.canOperate.value ? '操作员' : '只读用户')
const controllerLabel = computed(() => authRequired.value ? '请先登录' : loading.value ? '正在读取配置' : error.value ? '配置读取失败' : !state.overview.value ? '尚未读取配置' : hasDrift.value ? '发现配置差异' : '配置已读取')
const pageComponents = { overview: OverviewView, proxies: ProxiesView, subscriptions: SubscriptionsView, devices: DevicesView, rules: RulesView, infrastructure: InfrastructureView, activity: ActivityView } as const
const currentComponent = computed(() => pageComponents[currentPage.value] ?? OverviewView)

async function logout() {
  loggingOut.value = true
  try { await api.logout(); await state.load() }
  catch (cause) { error.value = cause instanceof Error ? cause.message : '退出登录失败' }
  finally { loggingOut.value = false }
}
function closeSidebar(restoreFocus = false) {
  sidebarOpen.value = false
  if (restoreFocus) void nextTick(() => menuButton.value?.focus())
}
function navigate(itemId: string) {
  currentPage.value = itemId as PageName
  window.location.hash = navigationHref({ page: itemId as PageName }).slice(1)
  closeSidebar()
  void nextTick(() => mainContent.value?.focus({ preventScroll: true }))
}
function sidebarKeys(event: KeyboardEvent) {
  if (!compact.value || !sidebarOpen.value) return
  if (event.key === 'Escape') { event.preventDefault(); closeSidebar(true); return }
  if (event.key !== 'Tab') return
  const controls = sidebar.value?.querySelectorAll<HTMLElement>('a[href], button:not(:disabled), select:not(:disabled), [tabindex="0"]')
  const first = controls?.[0]
  const last = controls?.[controls.length - 1]
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
}

let stopValidation: (() => void) | undefined
let abortController: AbortController | undefined
let stopNavigation: (() => void) | undefined
let media: MediaQueryList | undefined
let previousOverflow = ''
function syncViewport() { compact.value = media?.matches ?? false; if (!compact.value) sidebarOpen.value = false }
function updateTitle() { document.title = `${navItems.find(item => item.id === currentPage.value)?.label ?? '总览'} · EgressDeck` }
watch(currentPage, updateTitle)
watch([sidebarOpen, compact], async ([open, small]) => {
  document.body.style.overflow = open && small ? 'hidden' : previousOverflow
  if (open && small) { await nextTick(); sidebar.value?.querySelector<HTMLButtonElement>('.sidebar-close')?.focus() }
})
onMounted(() => {
  if (mainContent.value) stopValidation = installChineseValidation(mainContent.value)
  previousOverflow = document.body.style.overflow
  media = window.matchMedia?.('(max-width: 960px)')
  syncViewport()
  media?.addEventListener('change', syncViewport)
  updateTitle()
  abortController = new AbortController()
  void state.load(abortController.signal)
  stopNavigation = subscribeNavigationTarget(target => { currentPage.value = target.page; closeSidebar() })
})
onUnmounted(() => {
  stopValidation?.()
  abortController?.abort()
  stopNavigation?.()
  media?.removeEventListener('change', syncViewport)
  document.body.style.overflow = previousOverflow
})
</script>

<template>
  <div class="app-shell">
    <a class="skip-link" href="#main-content" @click.prevent="mainContent?.focus()">跳至主要内容</a>
    <div v-if="compact && sidebarOpen" class="sidebar-backdrop" aria-hidden="true" @click="closeSidebar(true)" />
    <aside id="main-sidebar" ref="sidebar" class="sidebar" :class="{ 'sidebar--open': sidebarOpen }" :role="compact ? 'dialog' : undefined" :aria-modal="compact && sidebarOpen ? true : undefined" :aria-label="compact ? '导航菜单' : undefined" @keydown="sidebarKeys">
      <div class="brand">
        <svg class="brand__mark" viewBox="0 0 40 40" aria-hidden="true"><path d="M29 8a14 14 0 1 0 2 22V19H19" fill="none" stroke="currentColor" stroke-width="6" stroke-linecap="round" stroke-linejoin="round" /><circle cx="23" cy="26" r="4" fill="var(--page)" stroke="currentColor" stroke-width="3" /></svg>
        <span><strong>EgressDeck</strong><small>家庭实验室代理管理</small></span>
        <button class="ed-icon-button sidebar-close" aria-label="关闭导航" @click="closeSidebar(true)"><UiIcon name="close" /></button>
      </div>
      <nav aria-label="主导航">
        <button v-for="item in navItems" :key="item.id" class="nav-item" :data-nav="item.id" :class="{ 'nav-item--active': currentPage === item.id }" :aria-current="currentPage === item.id ? 'page' : undefined" :disabled="!!item.disabledReason" :title="item.disabledReason ?? item.description" @click="navigate(item.id)">
          <UiIcon :name="item.id" :size="22" /><span>{{ item.label }}</span>
        </button>
      </nav>
      <section class="homelab-card" aria-label="家庭网络管理">
        <h2>让家庭网络<br />更安全、更可控</h2>
        <p>通过 dae 与 OPNsense<br />管理代理路由与防火墙，<br />让每次配置都有据可查。</p>
        <svg class="homelab-art" viewBox="0 0 220 128" aria-hidden="true">
          <path d="M0 67 40 35 64 51 98 25 139 49 168 30 220 56v72H0Z" fill="#102b44" />
          <path d="m0 91 45-31 46 20 67-37 62 27v58H0Z" fill="#0a2033" />
          <path d="M0 116 67 102l83 3 70 12v11H0Z" fill="#17364a" />
          <path d="m62 87 34-31 42 8 27 28-39-5-30-18-26 24Z" fill="#19496b" />
          <path d="M70 88 96 68l30 19v30H70Z" fill="#0a1827" stroke="#24445c" />
          <path d="M126 87h32v29h-32Z" fill="#0b2437" stroke="#24445c" />
          <path d="M88 94h10v23H88ZM109 94h8v10h-8ZM136 94h8v10h-8ZM80 82h7v9h-7Z" fill="#399be3" />
          <path d="m103 64 13 3 7 8-13-3Z" fill="#5ba6dd" />
          <path d="M24 120V70m-12 25 12-25 12 25Zm164 25V77m-11 22 11-22 11 22Z" fill="#05121e" stroke="#05121e" stroke-width="4" />
          <path d="m90 118 14-1 17 11H70Z" fill="#2d4354" />
        </svg>
      </section>
      <footer class="sidebar__footer">
        <span class="footer-icon"><UiIcon name="shield" /></span>
        <span><strong>EgressDeck</strong><small>{{ controllerLabel }}</small><small class="ui-build" :title="uiBuild.sourceSha256" data-ui-build>界面版本 {{ uiBuild.sourceSha256.slice(0, 10) }}</small></span>
        <button class="ed-icon-button" :disabled="loading || authRequired" aria-label="刷新控制器状态" @click="state.load()"><UiIcon name="refresh" :size="17" /></button>
      </footer>
    </aside>

    <div class="workspace" :inert="compact && sidebarOpen">
      <header class="topbar">
        <button ref="menuButton" class="ed-icon-button menu-button" aria-label="打开导航" aria-controls="main-sidebar" :aria-expanded="sidebarOpen" @click="sidebarOpen = true"><UiIcon name="menu" /></button>
        <div class="gateway-context">
          <label class="gateway-select"><span>默认网关</span><select v-model="selectedGatewayId" aria-label="默认操作网关" aria-describedby="gateway-context-help"><option :value="undefined">选择网关</option><option v-for="gateway in gateways" :key="gateway.id" :value="gateway.id">{{ gateway.name }}</option></select></label>
          <StatusPill v-if="selectedGateway" :label="loading ? '正在读取' : error ? '状态待确认' : healthLabels[selectedGateway.health]" :tone="loading || error ? 'neutral' : healthTone(selectedGateway.health)" />
          <span id="gateway-context-help" class="scope-hint">新建与诊断的默认目标，不筛选列表</span>
        </div>
        <div class="topbar__tools">
          <button class="ed-icon-button activity-link" aria-label="打开活动与诊断" title="活动与诊断" @click="navigate('activity')"><UiIcon name="activity" /></button>
          <div v-if="session" class="session">
            <span class="session__avatar"><UiIcon name="user" :size="18" /></span>
            <span class="session__identity"><strong>{{ roleLabel }}</strong><small :title="session.subject">{{ session.subject }}</small></span>
            <button class="ed-icon-button" :disabled="loggingOut" :aria-label="loggingOut ? '正在退出登录' : '退出登录'" @click="logout"><UiIcon name="logout" :size="17" /></button>
          </div>
          <a v-else :href="api.loginURL" class="ed-button ed-button--quiet login-link">单点登录</a>
          <button v-if="session" class="ed-button devices-shortcut" @click="navigate('devices')"><UiIcon name="devices" :size="17" />管理设备</button>
        </div>
      </header>
      <main id="main-content" ref="mainContent" class="main-content" tabindex="-1">
        <section v-if="authRequired" class="auth-panel ed-panel"><span class="ed-icon-tile"><UiIcon name="shield" :size="26" /></span><h1>登录 EgressDeck</h1><p>使用你的身份提供商登录，管理家庭网络的设备与代理策略。</p><a :href="api.loginURL" class="ed-button">通过单点登录继续<UiIcon name="arrow" :size="18" /></a></section>
        <template v-else>
          <p v-if="sessionUnavailable" class="session-warning" role="status"><UiIcon name="warning" />无法读取会话信息。管理操作需要已验证的登录会话。</p>
          <KeepAlive><component :is="currentComponent" :state="state" /></KeepAlive>
        </template>
      </main>
    </div>
  </div>
</template>

<style scoped>
.app-shell { display: grid; grid-template-columns: 244px minmax(0, 1fr); min-height: 100dvh; color: var(--text); background: radial-gradient(ellipse at 70% 0, #0b2037 0, transparent 60%), var(--page); }
.sidebar { position: sticky; top: 0; display: flex; flex-direction: column; height: 100dvh; padding: 0 12px 14px; border-right: 1px solid #15304a; background: linear-gradient(170deg, #061421, #081725); overflow-y: auto; z-index: 20; }
.brand { display: flex; align-items: center; gap: 12px; min-height: 72px; padding: 12px 6px; margin: 0 -12px 18px; padding-left: 20px; border-bottom: 1px solid #142c42; }
.brand__mark { width: 38px; height: 38px; flex: 0 0 auto; color: #1492ff; }
.brand strong, .brand small { display: block; }.brand strong { font-size: 1.3rem; letter-spacing: -.03em; }.brand small { margin-top: 3px; color: var(--muted); font-size: .71rem; }
.sidebar nav { display: grid; gap: 7px; }
.nav-item { display: flex; align-items: center; gap: 17px; width: 100%; min-height: 47px; padding: 10px 16px; border: 1px solid transparent; border-radius: 9px; background: transparent; color: #b9cde6; text-align: left; font-size: .94rem; }
.nav-item:hover { background: #102b46; color: #fff; }.nav-item--active { border-color: #1764ac; background: linear-gradient(95deg, #0e3b76, #0a2955); color: #dceaff; box-shadow: inset 3px 0 #118dff; }.nav-item--active .ui-icon { color: #62adff; }
.homelab-card { position: relative; overflow: hidden; flex: 0 0 auto; margin-top: clamp(2rem, 10vh, 7rem); border: 1px solid #17334c; border-radius: 11px; background: linear-gradient(140deg, #0c243b, #091a2b); }
.homelab-card h2 { margin: 23px 20px 10px; font-size: 1.04rem; line-height: 1.65; }.homelab-card p { margin: 0 20px; color: var(--muted); font-size: .78rem; line-height: 1.8; }.homelab-art { display: block; width: 100%; margin-top: 8px; }
.sidebar__footer { display: flex; align-items: center; gap: 10px; padding: 28px 4px 0; margin-top: auto; }.footer-icon { display: grid; place-items: center; width: 34px; height: 34px; border: 1px solid #315374; border-radius: 50%; color: var(--muted); }.sidebar__footer strong, .sidebar__footer small { display: block; font-size: .72rem; font-weight: 400; }.sidebar__footer small { margin-top: 4px; color: var(--muted); font-size: .65rem; }.sidebar__footer .ed-icon-button { margin-left: auto; width: 28px; height: 30px; border: 0; }
.workspace { min-width: 0; }.topbar { position: sticky; top: 0; z-index: 10; display: flex; justify-content: space-between; align-items: center; gap: 16px; min-height: 64px; padding: 10px 24px; border-bottom: 1px solid #19324c; background: linear-gradient(100deg, #0c1e33f5, #102d4cf5); backdrop-filter: blur(14px); }
.gateway-context, .gateway-select, .topbar__tools { display: flex; align-items: center; gap: 12px; min-width: 0; }.gateway-context { flex-wrap: wrap; gap: 7px 12px; }.gateway-select { font-size: .78rem; }.gateway-select > span { white-space: nowrap; }.gateway-select select { max-width: 240px; min-width: 130px; height: 34px; padding: 0 10px; border: 1px solid var(--border); border-radius: 6px; }.scope-hint { display: none; color: var(--muted); font-size: .65rem; }
.topbar__tools { flex: 0 0 auto; gap: 9px; }.activity-link { border-color: transparent; }.session { display: flex; align-items: center; gap: 9px; padding: 3px 5px 3px 7px; border: 1px solid #203e5b; border-radius: 8px; background: #0a1c30; }.session__avatar { display: grid; place-items: center; width: 29px; height: 29px; border: 1px solid #7a9aff; border-radius: 50%; color: #fff; background: #5578e8; }.session__identity strong, .session__identity small { display: block; }.session__identity strong { font-size: .72rem; }.session__identity small { max-width: 115px; margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); font-size: .65rem; }.session .ed-icon-button { width: 27px; height: 28px; border: 0; }
.main-content { width: 100%; max-width: 1680px; margin: 0 auto; padding: 24px; min-width: 0; }.main-content:focus { outline: none; }.session-warning { display: flex; align-items: center; gap: .6rem; padding: .8rem; margin: 0 0 1rem; border: 1px solid #69532a; border-radius: 7px; color: var(--warn); background: #2b261a; font-size: .82rem; }
.auth-panel { max-width: 600px; margin: 10vh auto; padding: clamp(1.25rem, 5vw, 3rem); }.auth-panel h1 { margin: 1.25rem 0 .75rem; }.auth-panel p { margin-bottom: 1.5rem; color: var(--muted); line-height: 1.8; }
.menu-button, .sidebar-close { display: none; }.skip-link { position: fixed; z-index: 100; top: 8px; left: 260px; padding: .8rem 1.2rem; border-radius: 6px; background: #fff; color: #07182c; transform: translateY(-180%); }.skip-link:focus { transform: translateY(0); }
@media (min-width: 1650px) { .scope-hint { display: block; } }
@media (max-width: 1200px) { .app-shell { grid-template-columns: 214px minmax(0, 1fr); }.brand strong { font-size: 1.2rem; }.brand { gap: 8px; }.topbar { padding-inline: 20px; }.activity-link, .devices-shortcut { display: none; } }
@media (max-width: 960px) { .app-shell { display: block; }.sidebar { display: none; position: fixed; inset: 0 auto 0 0; width: min(300px, 87vw); z-index: 40; box-shadow: 15px 0 60px #0009; }.sidebar--open { display: flex; }.sidebar-close { display: inline-grid; margin-left: auto; margin-right: 10px; border: 0; }.sidebar-backdrop { position: fixed; inset: 0; z-index: 30; background: #020914aa; backdrop-filter: blur(3px); }.menu-button { display: inline-grid; flex: 0 0 auto; }.topbar { padding: 10px 16px; gap: 10px; }.gateway-context { flex: 1; }.main-content { padding: 20px; }.skip-link { left: 12px; }.homelab-card { margin-top: 32px; } }
@media (max-width: 600px) { .topbar { gap: 8px; padding-inline: 12px; }.main-content { padding: 16px 12px; }.gateway-select > span, .gateway-context > .status-pill, .session__identity { display: none; }.gateway-select { min-width: 0; width: 100%; }.gateway-select select { width: 100%; min-width: 0; max-width: 100%; }.session { gap: 4px; }.topbar__tools { gap: 4px; }.session__avatar { width: 25px; height: 25px; }.login-link { padding-inline: .6rem; font-size: .73rem; }.topbar { min-height: 60px; } }
</style>
