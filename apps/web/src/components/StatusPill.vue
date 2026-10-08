<script setup lang="ts">
defineProps<{ label: string; tone?: 'neutral' | 'good' | 'warn' | 'bad' }>()
</script>

<template>
  <span class="status-pill" :class="`status-pill--${tone ?? 'neutral'}`">
    <span class="status-pill__dot" aria-hidden="true" />
    {{ label }}
  </span>
</template>

<style scoped>
.status-pill { display: inline-flex; align-items: center; gap: .4rem; border: 1px solid var(--border); border-radius: 999px; padding: .25rem .55rem; color: var(--muted); font-size: .75rem; white-space: nowrap; }
.status-pill__dot { width: .45rem; height: .45rem; border-radius: 50%; background: currentColor; }
.status-pill--good { color: var(--good); }
.status-pill--warn { color: var(--warn); }
.status-pill--bad { color: var(--bad); }
</style>

