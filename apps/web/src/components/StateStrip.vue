<script setup lang="ts">
import type { StateKind } from '../types'

defineProps<{ states: Partial<Record<StateKind, string>>; pending?: boolean }>()
</script>

<template>
  <div class="state-strip" aria-label="deployment state">
    <span v-for="kind in ['desired', 'applied', 'observed', 'verified']" :key="kind" class="state-strip__item" :class="{ 'state-strip__item--empty': !states[kind as StateKind] }">
      <strong>{{ kind }}</strong>
      <span>{{ states[kind as StateKind] ?? '—' }}</span>
    </span>
    <span v-if="pending" class="state-strip__pending">Readback pending</span>
  </div>
</template>

<style scoped>
.state-strip { display: flex; flex-wrap: wrap; gap: .35rem; align-items: center; }
.state-strip__item { display: inline-flex; gap: .35rem; align-items: baseline; padding: .3rem .45rem; border-radius: .35rem; background: var(--surface-alt); font-size: .75rem; }
.state-strip__item strong { color: var(--muted); font-size: .65rem; text-transform: uppercase; letter-spacing: .05em; }
.state-strip__item--empty { opacity: .55; }
.state-strip__pending { color: var(--warn); font-size: .75rem; }
</style>

