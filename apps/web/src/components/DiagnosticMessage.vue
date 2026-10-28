<script setup lang="ts">
import { computed, ref, useId, watch } from 'vue'
import { diagnosticPresentation } from '../localization'

const props = defineProps<{ message?: unknown; code?: string }>()
const presentation = computed(() => diagnosticPresentation(props.message, props.code))
const expanded = ref(false)
const originalId = useId()
watch(() => [props.message, props.code], () => { expanded.value = false })
</script>

<template>
  <span class="diagnostic-message">
    <span>{{ presentation.summary }}</span>
    <template v-if="presentation.original">
      <button type="button" class="diagnostic-toggle" :aria-expanded="expanded" :aria-controls="originalId" @click="expanded = !expanded">{{ expanded ? '收起原始诊断' : '查看原始诊断（未翻译）' }}</button>
      <span v-show="expanded" :id="originalId" class="diagnostic-original" lang="en" data-raw-diagnostic>{{ presentation.original }}</span>
    </template>
  </span>
</template>

<style scoped>
.diagnostic-message { overflow-wrap: anywhere; line-height: 1.65; }
.diagnostic-toggle { margin-inline-start: .5rem; padding: .1rem .3rem; border: 1px solid currentColor; border-radius: .25rem; background: transparent; color: inherit; font: inherit; font-size: .9em; cursor: pointer; }
.diagnostic-original { display: block; margin-top: .4rem; padding: .5rem; border-inline-start: 2px solid var(--border); white-space: pre-wrap; font-family: ui-monospace, monospace; font-size: .9em; }
</style>
