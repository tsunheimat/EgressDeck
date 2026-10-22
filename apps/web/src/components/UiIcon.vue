<script setup lang="ts">
/** Small, dependency-free line icons. The surrounding control owns its accessible name. */
withDefaults(defineProps<{ name: string; size?: number }>(), { size: 20 })
const paths: Record<string, string[]> = {
  overview: ['M3 10 12 3l9 7v10a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1Z'],
  proxies: ['M12 3 3 8l9 5 9-5-9-5Z', 'm3 12 9 5 9-5', 'm3 16 9 5 9-5'],
  subscriptions: ['M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9Z', 'M14 3v6h6', 'M8 13h8M8 17h5'],
  devices: ['M4 4h16v12H4Z', 'M8 21h8M12 16v5'],
  rules: ['M5 3v5m0 4v9M12 3v10m0 4v4M19 3v2m0 4v12', 'M2 8h6v4H2ZM9 13h6v4H9ZM16 5h6v4h-6Z'],
  infrastructure: ['M4 13h16v7H4Z', 'M7 13V4m10 9V4', 'M8 17h.01M12 17h4'],
  activity: ['M3 12h4l3-8 4 16 3-8h4'],
  check: ['m5 12 4 4L19 6'],
  chevron: ['m9 5 7 7-7 7'],
  down: ['m6 9 6 6 6-6'],
  plus: ['M12 5v14M5 12h14'],
  refresh: ['M20 7v5h-5M4 17v-5h5', 'M6 6a8 8 0 0 1 13 2M18 18A8 8 0 0 1 5 16'],
  menu: ['M4 6h16M4 12h16M4 18h16'],
  close: ['m6 6 12 12M6 18 18 6'],
  shield: ['M12 3 4 6v6c0 4 4 7 8 9 4-2 8-5 8-9V6Z', 'm8 12 3 3 5-6'],
  warning: ['m12 3 10 18H2Z', 'M12 9v5m0 3h.01'],
  clock: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z', 'M12 7v5l3 2'],
  user: ['M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z', 'M4 21v-2a8 8 0 0 1 16 0v2'],
  link: ['m10 14 4-4', 'M9 15 7 17a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0', 'm15 9 2-2a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0'],
  arrow: ['M4 12h16m-6-6 6 6-6 6'],
  globe: ['M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z', 'M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z'],
  rocket: ['M14 4 21 3l-1 7-9 9-6-6Z', 'm5 13-2-1 2-6 7-1', 'm11 19 1 2 6-2 1-7', 'm4 17-1 4 4-1', 'M15 8h.01'],
  logout: ['M9 3H4v18h5', 'M9 12h12m-4-4 4 4-4 4'],
  search: ['M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14Z', 'm15 15 6 6'],
}
</script>

<template>
  <svg class="ui-icon" :width="size" :height="size" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
    <path v-for="(path, index) in paths[name] ?? paths.overview" :key="index" :d="path" />
  </svg>
</template>

<style scoped>
.ui-icon { flex: 0 0 auto; vertical-align: middle; }
</style>
