// @vitest-environment jsdom
import { createApp, h, nextTick, reactive } from 'vue'
import { expect, it } from 'vitest'
import DiagnosticMessage from './DiagnosticMessage.vue'

it('defaults to a Chinese summary, preserves escaped original detail, and resets disclosure on a new error', async () => {
  const host = document.createElement('div'); document.body.append(host)
  const props = reactive({ message: '<img src=x onerror=alert(1)> unknown adapter failure', code: 'outcome_unknown' })
  const app = createApp({ render: () => h(DiagnosticMessage, props) }); app.mount(host)
  try {
    const button = host.querySelector<HTMLButtonElement>('button')!
    const original = host.querySelector<HTMLElement>('[data-raw-diagnostic]')!
    expect(button.textContent).toContain('查看原始诊断')
    expect(button.getAttribute('aria-expanded')).toBe('false')
    expect(original.style.display).toBe('none')
    expect(original.textContent).toBe(props.message)
    expect(host.querySelector('img')).toBeNull()
    expect(button.getAttribute('aria-controls')).toBe(original.id)
    button.click(); await nextTick()
    expect(button.getAttribute('aria-expanded')).toBe('true')
    expect(original.style.display).not.toBe('none')
    props.message = 'another unknown diagnostic'; await nextTick(); await nextTick()
    expect(button.getAttribute('aria-expanded')).toBe('false')
    expect(original.style.display).toBe('none')
  } finally { app.unmount(); host.remove() }
})
