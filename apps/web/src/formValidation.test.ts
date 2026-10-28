// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest'
import { installChineseValidation } from './formValidation'
let cleanup: (() => void) | undefined
const root = document.createElement('div')
afterEach(() => { cleanup?.(); root.replaceChildren(); root.remove() })
function setup(html: string) { root.innerHTML = html; document.body.append(root); cleanup = installChineseValidation(root) }
it('localizes required controls without making them valid, then clears only its own message', () => {
  setup('<form><input required><select required><option value="">Choose</option><option value="x">X</option></select></form>')
  const input = root.querySelector('input')!
  expect(input.checkValidity()).toBe(false)
  expect(input.validationMessage).toBe('请填写此字段。')
  input.value = '保留用户内容'; input.dispatchEvent(new Event('input', { bubbles: true }))
  expect(input.checkValidity()).toBe(true)
  const select = root.querySelector('select')!
  expect(select.checkValidity()).toBe(false)
  expect(select.validationMessage).toBe('请选择一个选项。')
  select.value = 'x'; select.dispatchEvent(new Event('change', { bubbles: true }))
  expect(select.checkValidity()).toBe(true)
})
it('preserves URL and range validation and clears messages when a form resets', () => {
  setup('<form><input type="url"><input type="number" min="5" max="9"></form>')
  const [url, number] = root.querySelectorAll('input')
  url!.value = 'bad'; expect(url!.checkValidity()).toBe(false)
  expect(url!.validationMessage).toBe('请输入完整有效的 URL。')
  number!.value = '4'; expect(number!.checkValidity()).toBe(false)
  expect(number!.validationMessage).toContain('不小于 5')
  root.querySelector('form')!.reset()
  expect(url!.validity.customError).toBe(false)
  expect(number!.validity.customError).toBe(false)
})
it('does not clear a page-owned custom validation error', () => {
  setup('<input>'); const input = root.querySelector('input')!
  input.setCustomValidity('页面校验未通过。')
  expect(input.checkValidity()).toBe(false)
  input.dispatchEvent(new Event('input', { bubbles: true }))
  expect(input.validationMessage).toBe('页面校验未通过。')
  cleanup?.(); expect(input.validationMessage).toBe('页面校验未通过。')
})

it('preserves a page-owned error that replaces an earlier localized browser message', () => {
  setup('<input required>'); const input = root.querySelector('input')!
  expect(input.checkValidity()).toBe(false)
  expect(input.validationMessage).toBe('请填写此字段。')
  input.setCustomValidity('当前设备地址已被占用。')
  input.value = '192.0.2.10'
  input.dispatchEvent(new Event('input', { bubbles: true }))
  expect(input.validationMessage).toBe('当前设备地址已被占用。')
  expect(input.checkValidity()).toBe(false)
  cleanup?.(); expect(input.validationMessage).toBe('当前设备地址已被占用。')
})
