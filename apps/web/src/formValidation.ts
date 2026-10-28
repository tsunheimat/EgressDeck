/** Translate browser-owned validation without changing constraints or submit behavior. */
type Control = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
function control(target: EventTarget | null): target is Control {
  return target instanceof HTMLInputElement || target instanceof HTMLSelectElement || target instanceof HTMLTextAreaElement
}
export function installChineseValidation(root: HTMLElement): () => void {
  const owned = new Map<Control, string>()
  function clearOwned(field: Control) {
    const message = owned.get(field)
    owned.delete(field)
    if (message !== undefined && field.validationMessage === message) field.setCustomValidity('')
  }
  function clear(event: Event) {
    if (control(event.target)) clearOwned(event.target)
  }
  function invalid(event: Event) {
    const target = event.target
    if (!control(target)) return
    // Respect any custom validator owned by the page.
    if (target.validity.customError && target.validationMessage !== owned.get(target)) { owned.delete(target); return }
    clearOwned(target)
    const validity = target.validity
    if (validity.valid) return
    let message = '输入格式不符合要求，请检查后重试。'
    if (validity.valueMissing) message = target instanceof HTMLSelectElement ? '请选择一个选项。' : '请填写此字段。'
    else if (validity.typeMismatch) message = target instanceof HTMLInputElement && target.type === 'url' ? '请输入完整有效的 URL。' : '请输入有效的内容。'
    else if (validity.badInput) message = '请输入有效的数字。'
    else if (validity.rangeUnderflow && target instanceof HTMLInputElement) message = `请输入不小于 ${target.min} 的数值。`
    else if (validity.rangeOverflow && target instanceof HTMLInputElement) message = `请输入不大于 ${target.max} 的数值。`
    else if (validity.stepMismatch) message = '请输入符合允许步长的数值。'
    else if (validity.tooLong) message = '输入内容超过允许的长度。'
    else if (validity.tooShort) message = '输入内容未达到要求的长度。'
    target.setCustomValidity(message)
    owned.set(target, message)
  }
  function reset(event: Event) {
    if (event.target instanceof HTMLFormElement) for (const field of owned.keys()) {
      if (field.form === event.target) clearOwned(field)
    }
  }
  root.addEventListener('invalid', invalid, true)
  root.addEventListener('input', clear, true)
  root.addEventListener('change', clear, true)
  root.addEventListener('reset', reset, true)
  return () => {
    root.removeEventListener('invalid', invalid, true)
    root.removeEventListener('input', clear, true)
    root.removeEventListener('change', clear, true)
    root.removeEventListener('reset', reset, true)
    for (const field of owned.keys()) clearOwned(field)
    owned.clear()
  }
}
