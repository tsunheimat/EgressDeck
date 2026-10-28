import { expect, test, type Page } from '@playwright/test'
import { signIn } from './auth'

const pages = [
  ['overview', '总览'], ['proxies', '代理'], ['subscriptions', '订阅'],
  ['devices', '设备与分组'], ['rules', '规则策略'], ['infrastructure', '基础设施'], ['activity', '活动与诊断'],
] as const
async function navigate(page: Page, id: string, title: string) {
  const menu = page.getByRole('button', { name: '打开导航', exact: true })
  if (await menu.isVisible()) await menu.click()
  await page.locator(`[data-nav="${id}"]`).click()
  await expect(page.getByRole('heading', { level: 1, name: title, exact: true })).toBeVisible()
}

// Real controller + real auth/CSRF; editors are inspected without applying live traffic policy.
test('Chinese copy covers all seven pages, editor controls, and responsive layouts', async ({ page, context }, testInfo) => {
  test.setTimeout(120_000)
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await signIn(context)
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto('/')
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-CN')
  const build = await (await page.request.get('/build-info.json')).json()
  expect(build.locale).toBe('zh-CN')
  expect(build.sourceSha256).toMatch(/^[0-9a-f]{64}$/)
  await expect(page.locator('meta[name="egressdeck-ui-build"]')).toHaveAttribute('content', build.sourceSha256)
  await expect(page.locator('[data-ui-build]')).toContainText(build.sourceSha256.slice(0, 10))

  await navigate(page, 'proxies', '代理')
  await expect(page.getByRole('searchbox', { name: '搜索节点' })).toBeVisible()
  await page.getByRole('button', { name: '新建代理组', exact: true }).click()
  await expect(page.getByLabel('代理组名称', { exact: true })).toBeVisible()
  await expect(page.getByRole('combobox', { name: '选择模式', exact: true }).locator('option')).toHaveText(['手动选择', '自动选择（暂不可用）'])
  await page.getByRole('button', { name: '取消', exact: true }).click()

  await navigate(page, 'subscriptions', '订阅')
  await page.getByRole('button', { name: '添加订阅', exact: true }).click()
  await expect(page.getByLabel('订阅名称', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '添加并暂存订阅', exact: true })).toBeVisible()

  await navigate(page, 'devices', '设备与分组')
  await page.getByRole('button', { name: '添加设备', exact: true }).click()
  await expect(page.getByLabel('设备名称', { exact: true })).toBeVisible()
  await expect(page.getByLabel('IP 地址', { exact: true })).toBeVisible()
  await expect(page.getByText('保存清单不代表地址已验证或代理已生效', { exact: false })).toBeVisible()

  await navigate(page, 'rules', '规则策略')
  await page.getByRole('button', { name: '新建策略', exact: true }).click()
  await expect(page.getByLabel('策略名称', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: '添加规则', exact: true }).click()
  const action = page.getByRole('combobox', { name: '规则动作', exact: true })
  await expect(action.locator('option')).toHaveText(['直连', '代理', '阻断', '代理组'])
  expect(await action.locator('option').evaluateAll(options => options.map(option => (option as HTMLOptionElement).value))).toEqual(['direct', 'proxy', 'block', 'outbound_group'])
  await expect(page.getByRole('button', { name: '保存策略', exact: true })).toBeVisible()

  await navigate(page, 'infrastructure', '基础设施')
  await page.getByRole('button', { name: '登记网关', exact: true }).click()
  const name = page.getByLabel('网关名称', { exact: true })
  await expect(name).toBeVisible()
  expect(await name.evaluate((input: HTMLInputElement) => input.reportValidity())).toBe(false)
  expect(await name.evaluate((input: HTMLInputElement) => input.validationMessage)).toBe('请填写此字段。')
  await name.fill('保持用户输入 English name')
  expect(await name.evaluate((input: HTMLInputElement) => input.checkValidity())).toBe(true)
  await expect(page.getByRole('button', { name: '保存网关', exact: true })).toBeVisible()

  await navigate(page, 'activity', '活动与诊断')
  for (const name of ['网关流量', '操作记录', '审计记录']) await expect(page.getByRole('heading', { name, exact: true })).toBeVisible()
  for (const [id, title] of pages) {
    await navigate(page, id, title)
    await page.waitForLoadState('networkidle')
    await page.screenshot({ path: testInfo.outputPath(`${id}-zh-desktop.png`), fullPage: true })
    const visible = await page.getByRole('main').innerText()
    expect(visible).not.toMatch(/Refresh policies|Add subscription|Register gateway|Readback pending|No outbound groups|Provider name|Device groups/)
  }
  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 })
    for (const [id, title] of pages) {
      await navigate(page, id, title)
      await page.waitForLoadState('networkidle')
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth), `${title} at ${width}px must not overflow`).toBeLessThanOrEqual(width)
      if (width === 390) await page.screenshot({ path: testInfo.outputPath(`${id}-zh-mobile.png`), fullPage: true })
    }
  }
  expect(errors).toEqual([])
})

test('English server diagnostics have a Chinese summary and a safe explicit original disclosure', async ({ page, context }) => {
  await signIn(context)
  const original = '<img src=x onerror=alert(1)> upstream inventory temporarily unavailable'
  await page.route('**/api/v1/providers?**', route => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'future_adapter_error', message: original } }) }))
  await page.goto('/#/subscriptions')
  const alert = page.getByRole('alert').first()
  await expect(alert).toContainText('控制器或网关返回了诊断信息')
  const raw = alert.locator('[data-raw-diagnostic]')
  await expect(raw).toBeHidden()
  await alert.getByRole('button', { name: '查看原始诊断（未翻译）' }).click()
  await expect(raw).toBeVisible()
  await expect(raw).toHaveText(original)
  await expect(alert.locator('img')).toHaveCount(0)
  await alert.getByRole('button', { name: '收起原始诊断' }).click()
  await expect(raw).toBeHidden()
})
