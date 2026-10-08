import { randomUUID } from 'node:crypto'
import { expect, test, type BrowserContext, type Page, type Request } from '@playwright/test'
import { signIn } from './auth'

type Resource = { id: string; name: string; revision: number }
type DocumentKind = 'policy' | 'rule set'

const collection = (kind: DocumentKind) => kind === 'policy' ? 'policies' : 'rule-sets'
const resourcePath = (kind: DocumentKind, item: Resource) => `/api/v1/${collection(kind)}/${encodeURIComponent(item.id)}`
const hasPath = (request: Request, method: string, path: string) => request.method() === method && new URL(request.url()).pathname === path

async function csrfHeaders(context: BrowserContext) {
  const csrf = (await context.cookies()).find(cookie => cookie.name === 'egressdeck_csrf')
  expect(csrf, 'The fixture must use the real CSRF session cookie').toBeDefined()
  return { 'X-CSRF-Token': csrf!.value }
}

function documentBody(kind: DocumentKind, name: string, extra: Record<string, unknown> = {}) {
  return kind === 'policy'
    ? { name, entries: [], default_action: { kind: 'direct' }, unknown_domain_action: { kind: 'direct' }, proxy_failure_action: { kind: 'block' }, ...extra }
    : { name, rules: [], ...extra }
}

async function createDocument(context: BrowserContext, kind: DocumentKind, label: string, extra: Record<string, unknown> = {}): Promise<Resource> {
  const response = await context.request.post(`/api/v1/${collection(kind)}`, {
    headers: await csrfHeaders(context),
    data: documentBody(kind, `${label} ${randomUUID().slice(0, 8)}`, extra),
  })
  expect(response.status(), await response.text()).toBe(201)
  const item = await response.json() as Resource
  expect(item).toMatchObject({ revision: 1 })
  return item
}

async function readDocuments(context: BrowserContext, kind: DocumentKind): Promise<Resource[]> {
  const response = await context.request.get(`/api/v1/${collection(kind)}`)
  expect(response.status(), await response.text()).toBe(200)
  return (await response.json()).items
}

async function openRules(page: Page) {
  await page.goto('/')
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Rules', exact: false }).click()
  await expect(page.getByRole('heading', { level: 1, name: 'Rules', exact: true })).toBeVisible()
}

function choice(page: Page, item: Resource) {
  return page.getByRole('button').filter({ has: page.getByText(item.name, { exact: true }) })
}

async function selectDocument(page: Page, kind: DocumentKind, item: Resource) {
  await choice(page, item).click()
  await expect(page.getByLabel(kind === 'policy' ? 'Policy name' : 'Rule set name', { exact: true })).toHaveValue(item.name)
}

async function confirmDelete(page: Page, kind: DocumentKind, item: Resource) {
  await page.getByRole('button', { name: `Delete ${kind}`, exact: true }).click()
  await expect(page.getByRole('heading', { name: `Delete ${kind} “${item.name}”?`, exact: true })).toBeVisible()
  const confirmation = page.getByRole('button', { name: `Confirm delete ${kind}`, exact: true })
  await expect(confirmation).toBeDisabled()
  await page.getByRole('checkbox', { name: `I confirm deletion of ${item.name} (${item.id}).`, exact: true }).check()
  await expect(confirmation).toBeEnabled()
  return confirmation
}

async function holdResponses(context: BrowserContext, page: Page, paths: string[]) {
  const network = await context.newCDPSession(page)
  const held = new Map<string, string>()
  let release = false
  let allPaused!: () => void
  const paused = new Promise<void>(resolve => { allPaused = resolve })
  const onPaused = (event: { requestId: string; request: { url: string; method: string } }) => {
    const path = new URL(event.request.url).pathname
    if (event.request.method !== 'GET' || !paths.includes(path)) { void network.send('Fetch.continueRequest', { requestId: event.requestId }); return }
    held.set(path, event.requestId)
    if (paths.every(path => held.has(path))) allPaused()
  }
  network.on('Fetch.requestPaused', onPaused)
  // This holds actual controller responses at the browser transport boundary;
  // it never substitutes a response body, status, or frontend API client.
  await network.send('Fetch.enable', { patterns: paths.map(path => ({ urlPattern: `*${path}*`, requestStage: 'Response' })) })
  return {
    paused,
    async release() {
      if (release) return
      release = true
      network.off('Fetch.requestPaused', onPaused)
      await Promise.all([...held.values()].map(requestId => network.send('Fetch.continueRequest', { requestId })))
      await network.send('Fetch.disable')
      await network.detach()
    },
  }
}

test('policy and rule-set deletion require saved-identity confirmation and controller list readback', async ({ page, context }) => {
  await signIn(context)
  const policy = await createDocument(context, 'policy', 'Delete saved policy')
  const ruleSet = await createDocument(context, 'rule set', 'Delete saved rule set')
  await openRules(page)

  for (const [kind, item] of [['policy', policy], ['rule set', ruleSet]] as const) {
    await selectDocument(page, kind, item)
    await page.getByLabel(kind === 'policy' ? 'Policy name' : 'Rule set name', { exact: true }).fill('Unsaved draft name must not identify deletion')
    const confirmation = await confirmDelete(page, kind, item)
    expect((await readDocuments(context, kind)).some(record => record.id === item.id)).toBe(true)

    const gate = await holdResponses(context, page, ['/api/v1/policies', '/api/v1/rule-sets'])
    try {
      const deleteResult = page.waitForResponse(response => hasPath(response.request(), 'DELETE', resourcePath(kind, item)))
      const policyReadback = page.waitForResponse(response => hasPath(response.request(), 'GET', '/api/v1/policies'))
      const ruleSetReadback = page.waitForResponse(response => hasPath(response.request(), 'GET', '/api/v1/rule-sets'))
      await confirmation.click()
      const deleted = await deleteResult
      expect(deleted.status()).toBe(204)
      expect(deleted.request().headers()['if-match']).toBe(String(item.revision))
      await gate.paused
      expect(await choice(page, item).isVisible(), 'Accepted deletion must retain the document until list readback confirms absence').toBe(true)
      expect(await page.getByRole('status').count(), 'Deletion success must wait for authoritative readback').toBe(0)

      await gate.release()
      const responses = await Promise.all([policyReadback, ruleSetReadback])
      // Chrome does not retain Network.getResponseBody for CDP-held response
      // events. Assert delivery status and rendered readback, then read the
      // authoritative list independently through the same controller API.
      for (const response of responses) expect(response.status()).toBe(200)
      await expect(choice(page, item)).toHaveCount(0)
      await expect(page.getByRole('status')).toContainText(/deleted/i)
      expect((await readDocuments(context, kind)).some(record => record.id === item.id)).toBe(false)
    } finally {
      await gate.release()
    }
  }
})

test('stale policy and rule-set revisions show typed conflicts and retain the selected records', async ({ page, context }) => {
  await signIn(context)
  const policy = await createDocument(context, 'policy', 'Stale deletion policy')
  const ruleSet = await createDocument(context, 'rule set', 'Stale deletion rule set')
  await openRules(page)

  for (const [kind, item] of [['policy', policy], ['rule set', ruleSet]] as const) {
    await selectDocument(page, kind, item)
    const confirmation = await confirmDelete(page, kind, item)
    const updatedName = `${item.name} changed elsewhere`
    const update = await context.request.put(resourcePath(kind, item), {
      headers: { ...await csrfHeaders(context), 'If-Match': String(item.revision) },
      data: documentBody(kind, updatedName),
    })
    expect(update.status(), await update.text()).toBe(200)
    expect((await update.json()).revision).toBe(item.revision + 1)

    const deleteResult = page.waitForResponse(response => hasPath(response.request(), 'DELETE', resourcePath(kind, item)))
    await confirmation.click()
    const rejected = await deleteResult
    expect(rejected.status()).toBe(412)
    expect(rejected.request().headers()['if-match']).toBe(String(item.revision))
    expect(await rejected.json()).toMatchObject({ error: { code: 'revision_conflict', message: 'resource revision conflict' } })
    await expect(page.getByRole('alert')).toContainText('[revision_conflict]')
    await expect(page.getByRole('alert')).toContainText('resource revision conflict')
    await expect(choice(page, item)).toBeVisible()
    await expect(page.getByLabel(kind === 'policy' ? 'Policy name' : 'Rule set name', { exact: true })).toHaveValue(item.name)
    await expect(page.getByRole('status')).toHaveCount(0)
    expect((await readDocuments(context, kind)).find(record => record.id === item.id)).toMatchObject({ name: updatedName, revision: item.revision + 1 })
  }
})

test('referenced rule sets are blocked locally and referenced policies retain the real controller conflict', async ({ page, context }) => {
  await signIn(context)
  const ruleSet = await createDocument(context, 'rule set', 'Referenced deletion rule set')
  const policy = await createDocument(context, 'policy', 'Referencing deletion policy', { entries: [{ rule_set_id: ruleSet.id }] })
  const groupResponse = await context.request.post('/api/v1/device-groups', {
    headers: await csrfHeaders(context),
    data: { name: `Disabled referencing group ${randomUUID().slice(0, 8)}`, gateway_id: 'fixture-gateway', policy_id: policy.id, enabled: false },
  })
  expect(groupResponse.status(), await groupResponse.text()).toBe(201)
  const group = await groupResponse.json() as Resource
  await openRules(page)

  const deleteRequests: string[] = []
  page.on('request', request => { if (request.method() === 'DELETE') deleteRequests.push(new URL(request.url()).pathname) })
  await selectDocument(page, 'rule set', ruleSet)
  await expect(page.getByRole('button', { name: 'Delete rule set', exact: true })).toBeDisabled()
  await expect(page.getByText(`Cannot delete this rule set while referenced by policy: ${policy.name} (${policy.id}).`, { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Confirm delete rule set', exact: true })).toHaveCount(0)
  expect(deleteRequests).toEqual([])
  expect((await readDocuments(context, 'rule set')).find(record => record.id === ruleSet.id)).toMatchObject(ruleSet)

  await selectDocument(page, 'policy', policy)
  const confirmation = await confirmDelete(page, 'policy', policy)
  const deleteResult = page.waitForResponse(response => hasPath(response.request(), 'DELETE', resourcePath('policy', policy)))
  await confirmation.click()
  const rejected = await deleteResult
  expect(rejected.status()).toBe(409)
  expect(rejected.request().headers()['if-match']).toBe(String(policy.revision))
  expect(await rejected.json()).toMatchObject({ error: { code: 'resource_referenced', message: `policy is referenced by device group ${group.id}` } })
  await expect(page.getByRole('alert')).toContainText('[resource_referenced]')
  await expect(page.getByRole('alert')).toContainText(`policy is referenced by device group ${group.id}`)
  await expect(choice(page, policy)).toBeVisible()
  await expect(page.getByLabel('Policy name', { exact: true })).toHaveValue(policy.name)
  await expect(page.getByRole('status')).toHaveCount(0)
  expect(deleteRequests).toEqual([resourcePath('policy', policy)])
  expect((await readDocuments(context, 'policy')).find(record => record.id === policy.id)).toMatchObject(policy)
})

test('viewer and operator sessions cannot expose or execute policy and rule-set deletion', async ({ page, context }) => {
  await signIn(context)
  const policy = await createDocument(context, 'policy', 'Protected deletion policy')
  const ruleSet = await createDocument(context, 'rule set', 'Protected deletion rule set')

  for (const role of ['viewer', 'operator']) {
    await signIn(context, role)
    await openRules(page)
    for (const [kind, item] of [['policy', policy], ['rule set', ruleSet]] as const) {
      await selectDocument(page, kind, item)
      await expect(page.getByRole('button', { name: `Delete ${kind}`, exact: true })).toHaveCount(0)
      await expect(page.getByRole('button', { name: `Confirm delete ${kind}`, exact: true })).toHaveCount(0)
      const rejected = await context.request.delete(resourcePath(kind, item), {
        headers: { ...await csrfHeaders(context), 'If-Match': String(item.revision) },
      })
      expect(rejected.status(), await rejected.text()).toBe(403)
      expect((await readDocuments(context, kind)).find(record => record.id === item.id)).toMatchObject(item)
      await expect(choice(page, item)).toBeVisible()
    }
  }
})

test('direct policy and rule-set links select the requested non-first rule after reactivation', async ({ page, context }) => {
  await signIn(context)
  const rule = (name: string) => ({ id: randomUUID(), name, enabled: true, match: { domain_suffix: [`${randomUUID().slice(0, 8)}.example`] }, action: { kind: 'block' } })
  const policyRules = [rule('First mandatory rule'), rule('Linked second mandatory rule')]
  const setRules = [rule('First reusable rule'), rule('Linked second reusable rule')]
  const policy = await createDocument(context, 'policy', 'Direct-link policy', { mandatory_rules: policyRules })
  const ruleSet = await createDocument(context, 'rule set', 'Direct-link rule set', { rules: setRules })
  const target = (resource: string, item: Resource, ruleId: string) => `#/rules?${new URLSearchParams({ resource, id: item.id, rule: ruleId })}`

  const policyReadback = page.waitForResponse(response => hasPath(response.request(), 'GET', resourcePath('policy', policy)))
  await page.goto(`/${target('policy', policy, policyRules[1]!.id)}`)
  expect((await policyReadback).status()).toBe(200)
  await expect(page.getByLabel('Policy name', { exact: true })).toHaveValue(policy.name)
  await expect(page.getByRole('combobox', { name: 'Evaluation phase', exact: true })).toHaveValue('mandatory_rules')
  await expect(page.getByLabel('Rule ID', { exact: true })).toHaveValue(policyRules[1]!.id)
  await expect(page.getByLabel('Rule name', { exact: true })).toHaveValue(policyRules[1]!.name)

  for (const [resource, item, linkedRule] of [['rule_set', ruleSet, setRules[1]!], ['policy', policy, policyRules[1]!]] as const) {
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Overview', exact: false }).click()
    await expect(page.getByText('Controller overview', { exact: true })).toBeVisible()
    const readback = page.waitForResponse(response => hasPath(response.request(), 'GET', resource === 'policy' ? resourcePath('policy', item) : '/api/v1/rule-sets'))
    await page.evaluate(hash => { window.location.hash = hash }, target(resource, item, linkedRule.id))
    expect((await readback).status()).toBe(200)
    await expect(page.getByRole('heading', { level: 1, name: 'Rules', exact: true })).toBeVisible()
    await expect(page.getByLabel(resource === 'policy' ? 'Policy name' : 'Rule set name', { exact: true })).toHaveValue(item.name)
    await expect(page.getByLabel('Rule ID', { exact: true })).toHaveValue(linkedRule.id)
    await expect(page.getByLabel('Rule name', { exact: true })).toHaveValue(linkedRule.name)
  }

  const reloadGate = await holdResponses(context, page, [resourcePath('policy', policy)])
  try {
    const oldReload = page.waitForResponse(response => hasPath(response.request(), 'GET', resourcePath('policy', policy)))
    await page.getByRole('button', { name: 'Reload policy', exact: true }).click()
    await reloadGate.paused
    await page.evaluate(hash => { window.location.hash = hash }, target('rule_set', ruleSet, setRules[1]!.id))
    await expect(page.getByLabel('Rule set name', { exact: true })).toHaveValue(ruleSet.name)
    await expect(page.getByLabel('Rule ID', { exact: true })).toHaveValue(setRules[1]!.id)
    await reloadGate.release()
    await (await oldReload).finished()
    await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
    await expect(page.getByLabel('Rule set name', { exact: true })).toHaveValue(ruleSet.name)
    await expect(page.getByLabel('Rule ID', { exact: true })).toHaveValue(setRules[1]!.id)
  } finally {
    await reloadGate.release()
  }
})
