#!/usr/bin/env node
/** Exercise the built UI served by the real controller and native gateway.
 *
 * Read one JSON fixture on stdin (never put the identity key in command args):
 * { endpoint, group_id, target_node_id, target_node_name, identity_key,
 *   screenshot_path?, subject?, browser_channel?, executable_path? }
 * The parent runner provisions and publishes the real native group beforehand.
 * No browser routes, controller handlers, or publisher functions are replaced.
 */
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { mkdir } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(new URL('../../apps/web/package.json', import.meta.url))
const { chromium, expect } = require('@playwright/test')
const privateValues = []

async function inputFixture() {
  let input = ''
  for await (const chunk of process.stdin) {
    input += chunk
    assert.ok(input.length <= 64 * 1024, 'fixture input exceeds 64 KiB')
  }
  let fixture
  try { fixture = JSON.parse(input) } catch { throw new Error('fixture must be valid JSON') }
  assert.ok(fixture && typeof fixture === 'object' && !Array.isArray(fixture), 'fixture must be an object')
  for (const key of ['endpoint', 'group_id', 'target_node_id', 'target_node_name', 'identity_key']) {
    assert.ok(typeof fixture[key] === 'string' && fixture[key].length > 0, `fixture requires ${key}`)
  }
  privateValues.push(fixture.identity_key)
  const endpoint = new URL(fixture.endpoint)
  assert.ok(['http:', 'https:'].includes(endpoint.protocol), 'fixture endpoint must use HTTP or HTTPS')
  assert.ok(!endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash, 'fixture endpoint must not include credentials, query, or fragment')
  assert.ok(endpoint.pathname === '/', 'fixture endpoint must be the controller origin')
  fixture.endpoint = endpoint.origin
  return fixture
}

async function main() {
  const fixture = await inputFixture()
  const subject = fixture.subject || 'native-browser-review'
  const signature = createHmac('sha256', fixture.identity_key).update(`${subject}\0admin`).digest('base64url')
  privateValues.push(signature)
  const channel = fixture.browser_channel || process.env.PLAYWRIGHT_CHANNEL
  const browser = await chromium.launch({
    headless: true,
    ...(fixture.executable_path ? { executablePath: fixture.executable_path } : channel ? { channel } : {}),
  })
  try {
    const context = await browser.newContext({ baseURL: fixture.endpoint, viewport: { width: 1440, height: 1100 } })
    context.setDefaultTimeout(20_000)
    const login = await context.request.post('/api/v1/auth/login', {
      headers: {
        'X-Auth-Request-User': subject,
        'X-Auth-Request-Role': 'admin',
        'X-Auth-Request-Signature': signature,
      },
    })
    assert.equal(login.status(), 201, 'signed login must create a real controller session')
    const cookies = await context.cookies()
    for (const cookie of cookies) privateValues.push(cookie.value)
    assert.ok(cookies.some(cookie => cookie.name === 'egressdeck_csrf'), 'login must issue the browser CSRF cookie')

    async function get(path) {
      const response = await context.request.get(path)
      assert.equal(response.status(), 200, `GET ${path} must succeed`)
      return response.json()
    }
    const session = await get('/api/v1/auth/session')
    assert.equal(session.subject, subject, 'browser session must retain the signed identity')
    const groupPath = `/api/v1/outbound-groups/${encodeURIComponent(fixture.group_id)}`
    const selectionPath = `${groupPath}/selection`
    const group = await get(groupPath)
    assert.equal(group.selection_scope, 'shared_tcp_udp', 'controller must expose the production native selection contract')
    assert.ok(group.node_ids.includes(fixture.target_node_id), 'target node must belong to the published group')
    const before = (await get(selectionPath)).items.filter(item => item.scope.gateway_id === group.gateway_id)
    assert.ok(before.length === 0 || before.some(item => item.observed_node_id !== fixture.target_node_id), 'fixture must exercise a changed selection')
    const expectedRevisions = Object.fromEntries(['tcp', 'udp'].map(transport => [transport, before.find(item => item.scope.transport === transport)?.revision ?? 0]))

    const page = await context.newPage()
    const document = await page.goto('/')
    assert.equal(document?.status(), 200, 'controller must serve the actual built frontend')
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: 'Proxies', exact: true }).click()
    await expect(page.getByRole('heading', { level: 1, name: 'Proxies', exact: true })).toBeVisible()
    const card = page.getByRole('article', { name: `Outbound group ${group.name}`, exact: true })
    await expect(card).toBeVisible()
    await expect(card.getByRole('combobox', { name: `Selection transport for ${group.name}`, exact: true })).toHaveCount(0)
    await expect(card.getByText('Shared TCP + UDP selection. Choosing a node changes both transports together.', { exact: true })).toBeVisible()
    const button = card.getByRole('button', { name: `Select ${fixture.target_node_name} for ${group.name} (TCP + UDP)`, exact: true })
    await expect(button).toBeEnabled()
    const [response] = await Promise.all([
      page.waitForResponse(response => response.request().method() === 'PUT' && new URL(response.url()).pathname === selectionPath),
      button.click(),
    ])
    const request = response.request()
    const payload = request.postDataJSON()
    assert.deepEqual(payload.transport_scopes, ['tcp', 'udp'], 'one browser click must select both native transports')
    assert.deepEqual(payload.expected_revisions, expectedRevisions, 'both transport preconditions must come from controller readback')
    assert.equal(payload.node_id, fixture.target_node_id, 'browser must select the requested stable node ID')
    assert.equal(payload.gateway_id, group.gateway_id, 'browser must target the group gateway')
    assert.equal(request.headers()['if-match']?.replaceAll('"', ''), String(expectedRevisions.tcp), 'If-Match must bind TCP precondition')
    assert.ok(request.headers()['idempotency-key'], 'browser mutation must provide an idempotency key')
    assert.ok(request.headers()['x-csrf-token'], 'browser mutation must retain CSRF protection')
    assert.equal(response.status(), 202, 'native selection must be accepted through the real controller')
    const accepted = await response.json()
    const operationId = accepted.operation_id
    assert.ok(typeof operationId === 'string' && operationId.length > 0, 'selection must return a durable operation ID')
    await expect.poll(async () => (await get(`/api/v1/operations/${encodeURIComponent(operationId)}`)).status, { timeout: 30_000 }).toBe('applied')
    let after
    await expect.poll(async () => {
      after = (await get(selectionPath)).items.filter(item => item.scope.gateway_id === group.gateway_id).sort((a, b) => a.scope.transport.localeCompare(b.scope.transport))
      return after.map(item => ({ transport: item.scope.transport, desired: item.desired_node_id, applied: item.applied_node_id, observed: item.observed_node_id }))
    }, { timeout: 30_000 }).toEqual(['tcp', 'udp'].map(transport => ({ transport, desired: fixture.target_node_id, applied: fixture.target_node_id, observed: fixture.target_node_id })))
    for (const selection of after) {
      assert.ok(selection.revision > expectedRevisions[selection.scope.transport], 'successful selection must advance each transport revision')
    }
    for (const transport of ['TCP', 'UDP']) {
      const row = card.getByRole('table', { name: `Selection readback for ${group.name}`, exact: true }).getByRole('row').filter({ has: page.getByRole('rowheader', { name: transport, exact: true }) })
      await expect(row.getByRole('cell', { name: fixture.target_node_name, exact: true })).toHaveCount(3)
    }
    await expect(button).toHaveAttribute('aria-pressed', 'true')
    await expect(button).toBeEnabled()
    let screenshot
    if (fixture.screenshot_path) {
      screenshot = resolve(fixture.screenshot_path)
      await mkdir(dirname(screenshot), { recursive: true })
      await page.screenshot({ path: screenshot, fullPage: true })
    }
    process.stdout.write(JSON.stringify({
      status: 'PASS', scenario: 'real-native-browser-shared-selection',
      group_id: fixture.group_id, target_node_id: fixture.target_node_id,
      selection_scope: group.selection_scope, transport_scopes: payload.transport_scopes,
      expected_revisions: payload.expected_revisions, request_status: response.status(),
      operation_id: operationId, operation_status: 'applied',
      selections: after.map(item => ({ transport: item.scope.transport, revision: item.revision, generation: item.generation, desired_node_id: item.desired_node_id, applied_node_id: item.applied_node_id, observed_node_id: item.observed_node_id })),
      ...(screenshot ? { screenshot_path: screenshot } : {}),
      script: fileURLToPath(import.meta.url),
    }) + '\n')
  } finally {
    await browser.close()
  }
}

main().catch(error => {
  let message = error instanceof Error ? error.message : 'native browser regression failed'
  for (const value of privateValues) if (value) message = message.replaceAll(value, '[redacted]')
  process.stderr.write(JSON.stringify({ status: 'FAIL', scenario: 'real-native-browser-shared-selection', error: message.slice(0, 4000) }) + '\n')
  process.exitCode = 1
})
