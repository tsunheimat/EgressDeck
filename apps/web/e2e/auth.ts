import { createHmac } from 'node:crypto'
import { expect, type BrowserContext } from '@playwright/test'

const identitySecret = 'egressdeck-e2e-identity-secret-public-fixture'

/** Establish a real cookie session through the signed identity assertion API.
 * This fixtures the upstream identity provider; auth/CSRF are not bypassed. */
export async function signIn(context: BrowserContext, role = 'admin') {
  const subject = 'browser-e2e'
  const signature = createHmac('sha256', identitySecret).update(`${subject}\0${role}`).digest('base64url')
  const response = await context.request.post('/api/v1/auth/login', {
    headers: {
      'X-Auth-Request-User': subject,
      'X-Auth-Request-Role': role,
      'X-Auth-Request-Signature': signature,
    },
  })
  expect(response.status(), await response.text()).toBe(201)
  const session = await context.request.get('/api/v1/auth/session')
  expect(session.status()).toBe(200)
  expect((await session.json()).subject).toBe(subject)
}
