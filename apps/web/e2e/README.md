# Browser acceptance harness

From `apps/web`:

```sh
npm ci
npx playwright install --with-deps chromium
npm run test:e2e
```

An installed Chrome can be used with `PLAYWRIGHT_CHANNEL=chrome npm run test:e2e`.
Set `EGRESSDECK_E2E_GO` to an absolute Go binary path when your normal `go`
command dispatches to a remote host; this fixture must run beside the browser.
Set `EGRESSDECK_E2E_GOCACHE` when `/tmp` is unsuitable for Go's build cache.
The suite starts two isolated loopback services and refuses to reuse a running
service: Vite on port 14173, and a Go controller fixture on port 18080. Ports must
be free. Go must be installed. The Go fixture imports the same `internal/api`,
auth, store, provider parser, outbound service, and operation journal as the
controller. The browser sends real HTTP requests through the Vite API proxy;
there are no Playwright route mocks or replacement frontend API clients.
Authorization uses the same `auth.RequiredRole` route policy as production.

The fixture uses a fresh memory store and public test-only session/signature
keys. `signIn` calls the real login endpoint with a signed upstream identity
assertion. Session cookies, authorization, and CSRF protection remain active.
The external identity provider is not exercised by this suite.

External provider fetches and gateway publication/selection are deterministic
functions supplied at the controller's existing service boundaries. The fixture
configures the same shared TCP/UDP selection scope as the native adapter. A
single browser node click must send both transports, and the real controller
must mirror the resulting desired, applied, and observed node into both scope
records. The fixture does not mutate those controller records itself.
Outbound-group publication updates a separate runtime membership map. Selection
preflight checks its exact group revision and candidates, as the native bridge
does, so a saved but unapplied edit is rejected before any selection mutation.
It never contacts dae, OPNsense, or subscription servers. These browser results
cover controller integration and UI behavior; they do not establish PostgreSQL
durability, real gateway hot publication, packet-path behavior, or OIDC-provider
acceptance. Those require their respective integration/qualification suites.

The scenarios cover signed sessions and rejected CSRF/viewer mutations,
subscription parsing/staging/publication and unconfirmed publication, shared
TCP/UDP selection request and readback, device/group create/edit, gateway
registration, policy compilation/explanation, and reusable rule-set revisions
and references.
The selection workflow also edits a two-node group down to one node, verifies
that selection is blocked until the group configuration is applied, and selects
the retained node again without changing the provider revision. It checks the
390px layout for horizontal overflow and records desktop/mobile screenshots.

Failures preserve a trace, screenshot, and HTML report in ignored output
directories. Open the report with `npx playwright show-report`.
