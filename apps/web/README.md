# EgressDeck web application

This is the controller's Vue/TypeScript management UI. It talks to the
controller's `/api/v1` contract through `src/api/client.ts`; it does not call
dae, OPNsense, or a gateway agent directly.

Management pages remain available for initial setup. Runtime operations are
gated by reported capabilities, and mutation forms are gated by the current
session's role. Long operations use idempotency keys and durable operation
readback. Configuration edits use revision preconditions. Desired, applied,
observed, and verified values stay separate; missing coverage is unavailable.

The UI includes provider URL registration and inline staging, revision changes
and publication, outbound candidates and transport selections, device/group
inventory editing, ordered policies and reusable rule sets with compiler
preview and predicted explanation, gateway registration, operation readback,
and audit history. Unfinished forms survive navigation between setup pages.
Traffic enrollment stays disabled until qualified deployment adapters exist.

Run locally:

```sh
npm ci
npm run dev
```

Validate the production bundle with `npm run build`; run unit checks with
`npm test`. Vite proxies `/api` to `http://localhost:8080` during development.

Browser integration tests use Playwright against a real Go controller HTTP
server with a test-only memory store and explicit fake provider/engine
adapters. See [e2e/README.md](e2e/README.md) for setup and the boundaries of this
evidence. Run `npm run test:e2e` after installing Playwright Chromium.

No Zashboard source is copied into this initial shell. A future Zashboard
adaptation must preserve its upstream notices and provenance and remain behind
the same typed controller adapter.
