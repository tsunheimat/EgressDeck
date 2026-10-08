# Development status

The [verification receipt](verification/2026-10-08-results.json) records commands,
hosts, boundaries and image digests. Its linked source manifest identifies the
final working-tree files; individual native/PostgreSQL receipts bind their own
tested snapshots.

Updated 8 October 2026. The controller, Vue workflows, durable storage,
security boundaries, native OPNsense client, stock dae agent and opt-in native
bridge have implementations. Scheduler, planner, event, filter and telemetry
follow-ups are present. The frozen Go snapshot, PostgreSQL lifecycle, browser
application and controller image passed their final checks documented below.
The full development plan is **not accepted for production**:
live hot publication, traffic enrollment, packet-path enforcement and the
target release matrix remain unqualified.

The distinction below is between implementation evidence and runtime
qualification. Tests with real HTTP, TLS, PostgreSQL or browser components
establish those boundaries; they do not prove that a live firewall and dae
gateway enforce the requested traffic policy.

## Work-package status

| Package | Delivered implementation and evidence | Remaining work and qualification |
| --- | --- | --- |
| **WP00 — capability/topology** | Complete pinned dae source audit, Zashboard client inspection, native OPNsense 26.7 source review, compatibility record and packet-path ADR. The audit established that the dae pin has no native management API and that its reload rebuilds a full control-plane generation. | Run the isolated two-client OPNsense/dae topology. Record source identity, NAT, routes/returns, deny ordering, DNS, IPv6, direct/proxy TCP/UDP and gateway-down behavior. No privileged packet-path proof exists here. |
| **WP01 — foundation** | Go controller, Vue application, typed API/agent contracts, schema and migrations; revision checks, address ownership, authorization, audit and durable operations. OIDC code flow uses PKCE/nonce/browser-bound state; separate signed-proxy mode, encrypted sessions, roles and CSRF are tested. File and pgx stores persist state; lifecycle secrets use an external-key AES-GCM vault. | Qualify the actual identity provider, key recovery, service accounts and deployment settings. Hosted Actions execution and a release artifact must be recorded separately from local checks. |
| **WP02 — agent/engine** | Stock executable digest/process/native-validation checks; TLS 1.3 mutual TLS and authenticated controller client. Explicit native mode bridges the private patched-daemon Unix API, with encrypted bounded agent recovery state. Exported `engine/dae` patch implements fixed handles, native TCP/UDP/DNS resource leases, affected-provider publication and durable manual selection; focused source race tests, broader upstream regression tests, vet and generated-BPF build passed. | Validate the current controller/agent/daemon chain and real traffic: unchanged listeners/tc/DNS, unrelated TCP/UDP continuity, restart and retained resources. Native scope is predeclared single-provider groups, manual selection shared by TCP/UDP, with external keys retained. Full reload/suspend, policy application, probes and traffic telemetry remain unsupported in native mode; stock hot capabilities stay disabled. |
| **WP03 — providers/nodes/outbounds** | URL fetch/paste/upload, bounded native/Base64/SIP008/JSON/supported Clash-node parsing, SSRF/redirect/rebinding guards, startup private-source allowlist, encrypted sources/private node serialization. Provider CRUD, references/deletion checks, source filters, metadata/candidate impact, scoped selections and CAS are implemented. Durable scheduler coalesces missed runs and stages revisions for review at intervals of 300–604800 seconds. | Qualify real gateway publication/selection and resource behavior. Scheduler auto-apply is explicitly unsupported; imported unsupported entries require review. Engine restart intent depends on the patched daemon and retained keys/layout. No full Clash configuration importer is claimed. |
| **WP04 — device policy** | Device/group inventory, primary group, address ownership, ordered rules/rule sets and persisted per-device exceptions. Deterministic manifests/source maps, preview/explain and impact reports. Stored-inventory planner captures gateway-scoped resource/selection revisions and hashes in an immutable checksum document; routing-only native output is provided when supported. | Complete native policy assembly and validate generated rules against the source-visible topology, including domain limits, unknown domains, IPv6 and strict failure. A checksum-bound routing plan does not supply daemon configuration, independent guard or traffic verification; plans remain non-deployable where these prerequisites are missing. |
| **WP05 — OPNsense** | Native HTTPS client pinned to **26.7**, core `821598263289e177b40971600f06f5a91d9faef3`. Version/TLS/auth checks, persisted alias UUID/type/content decoding, active-table existence/contents, independent empty-state confirmation, exact reviewed modern-rule shape, address deltas and partial/drift refusal are covered by TLS fixtures. External configuration omits write authority unless a reviewed managed-alias scope is provided. | Test an actual appliance: least privilege, existing deny preservation, active/persisted convergence, reload/reboot and canary steering. Native API lacks CAS, so external edits can race an individual mutation. Legacy rules, rule provisioning and targeted state deletion are unsupported. |
| **WP06 — deployment/reconciliation** | Encrypted request-bound operation journal, serialization/fencing, desired/applied/observed/verified state and startup/periodic readback recovery. Cross-system tests cover guard/gateway/firewall ordering, moves, lost acknowledgement, rollback, quarantine, cancellation and late writes. Optional runtime provider/selection wiring and native artifact executor use operator opt-in and observed capabilities. Offline journal migration preserves the plaintext source and refuses overwrite. | Supply and qualify independent guard, full gateway apply/readback, firewall session handling and client probe. The opt-in native daemon currently rejects full policy apply. Complete strict enrollment remains unsupported; native artifact wiring cannot create those missing semantics. Run real crash/failure injection at each boundary. |
| **WP07 — application experience** | Vue provider source CRUD/schedules, candidate filters, device/groups, policies/rule sets, immutable plans, firewall Host-binding attach/readback, gateway diagnostics, audit/activity pages. Forms preserve drafts, enforce roles/revisions/capabilities and read back outcomes. Controller exposes bounded resumable event polling, collection pagination and authenticated management metrics. **14 Chrome browser tests** passed through real Go handlers with session/RBAC/CSRF; desktop/mobile screenshots were inspected. | Complete the workflow against qualified remote adapters. Event feed stores polled management snapshots, not every transient transition; metrics are management measurements, not total traffic. No Zashboard source is imported; upstream component reuse/provenance is separate work. |
| **WP08 — qualification** | Frozen Go snapshot: **1,124 tests / 20 packages**, race and vet passed on `agnet-test`. Web: **73 unit/component tests**, typecheck/build and **14 Chrome E2E tests** passed. Final PostgreSQL 16.15 API/adapter race checks and final controller image smoke passed. Daemon patch: **60 no-stub hot race cases**, **1,055 broader stub-tag race cases**, vet/build and an actual adapter→source handler process/restart receipt. Hosted workflows and the protected evidence-required network gate are present. | Real packet, DNS/IPv6, throughput and retained-resource measurements remain blocked. Source/native/fixture/browser evidence does not replace live qualification; local execution does not establish hosted Actions success. |
| **WP09 — operational delivery** | Single Go/Vue management image; agent and optional development web images; durable Compose default plus PostgreSQL overlay; systemd and Kubernetes/PVC templates; OpenWrt qualification guidance; installation, backup/restore, key rotation, rollback and incident runbooks. Container smoke exercises authentication, encrypted staging, CRUD, unsupported-runtime refusal and restart restoration. | Produce source-bound immutable release digests, SBOM/provenance receipts and target-specific clean-install/restore/canary records. Qualify OpenWrt kernel/architecture/storage/firewall behavior before publishing a package. Migration from an existing proxy system remains an explicit mapping and dry run. |

## Verified boundaries

- **PostgreSQL:** [`TestPostgresIntegration`](../internal/store/postgres_integration_test.go)
  and [`TestPostgresAPILifecycle`](../tests/integration/postgres_api_test.go)
  use disposable databases and apply the canonical schema twice. The API test
  crosses actual HTTP, pgx/SQL, encrypted document persistence and a fresh
  connection/server restart. It verifies resource identity/revisions, rejected
  write snapshots, secret absence in SQL-visible rows, restored private node
  credentials, source decryption after restart and wrong-key refusal. Provider
  fetch and selection readback are explicit fixtures.
- **Browser:** [`apps/web/e2e`](../apps/web/e2e/README.md) starts a real Go API
  and Vite server with session cookies, authorization and CSRF enabled.
  External subscription/gateway calls are test adapters; no Playwright route
  mocks replace the API. The tests cover import/publication/selection,
  failure preservation, inventory forms, policy/rule-set compilation,
  gateway registration and navigation/draft behavior. The external OIDC
  provider and traffic path are not part of this harness.
- **Authentication and transport:** OIDC tests use a local TLS issuer, signed
  tokens and JWKS. Agent tests perform real mutual TLS handshakes and deny
  missing/untrusted identities. OPNsense tests use exact native request/response
  shapes through a local TLS server. These tests do not establish compatibility
  with a deployed Authentik, OPNsense appliance or dae binary.
- **Image:** [`container_smoke.py`](../tests/integration/container_smoke.py)
  exercises the built controller image, bundled static UI, signed login,
  RBAC/CSRF, encrypted provider staging, CRUD and restart restoration. It
  configures no production gateway/router and expects unsupported runtime
  publication to be refused.

Test totals describe this development run and may increase with new checks.
Use the source commit and the final command/job receipts when approving a
release; existing pass totals do not cover later edits or an untested target.

Final Go receipts: race job `rt-20261008-061842-rk815qb9` (1,124 passed,
20 packages, exit 0) and vet job `rt-20261008-061842-97rw5cm0` (exit 0), both
on `agnet-test`. Final PostgreSQL 16.15 runs used local `u25-code1`, Go 1.23.12:
`TestPostgresAPILifecycle` and `TestPostgresIntegration` passed with race
detection, preserving a 155-file source snapshot digest
`b8dadd4399255d893f7723ab3bb805e5ddb9eb16e4946a07de6c0ca1a141d877`.
The failed-revision case verifies a rejected 412 audit outcome and unchanged
durable resources.

Final browser run: 14/14 passed in 16.3 seconds using local Chrome against the
actual Go fixture; external provider/engine behavior remained explicit test
adapters. The controller image
`sha256:394fa74a92623394254e886b2b5060553c6d2b8e08f0a4b0cf0b19ef83adda3b`
passed the final smoke checks for static UI, signed login/RBAC, encrypted
staging, CRUD, immutable plans, resumable events, encrypted operation journal,
authenticated metrics, unsupported runtime refusal and restart restoration.

The [native daemon receipt](../engine/dae/VALIDATION.md) binds the exported
patch to SHA-256 `6dc2bbcb8270adfaac62eda4e33abab98eef9009bfa89e9f107d672cb904aa38`
and records the source, host, exact commands and build hashes. The separate
[native source integration receipt](../engine/dae/evidence/native-source-receipt.json)
on `u25-code1` records the actual NativeEngine → Unix HTTP handler → native
control-plane path, two groups, isolated choices, encrypted journals and
process/agent restart. The receipt's adapter/source hashes were checked.
Its native cases
include a local SOCKS5 tunnel and restart recovery; they do not attach eBPF or
exercise OPNsense-enrolled clients. Native mode uses the daemon's separate
64-hex `DAE_HOT_STATE_KEY` and the agent's base64 32-byte recovery key. Both
processes must share the effective UID and private socket layout.

## Remaining release gates

1. **R05/R06 real engine behavior:** promote a source-bound patched artifact
   after live qualification, and prove hot
   provider/selection mutations on active traffic. Implemented component
   publication, fake adapters and stock validation do not satisfy this gate.
2. **Enrollment and strict enforcement:** qualify source preservation, return
   paths, firewall order, persistent failure guard, targeted existing-session
   behavior, DNS unknown action and IPv6 coverage. Keep enrollment disabled
   until the executor and independent client verification can establish them.
3. **Release/operations:** run protected hosted/network jobs for an exact
   source/artifact, measure performance/resource budgets, rehearse backup and
   key recovery on the target, then enroll one explicitly approved canary.
   Preserve the prior infrastructure until the replacement is verified.

Track engine source work in [`engine/dae`](../engine/dae/README.md), native
firewall restrictions in [`internal/opnsense`](../internal/opnsense/README.md),
and runtime artifacts in [`compatibility.md`](compatibility.md). No production
network mutation or completed end-to-end rollout is claimed by this status.
