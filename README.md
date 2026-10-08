# EgressDeck

EgressDeck is a device-policy controller for a remote dae gateway and an
OPNsense traffic-enrollment alias. The controller owns management intent;
it does not forward client traffic. The [development plan](docs/homelab-proxy-development-plan.md)
defines the intended product and [compatibility record](docs/compatibility.md)
tracks the runtime evidence still required.

The repository provides a runnable Go controller and functional Vue management
dashboard: provider staging/schedules, node/outbound selection and filters, device and group
inventory, ordered policies/rule sets, compiler preview/explanation, gateway
registration, OPNsense binding attach/readback, operation readback, resumable
events, and audit history. Stored-inventory plans bind revisions to immutable
checksums; collection APIs paginate and authenticated metrics report bounded
management measurements. The
controller persists encrypted lifecycle state through the file or PostgreSQL
store and restores it across restart. OPNsense integration is a pinned native
26.7 client with bounded HTTPS, alias/rule identity checks, delta updates, and
persisted/active readback. The gateway agent uses authenticated transport and a
restricted stock dae adapter for executable identity, health, and validation.
Explicit native mode connects to the separately patched daemon for hot provider
publication, independent group-membership publication and durable shared-transport
manual selection; it requires private
socket ownership and external encryption keys. This is implemented source and
component behavior, with live network qualification still outstanding.

The controller and UI behavior is covered by Go race tests, API/fixture
contracts, PostgreSQL lifecycle tests, and browser acceptance using explicit
test adapters. Real dae hot publication, OPNsense packet-path enforcement,
strict DNS/IPv6 behavior, and OpenWrt support remain qualification gates.
Complete native policy assembly/application, the independent enrollment guard,
firewall session handling and client probes still require implementation and
qualification. The fake engine is for explicit tests; neither it nor a
successful management response is traffic verification.

## Delivery status

| Work package | Implemented in this repository | Remaining acceptance gate |
| --- | --- | --- |
| WP00 capability/topology | Pinned dae/Zashboard audit, native OPNsense 26.7 source record, compatibility matrix, packet-path ADR | Disposable OPNsense/Linux/dae two-client packet-path run and source/return-path evidence |
| WP01 foundation | Go/Vue workspace, OpenAPI and agent contracts, PostgreSQL schema, encrypted file/PG lifecycle, OIDC/header auth, roles, audit and durable operations | Deployment-specific identity, backup/restore and hosted artifact receipts |
| WP02 agent/engine | Stock/mTLS adapter; explicit native Unix bridge with encrypted recovery; exported upstream patch for fixed handles, native TCP/UDP/DNS leases, hot publication and durable manual selection; component tests/build pass | Live eBPF/OPNsense hot-operation proof, unrelated traffic continuity, bounded resources and qualified artifact promotion |
| WP03 providers/nodes/outbounds | Bounded parser/fetcher, operator private-source allowlist, encrypted sources, revisions, stage-only scheduler, source CRUD, candidate filters and scoped selection | Qualified remote publication/selection; automatic scheduled publication remains unsupported |
| WP04 policy/compiler | Device exceptions/ownership, groups, ordered rules/rule sets, deterministic manifests/source maps, stored-inventory plans, routing-only native output, preview and explanation | Complete native policy assembly and live enforcement of unknown domains, IPv6 and failure paths |
| WP05 OPNsense | Pinned native client, exact alias/rule scope, version/TLS checks, delta mutation and active/persisted readback | Appliance credentials, firewall order, reboot/drift and canary traffic evidence |
| WP06 deployment/reconcile | Durable operation runner, fencing, cross-system ordering, rollback/quarantine tests and desired/applied/observed/verified state | Complete policy/guard/firewall-session/client-probe adapters and injected live failure-boundary runs |
| WP07 UI | Dashboard pages for provider source/schedules, filters, policy/plans, device/groups, firewall attach/readback and activity; real Go browser harness, role/capability gates and readback | Live adapter-backed browser run after runtime capabilities are qualified |
| WP08 qualification | Go race/security/contract tests, PostgreSQL integration, image smoke, browser harness and protected network workflow | Real packet, DNS, IPv6, hot-update, performance and retained-resource evidence |
| WP09 operations | Compose single-image packaging, PostgreSQL overlay, Kubernetes/systemd/OpenWrt templates, backup/restore and incident runbooks | Target installation/restore rehearsal, immutable promotion and canary enrollment |

## Develop

Use Go 1.23 and Node.js 22 or later. Install frontend dependencies, then run the
checks from the repository root:

```sh
npm --prefix apps/web ci --ignore-scripts --no-audit --no-fund
make check
make build
# Isolated real-HTTP browser acceptance with a deterministic external adapter:
npm --prefix apps/web exec -- playwright install --with-deps chromium
npm --prefix apps/web run test:e2e
```

Start the controller with an explicit local storage path. Authentication can
be disabled only for an isolated development instance:

```sh
mkdir -p .local/state
umask 077
test -f .local/state/encryption-key || openssl rand -base64 32 > .local/state/encryption-key
APP_ENCRYPTION_KEY="$(cat .local/state/encryption-key)" \
  AUTH_MODE=disabled LISTEN_ADDR=127.0.0.1:8080 \
  STORAGE_PATH="$PWD/.local/state/store.json" \
  OPERATION_JOURNAL_PATH="$PWD/.local/state/operations.json" \
  STATIC_DIR="$PWD/apps/web/dist" go run ./cmd/controller
```

Open `http://127.0.0.1:8080` after building the web app. The dev server can also
be started with `npm --prefix apps/web run dev`; its Vite proxy uses the local
controller API. Health endpoints are `/healthz` and `/readyz`.

## Install

The default controller image builds the Vue application and serves it from the
same Go process. Compose uses a named volume for the single-process JSON store:

```sh
cp deploy/compose/.env.example .env
chmod 600 .env
# Set SESSION_SECRET, APP_ENCRYPTION_KEY, and OIDC settings in .env.
docker compose -f deploy/compose/compose.yaml up --build -d controller
```

Session mode performs the configured OIDC flow and requires a trusted identity
provider and TLS. Read
[installation](docs/runbooks/install.md) before exposing the management API.
The optional [PostgreSQL overlay](deploy/compose/README.md) uses the linked pgx
driver and canonical schema. [Kubernetes](deploy/kubernetes/README.md) and
[systemd](deploy/systemd/README.md) examples keep one active controller and
management routes independent of client steering.

| Setting | Purpose |
| --- | --- |
| `LISTEN_ADDR` | Controller bind address; default `:8080` |
| `AUTH_MODE` | `session` (OIDC), `header` (signed trusted proxy), or explicit local `disabled`/`development` mode |
| `SESSION_SECRET` | Session signing material; required in session mode and at least 32 bytes |
| `APP_ENCRYPTION_KEY` | Base64 encoding of exactly 32 random bytes; required for secret vault startup |
| `APP_ENCRYPTION_KEY_ID` | External key identifier stored with encrypted secret metadata |
| `COOKIE_SECURE` | Secure-cookie requirement; use `true` behind TLS |
| `IDENTITY_HEADER_SECRET` | Enables the signed reverse-proxy identity boundary |
| `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_REDIRECT_URL` | Required exact OIDC issuer/client/callback settings in session mode |
| `OIDC_CLIENT_SECRET` | Confidential OIDC client secret, when the issuer requires it |
| `OIDC_GROUP_ROLES` | JSON mapping from exact identity-provider groups to viewer/operator/admin roles |
| `STORAGE_PATH` | Single-process JSON store path; default `/var/lib/homelab-proxy-controller/store.json` |
| `STORAGE_DSN` / `DATABASE_URL` | Select PostgreSQL instead of the file store |
| `STORAGE_DRIVER` | PostgreSQL driver, default `pgx` |
| `OPERATION_JOURNAL_PATH` | Durable operation journal file path |
| `OPNSENSE_CONFIG_FILE` | Optional external mode-0600 JSON file for the pinned native OPNsense client |
| `CONTROLLER_GATEWAYS_FILE` | Optional private JSON file binding registered gateway IDs/endpoints to mTLS credentials |
| `PROVIDER_FETCH_CONFIG_FILE` | Optional private JSON private-source host/port/CIDR allowlist and tighter fetch/parser limits |
| `STATIC_DIR` | Built web assets served by the controller |
| `GATEWAY_AGENT_TOKEN` | Agent bearer credential; agent refuses unauthenticated startup unless development mode is explicit |
| `GATEWAY_AGENT_LISTEN` | Agent management bind address; default `127.0.0.1:9090` |
| `GATEWAY_AGENT_JOURNAL` | Agent operation-journal path |
| `GATEWAY_AGENT_DAE_EXECUTABLE` | Operator-installed stock dae executable |
| `GATEWAY_AGENT_DAE_SHA256` | Optional required digest for the installed dae executable |
| `GATEWAY_AGENT_TLS_CERT` / `GATEWAY_AGENT_TLS_KEY` | Agent server certificate and key for remote listeners |
| `GATEWAY_AGENT_CLIENT_CA` | Trusted controller client CA; remote agent listeners require mTLS |
| `GATEWAY_AGENT_NATIVE_SOCKET` | Private patched daemon Unix socket; requires the explicit `-engine=native` command flag |
| `GATEWAY_AGENT_NATIVE_ENCRYPTION_KEY` / `GATEWAY_AGENT_NATIVE_ENCRYPTION_KEY_ID` | Native agent recovery key: base64 of exactly 32 bytes, stable key ID (default `native-primary`) |
| `DAE_HOT_STATE_KEY` | Separate patched-daemon state key: exactly 64 hex characters encoding 32 bytes |

File-store and PostgreSQL backends are alternative authorities. Switching the
backend does not migrate data automatically. The controller also maintains its
encrypted operation journal on disk when PostgreSQL is selected; preserve
`OPERATION_JOURNAL_PATH` along with database backups and external key material.
Follow the [backup and restore runbook](docs/runbooks/backup-restore.md) and
preserve previous data until the restored application and canary pass readback.

OPNsense and gateway credentials are supplied through mounted external files,
not browser payloads. The [OPNsense client](internal/opnsense/README.md) requires
`base_url`, `api_key`, `api_secret`, and the exact `release: "26.7"`; private CA
configuration and a reviewed `managed_aliases` allowlist are optional. Omitting
the allowlist keeps the client read-only. Its file must be a regular mode-0600
JSON object of at most 1 MiB. Gateway configuration uses
`{"gateways":[{"id":"registered-id","endpoint":"https://gateway.example:9090",
"token":"<external secret>","client_cert":"/run/agent/client.crt",
"client_key":"/run/agent/client.key","ca_file":"/run/agent/ca.crt",
"server_name":"gateway.example"}]}` in a private regular file with no symlink
components. The configured endpoint must match the registered gateway. These
clients provide observation and explicit runtime adapter boundaries; loading
their files does not enable unsupported publication or enrollment. The
[gateway example](deploy/controller/gateways.example.json) leaves mutations off.
Opt-in `runtime` configuration requires the exact `dae-native-unix`
implementation, observed capabilities, predeclared group-name mappings,
explicit initial selected nodes, and shared TCP/UDP selection. Native groups
cannot span providers; stock and fake adapters cannot satisfy this runtime gate.

Native selection appears as one **TCP + UDP** control in the Proxies page.
The group response reports `selection_scope`; the UI submits and reads back
both transports for shared selection. Saving a group's candidates updates
desired configuration. Use **Apply configuration** to publish that
revision against the existing provider inventory, then inspect the desired,
applied and observed group revisions before selecting a node. This operation
does not need a changed subscription or provider refresh. The current selected
node must remain eligible in the applied group.

The [provider fetch example](deploy/controller/provider-fetch.example.json)
allows private sources only by exact host, port and private CIDR. Its JSON must
be a private regular file of at most 64 KiB with no symlink path components.
Limits can only tighten defaults; zero redirects disables redirects. Verified
HTTPS remains mandatory. The allowlist does not pin otherwise public DNS
answers or grant a non-Direct fetch route. Restart reloads operator settings.

Compose provides optional operator/native overlays, Kubernetes copies projected
operator Secrets to private regular files, and systemd includes an explicit
native drop-in. See the respective deployment READMEs for permissions and
mounts. Native daemon and agent must share the effective UID; the socket is
0600 within an owned 0700 directory. The agent journal directory is also 0700
with a 0600 file. Preserve the separate daemon/agent keys and group layout for
restart recovery. Native mode does not provide full policy application,
node/group probes, connection telemetry or strict enrollment.

## API and verification

The controller serves `/api/v1` inventory and configuration routes for devices,
device groups, gateways, providers, nodes, outbound groups, policies, and rule
sets. It exposes revision-checked mutations, provider source editing and
stage-only refresh schedules, immutable stored-inventory plans, policy preview,
operations, audit, resumable bounded event polling, collection pagination,
authenticated `/metrics`, and capability discovery. Event polling preserves
published snapshots; it does not promise every intermediate transition. See
[controller OpenAPI](api/openapi.yaml) and [agent contract](api/agent-contract.yaml).
Use observed capabilities and typed errors to determine whether an operation
is available on a particular backend.

The [review follow-up](docs/review-follow-up-2026-10-08.md) tracks the fixes and
remaining implementation gaps identified against commit `5b443b5`.
Its final source passed 1,267 Go race tests and 80 frontend tests. The
[native management-path receipt](tests/integration/artifacts/review-native-cross-layer.json)
also verifies the actual browser, controller, mTLS agent and patched dae Unix
control plane through group edits, shared selection, pre-send/post-commit
crashes and all-process restart. This receipt does not qualify eBPF or an
OPNsense-enrolled client traffic path.

The historical implementation snapshot recorded in
[the original verification receipt](docs/verification/2026-10-08-results.json)
passed **1,124 tests across 20 packages** with race
detection and `go vet` on `agnet-test`. The web snapshot passed **73 unit and
component tests**, type checking, production build and **14 Chrome browser
tests** through the actual Go controller. Desktop/mobile screenshots were
also inspected.
The browser suite uses the actual Go HTTP API, session/RBAC/CSRF middleware and
Vue application; external provider fetch/publication/selection use explicit
test adapters. The PostgreSQL API integration separately exercises encrypted
provider sources and node credentials, revision conflicts, unchanged rows
after rejected writes, restart restoration and wrong-key refusal. Final
PostgreSQL 16.15 API/adapter race checks passed locally on `u25-code1` using
Go 1.23.12. The final controller image
`sha256:394fa74a92623394254e886b2b5060553c6d2b8e08f0a4b0cf0b19ef83adda3b`
passed static UI, signed login/RBAC, CRUD, encrypted staging and operation
journal, immutable plan, resumable events, authenticated metrics,
unsupported-runtime refusal and restart smoke checks.

GitHub Actions workflows are configured for Go race tests, frontend/browser
checks, fixture contracts, OpenAPI validation, PostgreSQL schema and API
integration, and all three image builds. Local results do not establish a
hosted CI run or an installed release. The
protected [network qualification workflow](.github/workflows/network-qualification.yml)
requires a trusted isolated topology harness and source-bound redacted
artifacts. Missing evidence fails the gate. See [tests/network](tests/network/README.md)
and [development status](docs/development-status.md) for the limits of each
check.

The [pinned source audit](internal/gateway/STOCK-ADAPTER.md) found that stock
dae does not implement Zashboard's native management API or transactional
provider-only publication. The stock adapter returns `unsupported` for those
mutations and does not invoke a reload as a substitute. The isolated
[dae extension](engine/dae/README.md) now supplies the opt-in native execution
path. Its [source validation receipt](engine/dae/VALIDATION.md) records 60 hot
race cases without the BPF stub tag, 1,055 broader race cases with upstream's
stub tag, vet and a real generated-BPF daemon build. These are component/build
results, not tc attachment or enrolled traffic evidence. A separate
[native-source receipt](engine/dae/evidence/native-source-receipt.json)
also exercises the production NativeEngine against the real source Unix HTTP
handler/control plane, two groups, isolated selections, encrypted journals and
process/agent restart. Its source and adapter hashes were checked. The native adapter
reports only implemented, reachable capabilities; product release and traffic
verification remain unqualified. Optional runtime or native-policy wiring is not a
qualified guard/firewall/client-probe stack; strict traffic enrollment remains
unavailable and the UI enrollment action stays disabled.

No production enrollment or automatic upgrade is performed by this repository.
Start read-only, qualify one canary, retain the prior infrastructure, and expand
only after the requested policy is both observed and traffic-verified.
