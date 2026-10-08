# Compose deployment

This compose file packages the controller API and compiled web application
in one image. The Go controller serves both; Node is used only during the
image build. The gateway-agent profile is an isolated contract smoke target.
It does not attach dae, install tc/eBPF hooks, or forward client traffic. A
qualified gateway must run on a separately tested Linux/OpenWrt data-plane
host as described by the compatibility record.

The base profile persists a single-controller JSON store in the named
`controller-state` volume. Do not share that file with multiple controller
processes. The optional PostgreSQL overlay uses the canonical schema and the
linked pgx driver; backups and restores still need an isolated rehearsal.

The controller joins an egress-capable management network for HTTPS provider,
OIDC and adapter calls; the database/agent control network remains internal.
Use host-network policy to restrict destinations for the chosen environment.

## Start the API

```sh
cp deploy/compose/.env.example .env
chmod 600 .env
# Set SESSION_SECRET, APP_ENCRYPTION_KEY, and OIDC settings before starting.
docker compose -f deploy/compose/compose.yaml up --build controller
curl --fail http://127.0.0.1:8080/healthz
```

The API binds to loopback by default. Put it behind TLS before exposing it on
a management network. `AUTH_MODE=session` performs the configured OIDC code
flow and requires exact issuer/client/redirect settings; `AUTH_MODE=header`
requires a signed identity proxy and `IDENTITY_HEADER_SECRET`. `disabled` and
`development` modes are for isolated local development only. Set
`APP_ENCRYPTION_KEY` before startup; it must be base64 for exactly 32 bytes.

## Optional development images

`docker compose -f deploy/compose/compose.yaml --profile ui up --build` starts
a standalone nginx UI image on port 8081 for frontend-only rebuilds. It
reverse-proxies `/api/` to the controller. The UI remains capability-gated;
routes unavailable in the controller are not represented as successful
operations. The web image expects the compose `controller` service name; run
it through this compose file rather than as a standalone container.

`docker compose -f deploy/compose/compose.yaml --profile agent up --build`
starts the stock gateway-agent target on the private compose network. Set
`GATEWAY_AGENT_TOKEN` and provide the mounted `agent-certs/` mTLS files plus an
operator-installed `dae` executable before starting it. It has no host network
access or privileged capabilities in this profile and must not be mistaken for
a qualified traffic gateway. Use `-engine=fake` only in an isolated test
process, never as runtime evidence. The default agent image contains no dae
executable, so stock health reports unavailable until one is made visible.
`compose.agent-stock.yaml` mounts `DAE_EXECUTABLE_HOST` read-only for a compatible
binary's version/validation checks. It does not expose the host PID namespace
or qualify packet processing.

Pin `CONTROLLER_IMAGE`, `WEB_IMAGE`, and `GATEWAY_AGENT_IMAGE` to immutable
registry digests for any shared or release environment. Build context must be
the repository root so `.dockerignore` excludes local dependencies and build
outputs.

## PostgreSQL backend

Set a random `POSTGRES_PASSWORD` in `.env`, then start the overlay:

```sh
docker compose -f deploy/compose/compose.yaml \
  -f deploy/compose/compose.postgres.yaml up --build -d
```

The schema mount runs only for a newly created PostgreSQL volume. Apply future
numbered migrations explicitly after a backup; do not recreate the volume to
force migration. The base and PostgreSQL backends are alternative authorities,
so switching does not automatically import the file store. Use an explicit
export/import migration and readback before changing an existing installation.

## Private operator configuration

`compose.operator.yaml` binds one existing private directory to
`/run/egressdeck/operator`. Configure only the file variables you need in `.env`:

```sh
docker compose -f deploy/compose/compose.yaml \
  -f deploy/compose/compose.operator.yaml config --quiet
```

`CONTROLLER_OPERATOR_DIR` selects the host directory. Put copies of the
[provider fetch](../controller/provider-fetch.example.json),
[OPNsense](../controller/opnsense.example.json), and
[gateway](../controller/gateways.example.json) examples there after replacing
placeholders. Set the corresponding `PROVIDER_FETCH_CONFIG_FILE`,
`OPNSENSE_CONFIG_FILE`, and `CONTROLLER_GATEWAYS_FILE` to their container paths.
Leave unused variables empty. Certificate paths inside JSON must also point
into the mounted directory. The directory and files must be owned/readable by
UID 10001, with directory mode 0700 and JSON/private-key files mode 0600; use
regular files and no symlinks. These configs load on restart. Mounted trusted
certificates never imply relaxed TLS verification.

## Native daemon adapter

`compose.native.yaml` is an explicit opt-in template for an already installed
patched daemon on the qualified gateway host. It passes `-engine=native`;
`GATEWAY_AGENT_NATIVE_SOCKET` alone does not switch engines. Provide
`DAE_HOT_RUNTIME_DIR`, a separate base64 32-byte
`GATEWAY_AGENT_NATIVE_ENCRYPTION_KEY`, its stable key ID, and all agent mTLS
credentials. The agent's UID (10002 by default) must equal the daemon's UID;
the socket parent must be owned by that UID with mode 0700 and `control.sock`
must have mode 0600. The socket is checked with Linux peer credentials.
Keep the agent journal volume directory mode 0700, its file mode 0600, and its
ownership aligned when overriding `GATEWAY_AGENT_UID`.

The daemon separately requires `DAE_HOT_STATE_KEY` as 64 hex characters and
private durable state; never substitute the agent key for it. Keep both
external keys and the predeclared group layout across restart. This overlay
does not start dae, attach eBPF, generate a complete native policy or qualify
enrollment, probes or traffic. Follow [engine integration](../../engine/dae/README.md)
for the patch and remaining acceptance gates.
