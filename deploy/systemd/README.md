# systemd deployment

This unit runs the controller API on a dedicated management host. It does not
install dae, change OPNsense, or attach packet-processing hooks. Keep its
address and all database, identity-provider, OPNsense, and recovery routes
outside any traffic policy being managed.

## Install

Build the web bundle from the same source revision as the controller binary.
Run these commands from the repository root; Node is needed for the build,
while the installed Go process serves the resulting static files:

```sh
npm --prefix apps/web ci --ignore-scripts --no-audit --no-fund
npm --prefix apps/web run build
```

Create an unprivileged account and install the commit-pinned binary and bundle:

```sh
sudo groupadd --system homelab-proxy 2>/dev/null || true
sudo useradd --system --gid homelab-proxy \
  --home-dir /var/lib/homelab-proxy-controller --create-home \
  --shell /usr/sbin/nologin homelab-proxy 2>/dev/null || true
sudo install -o root -g root -m 0755 homelab-proxy-controller \
  /usr/local/bin/homelab-proxy-controller
sudo install -d -o root -g root -m 0755 /usr/share/egressdeck/web
sudo cp -R apps/web/dist/. /usr/share/egressdeck/web/
sudo chown -R root:root /usr/share/egressdeck/web
sudo chmod -R u=rwX,go=rX /usr/share/egressdeck/web
sudo install -d -o root -g homelab-proxy -m 0750 \
  /etc/homelab-proxy-controller
sudo install -o root -g homelab-proxy -m 0640 \
  deploy/systemd/controller.env.example \
  /etc/homelab-proxy-controller/controller.env
sudoedit /etc/homelab-proxy-controller/controller.env
sudo install -o root -g root -m 0644 \
  deploy/systemd/homelab-proxy-controller.service \
  /etc/systemd/system/homelab-proxy-controller.service
sudo systemctl daemon-reload
sudo systemctl enable --now homelab-proxy-controller.service
```

The environment file must contain a random `SESSION_SECRET` of at least 32
bytes and a base64 `APP_ENCRYPTION_KEY` encoding exactly 32 bytes.
`AUTH_MODE=session` requires the exact OIDC issuer/client/redirect settings;
`AUTH_MODE=header` requires a signed proxy and `IDENTITY_HEADER_SECRET`.
`AUTH_MODE=disabled` is only for local development. The current binary uses
a durable single-process JSON store at `STORAGE_PATH`. Keep that directory
owned by the service account. To use PostgreSQL instead, set `STORAGE_DSN`
(or `DATABASE_URL`) and `STORAGE_DRIVER=pgx` in the protected environment file
after applying `migrations/schema.sql` and rehearsing a restore.
`STATIC_DIR` must point to the installed bundle, including `index.html` and
its assets; the controller fails startup when that directory is missing.
The operation journal remains in the local state directory even when the
inventory/service store uses PostgreSQL, so preserve both during recovery.

## Optional controller integrations

Uncomment the appropriate file variables in `controller.env` to enable
provider fetch policy, the OPNsense adapter, or gateway connections. Their
paths are read at startup. Install each operator-prepared JSON file as the
controller account with mode `0600`, for example:

```sh
sudo install -o homelab-proxy -g homelab-proxy -m 0600 \
  provider-fetch.json /etc/homelab-proxy-controller/provider-fetch.json
sudo install -o homelab-proxy -g homelab-proxy -m 0600 \
  opnsense.json /etc/homelab-proxy-controller/opnsense.json
sudo install -o homelab-proxy -g homelab-proxy -m 0600 \
  gateways.json /etc/homelab-proxy-controller/gateways.json
```

Use only the files needed for your deployment. The provider policy example
is [provider-fetch.example.json](../controller/provider-fetch.example.json).
`OPNSENSE_CONFIG_FILE` carries the pinned release, HTTPS endpoint and API
credentials; `CONTROLLER_GATEWAYS_FILE` binds registered gateway IDs and
endpoints to bearer tokens and mTLS certificate paths. Install any referenced
certificate/key files under this directory with access for `homelab-proxy`.
Private JSON files must be regular files; use paths without symlinks because
the gateway and provider readers reject them. The protected environment file
uses `0640`, but JSON files require `0600` and service-account ownership.

Restart the controller after changing these files, and check authenticated
integration health separately from the process health endpoint.

Check the process and health endpoint from the independent management path:

```sh
systemctl status homelab-proxy-controller.service
curl --fail http://127.0.0.1:8080/healthz
```

Pin the binary checksum and retain the previous binary for rollback. Do not
restart or upgrade the service during a gateway traffic change without an
explicit operation/recovery plan; already-applied data-plane state is owned
by the gateway agent and must be observed separately.

## Gateway agent

The gateway-agent unit requires `GATEWAY_AGENT_TOKEN`; it refuses to
start without one. Keep its listener on a private management address and
rotate the token through the environment file, then restart both sides after
updating the controller's agent credential.

Install it as a separate account and unit only on a qualified gateway host:

```sh
sudo groupadd --system homelab-proxy-agent 2>/dev/null || true
sudo useradd --system --gid homelab-proxy-agent \
  --home-dir /var/lib/homelab-proxy-gateway-agent --create-home \
  --shell /usr/sbin/nologin homelab-proxy-agent 2>/dev/null || true
sudo install -o root -g root -m 0755 homelab-proxy-gateway-agent \
  /usr/local/bin/homelab-proxy-gateway-agent
sudo install -d -o root -g homelab-proxy-agent -m 0750 \
  /etc/homelab-proxy-gateway-agent
sudo install -o root -g homelab-proxy-agent -m 0640 \
  deploy/systemd/gateway-agent.env.example \
  /etc/homelab-proxy-gateway-agent/gateway-agent.env
sudo install -o root -g homelab-proxy-agent -m 0640 \
  agent-server.crt /etc/homelab-proxy-gateway-agent/agent-server.crt
sudo install -o root -g homelab-proxy-agent -m 0640 \
  agent-server.key /etc/homelab-proxy-gateway-agent/agent-server.key
sudo install -o root -g homelab-proxy-agent -m 0640 \
  controller-ca.crt /etc/homelab-proxy-gateway-agent/controller-ca.crt
sudoedit /etc/homelab-proxy-gateway-agent/gateway-agent.env
sudo install -o root -g root -m 0644 \
  deploy/systemd/homelab-proxy-gateway-agent.service \
  /etc/systemd/system/homelab-proxy-gateway-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now homelab-proxy-gateway-agent.service
```

Do not grant this unit `CAP_NET_ADMIN`, host-wide eBPF access, or raw packet
privileges from this generic unit. A target-specific, reviewed qualification
must establish any narrower engine boundary before it can manage a real dae
process.

The default unit explicitly selects `-engine=stock`. Install and pin the
separate operator-owned dae executable before relying on stock configuration
validation. Stock mode reports executable/process observations and native
configuration validation; it does not provide hot publication or runtime
selection. A live agent process can report an unavailable engine when dae is
absent, and process health never establishes successful traffic forwarding.

## Optional native daemon adapter

Native mode connects to the patched dae Unix API. Its adapter implements
provider publication and group/manual selection, including shared TCP/UDP
selection and persistence; target capability readback and traffic evidence
still determine availability and acceptance. This template does not install
the daemon or establish eBPF, packet-path, or hardware qualification.

Prepare the patched daemon separately, then uncomment these entries in
`/etc/homelab-proxy-gateway-agent/gateway-agent.env`:

```ini
GATEWAY_AGENT_NATIVE_SOCKET=/run/egressdeck/dae.sock
GATEWAY_AGENT_NATIVE_ENCRYPTION_KEY=replace-with-base64-encoding-of-32-random-bytes
GATEWAY_AGENT_NATIVE_ENCRYPTION_KEY_ID=native-primary
```

Generate the agent journal key with `openssl rand -base64 32`. Configure the
daemon's separate `DAE_HOT_STATE_KEY` in its own protected environment file;
that key is 64 hexadecimal characters, generated with `openssl rand -hex 32`.
Keep these independent from each other and from `APP_ENCRYPTION_KEY`. Preserve
each key and its associated durable state together; substituting a new key
does not decrypt previous recovery state. The agent key ID defaults to
`native-primary` when omitted.

The daemon and agent must run with the same effective UID. The native client
checks socket ownership and the connected daemon's peer UID: a root-owned
daemon cannot be made compatible with this unprivileged agent just by granting
group access. The socket must have mode `0600`, and its immediate parent must
be owned by that same UID with mode `0700`. Arrange creation of the example
`/run/egressdeck` directory and socket in the daemon's own service; `/run` is
recreated on boot. Qualify the daemon's privileges separately while retaining
the agent's restricted service boundary.

Keep the agent journal on durable storage. Its immediate parent directory
must have mode `0700`, and an existing journal must have mode `0600` and be
accessible to the agent. This unit's `StateDirectoryMode=0700` and
`UMask=0077` supply those defaults under
`/var/lib/homelab-proxy-gateway-agent`. Back up the daemon's durable state and
the encrypted agent journal with their respective keys.

Install the explicit engine override after these prerequisites are ready:

```sh
sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system/homelab-proxy-gateway-agent.service.d
sudo install -o root -g root -m 0644 \
  deploy/systemd/homelab-proxy-gateway-agent.service.d/native.conf.example \
  /etc/systemd/system/homelab-proxy-gateway-agent.service.d/native.conf
sudo systemctl daemon-reload
sudo systemctl restart homelab-proxy-gateway-agent.service
```

The drop-in resets `ExecStart` to select `-engine=native`; socket/key environment
variables alone do not change the default stock backend. A command-line
`-native-socket=/absolute/path` can override `GATEWAY_AGENT_NATIVE_SOCKET`.
Read authenticated engine health and capabilities after restart before
enabling controller operations.
