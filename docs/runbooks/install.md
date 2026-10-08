# Install and first qualification

This procedure installs the management service on a dedicated management host.
The base Compose profile stores its single-controller JSON state in a named
volume. Add `compose.postgres.yaml` to use the PostgreSQL adapter instead.
Neither profile installs dae, alters OPNsense, or enrolls clients. Qualify the
gateway and packet path separately before enabling traffic steering.

## Preconditions and stop conditions

- Confirm a supported, isolated host and an independent console/SSH path. Keep OPNsense, PostgreSQL, identity provider, and recovery routes outside policy steering.
- Obtain the release commit and immutable image digest. Do not use `main` or `latest` in production.
- Have the application encryption-key recovery material, OIDC settings, and an empty canary address ready. If using an external PostgreSQL adapter build, also have its password ready. Never put these values in shell history or Git.
- Stop if `GET /api/v1/capabilities` reports a required capability as `false`, if IPv6 is uncontrolled while strict protection is requested, or if a gateway/OPNsense version is not in the qualification record.

## Compose installation

```sh
set -Eeuo pipefail
cd /opt/homelab-proxy-controller
test -f deploy/compose/compose.yaml
test -f .env
umask 077
docker compose -f deploy/compose/compose.yaml config >/tmp/hpc-compose-config.yml
docker compose -f deploy/compose/compose.yaml build --pull=false
docker compose -f deploy/compose/compose.yaml up -d controller
```

The base compose file builds the controller from the checkout. Use the
PostgreSQL overlay documented in `deploy/compose/README.md` when choosing that
backend, and rehearse a restore before treating it as recovered state. In a
release, pin the registry image to the reviewed commit and record the digest:

```sh
docker image inspect homelab-proxy-controller-controller --format '{{index .RepoDigests 0}}'
docker compose -f deploy/compose/compose.yaml ps
curl --fail --silent --show-error http://127.0.0.1:${CONTROLLER_PORT:-8080}/healthz
curl --fail --silent --show-error http://127.0.0.1:${CONTROLLER_PORT:-8080}/readyz
curl --fail --silent --show-error http://127.0.0.1:${CONTROLLER_PORT:-8080}/api/v1/capabilities | tee /tmp/hpc-capabilities.json
```

Do not expose port 8080 directly to an untrusted network. Put the controller behind the approved TLS/authentication boundary, restrict ingress to management addresses, and validate the OIDC callback before creating any device or gateway object.

## systemd installation

```sh
set -Eeuo pipefail
install -o root -g root -m 0755 ./homelab-proxy-controller /usr/local/bin/homelab-proxy-controller
install -d -o root -g root -m 0750 /etc/homelab-proxy-controller /var/lib/homelab-proxy-controller
install -o root -g root -m 0600 controller.env /etc/homelab-proxy-controller/controller.env
getent passwd homelab-proxy >/dev/null || useradd --system --home-dir /var/lib/homelab-proxy-controller --shell /usr/sbin/nologin homelab-proxy
systemctl daemon-reload
systemctl enable --now homelab-proxy-controller.service
systemctl is-active --quiet homelab-proxy-controller.service
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --fail --silent --show-error http://127.0.0.1:8080/readyz
```

The service unit does not supervise dae. Confirm that this is intentional before continuing.

## First qualification

1. Register the gateway in read-only mode and capture its reported version, capabilities, interface, kernel, and address-family coverage.
2. Attach/read back an existing OPNsense steering alias without changing it.
3. Create a policy and provider in the controller, but do not enroll a client.
4. On an isolated canary, verify management access, direct traffic, proxy traffic, DNS, and (if declared supported) IPv6. Capture before/after engine PID, listener identity, tc attachment, policy/provider generations, and active connection counts.
5. Enroll one reserved/static address only after the previous checks pass. Verify OPNsense persisted and active alias contents, the source address observed at dae, and an independent traffic result.

If any step cannot be read back, leave the canary unenrolled and mark the capability unqualified in `docs/compatibility.md`.
