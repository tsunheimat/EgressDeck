# Credential rotation

Rotate one credential boundary at a time so a failure has a clear owner and the prior path remains recoverable. Use a maintenance window for OPNsense, agent mTLS, database, and application encryption-key changes. Never print secrets, place them in Git, or pass them as command-line arguments where process listings expose them.

## Common controls

```sh
set -Eeuo pipefail
umask 077
date -u
git -C /opt/homelab-proxy-controller rev-parse HEAD
```

Take a verified backup first. Confirm an independent console/recovery path and a canary. Record old/new credential IDs and expiry times, never the secret values.

## OIDC/session secret

Create the new secret in the approved secret manager, update the controller environment file atomically (`install -m 0600`), then restart one controller instance during the window. Existing signed sessions may become invalid; verify logout/login, CSRF, role mapping, and the break-glass path. Do not run with `AUTH_MODE=disabled` outside an isolated development environment.

```sh
install -o root -g root -m 0600 controller.env.new /etc/homelab-proxy-controller/controller.env
systemctl restart homelab-proxy-controller.service
systemctl is-active --quiet homelab-proxy-controller.service
curl --fail --silent --show-error https://<controller>/healthz
```

## Database password

Create/rotate the database role password with an existing admin channel, update the controller secret, then restart the controller and verify `/readyz` and a read-only list request. Keep the old password valid only for the bounded overlap window; revoke it after successful readback. Do not rotate by deleting the role or dropping the database.

## OPNsense API key/certificate

Create a least-privilege replacement key and install/approve the new CA/certificate before revoking the old one. Perform a read-only firmware/alias request, then a no-op binding readback. Only after both succeed revoke the old key/certificate and verify denied access with it. Never use an unrestricted OPNsense account as a fallback.

## Agent mTLS

Install the new agent certificate/key and controller trust material on the gateway and controller, test the new channel, then revoke the old certificate. Verify gateway identity, capabilities, and generation readback. A TLS handshake alone does not prove the authenticated agent is the intended gateway.

## Provider credentials and node secrets

Create a new provider credential, stage a fetch, and compare the normalized inventory/diff. Do not publish until the provider revision and selected-node impact are reviewed. After successful hot publication and canary traffic verification, revoke the old credential. A changed password/UUID creates a new connection identity unless a trustworthy provider identity establishes continuity; review any selected-node replacement explicitly. Never merge unrelated provider accounts by endpoint/name.

## Encryption-key rotation

The vault library supports historical keyrings and rewrapping, but the shipped
controller loads one `APP_ENCRYPTION_KEY` and key ID; there is no complete
operator key-rotation command. Do not replace that key in place: lifecycle
documents and the encrypted operation journal would become unreadable.
Retain the original key/ID with recovery material. A future migration must
rewrap every affected document and journal atomically, then restore in
isolation before changing the active installation. `journal-migrate` only
converts an offline plaintext journal into a new encrypted destination; it is
not a key-rotation tool. The daemon and native-agent recovery keys are separate
and also must be retained. If decryption fails, restore the last-known-good
key and matching state rather than resetting secrets to empty values.
