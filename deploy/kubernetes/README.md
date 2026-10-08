# Kubernetes / k3s deployment

The default kustomization deploys one controller replica with a ClusterIP
service. It uses a required, externally-created secret and runs as a
non-root process with a read-only root filesystem. It does not create a
PostgreSQL instance, OPNsense object, ingress, or dae gateway.

The controller stores its single-process JSON state on a 1 GiB PVC. The
deployment uses `Recreate` and one replica so that only one process owns this
file. To use PostgreSQL instead, add `STORAGE_DSN` and `STORAGE_DRIVER=pgx`
through `controller-secret` after applying `migrations/schema.sql` to a
separately managed database. Complete backup/restore qualification before
relying on either backend.

## Controller

Create a secret without putting it in Git:

```sh
kubectl create namespace egressdeck-system
# Create controller-secret using the approved secret mechanism. It must
# contain SESSION_SECRET, APP_ENCRYPTION_KEY, and exact OIDC settings.
# See secret.example.yaml for keys; never apply its placeholder values.
kubectl apply -k deploy/kubernetes
kubectl -n egressdeck-system rollout status deploy/controller
kubectl -n egressdeck-system port-forward svc/controller 8080:8080
curl --fail http://127.0.0.1:8080/healthz
```

Replace the development image with an immutable digest through an overlay:

```yaml
images:
  - name: homelab-proxy-controller
    newName: registry.example.invalid/egressdeck/controller
    digest: sha256:replace-with-a-published-digest
```

The service should be placed behind a TLS ingress. `AUTH_MODE` is `session`
with the configured OIDC issuer, `COOKIE_SECURE` is true, and health endpoints remain available
for the orchestrator. Restrict ingress and egress policies further to the
actual identity provider, OPNsense, database, and gateway CIDRs in the target
cluster.

## Gateway-agent qualification overlay

The agent overlay is intentionally separate. Create `gateway-agent-secret`
with key `token` and `gateway-agent-tls` with keys `tls.crt`, `tls.key`, and
`ca.crt` using the approved secret workflow before applying it:

```sh
kubectl apply -k deploy/kubernetes/agent
```

Create its bearer token before applying the overlay (the example secret is
documentation only):

```sh
kubectl -n egressdeck-system create secret generic gateway-agent-secret \
  --from-literal=token="$(openssl rand -base64 48)"
```

It runs with no host networking, Linux capabilities, or privileged mounts and
only exercises the authenticated agent contract. It cannot see a host dae
process or forward client traffic. A real gateway requires a qualified
dedicated Linux/OpenWrt host and a target-specific manifest after WP00/WP08;
do not add `hostNetwork`, `NET_ADMIN`, or eBPF mounts as a shortcut.

The agent journal in this overlay is an `emptyDir`; it is intentionally not a
durability claim. Use a reviewed persistent volume and tested key/backup
procedure only after the gateway agent's last-known-good recovery behavior is
qualified.

## Optional operator files

Use `deploy/kubernetes-operator` when setting `PROVIDER_FETCH_CONFIG_FILE`,
`OPNSENSE_CONFIG_FILE` or `CONTROLLER_GATEWAYS_FILE` in `controller-secret`.
Create `controller-operator-files` from reviewed JSON and certificate/key
files, then render the overlay with `kubectl kustomize deploy/kubernetes-operator`.
The init container copies projected Secret data into private mode-0600 regular
files owned by UID 10001 under `/run/egressdeck/operator`. Direct projected
Secret/ConfigMap paths contain symlinks and fail the controller's gateway and
provider configuration checks. Certificate paths inside the JSON must refer
to the copied paths as well. Restart pods after updating these startup-only
configuration files. See the examples in [`deploy/controller`](../controller).

## Explicit native-agent target template

`deploy/kubernetes-native-agent` switches only the agent to `-engine=native`,
adds a persistent journal PVC and mounts the pre-existing daemon socket from
`/run/dae-hot`. It requires `gateway-agent-native-key` with key
`encryption-key` containing base64 for exactly 32 random bytes, plus the
ordinary token/mTLS Secrets. Replace the target node selector only after the
host is reviewed. It deliberately installs no daemon, BPF privileges or
firewall state.

The daemon and container must both run as UID 10002 for this template. If the
qualified target uses another UID, change both the pod and journal init
ownership together. The socket directory must be mode 0700 and socket 0600,
owned by that UID; Linux peer-credential checks reject other daemon owners.
The daemon's separate `DAE_HOT_STATE_KEY` is a 64-hex-character key kept outside
the agent Secret. Preserve both keys, journal/PVC, native daemon state and
predeclared group layout across recovery. The native template remains
unqualified for Kubernetes packet-path use and does not make native full
policy application, probes or strict enrollment available.
