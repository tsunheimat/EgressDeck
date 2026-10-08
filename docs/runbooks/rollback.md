# Release, manifest, and policy rollback

Rollback restores a known-good, verified state. It is not a database rewind followed by blind overwrite. First determine which system is ahead: controller desired state, gateway applied state, or OPNsense active state.

## Prepare

```sh
set -Eeuo pipefail
git -C /opt/homelab-proxy-controller rev-parse HEAD
docker image inspect <controller-image> --format '{{index .RepoDigests 0}}' || true
curl --fail --silent --show-error "$HPC_URL/healthz"
curl --fail --silent --show-error -H "Authorization: Bearer $HPC_TOKEN" "$HPC_URL/api/v1/capabilities"
```

Export the current database and OPNsense/gateway artifacts using [backup-restore](backup-restore.md). Save the target previous release's image digest, binary checksum, schema version, manifest, provider snapshots, and compatibility record. Freeze new provider refreshes, selections, and enrollments.

## Roll back the controller

With independent recovery access and a canary still enrolled:

```sh
docker compose -f /opt/homelab-proxy-controller/deploy/compose/compose.yaml stop controller
docker tag <previous-image-digest> homelab-proxy-controller:rollback
docker compose -f /opt/homelab-proxy-controller/deploy/compose/compose.yaml up -d controller
curl --fail --silent --show-error "$HPC_URL/healthz"
curl --fail --silent --show-error "$HPC_URL/readyz"
```

Do not roll back the schema if the previous binary cannot read the current schema. Restore into an isolated database first; if a migration is irreversible, use the documented forward-compatible recovery path or restore the matching database backup.

## Roll back a gateway/policy

Use the gateway's retained last-known-good manifest/provider snapshots and the supported agent operation. Read current generation first. Apply only when the expected base generation matches; if it does not, reconcile forward or stop. Never replace a selected proxy with Direct implicitly. If rollback cannot be acknowledged, treat it as unknown and read back engine PID/listener/tc identity, policy/provider generations, active connections, and canary behavior.

For a bad OPNsense binding, restore only the controller-owned alias/rule delta from the verified export. Preserve unrelated aliases, deny rules, order, and IPv6 state. Verify saved and active state before re-enrolling.

## Verify and close

Run direct/proxy/block, DNS, management, IPv4, IPv6 (if claimed), and control-client tests. Confirm unrelated connections and providers were not disrupted. Keep the failed release artifacts and logs for analysis. Do not delete them until the incident is closed and the retention policy permits removal.
