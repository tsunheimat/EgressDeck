# Stuck or unknown operation

Operations are durable state machines. A missing acknowledgement, a controller restart, or a gateway timeout must not be converted into a blind retry. First determine whether the target changed.

## Capture and inspect

```sh
set -Eeuo pipefail
OP=<operation-id>
curl --fail --silent --show-error -H "Authorization: Bearer $HPC_TOKEN" \\
  "$HPC_URL/api/v1/operations/$OP" | tee /tmp/operation-$OP.json
curl --fail --silent --show-error -H "Authorization: Bearer $HPC_TOKEN" \\
  "$HPC_URL/api/v1/events?operation_id=$OP" | tee /tmp/operation-$OP-events.json
docker compose -f /opt/homelab-proxy-controller/deploy/compose/compose.yaml logs --since 30m controller > /tmp/controller-$OP.log
```

The operations/events endpoints are part of the planned contract and may be unavailable in the current foundation. If unavailable, record HTTP status and use the controller and gateway journals; do not claim completion.

Classify the operation as `pending`, `running`, `succeeded`, `failed`, `cancel_requested`, or `unknown`. Record the last completed step, requested/base generation, idempotency key, and target.

## Resolve without damage

1. If the operation is still running and a worker has a live lease, wait for the documented bounded timeout. Do not launch a second worker.
2. Read back the target's desired, applied, and observed generations. For a gateway, also read provider/group IDs, selection, engine PID/listeners/tc identity, and resource counts. For OPNsense, read saved and active alias/rule state.
3. If the target equals the requested generation, mark the operation complete only after traffic/canary verification. If it equals the previous generation, retry from the same idempotency key after the cause is fixed. If it is a third/unknown generation, stop and reconcile forward from target state.
4. If a worker lease is stale, expire it through the supported controller operation. Never delete database rows or edit generated files to clear a stuck operation.
5. If a crash occurred between boundaries, follow the rollback runbook and preserve all journals. A partial operation may be safely blocked; it must not silently fall through to Direct.

## Final verification

Run a single canary test for the affected source and an unaffected control client. Confirm no unrelated provider was fetched, no unrelated connection was closed, and the operation's generation/readback matches. Attach logs and exact timestamps to the audit record.
