# Stuck or unknown operation

Use the controller's durable operation record and the agent's authoritative
mutation receipt. An unchanged gateway generation does not prove that a
request was never sent or can no longer commit. Keep the controller, agent and
daemon journals and their separate external encryption keys intact.

## Capture and inspect

Open Activity or read `GET /api/v1/operations/{id}` through the authenticated
controller session. Capture the event stream at `GET /api/v1/events` and the
controller/agent logs for the incident interval. The API redacts request hashes
and private state; do not reconstruct recovery identities from public fields.

Record the operation ID, target, action, requested generation, status and the
applied/observed views. Actual controller statuses are `draft`, `validated`,
`staged`, `applying`, `verifying`, `applied`, `partially_applied`, `failed` and
`outcome_unknown`. `applied` indicates management readback, not client traffic
verification.

## Native recovery

Startup and periodic controller reconciliation inspect uncertain operations.
The configured native client sends the exact persisted operation ID, request
hash, target kind/id and fencing token as the five
`X-EgressDeck-Mutation-*` identity headers. The authenticated agent routes are
`GET /v1/mutations/{mutationId}` and
`POST /v1/mutations/{mutationId}/resolve`; there is no public controller
force-complete or journal-edit operation.

| Authoritative evidence | Recovery behavior |
| --- | --- |
| Daemon `committed` receipt for the exact ID and request digest | Require healthy, unfenced fresh inventory matching the requested provider/group/selection before controller completion. |
| Daemon `not_started` for the persisted operation | The native agent may replay the exact saved ID and payload. Daemon deduplication prevents a delayed original request from committing a second time. |
| Daemon `rejected` receipt | Clear native pending intent and retain the rejection. The controller marks the operation failed only after exact identity-bound rejection is established on every required gateway. |
| Agent has no record of the correlated request | Status returns `unknown`. Resolution writes a durable `never_accepted` tombstone and target fence before returning `rejected`; a delayed request with that identity cannot execute. |
| Unreachable/fenced daemon, mismatched receipt, or mixed committed/rejected provider targets | Keep the operation unresolved and retain journals. Restore the dependency and allow another bounded reconciliation sweep. |

A definite preflight rejection can also carry `rejected_before_mutation: true`
and the complete matching `mutation_identity`. A generic HTTP error or a
generation comparison alone is insufficient. The controller does not blindly
resend mutations; exact daemon replay is confined to the native agent's
persisted-request recovery protocol.

When a selection is authoritatively rejected, its previous controller
selection state is restored and persisted before the operation becomes
`failed`. After fixing the cause, submit a new explicit operation with a new
idempotency key. Reusing the old key returns the old terminal operation. Never
delete database rows or edit encrypted journals to unblock management.

Legacy unresolved records without durable operation IDs/correlations cannot
gain this proof retroactively. Preserve them and inspect their source/version
and target state; do not infer successful migration or safe replay. Before an
upgrade, quiesce new native mutations and drain or explicitly quarantine such
legacy records with the prior component version. The new native adapter
refuses startup with `upgrade_required` for pending legacy records without an operation ID;
it cannot claim an old pre-operation request was never accepted.

## Final verification

Confirm desired, applied and observed group/provider/selection state and that
the operation reaches the corresponding terminal status. For release or
enrollment acceptance, separately run an affected canary and unaffected
control client, retaining packet-path and continuity evidence. Successful
management recovery does not enable the still-unimplemented complete policy
application or strict enrollment path.
