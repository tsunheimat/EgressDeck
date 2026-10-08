# Local native engine contract

This is the patched engine's private Unix API, not stock dae's API or the
controller's `/api/v1`. Requests authenticate by same effective UID through
`SO_PEERCRED`. The listener requires a private owned directory and a mode-0600
socket. Send JSON with `Content-Type: application/json`; unknown fields, trailing
JSON, over-limit bodies, missing identifiers and incorrect methods are rejected.

## Readback

`GET /v1/inventory` returns:

```json
{
  "generation": 4,
  "groups": [
    {"handle": 2, "name": "development", "identity": "provider-a/revision-2", "selection": "node-b", "group_revision": 2, "candidate_ids": ["node-a", "node-b"]},
    {"handle": 3, "name": "unchanged", "identity": "baseline", "selection": ""}
  ]
}
```

`identity` uses `/` between the provider ID and revision ID. Both are validated
opaque identifiers; `/` is prohibited within either identifier. It contains no
credential-derived hash. Baseline groups are outside the hot inventory and have
no hot selected identity. Generation is global and monotonically increases only
for accepted non-no-op mutations, including selection changes.

## Provider publication

`POST /v1/providers/publish`:

```json
{
  "operation_id": "0123456789abcdef0123456789abcdef:1",
  "expected_generation": 4,
  "provider_id": "provider-a",
  "revision_id": "revision-3",
  "nodes": [
    {"id": "node-a", "link": "socks5://127.0.0.1:1080#Example"},
    {"id": "node-b", "link": "socks5://127.0.0.1:1081#ExampleB"}
  ],
  "groups": [
    {"name": "development", "revision": 3, "candidate_ids": ["node-a", "node-b"], "selection": "node-b"}
  ]
}
```

Links are secret request data, never inventory readback. The caller must provide
all groups already owned by this provider; ownership cannot move silently. Every
node must be referenced by a submitted group and parse successfully. Names must
already exist in the daemon configuration. Group membership is a single-provider
manual subset. Preparation does not fetch URLs.

First publication requires an explicit selection. Refresh retains the existing
stable selection if present; removal requires an explicit valid replacement.
The same immutable revision ID with unchanged content is a no-op. Reusing a
revision ID with different content is rejected. Inputs and aggregate memberships
are bounded.

Successful response:

```json
{
  "snapshot": {"generation": 5, "groups": [{"handle": 2, "name": "development", "identity": "provider-a/revision-3", "selection": "node-b"}]},
  "adopted": [2],
  "cleanup_pending": false
}
```

The actual snapshot includes every configured user outbound group. `adopted` is
an array of numeric handles whose prepared group ownership transferred; an empty
array identifies a no-op or selection-only mutation. Resource cleanup errors are
reported separately after publication and must not be confused with failure to
publish. Existing retained flows can keep old resources after a successful
response; the response is not traffic verification.

## Selection

`POST /v1/selection`:

```json
{"operation_id": "0123456789abcdef0123456789abcdef:2", "expected_generation": 5, "handle": 2, "candidate_id": "node-a"}
```

Returns the same publication/readback response. The choice is durable and affects
new native admissions for both TCP and UDP. Existing sessions retain their prior
choice. Unknown membership, unmanaged baseline groups and stale generations fail;
there is no automatic fallback or clear-to-Direct operation.

## Independent group publication

`POST /v1/groups/publish` changes candidates and the group revision while retaining
the provider connection revision and its private definitions:

```json
{"operation_id":"0123456789abcdef0123456789abcdef:3","expected_generation":6,"provider_id":"provider-a","revision_id":"revision-3","group":{"name":"development","revision":4,"candidate_ids":["node-a"],"selection":"node-a"}}
```

The provider revision must already be active. The named group keeps its stable
kernel handle, has a strictly newer group revision, and only references nodes in
the provider's inventory. Selection must name a retained candidate. Group edits
have a separate encrypted restart representation; they do not manufacture a new
provider connection revision or fetch subscriptions.

## Durable operation recovery

Every Unix mutation requires `operation_id`, composed of a 32-character lowercase
hexadecimal client identity, a colon, and a positive decimal sequence. Each client
starts at sequence 1 and submits one pending operation at a time. The daemon
accepts only the next sequence; it retains the latest receipt per client, never
automatically evicts client authorities, and permits at most 64 client identities.
An older sequence cannot execute again. Reusing the current sequence with a
different payload is rejected.

`GET /v1/operations/{operation_id}` returns:

```json
{"operation_id":"0123456789abcdef0123456789abcdef:3","request_digest":"<64 lowercase SHA-256 hex>","kind":"group_publish","state":"committed","generation":7}
```

Kinds are `provider_publish`, `group_publish`, and `selection_set`. States are
`committed`, `rejected`, and `not_started`. A rejected receipt includes a sanitized
`error_code`. The digest hashes canonical JSON `{"kind":kind,"request":request}`;
request object keys are sorted, integers retain exact precision, and the request
excludes `operation_id`. Omitted zero-valued optional fields remain omitted.

The daemon serializes status lookup with execution. A `not_started` receipt for
the next sequence permits replay of the exact persisted ID and request; a delayed
original request is deduplicated by the same transaction barrier. A committed
receipt is encrypted atomically with the inventory before native adoption. A
known rejection is also durably recorded before acknowledgement. Process death
before that atomic commit leaves no side effect and permits the same-ID replay.
Postcommit kernel-readback or ambiguous storage failure fences the runtime;
status and inventory remain unavailable until restart restores the durable state.

The agent persists its client identity, sequence, complete pending request, and
controller correlation before sending. It checks the native receipt digest and
then healthy inventory before releasing pending state. Controller recovery uses
its authenticated mutation identity and explicit resolve endpoint: absent agent
intent becomes a durable rejection tombstone under the mutation lock, fencing a
late request. Latest receipts are retained per controller target (at most 4,096
targets); superseded receipts can be removed only after a newer target fence.
Missing old receipts are unknown, never evidence of rejection.

## Errors and unknown outcomes

```json
{"error":{"code":"generation_conflict","message":"inventory generation changed"}}
```

| HTTP status | Code | Meaning |
|---|---|---|
| 400 | `invalid_request` | Invalid JSON, identifiers, references, state, or unsupported mutation. |
| 403 | `forbidden` | Peer identity does not match the daemon's effective UID. |
| 409 | `generation_conflict` | Read current inventory before resubmitting intent. |
| 429 | `inventory_busy` | Retained group versions have reached their bound; drain and retry. |
| 503 | `inventory_closed` | Runtime has stopped admitting mutations/leases. |
| 503 | `outcome_unknown` | Persistence or kernel admission acknowledgement is ambiguous; runtime is fenced. Recover by inspecting/restarting from durable state and reading back. |
| 500 | `internal_error` | Sanitized internal failure. |

Timeout/disconnection means outcome unknown to the client. Query the durable
operation status; replay only the identical operation when status permits it,
and require healthy inventory readback after commit. An unchanged generation
alone never releases pending intent. Secret native errors are never returned
verbatim, and configuration readback is not packet verification.
