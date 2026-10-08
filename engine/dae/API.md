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
    {"handle": 2, "name": "development", "identity": "provider-a/revision-2", "selection": "node-b"},
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
  "expected_generation": 4,
  "provider_id": "provider-a",
  "revision_id": "revision-3",
  "nodes": [
    {"id": "node-a", "link": "socks5://127.0.0.1:1080#Example"},
    {"id": "node-b", "link": "socks5://127.0.0.1:1081#ExampleB"}
  ],
  "groups": [
    {"name": "development", "candidate_ids": ["node-a", "node-b"], "selection": "node-b"}
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
{"expected_generation": 5, "handle": 2, "candidate_id": "node-a"}
```

Returns the same publication/readback response. The choice is durable and affects
new native admissions for both TCP and UDP. Existing sessions retain their prior
choice. Unknown membership, unmanaged baseline groups and stale generations fail;
there is no automatic fallback or clear-to-Direct operation.

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

Timeout/disconnection also means outcome unknown to the client: read inventory and
match provider/revision/selection before retrying. Do not blindly increment a
generation, manufacture observed results, or label native configuration readback
as packet verification. Secret native errors are never returned verbatim.
