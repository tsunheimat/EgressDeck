# Collection pagination and retained history

The controller collection endpoints for devices, device groups, gateways,
providers, nodes, outbound groups, policies, rule sets, firewall bindings,
operations, audit events and provider revisions accept `limit` (default 100,
maximum 500) and `cursor`. Responses preserve the `items` array and add `limit`,
`total` and an optional `next_cursor`. Existing item fields and provider revision
node/report detail are preserved. Firewall responses also retain
`adapter_configured`.

For example, read `/api/v1/devices?limit=100`, then request
`/api/v1/devices?limit=100&cursor=<URL-encoded next_cursor>`. Keep the original
route, query and limit. IDs determine stable ascending order; provider revision
numbers use numeric ascending order. The cursor contains authenticated hashes,
not resource or secret data. It expires after 15 minutes and is invalid after
controller restart. Malformed, mismatched or modified cursors return HTTP 400;
expired cursors or changed collection snapshots return HTTP 409. Restart from
the first page on 409 rather than combining partial results. Gateway health and
firewall observation refreshes do not invalidate a configuration snapshot.

Each JSON page is at most 4 MiB and can contain fewer than `limit` items when
large records consume that budget. One record that cannot fit returns HTTP 413
(`collection_item_too_large`). A scan exceeding 100000 items or 64 MiB of public
item encoding returns HTTP 503 (`collection_capacity`). This is bounded HTTP
pagination: the storage and journal `List` implementations still materialize
full collections before the public snapshot scan. It is not database cursor
pagination or a bound on underlying durable store size. Aggregate `/overview`
and individual resource endpoints are outside this collection protocol.

The browser follows up to 100 pages and 10000 items, streams at most 4 MiB per
page, forwards cancellation and rejects repeated cursors. It reports an error
when limits are exceeded or the snapshot changes; it does not display a
silently truncated collection. Larger exports should use the paginated API.

Pagination does not delete durable operations or change their idempotency,
recovery and rollback records. There is no automatic operation-journal garbage
collection: monitor storage growth and retain recovery material. Audit history
currently retains the latest 5000 records. Provider revision admission is
limited to 128 retained revisions per provider; capacity refusal never silently
deletes revisions that might still support sessions or rollback. The resumable
`/events` feed has its own durable cursor and retention protocol and is not
wrapped by collection pagination.
