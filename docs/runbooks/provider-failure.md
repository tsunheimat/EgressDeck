# Provider refresh or publication failure

The safe result of a failed provider update is the previous verified provider revision remaining active. A non-empty download, a successful parse, or an HTTP 200 response does not prove that nodes are usable.

## Triage

Capture the provider ID, requested/base revision, operation ID, source commit/image digest, and current active revision. Read state before retrying:

```sh
set -Eeuo pipefail
curl --fail --silent --show-error -H "Authorization: Bearer $HPC_TOKEN" \
  "$HPC_URL/api/v1/providers/<provider-id>" | tee /tmp/provider.json
curl --fail --silent --show-error -H "Authorization: Bearer $HPC_TOKEN" \
  "$HPC_URL/api/v1/capabilities" | tee /tmp/capabilities.json
```

Check the provider URL certificate, DNS, HTTP status, content length, content type, redirect chain, decompression limit, parser result, credential reference, and whether the gateway fetch route is reachable. Use an approved test fetch with bounded output only; never print a provider URL containing credentials.

```sh
curl --fail --silent --show-error --location --max-time 30 --connect-timeout 10 \
  --max-filesize 10485760 -o /tmp/provider-body '<redacted-provider-url>'
sha256sum /tmp/provider-body
```

## Decision tree

- **Fetch failed or timed out:** leave the active revision unchanged. Correct DNS/TLS/route/credential settings, then retry once with the same idempotency key.
- **Parse/validation failed:** quarantine the staged bytes and parse report. Do not publish an empty or partial inventory. Ask the provider owner to correct the source or use the last approved snapshot.
- **Empty or unexpectedly small result:** require deliberate operator approval and an impact preview. An empty result never silently deletes pinned nodes.
- **Prepare/probe failed:** preserve the current revision and close only resources created by the failed prepare. Check for leaked descriptors/connections before retrying.
- **Publish acknowledgement lost:** treat the result as unknown. Read back provider and affected-group generations and node IDs before retrying; do not blindly publish twice.

If `provider.publish_hot` is false, do not claim R05. A stock full reload may be used only in an isolated development test with explicit disruption evidence; production refresh must remain staged until a qualified hot publication capability exists.

## Recovery and verification

1. Inspect the staged diff: added/removed/renamed nodes, credential/transport changes, candidate-group impact, and selected-node impact.
2. Verify the old revision is still active and that unrelated providers, listeners, tc attachments, and active TCP/UDP sessions are unchanged.
3. Retry with a new staged revision only after the cause is fixed. Keep per-provider serialization and a bounded revision count.
4. After publication, read back the exact generation, affected groups, selected nodes, and node probes. Run a canary traffic test through the gateway and record connection disruption.
5. If a selected node disappeared, follow its explicit replacement policy. Direct is never an implicit replacement for a proxy-required rule.
