# OPNsense API or steering failure

This runbook protects existing firewall restrictions while diagnosing controller-owned aliases/bindings. It assumes API access is limited to the required OPNsense privileges and uses a dedicated test alias/rule where possible.

## Read-only checks

```sh
set -Eeuo pipefail
curl --fail --silent --show-error --connect-timeout 5 --max-time 15 \
  --cacert /etc/homelab-proxy-controller/opnsense-ca.pem \
  -u "$OPNSENSE_KEY:$OPNSENSE_SECRET" \
  "https://<opnsense-host>/api/core/firmware/status" | tee /tmp/opnsense-status.json
curl --fail --silent --show-error --connect-timeout 5 --max-time 15 \
  --cacert /etc/homelab-proxy-controller/opnsense-ca.pem \
  -u "$OPNSENSE_KEY:$OPNSENSE_SECRET" \
  "https://<opnsense-host>/api/firewall/alias_util/list/<alias-id>" | tee /tmp/opnsense-alias.json
```

Endpoint names vary by OPNsense release and adapter version. If an endpoint returns 404/403, record it and stop; do not substitute a guessed endpoint or use an unrestricted account. Verify the API certificate/SAN, clock, account status, privilege, and whether the saved configuration and active table agree.

On OPNsense, use the UI diagnostics/status pages or the documented API to read the alias and rule. Preserve a configuration backup before any mutation. Capture rule order, interface/family, source scope, gateway, and existing deny restrictions.

## Failure handling

- **Timeout/TLS/authentication failure:** do not retry mutations. Correct reachability, certificate, clock, or credential issues, then perform a read-only check.
- **Alias mutation partially acknowledged:** read saved and active alias contents. If they differ, do not issue a broad reload; reconcile the exact delta through the supported adapter or restore the prior alias from the configuration backup.
- **Manual drift:** report the expected shape and observed shape. Never overwrite unrelated aliases/rules. Require an explicit repair approval for a controller-owned object.
- **Rule/order mismatch:** leave the client unenrolled or quarantine its policy until the source-scope, interface, family, and order are verified. Existing deny rules must remain present.
- **OPNsense reboot/reload:** wait for API readiness and active-table readback, then test only the canary. A successful API response before firewall reload is not traffic verification.

## Safe readback

After a targeted change, verify all of the following independently: persistent alias membership, active alias membership, rule order/shape, gateway/route, IPv4 and IPv6 family coverage, one enrolled canary, and one unenrolled control client. Compare firewall counters and an independent packet/traffic observation. If any check is unavailable, keep the previous binding and mark the operation unknown.
