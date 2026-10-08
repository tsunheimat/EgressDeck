# DNS failure, loop, or classification drift

Domain rules depend on the actual DNS/sniffing path. DNS success alone does not prove that a domain rule matched, and a proxy counter does not represent all direct traffic.

## Establish the path

```sh
set -Eeuo pipefail
resolvectl status 2>/dev/null || cat /etc/resolv.conf
dig +time=2 +tries=1 A example.com
dig +time=2 +tries=1 AAAA example.com
dig +tcp +time=2 +tries=1 A example.com
dig +tls +time=3 +tries=1 @<dns-tls-host> example.com 2>/dev/null || true
```

Capture the client, OPNsense, gateway, and upstream resolver addresses. Confirm management and recovery names resolve independently of the selected outbound. On the gateway, inspect DNS listeners, routing rules, cache/error counters, and loop protection. Never point the resolver at itself unless the listener and upstream path are explicitly distinct.

## Symptoms and actions

- **Loop/refused queries:** stop changing policy; identify the listener and upstream socket with `ss -lntup`, inspect logs, and restore the last-known-good DNS manifest. Do not restart all network services as a first action.
- **DNS leak:** capture UDP/TCP/DoT/DoH destinations with a canary. Correct the OPNsense/gateway path or block the unsupported transport explicitly. A browser's encrypted DNS can bypass a resolver rule unless the network policy addresses it.
- **Wrong domain rule:** test an exact domain, suffix, shared IP, CNAME, direct-IP request, and an absent/unknown domain. Record whether classification came from DNS, sniffing, or an unavailable field. Do not call unknown traffic compliant with a domain-only rule.
- **Resolution outage:** preserve the prior provider/selection and apply the configured unknown-domain/proxy-failure action. If strict mode requires proxy-or-block, verify that Direct is impossible for the affected match.

Read back policy generation and observed route, then run a canary with `curl --resolve` and a direct-IP request to distinguish DNS classification from transport routing:

```sh
curl --fail --silent --show-error --resolve example.com:443:<expected-address> https://example.com/
curl --fail --silent --show-error https://<expected-address>/  # expected to follow explicit IP policy
```

Redact client addresses and credentials in captures. Record cache state, TTL, resolver transport, unknown-domain action, and whether IPv6 queries followed the same path.
