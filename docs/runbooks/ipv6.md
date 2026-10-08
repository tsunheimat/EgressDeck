# IPv6 coverage and bypass

IPv4-first enrollment does not provide strict protection for uncontrolled IPv6. Use this runbook before claiming dual-stack enforcement or when a client appears to bypass a proxy policy.

## Inventory

On the client, gateway, and OPNsense, record addresses, routes, interface scope, and DNS transport:

```sh
ip -6 addr show
ip -6 route show table all
resolvectl status 2>/dev/null || cat /etc/resolv.conf
curl -6 --fail --silent --show-error https://<controlled-test-host>/ip
curl -4 --fail --silent --show-error https://<controlled-test-host>/ip
```

On OPNsense, read the controller binding for `family=ipv6` and verify its source scope, interface, rule order, and active table. On the gateway, read advertised `supports_ipv6`, actual listener/route state, and policy generation. A capability flag without a packet-path result is insufficient.

## Safe decisions

- If IPv6 is supported and enrolled, test direct/proxy/block behavior for TCP, UDP (where supported), DNS, and PMTU on a canary. Verify the source address seen at dae and return path.
- If IPv6 is not supported or temporary/prefix addresses are not tracked, refuse strict enrollment for that device or explicitly set a quarantined/blocked state. Do not silently rely on IPv4-only aliases.
- If IPv6 bypass is observed, stop policy changes, preserve evidence, and disable/quarantine the affected enrollment using the deliberate control-plane action. Do not broadly disable IPv6 on the LAN without an approved network change.

Useful read-only checks on Linux:

```sh
sudo nft list ruleset > /tmp/nft-v6.txt
sudo tc -s filter show dev <gateway-interface> ingress > /tmp/tc-v6.txt
sudo tcpdump -ni <interface> 'ip6 and host <client-v6-address>' -c 50
```

Repeat after an RA/prefix renewal. Verify that old addresses are not retained as an unintended identity and that new addresses cannot bypass source enforcement. Record the exact address lifetime and enrollment validity.
