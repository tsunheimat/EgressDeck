# ADR: OPNsense steering and dae packet path

- **Status:** Proposed; runtime qualification blocked
- **Date:** 2026-10-08
- **Decision owners:** WP00/WP05/WP06 release owners
- **Related requirements:** R01, R05, R08, R09, R11
- **Qualification record:** [`docs/compatibility.md`](../compatibility.md)

## Context

The controller owns policy intent, while OPNsense admits selected client
traffic to a separate Linux host and dae chooses proxy, direct, or blocked
handling. The controller never forwards client packets. This separation keeps
management outage from stopping an already applied policy, but it creates a
packet-path obligation: the original source must reach the dae enforcement
point, the return path must work for direct traffic, and a failed dae process
must not silently expose a kernel forwarding path.

The development plan records that dae intercepts through Linux tc/eBPF and that
direct forwarding does not automatically supply SNAT. OPNsense floating-rule
ordering, quick rules, existing denies, state tracking, DNS forwarding, and
IPv6 can all change the result. No source observation or runtime integration in
this repository proves the proposed path, so this ADR is a design decision and
test contract rather than an acceptance claim.

## Decision

Use a routed, explicitly scoped OPNsense-to-dae gateway path for the first
qualified topology:

```text
client (source identity)
    │
    │  client LAN; no NAT before classification
    ▼
OPNsense interface rules / owned steering alias
    │
    │  route selected traffic to dae gateway; preserve existing denies
    ▼
Linux dae host ingress
    │
    ├─ tc/eBPF classification and policy lookup
    │      ├─ required proxy → selected stable outbound/node → proxy egress
    │      ├─ permitted direct → kernel route/NAT only where explicitly proven
    │      └─ blocked/unknown/failure → deny guard
    │
    └─ return path → dae/route state → OPNsense → original client

Management/recovery: controller, OPNsense API, agent, DNS administration,
and recovery access use addresses/routes outside client steering.
```

The controller initially attaches to an existing OPNsense Host/Network alias
and reviewed steering rule. It owns the complete managed alias contents for the
binding and verifies both persisted configuration and active-table state. It
does not create a broad quick pass, use a port-forward to a tproxy port, or add
unrestricted masquerading to conceal an unresolved route. Provisioning new
application-owned rules is a later mode after attach/readback qualification.

The first supported enrollment is an explicit, verified IPv4 address on a
known client segment. A dual-stack client is marked incomplete unless IPv6 is
also visible and enforced, or an independent segment guard blocks uncontrolled
IPv6. Domain rules are best-effort unless the classifier can prove the name;
unknown classification follows the configured proxy-or-block policy. Direct is
never an implicit fallback for required-proxy traffic.

## Invariants

1. **Source preservation:** the client source address visible at the dae
   ingress is the address selected by the device binding. If NAT occurs before
   classification, enrollment is rejected or explicitly limited to the
   resulting identity.
2. **Scoped steering:** every generated branch includes the source selector and
   family/interface scope. Existing OPNsense deny rules and management routes
   retain precedence according to the reviewed rule order.
3. **Return-path proof:** a direct flow is accepted only after return route,
   outbound NAT (if required), ICMP/PMTU, and state behavior are observed.
4. **Failure guard:** proxy-required traffic is blocked when dae or the gateway
   is unavailable. Agent/controller loss leaves the applied policy and guard
   active. A userspace watcher reacting after a crash is insufficient; the
   guard must exist in the persistent network path.
5. **State distinction:** desired policy, engine-applied generation,
   firewall-observed state, and client traffic verification are recorded
   separately. An API 200 or gateway ping does not prove packet enforcement.
6. **Management reachability:** OPNsense, PostgreSQL, controller, identity
   provider, agent, and recovery access do not depend on a selected outbound
   group or client steering rule.

## Alternatives considered

### Port-forward every client flow to a tproxy port

Rejected for the initial path. It does not establish source identity, rule
ordering, return behavior, or safe failure semantics and can bypass the
validated gateway design.

### NAT all clients before dae

Rejected. It destroys per-device source identity and makes device-group policy
and source-level verification ambiguous. Any deployment that needs NAT must
place it after the relevant classification and prove the return path.

### Add an unrestricted OPNsense quick pass or global masquerade

Rejected. It can override existing denies or hide the real routing failure.
Rule changes must remain narrow, owned, version-checked, and observable.

### Rely on a controller/agent watcher to add a deny after dae failure

Rejected as the only guard. Process crash, network partition, and kernel
forwarding can create a leakage window before a watcher reacts. The persistent
deny-first path must be tested independently.

### Treat a full dae reload as hot provider publication

Rejected for R05. Reload can be useful for bootstrap or a declared fallback,
but the release path needs affected-provider publication, stable handles,
unrelated-session survival, and generation readback without a full reload.

## Required qualification scenarios

Run these on an isolated OPNsense VM/appliance, one pinned Linux gateway, two
distinct clients, a controlled direct endpoint, and a controlled proxy
endpoint. Attach artifacts and hashes using `docs/compatibility.md`.

| Scenario | Pass evidence | Blocking failure |
| --- | --- | --- |
| Source identity | Client A and B remain distinguishable at dae ingress; capture shows no pre-classification NAT | Same source for both clients, unknown ingress, or unverified capture |
| Direct TCP/UDP | New and return flows complete with proven route/NAT/state; PMTU/ICMP works | One-way flow, hidden state workaround, or broad masquerade added |
| Proxy TCP/UDP | Required flows use selected node and proxy counters match independent capture | Gateway ping only, wrong node, or no client-side proof |
| Existing firewall policy | Unmanaged client and existing denies behave unchanged; rule order/readback attached | Broad quick allow, deny bypass, or status-only API result |
| Enrollment delta | Alias add/remove is idempotent and persisted/active contents match desired set | Whole-table flush, partial update unrecorded, or stale active table |
| Dae process crash/SIGKILL | Protected traffic remains blocked; direct exceptions behave only as explicitly qualified | Kernel forwarding leaks before/without guard |
| Agent/controller loss | Applied policy remains in force; management recovery remains reachable | Policy disappears or recovery depends on controller |
| Gateway loss | OPNsense fallback produces the declared blocked/quarantine behavior | Silent direct fallback or unbounded bypass |
| DNS | UDP/TCP, truncation, cache, internal zone, encrypted DNS, shared IP and unknown name have recorded outcomes | Loop, unclassified direct leak, or browser-only test |
| IPv6 | Dual-stack flow is enforced or strict enrollment is refused with evidence | IPv4 pass presented as dual-stack protection |
| Hot provider update | Engine PID/listener/tc identity and unrelated TCP/UDP survive; changed generation read back | Full reload/restart, unrelated provider change, session loss, or leak |

## Runtime evidence required for adoption

Before changing this ADR to **Accepted**, attach a qualification run containing:

* exact controller commit, dae source/binary/image digest, OPNsense release,
  gateway kernel/architecture, interfaces, routes, NAT and firewall order;
* capability readback and operation journal for attach, enrollment, selection,
  refresh, failure, and recovery;
* redacted captures at client ingress, dae ingress, direct/proxy egress, and
  return path, with timestamps correlated to operation generations;
* pre/post OPNsense persisted config and active-table output;
* tc/eBPF attachment, listener identity, engine PID, provider generations,
  selected stable node IDs, active connection counts, and retained-resource
  counts before/after repeated updates;
* explicit results for skipped checks, including why a test was unavailable;
* a release decision naming which capabilities are qualified and which remain
  blocked.

Until those artifacts exist, this ADR authorizes implementation and isolated
testing only. It does not authorize production enrollment or a strict
fail-closed claim.
