# Homelab Proxy Controller — Full Development Plan

**Plan date:** 8 October 2026  
**Working project name:** `homelab-proxy-controller` (a proposed name, not an existing repository)  
**Status:** Implementation plan. Repository capabilities have been inspected; no working end-to-end installation, deployed version compatibility, or packet-path behavior is claimed.  
**Target:** dae data plane, OPNsense traffic enrollment, device-group policies, and a Zashboard-derived subscription/proxy interface.

## 1. Product decision and requirements

Build a device-policy controller with a familiar proxy dashboard, not a replacement firewall and not a new packet-processing engine.

The user-facing workflow is:

> Import subscriptions → organize proxy nodes into outbound groups → define a device group's ordered rules → assign machines → apply and verify.

OPNsense decides which managed client traffic enters the dae gateway. dae decides whether that traffic uses a proxy, goes direct, or is blocked. The controller owns policy intent and coordinates both systems. Zashboard-derived components provide the node/provider/group interaction.

### Requirements and acceptance ownership

| ID | Requirement | Principal work packages |
|---|---|---|
| R01 | Enroll/unenroll a machine through an existing OPNsense steering alias | WP05, WP06 |
| R02 | One primary routing group per device, with shared ordered policies | WP04, WP07 |
| R03 | Reusable rule sets and explicit per-device exceptions | WP04 |
| R04 | Zashboard-style subscription cards, proxy cards, manual selection, and gateway-side tests | WP02, WP03, WP07 |
| R05 | Refresh one provider without a full dae reload or restart, unrelated provider downloads, or unrelated connection disruption | WP02, WP03, WP08 |
| R06 | Durable manual selection, independent or shared across device groups | WP02, WP03, WP04 |
| R07 | Separate management service from the remote Linux/OpenWrt data plane | WP00, WP01, WP02, WP09 |
| R08 | Preserve working configuration on failed updates and recover from partial deployment | WP06, WP08 |
| R09 | Preserve existing firewall restrictions; make DNS, IPv6, unknown-domain, and failure behavior explicit | WP00, WP04, WP05, WP08 |
| R10 | Build and test through GitHub Actions, including isolated real-network integration | WP01, WP08, WP09 |
| R11 | Show desired, applied, observed, and verified state instead of optimistic success | WP01, WP06, WP07 |
| R12 | Authentication, restricted credentials, secret handling, audit, and backup/restore | WP01, WP03, WP05, WP09 |

R05 is a release gate. A prototype that downloads one provider and then performs a full reload is useful for integration, but does not satisfy the intended subscription-update experience.

### Initial scope

Support a single OPNsense installation and a single active dae gateway first. Include a gateway identifier throughout the model so additional gateways can be added without redesigning identities. Finish the single-gateway lifecycle before promising automatic multi-gateway failover.

Support explicit device enrollment using reserved/static IPv4 addresses. Dual-stack identity and enforcement are part of the full plan; an IPv4-first deployment must clearly declare its coverage and cannot advertise strict protection for uncontrolled IPv6.

Do not initially implement arbitrary nested device-group inheritance, multiple competing routing groups per machine, nested outbound-group semantics, a complete Clash API, a complete Clash configuration importer, a generic firewall editor, per-pod Kubernetes identity, traffic billing, automatic WAN migration, or automatic production upgrades.

## 2. Verified baseline and unresolved compatibility

The following are source observations, not runtime acceptance results.

| Area | Observation | Consequence |
|---|---|---|
| Zashboard | The inspected source has a dae API client, a dae driver, asynchronous operations, and capabilities. [S1–S3] | Reuse the frontend structure, but do not infer server support from client methods. |
| dae CLI | The documented reload updates subscriptions and generally preserves connections. [S4] | A reload-based wrapper alone does not meet R05. |
| dae subscriptions | The inspected loader handles SIP008 and Base64 node lists and constrained local file sources. [S5] | Import formats and file permissions must be tested; Clash YAML conversion is separate work. |
| dae validation | The inspected command validates configuration and routing-related data without providing an end-to-end network test. [S6] | Validation is necessary but cannot be the only apply check. |
| OPNsense aliases | Alias utility APIs exist; inspected Host/Network mutations update configuration and active tables. [S7–S8] | Use persistent Host aliases and verify saved and active contents. |
| OPNsense rules | Modern and legacy rule implementations coexist; legacy rules do not have equivalent API editing support. [S9] | Start by attaching to existing steering objects; provision API-managed rules later. |
| Packet handling | dae intercepts at Linux tc/eBPF; direct forwarding does not automatically supply SNAT. [S10] | Prove source preservation, return paths, state behavior, and enforcement hook placement. |
| DNS classification | Domain classification has DNS/sniffing limitations. [S10–S12] | Do not advertise universal domain-based enforcement. |

The dae source snapshot seen in code-search results was `e3fee8fbc68a65167af13b685ab0b958757e20ee`. Zashboard's inspected dae integration was at `9b867b76a8cbca014423e93af59f7ce0996bc4f4`. These are research snapshots, not recommended release artifacts. WP00 must pin tested versions and container/binary digests.

**Unresolved:** a server implementation matching all of Zashboard's `/api/v1` expectations has not been verified here. Do not invent such a server, assume a matching release, or implement pretend responses. Build the controller against its own explicit adapter contract and record actual capabilities.

## 3. Architecture and deployment boundaries

Use a modular monolith rather than a microservice platform.

| Component | Proposed implementation | Responsibility |
|---|---|---|
| Web application | Vue/TypeScript, adapting Zashboard | Device groups, rules, subscriptions, proxy selection, diagnostics |
| Controller | Go service | API, authorization, desired state, compiler, deployment worker, reconciliation |
| Database | PostgreSQL | Configuration, secrets metadata, operations, audit, revision state |
| Gateway agent | Small Go service on the dae host | Authenticated local operations, journal, validation, snapshots, engine supervision |
| Engine adapter | Local package behind the agent | Runtime capabilities, selection, provider publication, policy application, probes |
| dae | Pinned upstream-based engine | Traffic interception and forwarding |
| OPNsense adapter | Controller module | Owned aliases, supported rule inspection/provisioning, readback |

The web application and controller can share one container image, with compiled static assets served by the Go service. Do not require a Node.js server in production solely to host the frontend. The database is external. Start with one active controller instance; no Redis, Kafka, or custom distributed consensus is required.

```text
Browser → Controller API → PostgreSQL
                    ├── OPNsense HTTPS API
                    └── Gateway agent → dae adapter → dae

Traffic:
Clients → OPNsense → selected traffic → remote dae host → proxy or direct
```

The controller does not forward client traffic. Stopping it must not stop an already applied policy. The gateway keeps durable last-known-good deployment manifests and approved provider snapshots locally, while PostgreSQL remains the authority for management intent.

Prefer a dedicated Linux VM/host for the first validated topology. OpenWrt is a supported target only after testing its actual kernel configuration, networking/firewall interaction, service manager, architecture, storage, and dae build. Keep the management service separate from whichever data-plane host is chosen. Do not attach dae to Cilium-managed Kubernetes interfaces in the first deployment.

Use management addresses/routes outside policy steering. Keep OPNsense, database, agent, identity-provider, and recovery access reachable independently of a selected subscription or outbound group.

## 4. Domain model and invariants

### Core entities

| Entity | Important proposed fields |
|---|---|
| Device | UUID, name, network scope, primary group, enrollment state, explicit overrides |
| DeviceAddress | Device UUID, family, address, provenance, last verification, validity state |
| DeviceGroup | UUID, name, policy, gateway binding, enabled state |
| Policy | UUID, ordered entries, final action, unknown-domain action, proxy-failure behavior |
| RuleSet | UUID, ordered reusable matches/actions, no terminal default |
| Rule | UUID, typed match expression, action, enabled flag, order |
| OutboundGroup | UUID, source filters, explicit candidates, selection mode, replacement behavior |
| OutboundSelection | Outbound group + gateway + transport scope, desired node, observed node, revision |
| Provider | UUID, source kind, secret reference, format, refresh schedule, fetch route, update mode |
| ProviderRevision | Provider UUID, content hash, normalized inventory, parse report, lifecycle state |
| Node | Stable UUID, provider association, display name, logical identity, secret reference |
| NodeRevision | Node UUID, connection-definition hash, protocol capabilities, normalized fields |
| Gateway | UUID, endpoint, adapter kind/version, capabilities, observed generation, health |
| FirewallBinding | UUID, gateway, family, interface scope, alias, rule identifiers, expected shape |
| Deployment | UUID, component revisions, compiled manifest, observed results, status |
| Operation | UUID, idempotency key, target, requested generation, step journal, result/error |
| AuditEvent | Actor, object, action, redacted diff, outcome, timestamp |

Separate logical identity from content revisions. A node can retain its identity across a verified rename, while a changed credential or transport produces a new connection revision. Do not merge different provider accounts merely because endpoints have matching names or addresses.

### Mandatory invariants

A device has one primary routing group. Organizational tags do not imply routing policy. A reusable rule set falls through; only a complete policy supplies the final default. An outbound group is not a device group. Source scoping is present on every generated device/group rule.

Selections are scoped to outbound group, gateway, and applicable transport. Two device groups sharing one outbound group intentionally share its selection on that gateway. Independent selection creates a distinct outbound group referencing the same nodes; it does not duplicate the subscription.

Store desired, engine-applied, firewall-observed, and traffic-verified state separately. An API request being accepted is not deployment success. An outbound being reachable is not proof that a particular client's policy is correct.

Do not automatically inherit a device's policy when an address is reused. Conflicting address ownership blocks enrollment. An overlapping network scope is usable only when the enforcement point can distinguish it; database namespaces alone do not make identical source addresses distinguishable at dae.

Do not identify machines behind a NAT using their original MAC at a routed dae ingress. Retain MAC/DHCP information for inventory, but enforce only identities actually visible and validated at the chosen network point. IP grouping is not strong protection against a malicious client spoofing addresses; stronger isolation needs network-level source validation or dedicated segments.

### Example conceptual configuration

The following is an application model, not dae syntax:

```yaml
device_group:
  name: Development
  gateway: gateway-1
  members: [dev-vm, build-runner]
  policy:
    entries:
      - ruleset: mandatory-blocks
      - match: {domain_suffix: [ai.example.com]}
        action: {outbound_group: development-us}
      - match: {domain_suffix: [packages.example.com]}
        action: {outbound_group: hk-auto}
    default_action: direct
    unknown_domain_action: policy_default
    proxy_failure: block_matching_traffic
```

That last setting does not make domain classification infallible. A strict guarantee for unknown domains requires a proxy-or-block default, not a direct default disguised as mandatory protection.

## 5. Repository layout and upstream strategy

Suggested new monorepo layout:

```text
apps/web/                       # Zashboard-derived frontend
cmd/controller/
cmd/gateway-agent/
internal/api/
internal/auth/
internal/domain/
internal/store/
internal/providers/
internal/nodes/
internal/outbounds/
internal/policy/
internal/compiler/
internal/deployment/
internal/reconcile/
internal/opnsense/
internal/gateway/
internal/telemetry/
api/openapi.yaml
api/agent-contract.yaml
migrations/
tests/fixtures/
tests/contract/
tests/integration/
tests/network/
tests/e2e/
deploy/compose/
deploy/kubernetes/
deploy/systemd/
deploy/openwrt/
docs/adr/
docs/runbooks/
docs/compatibility.md
.github/workflows/
```

These are proposed paths. They do not assert any existing repository structure.

Preserve upstream provenance and notices in imported frontend code. Keep UI adaptation in a small driver/API boundary, with device/group pages in new modules. Avoid unnecessarily rewriting Zashboard's proxy components.

Keep any required dae engine changes in a separate upstream-based patch branch or repository. Record the exact upstream base and patch series. Keep OPNsense logic, UI concepts, and controller database models out of the engine. Record third-party license obligations and a reproducible source manifest before distribution; do not assume a separately running service removes obligations associated with any code actually copied or linked.

An existing proxy-port-manager may supply reusable utilities or data, but its current implementation has not been reviewed for this plan. Do not import its port-per-instance architecture as a requirement. Treat migration as explicit mapping and validation, not an automatic schema conversion.

## 6. Engine contract and the hot-update work

### Capability contract

The following names are proposed application capabilities, not claims about stock dae endpoints:

```text
inventory.read
provider.stage
provider.publish_hot
selection.set_runtime
selection.persist_restart
policy.validate
policy.apply_generation
probe.node
probe.group
connections.observe
connections.close_filtered
traffic.proxy_counters
traffic.direct_counters
events.resume
```

Return implementation/version information and capability-specific restrictions. An unsupported operation must produce a typed error or disabled UI, not fabricated success. Determine publication behavior per mutation; do not expose one misleading global `supports_hot_reload` boolean.

### Decision order

First, test any existing matching runtime integration. Reuse only operations whose actual semantics pass the contract suite. Next, use stock validation/configuration application where appropriate for policy deployments. Where required hot provider/selection behavior is absent, implement the smallest local in-process engine extension needed. An external sidecar cannot mutate internal live groups safely merely by presenting REST endpoints.

A configuration-only adapter remains useful for bootstrap, debugging, and compatibility tests. It is not the release backend for R05 if provider publication still performs a full reload.

### Required hot provider publication algorithm

1. Accept an immutable normalized provider revision and its expected base generation.
2. Build new or changed dialers separately from the active inventory.
3. Validate protocol options, references, candidate availability, and explicitly requested pre-publication probes.
4. Recompute only affected candidate groups and selected-node mappings.
5. Persist the accepted revision and recoverable operation intent before reporting success.
6. Atomically publish the new provider/group snapshot for new connections.
7. Retain references used by existing sessions; retire old resources after drain or an explicitly configured bounded retirement action.
8. Read back the published generation, affected nodes/groups, and any missing selections.

Do not destroy unrelated DNS state, routing state, listeners, tc attachments, or healthy connections. Do not launch a second full dae instance on the same interfaces as a substitute for updating inventory.

Preserve stable route/outbound handles across a provider update. Adding or removing nodes must not renumber destinations still referenced by installed eBPF policy. If the pinned engine cannot publish inventory without invalidating those handles, that is required engine work, not a capability flag the adapter may claim. Creating a new routing/outbound structure can be a separate controlled policy deployment; refreshing an existing provider cannot silently become one.

No-op content produces no runtime publication. A failed prepare leaves the old revision active. A failed/unknown acknowledgement triggers readback, not blind retry. Cap retained generations, obsolete node revisions, open descriptors, and retired-session lifetime; surface a busy condition rather than allowing unbounded retained state during repeated updates.

### Required runtime selection algorithm

Validate membership and current provider/group revision. Apply the requested stable node identity to the relevant transport scopes, persist the desired choice, and report the observed result. New connections use the new choice; existing sessions drain unless an explicit disconnect was requested. Manual selection does not imply automatic failover. Missing selected nodes follow an explicit replacement policy; Direct is never an implicit replacement.

### Hot-operation release evidence

Compare before/after engine PID, listener identity, tc attachment identity, policy generation, provider generations, DNS behavior, active TCP streams, UDP conversations, and resource counts. PID survival alone does not prove absence of a full in-process reload. Require logs or counters identifying the publication path. Repeating provider edits must not leak generations or close unrelated traffic.

## 7. Subscription and node service

### Import behavior

Support native-compatible subscriptions, individual node links, and a tested subset of Clash/Mihomo node definitions. Detect format from bounded content inspection rather than filename alone. Show unsupported nodes/options separately. Never silently drop TLS, transport, authentication, or protocol properties that change semantics.

Import a full Clash document as node inventory by default. Do not import its listeners, external-controller credentials, DNS policy, routing policy, scripts, or firewall effects into the homelab policy automatically.

### Refresh workflow

```text
scheduled/manual refresh
  → fetch the selected provider
  → enforce response/body/parser limits
  → parse and normalize
  → compare identities and content
  → save staged revision + change report
  → approve or auto-approve under configured policy
  → hot-publish on affected gateways
  → verify observed provider/group state
```

Use per-provider serialization and coalesce duplicate refresh requests. Store last-attempt and last-success separately. A provider-level success can still be partially deployed across gateways; display both. An unreachable or malformed provider must not replace its last working revision with an empty inventory.

The UI can offer Refresh and Apply separately, plus an explicit safe auto-apply preference. Even in auto mode, empty results, unsupported changed options, identity ambiguities, and removal of a pinned node must obey the configured protection policy.

### Identity rules

Prefer stable provider-issued identifiers only when trustworthy and scoped to that provider. Otherwise use a provider-scoped normalized fingerprint with explicit ambiguity handling. Exclude display name/order from identity. A connection-definition hash must include security-relevant changes, but do not expose raw credential-derived fingerprints publicly. If credential rotation cannot be confidently linked to a previous logical node, report the ambiguity rather than silently claiming continuity.

Deduplicate identical entries within a provider only under documented behavior. Do not globally merge nodes across providers, since account, quota, and ownership may differ.

### Fetch security and metadata

Default to HTTPS with certificate verification. Bound time, body size, decompressed size, redirect count, parser depth, and node count. Revalidate destination addresses on redirects and connections to prevent DNS-rebinding/SSRF. Private homelab sources require an explicit administrative allowlist; public import must not access loopback, metadata services, or arbitrary internal endpoints.

Credentials are encrypted at rest using an externally supplied application key. Redact subscription query strings, headers, node links, and secrets from logs, operation payloads, support bundles, and UI errors. Keep the encryption key outside database backups.

A fetch route can be Direct or a verified existing outbound route. Track dependencies so a provider cannot require a missing node from its own first download. Do not silently change fetch route on failure. Probes and downloads should run on the chosen gateway where route behavior matters.

Provider traffic/expiry is optional provider-reported metadata. Keep source and observation time. Do not treat it as locally measured billing, and do not show zero as a substitute for unavailable data.

### Local snapshots

Keep the last working provider revisions on the gateway for boot and recovery. Stock dae's inspected local-file loader constrains files to the configuration tree and checks permissions. Generate compatible content and relative file references under a revision directory, not invented arbitrary absolute file URLs. [S5]

Only retain a bounded number of unreferenced revisions. Revisions referenced by active sessions or pending rollback cannot be garbage-collected prematurely.

## 8. Policy compiler and device-group semantics

Use typed data and a compiler, not string concatenation from UI text. Start with domain exact/suffix and tested domain sets, destination IP/CIDR, destination port/range, transport, and address family. Gate advanced matchers by actual adapter support.

Evaluation order is mandatory restrictions, explicit device exceptions, ordered group rules/rule sets, then the policy's final default. Mandatory restrictions cannot be overridden by a normal exception. Apply a device source selector to every generated branch.

Resolve reusable rule-set references into an immutable deployment snapshot. Preserve order; do not merge rules simply because the text looks similar. dae documents source-selector/domain interactions, so source-list aggregation must pass semantic tests before being used as an optimization. [S12]

Compiler outputs are a normalized policy representation, per-gateway engine configuration or runtime mutation, required OPNsense enrollment/enforcement sets, a manifest with revisions/hashes, a source map back to user rules, and a change-impact report.

The compiler rejects duplicate/conflicting ownership, invalid CIDRs, overlapping identities that the gateway cannot distinguish, unknown outbound groups, unsupported transport requirements, empty candidate groups unless explicitly handled, invalid defaults, unresolved references, unsafe raw-config overrides, and attempts to claim strict protection with uncontrolled IPv6.

Provide an explain operation with packet inputs and optional domain context. Label the result as a predicted match, not proof that the domain was observed or that a real packet took that route. Source maps should let the UI show the original group/rule behind a generated engine expression.

## 9. OPNsense integration

### Attach-first workflow

Allow the user to register an existing gateway, interface scope, Host alias, and steering rule. Read and validate the association. Where a legacy rule cannot be fully inspected through the supported API, record operator-confirmed details and require real packet-path validation; do not pretend full automatic verification was possible.

Use separate bindings by gateway, IP family, client interface scope, and enforcement behavior as needed. A group name alone is not a reason to create another floating rule.

The controller computes a flattened union of active addresses for each binding. Own the complete managed alias contents. Optional per-group aliases are informational unless their propagation is tested. Do not use nested aliases as an assumed immediate consistency mechanism.

The documented alias operations include add/delete/list. Use version-tested request formats and readback, not response status alone. Host/Network persistence in the inspected implementation is different from externally populated aliases. [S7–S8, S13]

### Mutation safety

Canonicalize IPv4/IPv6/CIDRs. Compute deltas rather than flushing the whole table. Make repeated requests idempotent at the application level. Verify both persisted configuration and the active table. For multi-address enrollment, treat partial updates as partial deployment and compensate according to the selected safety mode.

OPNsense requests are not assumed to have object-level compare-and-swap. Record owned UUIDs/names, compare expected object shape before writes, serialize the controller's requests, and pause on unexpected administrator changes. An ownership tag is not an authorization boundary. The service account may still have broader API privileges than individual aliases; constrain the adapter and disclose that scope.

### Rule safety

OPNsense evaluates floating rules before interface rules, and quick rules can terminate evaluation. [S9] The installation must preserve existing denies rather than add an unrestricted quick pass above them. Validate a narrow reviewed steering scope, and refuse automatic enrollment when its relationship to existing security policy cannot be established.

Exclude the transit ingress from client steering and preserve normal routing for management/local destinations. A proxy exclusion is not a blanket allow rule. Avoid source NAT before dae classification. Verify gateway monitoring, route-to/reply-to, return path, ICMP/PMTU, outbound NAT, and persistent state behavior.

Do not use a TCP/UDP port-forward to the tproxy port as a replacement for the validated gateway routing design. Do not globally disable state tracking, set sloppy states everywhere, or introduce unrestricted masquerading to hide an unresolved path problem.

### Provisioning mode

After attach mode is reliable, add creation/update of application-owned API-backed rules and aliases, with a diff preview, supported-version check, configuration backup, and tested rollback. Do not migrate or rewrite unrelated legacy rules automatically. Use tested rollback/savepoint mechanisms where available; do not fabricate endpoint support from documentation for another installed version.

Existing connections may retain old state after rule/alias changes. [S9] Offer graceful new-connection behavior and a separate explicit targeted state/connection cleanup action. For strict enrollment or a security-tightening change, retiring the affected pre-existing direct/proxy states is part of activation whenever they would bypass the new intent. Verify targeted cleanup across OPNsense, dae, and Linux connection tracking where applicable. If safe targeted cleanup or equivalent enforcement is unavailable, report the strict transition as incomplete rather than claiming immediate protection. Never flush all firewall states as a normal group update.

## 10. DNS, IPv6, and failure enforcement

### DNS

Use one shared DNS policy per gateway initially. Route enrolled clients' DNS through a tested dae-visible path; internal zones go to the internal resolver and external names to the configured upstreams. Prevent an OPNsense↔dae forwarding loop. Do not assume that DNS addressed to the firewall itself follows an Internet steering rule.

dae's ordinary DNS request-routing matchers do not automatically provide per-device upstream selection. Treat independent per-group DNS as a later resolver/instance design, not a feature obtained for free from traffic source rules. [S11]

Test UDP and TCP DNS, truncation fallback, cached answers, client encrypted DNS, shared destination addresses, and missing sniffed names. For standard split routing, declare best-effort domain classification. For strict intent, unknown classification must use proxy or block, not silently select direct.

### IPv6

Expose per-device coverage as IPv4, IPv6, dual stack, or incomplete. Discovering a DHCPv4 lease does not establish all IPv6 identities. Handle prefix changes and temporary addresses only through a tested ownership/enforcement method.

An IPv4-first strict deployment is allowed only on a segment where uncontrolled IPv6 Internet egress is independently blocked, or where all relevant IPv6 traffic is otherwise enforced. Refuse strict enrollment on an uncontrolled dual-stack segment. Do not claim per-device IPv6 blocking merely because the controller knows the IPv4 address.

### Failure policy

Keep these separate: unmatched-traffic action; unknown-domain action; required-proxy unavailable action; whole gateway unavailable action; explicit operator bypass.

For proxy-required traffic, no silent Direct fallback is permitted. A gateway ping is only host reachability. Test the specific outbound, DNS, and required transports from the actual gateway.

For fail-closed operation, enforce both the OPNsense fallback path and the Linux raw-forwarding path independently of controller availability. Gateway-down rule behavior alone is not a complete guarantee. [S14] Because dae intercepts before portions of normal stack processing, verify the exact path before relying on nftables or any other guard. [S10]

Use a persistent deny-first guard for protected source traffic and narrowly defined direct exceptions where proven safe. It must work on boot, process crash, SIGKILL, agent loss, controller loss, kernel-forwarding fallback, and partial reload. A userspace watcher reacting after failure is not sufficient evidence of zero leakage.

For a mixed direct/proxy policy, whole-daemon failure may deliberately block all external traffic in strict mode. Do not attempt to preserve domain-dependent Direct exceptions without the classifier needed to distinguish them. Document availability-versus-enforcement behavior plainly.

## 11. Deployment state machine and recovery

Persist operations with states such as:

```text
draft → validated → staged → applying → verifying → applied
                                 ├── partially_applied
                                 ├── failed
                                 └── outcome_unknown
```

Track rollback separately as pending/running/succeeded/failed, retaining the original error. A timeout can mean the remote operation succeeded; always inspect the actual generation before retrying or rolling back.

Use one serialized mutation stream per gateway and one per OPNsense target. PostgreSQL transactions/advisory locks and a durable operation table are sufficient for the initial controller. Add monotonic gateway generations/fencing so an older operation cannot overwrite newer state after retries or reconnection. The gateway journal makes individual operations restart-safe. Do not hold a database transaction open while making slow network calls.

### Operation ordering

| Change | Safe proposed ordering |
|---|---|
| Enable unmanaged device | Prepare guards → apply/verify dae policy → enroll and verify alias → verify new flow |
| Move group, same gateway | Apply new scoped policy while retaining enrollment → verify; no unnecessary alias remove/add |
| Operator selects Bypass | Confirm bypass intent → remove/verify enrollment → handle existing sessions explicitly → retire unused policy |
| Disable/delete management record | Reject ambiguous behavior; require explicit retain, block, or bypass disposition |
| Change proxy member | Persist intent → runtime selection → observe/read back; no OPNsense mutation |
| Refresh provider | Stage/validate revision → affected-group impact → hot publish → read back; no OPNsense mutation |
| Change routing rules | Compile/validate generation → controlled policy apply → verify; aliases change only when enrollment/enforcement changed |
| Move gateway | Prepare destination → protect ambiguous interval → coordinate source/destination bindings → verify → clean old state |

Gateway moves are not advertised as seamless in v1. Break-before-make can cause an intentional interruption; make-before-break can create ambiguous routing. Choose and test the behavior explicitly.

### Reconciliation and rollback

On controller/agent restart, read desired state, the operation journal, gateway generation, provider/group revisions, persisted aliases, and active tables. Reconcile within owned scope only. Unexpected external changes produce drift and halt destructive writes rather than being immediately overwritten.

Ordinary deployment failure should preserve the last working policy when that remains safe. A security-tightening change must not automatically roll back to a more permissive policy without acknowledging the consequence; use quarantine/block where required.

A group is not marked Applied until every required component is applied and read back. Network verification can be separate when no enrolled-client probe is available. Display configuration-applied and traffic-verified independently instead of implying that an agent-origin probe covers the client ingress path.

## 12. API design

Define the controller's public API in OpenAPI. These are proposed routes, not existing dae or OPNsense endpoints.

| Namespace | Purpose |
|---|---|
| `/api/v1/devices` | Inventory, address ownership, enrollment, membership |
| `/api/v1/device-groups` | Members, policy association, usage |
| `/api/v1/policies` and `/rule-sets` | Typed policy editing and explanation |
| `/api/v1/providers` | Import, settings, refresh, revision history |
| `/api/v1/providers/{id}/revisions/{rev}/apply` | Publish a staged provider revision |
| `/api/v1/nodes` | Inventory and manual node management |
| `/api/v1/outbound-groups` | Candidate membership and policy mode |
| `/api/v1/outbound-groups/{id}/selection` | Selection intent for a gateway/transport scope |
| `/api/v1/gateways` | Registration, capabilities, versions, health |
| `/api/v1/firewall-bindings` | OPNsense association and observed shape |
| `/api/v1/deployments/preview` | Diff, impact, validations, required changes |
| `/api/v1/deployments` | Submit an approved manifest |
| `/api/v1/operations/{id}` | Durable progress/result |
| `/api/v1/events` | Resumable management events |
| `/api/v1/audit-events` | Authorized redacted history |

Use stable IDs, revision/ETag preconditions, typed errors, bounded pagination, and idempotency keys. Long operations return an operation identifier and 202; completion is obtained through readback/events. Return 409/412 for conflicts rather than silently taking the last writer. Treat capability absence differently from transient health failure.

Patch Zashboard's driver to consume this contract or provide a narrowly scoped internal translation layer. Do not expose two competing `/api/v1` meanings and guess based on payload shape. Hide unsupported Clash-specific settings, fake-IP actions, core-upgrade buttons, and connection controls.

## 13. UI work

### Main navigation

| Page | Required behavior |
|---|---|
| Overview | Gateway/OPNsense status, unapplied/drifted changes, coverage, recent operations |
| Proxies | Zashboard-style cards, search/filter/sort, Manual/Automatic, selection, health, Used by |
| Subscriptions | Add/edit source, refresh, staging, diff, provider metadata, supported/unsupported nodes |
| Devices & Groups | Membership, address verification, routing group, enrollment, effective policy, exceptions |
| Rules | Ordered editor, reusable rule sets, default/failure behavior, validation, impact preview |
| Infrastructure | Gateway capabilities, firewall bindings, DNS/IPv6 coverage, versions, guard state |
| Activity/Diagnostics | Operations, errors, audit, predicted routing, observed connections when available |

Reuse Zashboard's existing presentation and driver separation. [S1–S3] Add frontend capability gating so an absent backend feature cannot be accidentally presented as operational.

Manual selection is saved only after the operation succeeds and observed state is available. Display desired and observed choices during transition. Show transport-specific results when they differ. Label tests by gateway and measurement type; a browser-to-controller ping is not proxy latency.

Provider refresh shows fetched, staged, active, and per-gateway publication state. A nonempty node list is not proof every node is valid. Explain removals, unsupported fields, stale quota information, and unavailable pinned nodes.

A proxy group's Used by panel links to referencing rules and device groups. Creating independent selections reuses the node inventory while allocating separate outbound groups. Deleting a referenced provider, group, or node requires a valid replacement or an explicit blocked state; never silently rewrites rules to Direct.

Do not offer arbitrary raw edits to controller-owned generated configuration. Provide a read-only preview and a deliberate unmanaged/advanced area with defined ownership and reference constraints. Disable generic upstream configuration editors that bypass the controller's revision model.

## 14. Authentication, authorization, and observability

Integrate Authentik through server-side OIDC sessions. The browser receives an application session, not OPNsense credentials or agent certificates. Use secure HTTP-only cookies, CSRF protection, exact redirect configuration, session expiry, and clear logout. Keep a protected break-glass administrative path independent of the traffic policy.

Proposed roles: Viewer for read-only state; Operator for approved selections, tests, and deployment actions; Administrator for credentials, gateways, policy/security settings, and enrollment. Authorize server-side, including event streams and exported diagnostics. Record actors for automated refreshes and agent actions.

Use mutual TLS or an equivalently authenticated pinned channel for the gateway. Restrict its network reachability. Expose typed operations, not arbitrary shell. File paths must remain inside managed directories; reject traversal and symlink escapes. Narrow any sudo/helper boundary. Keep the agent and engine permissions distinct where the implementation permits.

OPNsense API access follows its account/privilege model; validate TLS and assign only the required API privileges. [S15] Test denied actions, revoked credentials, certificate rotation, and account lockout separately from proxy health.

Record structured operations, durations, revision changes, refresh failures, unsupported imports, current candidate/selection state, stale observations, reconciliation drift, guard state, and deployment outcomes. Bound logs and history retention. Export metrics without raw domains, credentials, or user addresses as unbounded labels.

When connection telemetry is available, include gateway, source, destination, matched rule, chain, and generation where actually observed. Mark unavailable fields explicitly. dae direct traffic can follow a kernel path; userspace proxy counters must not be labeled total device traffic without a separately verified accounting source. [S10] Keep proxy traffic, direct traffic, provider quota, and firewall statistics distinct.

## 15. Development work packages and merge sequence

All packages include tests, documentation, migration impact, and rollback behavior in their definition of done. No phase includes an unapproved production change.

### WP00 — Capability and topology qualification

Inspect the pinned engine/Zashboard pair and actual target OPNsense API. Inventory supported kernel features, interfaces, addressing, firewall order, DNS, IPv6, NAT, and return paths. Build an isolated two-client topology with a dae host and OPNsense VM. Test source identity, direct/proxy TCP and UDP, and gateway-down behavior.

**Deliverables:** `docs/compatibility.md`; packet-path ADR; capability matrix; runtime-operation evidence; redacted packet captures; explicit gaps for hot publication and strict enforcement.

**Exit:** known working bootstrap path and a concrete implementation decision for every required operation. Absence of hot publication creates required WP02 work; it is not deferred behind UI polish. The prototype does not qualify for R05 yet.

### WP01 — Repository, schemas, API, auth, and durable operations

Establish Go/Vue workspace, PostgreSQL migrations, OpenAPI, typed clients, authentication skeleton, roles, audit, operation table, revision constraints, fake adapters, and baseline Actions workflows. Import/adapt the frontend with provenance.

**Exit:** authenticated CRUD, conflict handling, replay-safe operation submission, restart recovery, and CI builds/tests pass against fixtures. No external mutation is needed to exercise this foundation.

### WP02 — Gateway agent and engine capabilities

Implement registration, secure transport, last-known-good journal, capability discovery, validation, generation readback, probes, runtime selection, and required hot provider publication. Reuse a tested backend implementation if one exists; otherwise implement minimal in-process extension work.

**Exit:** real engine tests prove provider publication and manual selection without full reload, restart, unrelated connection loss, or state leakage. Repeated updates and process restart preserve selected-node intent. A fake server is insufficient.

### WP03 — Providers, normalized nodes, and outbound groups

Implement supported import formats, secret storage, protected fetches, metadata, revisions, identity reconciliation, filters, independent/shared selections, staged updates, missing-node policy, and schedules. Connect to WP02 hot publication.

**Exit:** provider refresh affects only its own inventory and dependent groups. Rename/reorder, corruption, credential changes, empty results, and removal of a pinned node have tested outcomes. Local snapshots recover after provider unavailability.

### WP04 — Devices, groups, policies, and compiler

Implement address ownership, single primary group, shared rule sets, explicit overrides, ordered rules, strict-mode validation, manifest/source-map generation, and predicted routing explanations.

**Exit:** deterministic output and semantic tests prove source isolation, precedence, references, defaults, and rejection of unsupported/ambiguous configurations. Moving a member to another same-gateway group produces the correct policy delta without unnecessary enrollment changes.

### WP05 — OPNsense adapter and verified bindings

Implement attach/readback, account/TLS checks, alias delta updates, persistence checks, firewall-shape ownership, drift handling, and supported targeted state operations. Add rule provisioning only after attach mode works.

**Exit:** an enrolled test client is steered correctly; another client and existing deny rules are unaffected. Membership survives firewall reload/reboot. Partial calls and manual edits cannot trigger destructive overwrites.

### WP06 — Cross-system deployment and reconciliation

Implement preview/approve/apply, per-target serialization, fencing, retries/readback, enrollment order, disable/bypass semantics, partial success, rollback, and startup reconciliation. Include independent guard enforcement from the networking proof.

**Exit:** injected failure at every boundary converges to a verified previous/new state or an explicit safe partial state. No pending device is routed into an unprepared engine. Strict changes cannot silently roll back into a less restrictive path.

### WP07 — Integrated Zashboard-derived experience

Finish proxy/provider pages and add device/group/rule/infrastructure workflows. Wire operation streams, version conflicts, capability gating, desired-versus-observed state, and impact/usage views.

**Exit:** browser end-to-end test completes subscription import → outbound group → device group → rules → enrollment → node switch → provider refresh → verified status. Unsupported operations are absent or clearly disabled.

### WP08 — Network, failure, security, and performance qualification

Run the full matrix below through Actions on isolated hosts. Add parser fuzzing, concurrency/race tests, restore tests, negative authorization tests, and retained-resource checks. Verify traffic measurements against independent observations.

**Exit:** required tests pass for the pinned release matrix. Skipped networking, hot-update, or strict-enforcement tests block the corresponding release capability. Record actual results, not only pass/fail summaries.

### WP09 — Packaging, migration, operational readiness

Publish versioned controller and agent artifacts, engine provenance, compose/k3s manifests, systemd service, and OpenWrt package only for qualified targets. Produce backup/restore, credential rotation, enrollment, rollback, troubleshooting, and update runbooks. Dry-run migration from existing sources/policies.

**Exit:** clean installation and restore reproduce intended state without contacting a live subscription first. One canary client passes, then an explicitly approved group is enrolled. Existing proxy infrastructure is retained until the replacement is verified.

### Dependency order

```text
WP00 → WP01 → WP02
            ├→ WP04
            └→ WP05
WP02 → WP03
WP02 + WP03 + WP04 + WP05 → WP06 → WP07 → WP08 → WP09
```

UI scaffolding and reusable components can progress after WP01, but production interactions cannot bypass the adapter/operation contracts. Keep source-identity, hot-provider, firewall-order, and strict-enforcement proofs on the critical path.

Suggested pull-request sequence: foundation/contracts; agent discovery/journal; engine hot primitives; providers/nodes; outbound selection; policy/compiler; OPNsense binding; orchestrator; proxy/provider UI; device/rule UI; failure/security integration; packaging/runbooks. Split oversized engine changes further rather than combining packet-path changes with UI changes.

## 16. CI, test matrix, and release gates

Run compilation and tests through GitHub Actions. Do not require the developer workstation or production router to serve as the build/test environment.

Hosted CI handles formatting, linting, type checking, unit tests, parser/compiler fixtures, API contract tests, PostgreSQL-backed integration, frontend tests, and image builds. Use isolated trusted self-hosted runners/VMs for real Linux eBPF, OpenWrt, and OPNsense tests. Never run untrusted pull-request code on a privileged runner with production-network credentials.

Mocks validate controller behavior and UI flows; they do not prove dae supports hot updates or that OPNsense routes correctly. Cross-compiled artifacts are not proof of runtime compatibility on that architecture.

| Category | Required scenarios |
|---|---|
| Source identity | Original address visible, NAT-before-dae detected, address conflict/reuse, unsupported overlapping scopes |
| Basic routing | Direct/proxy/blocked TCP, UDP, QUIC where supported, DNS UDP/TCP, local access and PMTU |
| Group semantics | Two groups share one policy; independent selections; shared selection intentional; overrides preserve mandatory restrictions |
| Subscription parsing | Supported native lists, manual links, supported YAML subset, rejected options, malformed/huge/compressed/empty content |
| Provider lifecycle | Single-provider refresh, no-op refresh, node rename/reorder, deleted pinned node, failed prepare/publish, restart |
| Hot behavior | No full reload/restart; unrelated provider unchanged; unrelated TCP/UDP survives; bounded retained resources |
| Selection | Stable ID, revision conflict, independent TCP/UDP when supported, explicit failover, persistence after restart |
| OPNsense | Idempotent delta, active/persisted readback, reboot, manual drift, partial address update, deny-rule preservation |
| Failure enforcement | dae crash/SIGKILL, agent/controller loss, OPNsense/gateway loss, boot ordering, update failure, raw-forwarding bypass attempts |
| IPv6 | Dual-stack pass/fail, temporary/prefix changes, explicit incomplete state, strict enrollment refusal when coverage cannot be enforced |
| DNS | Internal resolution, no loops, caching, shared IPs, encrypted DNS, absent domain, strict unknown action |
| Reconciliation | Crash after each boundary, acknowledgement lost, stale generation, retry, rollback conflict, restore |
| Security | Viewer denial, CSRF/session controls, SSRF redirects/rebinding, path escape, secret redaction, TLS/auth failures |
| UI | Loading/partial/error states, no optimistic final success, source coverage, Used by, unsupported features hidden |

Proposed qualification dataset: 100 devices, 20 device groups, 10 subscriptions, 500 nodes, and 1,000 generated rules. These are development targets, not measured supported limits. Use smaller deterministic fixtures on every PR and larger/repeated tests for integration qualification.

Record p50/p95 read latency, operation latency by type, memory/CPU, direct/proxy throughput, connection disruption, provider-fetch counts, engine reload counters, and retained resources after repeated refreshes. Establish numerical budgets from WP00's pinned baseline rather than inventing a performance guarantee. Compare the same network topology with and without the management layer; do not conflate a topology change with controller overhead.

Build immutable commit-tagged artifacts. Promote a pinned digest only after required gates pass. A moving main/latest image must not automatically update the production gateway. Publish SBOM/provenance, dependency versions, supported feature matrix, and redacted integration artifacts.

## 17. Rollout, recovery, and definition of done

Start read-only: register OPNsense and gateway, inspect capabilities, and compare intended bindings. Import subscriptions and build policies without enrolling machines. Validate a canary with explicit console/recovery access, then expand group by group with recorded verification.

Keep previous infrastructure available during migration. Export and back up controller state, encrypted secrets, external encryption-key recovery material, agent manifest, engine artifacts, and relevant OPNsense configuration separately. Restore into an isolated environment before relying on backups. Resolve an already-ahead gateway by readback rather than overwriting it with an old database snapshot.

Provide runbooks for failed provider refresh, missing selected node, unreachable agent, OPNsense API failure, stuck/unknown operation, wrong-device enrollment, rule drift, DNS loop, IPv6 coverage failure, engine upgrade, and rollback. Include a deliberate bypass action and a separate fail-closed quarantine action; neither should be triggered just because the web service is down.

The project is complete when a user can import a subscription, create proxy groups, build a shared device-group policy, enroll selected machines through OPNsense, switch exits, refresh one provider without full reload, and observe verified results. Failures preserve the last working state or the explicitly required blocked state; unrelated firewall policy and unrelated sessions remain intact. Builds, installation, restore, and the declared network capabilities are reproducible through the CI/release process.

The first development action is WP00: prove the engine's real mutation capabilities and the OPNsense↔dae packet path. The highest-risk implementation is WP02 hot inventory/selection publication. The interface should be built around those verified semantics, not used to conceal a reload-based backend.

## Source register

Sources below support upstream observations. Proposed architecture, workflows, schemas, acceptance targets, and work packages are recommendations in this plan, not claims that upstream already implements them. Sources were inspected on 8 October 2026.

- **S1:** Zashboard dae client: https://github.com/Zephyruso/zashboard/blob/9b867b76a8cbca014423e93af59f7ce0996bc4f4/src/api/dae.ts
- **S2:** Zashboard dae driver: https://github.com/Zephyruso/zashboard/blob/9b867b76a8cbca014423e93af59f7ce0996bc4f4/src/assembly/driver/dae.ts
- **S3:** Zashboard native-contract update: https://github.com/Zephyruso/zashboard/commit/9b867b76a8cbca014423e93af59f7ce0996bc4f4
- **S4:** dae reload documentation: https://github.com/daeuniverse/dae/blob/main/docs/en/user-guide/reload-and-suspend.md
- **S5:** dae subscription loader: https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/common/subscription/subscription.go
- **S6:** dae validation command: https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/cmd/validate.go
- **S7:** OPNsense firewall API reference: https://docs.opnsense.org/development/api/core/firewall.html
- **S8:** OPNsense alias utility controller: https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/AliasUtilController.php
- **S9:** OPNsense rule implementations, order, and states: https://docs.opnsense.org/manual/firewall.html
- **S10:** dae packet processing, classification, and direct forwarding: https://github.com/daeuniverse/dae/blob/main/docs/en/how-it-works.md
- **S11:** dae DNS configuration: https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/dns.md
- **S12:** dae routing configuration: https://github.com/daeuniverse/dae/blob/main/docs/en/configuration/routing.md
- **S13:** OPNsense aliases: https://docs.opnsense.org/manual/aliases.html
- **S14:** OPNsense gateway-down settings: https://docs.opnsense.org/manual/firewall_settings.html
- **S15:** OPNsense API usage and authentication: https://docs.opnsense.org/development/how-tos/api.html
