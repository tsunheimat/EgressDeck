# Compatibility and runtime qualification

This document is the WP00 qualification record for the homelab proxy
controller. It distinguishes facts established by source inspection or local
builds from facts that require a real OPNsense, Linux, and dae topology. A
successful controller build, a mock adapter, or a dae configuration check does
not qualify the packet path or the hot-update release gate (R05).

The record is intentionally conservative: a blank result is **blocked**, not a
pass inferred from a related test. Replace a placeholder only with an attached,
redacted artifact and the command that produced it.

The gateway agent defaults to its `stock` adapter. It checks executable
identity, observes the configured daemon process, and invokes bounded native
validation. The pinned dae source has no native `/api/v1` management server;
reload rebuilds a complete control-plane generation. Provider-only hot
publication and stable runtime selection therefore remain explicitly
unsupported by this adapter. The `fake` adapter is test-only. See
[stock adapter source qualification](../internal/gateway/STOCK-ADAPTER.md) for
the pinned file evidence and the required upstream runtime patch.

## Qualification state

As of 8 October 2026 the controller/UI, native OPNsense client, stock agent and
opt-in patched-daemon bridge have implementations and local evidence. The
daemon patch has native component tests and a generated-BPF build. No live
OPNsense appliance, privileged Linux tc/eBPF attachment, OpenWrt host or
two-client enrolled packet-path run has been qualified. The traffic claims
below remain **unqualified**; see [development status](development-status.md)
and [native source receipts](../engine/dae/VALIDATION.md) for exact boundaries.

| Gate | Source/build baseline | Required runtime evidence | Current state | Release consequence |
| --- | --- | --- | --- | --- |
| Controller build | Go/Vue build, local container smoke and encrypted restart integration | Final exact-source build/checksums and hosted CI job URL | Locally exercised; latest-tree final receipt separate | No gateway traffic claim |
| Engine provenance | dae source `e3fee8fbc68a65167af13b685ab0b958757e20ee`, exported patch/file hashes, generated-BPF build and component race tests | Qualified installed binary digest, kernel/topology and runtime evidence | Source/build established; live gate blocked | No live packet-path support claim |
| Frontend provenance | Zashboard dae integration snapshot `9b867b76a8cbca014423e93af59f7ce0996bc4f4` was inspected | Vendored commit/license manifest and adapter contract tests | Baseline only | UI cannot imply upstream server compatibility |
| Dae API/operations | Stock validate/health plus explicit native Unix API bridge for patched provider/selection operations | Exact adapter/daemon deployment and capability readback | Source path implemented; live qualification pending | Only observed implemented capabilities may be offered |
| Hot provider publication (R05) | Patched daemon prepares native resources and publishes affected groups under fixed handles; native component tests pass | Provider update with unchanged engine identity, listener/tc identity, unaffected sessions, bounded resources, and readback generation | Source/native path tested; network gate blocked | R05 release acceptance remains open |
| Runtime selection | Native shared TCP/UDP manual choice and encrypted daemon/agent restart state implemented | Selected-node readback and restart proof on the installed gateway with active traffic | Source/native path tested; network gate blocked | Independent transport selection and implicit failover unsupported |
| Source identity | The design requires the original client source at dae ingress | Two clients, NAT-before-dae detection, source and return-path captures | Blocked | Device grouping and strict enforcement remain unqualified |
| OPNsense steering | Host/Network alias API operations are documented | Persisted alias plus active-table readback, rule-order proof, reboot, and deny preservation | Blocked | Enrollment is not safe to enable |
| Direct forwarding/NAT | dae documentation warns direct forwarding does not automatically provide SNAT | Independent direct flow, return path, PMTU/ICMP, and state evidence | Blocked | Direct policy path cannot be declared working |
| DNS classification | DNS/sniffing limitations are documented upstream | UDP/TCP, cache, encrypted DNS, shared IP, missing name, and no-loop tests | Blocked | Domain policy is best effort only |
| IPv6 coverage | Scope permits IPv4-first only with an independently blocked/unmanaged IPv6 path | Dual-stack identity, temporary/prefix changes, and strict-mode refusal tests | Blocked | No dual-stack strict claim |
| Failure guard | The design requires a persistent deny-first or equivalent guard | Boot, crash/SIGKILL, agent/controller loss, gateway loss, raw-forwarding bypass, and recovery evidence | Blocked | Fail-closed release claim is prohibited |

## Pinned source and tool baseline

These pins identify the source and local build baseline used for development;
they are not a declaration that the corresponding runtime has passed
qualification. Keep the exact binary/container digest next to every deployed
pin.

| Component | Baseline pin | Evidence/qualification requirement |
| --- | --- | --- |
| dae | Upstream source `e3fee8fbc68a65167af13b685ab0b958757e20ee` (research snapshot) | Record `dae --version`, build flags, binary SHA-256, image digest if used, and any local patch commit |
| Zashboard integration | Upstream source `9b867b76a8cbca014423e93af59f7ce0996bc4f4` (research snapshot) | Record vendored tree SHA, license notices, and the controller adapter contract version |
| Go toolchain | `go 1.23` in `go.mod` | Record `go version`, `go env`, module checksum file, and CI image digest |
| Vue | `3.5.13` range in `apps/web/package.json` | Lockfile and package checksum; record npm/bun version used by CI |
| Vite | `6.0.11` range in `apps/web/package.json` | Lockfile and package checksum; attach build log |
| TypeScript | `~5.7.2` range in `apps/web/package.json` | Lockfile and typecheck log |
| OPNsense | Native client exact release `26.7`, source core `821598263289e177b40971600f06f5a91d9faef3`; no live appliance qualified | Record appliance release/kernel/plugin set/config revision and backup ID before testing; patch versions require explicit qualification |
| Linux gateway | No target kernel or architecture has been selected | Record distro/release, kernel config, architecture, tc/eBPF support, interfaces, routes, nftables, and service manager |
| OpenWrt | Supported only after target-specific testing | Record image release, target/arch, kernel config, firewall4/nftables state, storage, service manager, and dae artifact |

Do not replace the research SHAs with a moving branch or `latest` image. When a
runtime version is selected, add it as a new immutable row with the digest and
retain the research pin for provenance.

## Compatibility matrix

Status meanings: **source baseline** means the behavior is supported by an
inspected source or local contract; **blocked** means the required runtime test
has not passed or the required version is not pinned; **qualified** may be used
only after the evidence fields below are complete.

| Boundary | Source baseline | Minimum test topology | Required checks | Current status |
| --- | --- | --- | --- | --- |
| Controller ↔ PostgreSQL | Real pgx/SQL API lifecycle, encrypted sources/nodes, rejected-write snapshots, new-pool restart and wrong-key tests | Disposable PostgreSQL service, then target restore rehearsal | Schema twice, CRUD/CAS, secret absence and restart restoration | Local integration passed; target/hosted receipts separate |
| Controller ↔ OPNsense API | Native 26.7 endpoints decoded and tested through TLS fixtures, exact reviewed rule/alias scope and bounded deltas | Isolated OPNsense VM/appliance with disposable backup | TLS/auth, versioned request shape, persisted config, active table, drift, partial delta, reboot | Native client implemented; appliance gate blocked |
| OPNsense ↔ dae ingress | Proposed routed gateway path | OPNsense VM + Linux gateway + two distinct clients | Source address, route/reply-to, state, return path, ICMP/PMTU, no NAT before classification | Blocked |
| dae ↔ Linux kernel | dae source/docs describe tc/eBPF interception | Target kernel and interfaces used by deployment | Hook attach/readback, process crash, boot ordering, raw-forward path, listener identity | Blocked |
| dae direct outbound | Direct forwarding requires a proven return/NAT path | External direct endpoint through disposable WAN | TCP/UDP, DNS, PMTU, state timeout, source/NAT observation | Blocked |
| dae proxied outbound | Proxy node inventory is an application concern | Test provider with controlled proxy endpoint | Node probe, TCP/UDP as supported, selected-node readback, unrelated flow survival | Blocked |
| Provider fetch/parser | Bounded parsing/fetch, native/JSON/SIP008/Clash subset, exact private-source allowlist and stage-only scheduler | TLS fixtures plus selected real provider transport | Limits, redirect/SSRF checks, identity reconciliation, empty/invalid preservation | Fixture/security tests passed; live provider route qualification separate |
| Provider publication | Native daemon patch and encrypted agent bridge implement affected-group publication; stock remains unsupported | Real patched engine with active unrelated TCP/UDP | No full reload/restart, unaffected provider/group, generation/readback, leak bound | Native source tests passed; live R05 gate blocked |
| OPNsense DNS ↔ dae DNS | Shared gateway DNS is proposed; loops are a known risk | Clients using UDP/TCP and encrypted DNS variants | Internal/external split, cache, truncation, shared destination, no loop, unknown name action | Blocked |
| IPv4/IPv6 identity | IPv4-first scope is explicit; dual stack is required for strict claims | Dual-stack clients with temporary/prefix changes | Address ownership, leakage check, strict refusal when IPv6 uncontrolled | Blocked |
| OpenWrt target | No target image/kernel/runtime tested | Exact selected image and storage | Install/start/upgrade, tc/eBPF, firewall interaction, rollback, resource bounds | Blocked; unsupported until qualified |

## Runtime qualification run

Use a disposable topology with at least two clients (`client-a` and
`client-b`), one OPNsense instance, one Linux gateway running the pinned dae
artifact, a controlled direct endpoint, a controlled proxy endpoint, and an
independent management/recovery path. Keep management addresses outside policy
steering. Capture enough metadata to reproduce the run without exposing
subscription credentials or client-sensitive payloads.

Before the run, record:

```text
source_commit: <git SHA>
dae_source_commit: e3fee8fbc68a65167af13b685ab0b958757e20ee
dae_binary_sha256: <required>
dae_image_digest: <required or none>
zashboard_source_commit: 9b867b76a8cbca014423e93af59f7ce0996bc4f4
opnsense_release: <required>
opnsense_api_version: <required>
gateway_os_kernel_arch: <required>
gateway_interfaces_routes: <redacted but complete>
firewall_nat_state: <required>
dns_mode_upstreams: <redacted endpoints and mode>
topology_manifest: <artifact path and SHA-256>
run_id_started_utc: <required>
```

Record exact commands, exit codes, and artifact hashes. At minimum, attach:

* engine/agent capability and version readback;
* OPNsense configuration and active-alias readback before and after enrollment;
* tc/eBPF attachment and listener identity before and after each operation;
* redacted packet captures at client ingress, dae ingress, and egress;
* direct/proxy TCP and UDP flow results for both clients;
* DNS UDP/TCP, cache, encrypted-DNS, and unknown-classification results;
* provider revision, publication generation, selection, and operation journal;
* connection disruption and resource counts during repeated refreshes;
* crash/restart/failure-guard results and recovery readback.

## Acceptance evidence template

Copy this block for each capability run. A `PASS` without the linked artifact,
source hash, topology, and observed values is incomplete.

```yaml
run_id: <unique id>
capability: <for example provider.publish_hot>
status: BLOCKED # PASS | FAIL | BLOCKED
source_commit: <controller git SHA>
engine:
  source_commit: <dae SHA>
  binary_sha256: <sha256>
  image_digest: <digest or null>
  pid_before: <value>
  pid_after: <value>
  listener_identity_before: <value>
  listener_identity_after: <value>
  tc_identity_before: <value>
  tc_identity_after: <value>
topology:
  opnsense_release: <value>
  gateway_kernel: <value>
  clients: [client-a, client-b]
  source_addresses: <redacted mapping>
commands:
  - command: <exact command with secrets removed>
    exit_code: <integer>
    output_artifact: <path>
observed:
  desired_generation: <value>
  applied_generation: <value>
  observed_generation: <value>
  verified_generation: <value or null>
  active_tcp_disrupted: <count and method>
  active_udp_disrupted: <count and method>
  unrelated_provider_changed: <yes/no/evidence>
  retained_resources_after_repeats: <count/bytes>
artifacts:
  - path: <redacted log/pcap/readback>
    sha256: <required>
skipped_checks: [<explicit reasons>]
notes: <failure mode, limitation, or qualification decision>
```

## Release interpretation

The following claims remain unavailable until their corresponding gates are
qualified:

* “refreshes one provider without a full dae reload/restart” requires the hot
  publication evidence and repeated-update resource bound;
* “device traffic is enrolled” requires source identity, OPNsense readback,
  packet-path, and return-path evidence for the selected address family;
* “strict” or “fail closed” requires crash, raw-forwarding, IPv6, DNS unknown,
  and gateway-loss evidence;
* “OpenWrt supported” requires the exact image/architecture/kernel and rollback
  run, not a cross-compiled binary;
* “selection persisted” requires a restart/reconnect readback, not a successful
  API response.

A missing trusted runner or skipped network test is a blocked release gate for
that capability. It may be recorded as an explicitly limited prototype, but it
must not be presented as end-to-end acceptance.

## Sources

* S4 — dae reload documentation: <https://github.com/daeuniverse/dae/blob/main/docs/en/user-guide/reload-and-suspend.md>
* S5 — dae subscription loader at `e3fee8fbc68a65167af13b685ab0b958757e20ee`: <https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/common/subscription/subscription.go>
* S6 — dae validation command at `e3fee8fbc68a65167af13b685ab0b958757e20ee`: <https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/cmd/validate.go>
* S7 — OPNsense firewall API reference: <https://docs.opnsense.org/development/api/core/firewall.html>
* S8 — OPNsense alias utility controller: <https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/AliasUtilController.php>
* S9 — OPNsense firewall order and state behavior: <https://docs.opnsense.org/manual/firewall.html>
* S10 — dae packet processing and direct forwarding: <https://github.com/daeuniverse/dae/blob/main/docs/en/how-it-works.md>
* S11–S12 — DNS and source-selector behavior cited in the development plan.
