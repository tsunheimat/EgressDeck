# Stock dae adapter and source qualification

The gateway agent defaults to `-engine=stock`. `-engine=fake` selects a development simulation and is never evidence that dae supports an operation.

The stock adapter invokes `dae --version` and `dae validate --config <private temporary file>`. It records the executable's SHA-256, optionally enforces an operator-supplied digest, and compares the configured PID's `/proc/<pid>/exe` identity with the configured executable. A live process is reported as degraded because process existence does not establish policy, eBPF, inventory, or traffic health.

Native validation accepts `Policy.payload.native_config`. It uses a mode-0600 file in a private temporary directory, bounds runtime and diagnostic output, rejects includes, and withholds native diagnostics that could expose credentials. Geo-data files and arbitrary included configuration are not supplied to this restricted validator. Successful syntax validation does not establish packet-path acceptance.

Provider staging/publication, selections, runtime inventory, policy application, probes, counters, connection operations, and events return typed `unsupported` errors. The stock reload command cannot truthfully implement hot publication or applied-generation readback, so this adapter does not invoke reload or start a daemon.

Remote listeners require TLS 1.3 with verified controller client certificates. Configure `GATEWAY_AGENT_TLS_CERT`, `GATEWAY_AGENT_TLS_KEY`, `GATEWAY_AGENT_CLIENT_CA`, and `GATEWAY_AGENT_TOKEN`. Plain HTTP is restricted to literal loopback listeners. `LoadClientTLS` provides the corresponding controller transport configuration. Tests perform real TLS handshakes and reject absent/untrusted client certificates, untrusted server certificates, hostname mismatch, malformed trust roots, and TLS 1.2.

The controller uses `NewClient(ClientOptions{Endpoint, Token, TLSConfig, Timeout, MaxResponseBytes})` with the TLS configuration returned by `LoadClientTLS`. This implements `Engine`, `HealthReader`, `Readback`, and `JournalEntries` using the actual agent routes. It forbids redirects and environment proxies, bounds headers and response bodies, and returns redacted typed errors. Lost or malformed mutation acknowledgements return `ErrOutcomeUnknown`; mutations are never automatically retried. A staged provider receipt's generation is retained for publication; after restart use `PublishStaged` with the durably stored stage ID and base generation. Stock unsupported operations remain unsupported through the remote client.

## Inspected upstream sources

Source inspection performed 2026-10-08:

- dae: `e3fee8fbc68a65167af13b685ab0b958757e20ee`
- Zashboard: `9b867b76a8cbca014423e93af59f7ce0996bc4f4`

All 605 dae archive files were checked against the upstream nontruncated Git tree's blob hashes with zero mismatches. The archive SHA-256 is `56afe206b2c3f05402d99ade267744a7288bf7d6cce94254b52f036d8d4893a7`. The pinned Zashboard `src/api/dae.ts` SHA-256 is `dd5066a02f76c293ae8ccfc44983aae33eac6c7730a32ec2ac947c017fb1403b`. These identify inspected source bytes, not a qualified installed binary. No upstream source was copied or linked into this package.

| Finding | Pinned evidence |
| --- | --- |
| Native config validation reads config, lowers routing, validates DNS rules and fixed-domain TTL without touching BPF. | [cmd/validate.go](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/cmd/validate.go) |
| No `/api/v1`, group/provider management routes, or HTTP handler implementation occurs across 237 production Go files. Only pprof HTTP servers are constructed. | [cmd/run.go](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/cmd/run.go#L420-L423), [cmd/reload_manager.go](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/cmd/reload_manager.go#L477-L490) |
| CLI reload signals SIGUSR1 and waits for reload progress. The reload worker reads configuration and constructs a new control plane. | [cmd/reload.go](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/cmd/reload.go#L108-L122), [cmd/run_reload_worker.go](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/cmd/run_reload_worker.go#L179-L209) |
| A reload traverses subscriptions and rebuilds groups and routing matcher. It is not provider-only publication. | [cmd/run_controlplane.go](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/cmd/run_controlplane.go#L214-L309), [control/control_plane.go](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/control/control_plane.go#L634-L788) |
| Outbound numeric IDs derive from generation-local group slice positions. | [control/control_plane.go](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/control/control_plane.go#L710-L722) |
| The in-process `DialerGroup.SetSelectionPolicy` primitive exists, but has no production caller or external API. A single group-wide FixedIndex selects from the current dialer slice. | [dialer_group.go](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/component/outbound/dialer_group.go#L120-L156), [dialer_selection_policy.go](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/component/outbound/dialer_selection_policy.go#L16-L19) |
| Zashboard issues `/api/v1/groups/{id}/selection` and `/api/v1/providers/{id}/refresh` requests, but the inspected dae pin lacks their server implementation. | [src/api/dae.ts](https://github.com/Zephyruso/zashboard/blob/9b867b76a8cbca014423e93af59f7ce0996bc4f4/src/api/dae.ts#L148-L196) |

## Required engine work

R05 requires an upstream-based runtime patch that publishes only affected immutable provider/group snapshots, retains existing session dialers, preserves installed outbound identities, and bounds retired resources. R06 additionally requires stable member IDs, scoped membership/revision checks, explicit missing-member policy, durable selection recovery, and a transport-scope decision because the inspected primitive applies to the whole group.

An authenticated runtime API must expose actual capabilities, generation readback, acknowledged/recoverable operations, and measurements showing that the hot path leaves listeners, tc attachments, DNS/routing state, and unrelated traffic intact. Source inspection and command fixtures do not satisfy those engine/network release gates. No dae executable was installed in this workspace; stock adapter tests use a disclosed shell fixture for command-boundary validation. No privileged network test was executed.

The separately maintained prerequisite engine patch and its remaining integration limits are described in [engine/dae](../../engine/dae/README.md).
