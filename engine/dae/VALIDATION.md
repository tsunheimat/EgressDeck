# Native source validation receipts

## Review follow-up, 8 October 2026

Current patch SHA-256:
`f3266aa1e69de7f1798343c4d3623ed035f5ee30e85c5cb1e4a97fd50c23975d`.
Capacity follow-up: `go test -race ./control -run TestHotOperation -count=1`
passed 16 checks on `agnet-test` (job `rt-20261008-110049-qjafgr88`).
Agent `go test -race ./internal/gateway -run TestNative -count=1` passed
48 checks (job `rt-20261008-110049-pqcgp21q`). The earlier 1,402-check
run below precedes this narrow non-evicting client-capacity refusal fix.

All 26 source files are bound in `source-manifest.json`. Reverse application
check against the pinned source tree passed.

On `agnet-test`, `go test -race ./control ./cmd -run TestHot -count=1`
passed 74 checks (job `rt-20261008-104308-07q5hoyv`), and `go test ./...`
passed 1,402 checks in 34 packages (job `rt-20261008-104425-hdbsdz2k`).
These include durable provider/group/selection operation receipts, same-ID
deduplication, interrupted precommit recovery, source process restart, retention,
and postcommit datapath-readback fencing.

The prior receipts below describe the previous exported patch and binaries.
They are historical evidence, not proof that the current source was built or
qualified on a live network. Current cross-layer receipts:
[production controller/agent/browser recovery scenario](../../tests/integration/artifacts/review-native-cross-layer.json)
and [exact native-source CI fixture](evidence/native-source-review-receipt.json).
The latter passed on the local host with actual daemon and adapter process
restart, verified 26 exported native source hashes, and zero process exits.

## Original implementation receipt

Exact upstream base: `e3fee8fbc68a65167af13b685ab0b958757e20ee`.
Patch SHA-256: `6dc2bbcb8270adfaac62eda4e33abab98eef9009bfa89e9f107d672cb904aa38`.
The patch applies cleanly to the independently downloaded base snapshot. All 22
changed source file hashes are recorded in `source-manifest.json`.

Validation ran on 8 October 2026. Native source checkout:
`/mnt/vibe-coding-share/test/egressdeck-dae-r05`; build/test execution host:
`agnet-test` (remote runner), Linux/amd64, Go 1.26.0.

| Command / boundary | Actual result |
|---|---|
| `go test -race ./component/outbound ./control ./cmd -run '^TestHot' -count=1` | **60 passed**, no kernel-stub build tag; job `rt-20261008-060924-53db09vv`, exit 0. |
| `go test -race -tags dae_stub_ebpf ./component/outbound ./control ./cmd -count=1` | **1,055 passed**, existing and new component/control/CLI regression cases; job `rt-20261008-061048-ucpvizot`, exit 0. |
| `go vet ./component/outbound ./control ./cmd` | Passed; job `rt-20261008-061301-ma9cja4i`, exit 0. |
| `go build -o .../dae-r05 .` | Passed with real generated BPF objects; job `rt-20261008-061049-cxg849b4`, exit 0. |
| `dae-r05 run --help` | Actual binary lists the paired hot-state-dir / hot-control-socket flags. |
| `git apply --check` on independently downloaded base | Passed. |
| Patch whitespace check | Passed. |

The 60 hot cases include native dialer/group leases, held TCP and UDP dial
admissions, failure/retry/rejected adoption, same-name DNS replacement during an
exchange, actual local SOCKS5 handshake/tunnel echo, stable selection and journal
restart, CAS/no-op/immutable revision reuse, bounded retention, encrypted-secret
absence and wrong-key rejection, fsync rollback/fencing, Unix peer authentication,
strict request parsing and request-drain shutdown. Some native transport tests use
in-process pipes or local loopback fixtures. They do not send enrolled-client
traffic through Linux tc or OPNsense.

BPF generation used the exact pinned header submodule
`56937c66784879fe5e2ff89db5bc05aa061d594c` and host clang:

```sh
env BPF_CLANG=clang BPF_STRIP_FLAG=-no-strip \
  BPF_CFLAGS='-O2 -Wall -Werror -DMAX_MATCH_SET_LEN=1024' \
  BPF_TARGET=bpfel go generate ./control/control.go
```

Generated `control/bpf_bpfel.o` SHA-256:
`06ca4cddfb8eb8556f6cc151546cb876abdbc7783343336e591bea7a1e80b640`.
Generated `control/bpf_bpfel.go` SHA-256:
`4ff8f22a878f42459b805f3d356269a80fc849a928c6ec08907822959bf19086`.
The test binary SHA-256:
`1560c7c2b88f18a2632705a9cfb940df3d47e840889a9632a41512af86e75aeb`.
These are validation artifacts, not a promoted engine release.

The normal clean-source control build initially failed because BPF generated
objects were absent. That prerequisite was resolved by initializing the exact
submodules and generating them. Temporary `/tmp` checkouts were not present on
the remote runner and produced `200/CHDIR`; successful receipts above used the
shared source checkout. The full regression command intentionally uses upstream's
`dae_stub_ebpf` CI tag; the focused hot command and build also passed without it.

The actual adapter/source API compatibility fixture also passed on `u25-code1`,
Go 1.26.0. It compiles the real `cmd.startHotControl` handler and native
`ControlPlane` publication/selection implementation into a test-only server and
connects the production `NativeEngine` over its authenticated Unix socket. It
publishes two groups for one provider, changes one group's selection, restarts
both the source process and adapter journal, and verifies recovered choices,
generations, permissions and encrypted credential storage. No manually copied
HTTP response DTO server is used for this receipt.

The reusable fixture is under `fixtures/`; the source/base/adapter/generated-BPF
hashes and actual process exits are in
[evidence/native-source-receipt.json](evidence/native-source-receipt.json).
The fixture bypasses control-plane kernel/ingress construction and does not
attempt packet-path or live provider qualification.

No live eBPF attachment, tc/listener identity comparison, real proxy-provider
network, OPNsense steering, client source identity, strict failure guard, OpenWrt,
or complete deployed application flow was tested. These release gates remain
open. See `INTEGRATION.md` for current restrictions and the next acceptance work.
