# Pinned dae policy artifact

`policy.RenderDAE(policy.CompileInput)` runs the controller compiler and returns
a typed `DAEArtifact` in format `dae-routing-v1`. It emits a `routing { ... }`
section only. It does not create interfaces, choose DNS resolvers, import node
credentials, alter firewall state, or report an applied generation.

The format is pinned to upstream dae commit
`e3fee8fbc68a65167af13b685ab0b958757e20ee`. The controller does not link or copy
the upstream parser. The integration test executes a separately built dae CLI.

## Native semantics

The source reference is
[`docs/en/configuration/routing.md`](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/docs/en/configuration/routing.md).
The exact native parser registry is
[`control/routing_matcher_builder.go`](https://github.com/daeuniverse/dae/blob/e3fee8fbc68a65167af13b685ab0b958757e20ee/control/routing_matcher_builder.go),
and `cmd/validate.go` invokes that registry after the normal alias, data-set,
merge/sort and parameter-deduplication passes.

| Typed intent | Generated dae syntax |
| --- | --- |
| One source host | `sip('192.0.2.10/32')`, `sip('2001:db8::1/128')` |
| Exact domain | `domain(full: 'api.example.com')` |
| Domain suffix | `domain(suffix: 'example.com')` |
| Immutable domain set | Expanded suffix operands; no external files or downloads |
| Destination CIDR | `dip('203.0.113.0/24')` |
| Port / inclusive range | `dport(443, 8000-8080)` |
| Transport | `l4proto(tcp, udp)` |
| Family | `ipversion(4, 6)` |
| Action | `direct`, `block`, or generated named outbound |

Native functions are combined with `&&`; values within a function are ORed.
Exact and suffix patterns form one OR dimension. A separate domain-set
dimension remains a second `domain(...)` function joined with `&&`. The pinned
`component/routing/matcher_builder.go` lowers parameter-key groups into logical
OR and function boundaries into logical AND.

Each device selector is emitted individually for each rule. Rule order remains
mandatory restrictions, exceptions, group entries, then a source-specific
default. The final unscoped fallback is always `block`. No source-list/domain
aggregation optimization is performed by this renderer. The native optimizer
may combine adjacent source-only rules with the same action; those rules have
no domain dimension.

This artifact is for a dedicated managed ingress. The assembler must preserve
management routing outside that ingress; it must not substitute a permissive
global fallback to make unrelated traffic work.

dae domain matching uses DNS-derived destination-IP bitmaps shared by the
gateway. The bitmap can contain domains resolved by other clients, and missing
DNS visibility can result in no domain match. A syntax-valid artifact does not
establish that a requested domain was observed. The required global settings
are `dial_mode: ip` and `auto_sniff_punt: false`, which disable additional
sniffing/rerouting and injected recovery rules. A tested dae-visible DNS path
remains a deployment prerequisite.

## Rejected intent

Rendering fails without returning partial native configuration for:

- An unknown-domain action different from the policy default: pinned dae has no
  equivalent dedicated unknown-domain matcher.
- An unnamed `proxy` action or a QUIC-only transport match.
- Source subnets. This initial native format accepts explicit host `/32` and
  `/128` selectors only.
- Malformed or non-ASCII domain labels, wildcards, metacharacters, or empty
  domain sets. IDNA names must already be represented as ASCII labels.
- Unsupported failure behavior, raw configuration overrides, unresolved
  references, or any error produced by the typed compiler.
- Excessive source expansion: the conservative lowering budget is 512 match
  terms, and output is bounded to 1 MiB. The pinned native default allows 1024
  match sets; a qualified build must retain at least that limit.

Strict policies retain `requires_guard: true` in the artifact. They still need
independently qualified persistent firewall and Linux guards; generating a
block fallback is not evidence for daemon-down protection. A strict mixed
policy whose unknown action differs from its default is rejected by this
native format instead of approximating its behavior.

## Artifact and assembly contract

The artifact contains the compiled manifest, exact routing bytes and their
SHA-256, a source map with one-based line numbers, required globals, and required
outbound bindings. Outbound names are `eg_` followed by the full SHA-256 of the
logical outbound-group ID. They remain stable when provider inventory changes;
user-facing names and arbitrary IDs never enter native syntax.

`content_hash` hashes the JSON artifact with `content_hash` set to the empty
string. It binds routing bytes, manifest, mapping, required globals, and the
strict guard requirement. `routing_sha256` independently hashes the exact
UTF-8 routing string, including its final newline.

The gateway must assemble this routing stanza with its locally approved
global/DNS/node/group configuration. It must define every required outbound
under the supplied stable name, verify its intended candidate membership and
selection, prevent Direct candidates or fallback substitutes, and preserve
management reachability. The pinned `control/dial.go` returns group-selection
errors; it does not substitute the built-in Direct outbound. Candidate-group
definition is therefore part of the security boundary, not just name lookup.

The complete assembled bytes require native `dae validate`, controlled policy
application, and observed-generation readback. Existing sessions and
security-tightening cleanup remain the deployment state machine's
responsibility. This package does not enable stock `policy.apply_generation`.
Do not send a routing stanza as `payload.native_config`, which expects a
complete configuration.

## Reproducible native validation

Build a separate pristine upstream checkout at the exact commit:

```sh
git clone https://github.com/daeuniverse/dae.git dae-policy-validate
git -C dae-policy-validate checkout --detach e3fee8fbc68a65167af13b685ab0b958757e20ee
cd dae-policy-validate
go build -tags dae_stub_ebpf -o dae-validator .
sha256sum dae-validator
```

From this repository, supply that absolute executable path and its digest:

```sh
DAE_POLICY_VALIDATOR=/absolute/path/dae-validator \
DAE_POLICY_VALIDATOR_SHA256=<recorded-digest> \
go test ./internal/policy -run '^TestDAEPinnedNativeValidation$' -count=1 -v
```

The test is explicitly skipped when the binary is absent. Ordinary unit tests
do not claim native validation. The native fixture supplies minimal global
settings and named `fixed(0)` group declarations solely for the real parser's
outbound-reference resolution; it does not construct or probe usable dialers.

Recorded validation on 8 October 2026:

- All 605 source blobs matched the upstream Git tree for the pinned commit.
- Build host: `agnet-test`, Go `1.26.0`; build tag `dae_stub_ebpf` disables BPF
  attachment while retaining the actual CLI parser and routing lowering.
- Binary SHA-256:
  `af8cc430dc8e3462c5ad7b1a34e327568052b03541f6efec7bebfa6e979a71a0`.
- Build job: `rt-20261008-060053-4ebx8vwn`, exit 0.
- Native test job: `rt-20261008-060325-bcgb79a4`, exit 0. IPv4/all-matchers,
  IPv6, and domain-set conjunction configurations passed. The same executable
  rejected QUIC `l4proto` operands and undefined fallback groups in each case.

Selected source SHA-256 receipts:

| File | SHA-256 |
| --- | --- |
| `cmd/validate.go` | `5bd9eeda6f32ae3146e0c0bb9996c9661e97f6219748b61987874a560f6b217d` |
| `control/routing_matcher_builder.go` | `72b6d332e0d316361da7c328c341b466c3c4f22e7fc10c00a54c03c28bbf10f9` |
| `component/routing/matcher_builder.go` | `4aff54d8ac36cf632d99f4de2ab6b139a31f7c59192198cca67c21fb90fc2681` |
| `component/routing/optimizer.go` | `ed06898543d915a64685bfab798a022d8a2cde641ddd4196baa02423afeb6c34` |
| `pkg/config_parser/config_parser.go` | `b086ea461dd594224111a969cc5049d522faeb0220bfa7d971c94c8ed1e060bd` |
| `config/config.go` | `07ec201560cb37556e7789eb3de4e282c88d3fd92b863d1f41fc361d0f7f1a67` |

This evidence establishes native parsing and run-path operand/reference
validation. No privileged eBPF packet path, live DNS flow, real outbound,
OPNsense enrollment, or policy-generation publication was exercised.
