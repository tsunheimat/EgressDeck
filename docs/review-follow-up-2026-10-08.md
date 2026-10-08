# Review follow-up: native proxy workflows

Review subject: `main` at
`5b443b5c9aab66c6312f084a29d7dc4b452229fd`. The following IDs preserve the
five findings supplied by the owner. The original
[verification receipt](verification/2026-10-08-results.json) remains historical;
its pass totals do not establish acceptance of this follow-up working tree.

The frozen follow-up source passed **1,267 Go tests in 20 packages with race
detection** (`rt-20261008-110158-tqj22y58`), **80 frontend tests in 14 files**
(`rt-20261008-110158-svoua6ly`), and Go vet
(`rt-20261008-110158-68lucigz`). The final exported dae patch contains 26
source files and has SHA-256
`f3266aa1e69de7f1798343c4d3623ed035f5ee30e85c5cb1e4a97fd50c23975d`.
These aggregate tests cover the source and component boundaries described
below; they do not establish a hosted release or live packet path.

## Findings and acceptance boundaries

| ID | Reviewed trigger | Implemented follow-up | Regression boundary and remaining acceptance |
| --- | --- | --- | --- |
| **REV-1 — P1** | Clicking a node sent only TCP or UDP to a native backend requiring both. | Group responses expose `selection_scope`. Shared groups have one TCP + UDP control, send both scopes, and read back both states. Optional `expected_revisions` checks each transport independently before any mutation, including unequal legacy revisions. | API shared-scope/CAS regressions and the real browser → controller → mTLS agent → native daemon scenario pass, with both transport readbacks converged. Live packet-path qualification remains open. |
| **REV-2 — P1** | Saving `{A, B}` as `{A}` changed only controller membership, so later selection failed; unchanged provider content could not create a repair publication. | `POST /api/v1/outbound-groups/{id}/apply` publishes an independent group revision through `group.publish_hot`, retaining the active provider connection revision. Desired/applied/observed group fields distinguish saved intent from readback. Selection rejects unapplied configuration before mutating, and definite rejection is terminal rather than `outcome_unknown`. | Controller HTTP/mTLS regressions and the actual native daemon scenario apply candidate removal/restoration while the provider revision remains unchanged, then select successfully. Live traffic continuity remains unqualified. |
| **REV-3 — P1** | A crash after persisting native intent but before sending it could leave management permanently unresolved. | Native mutations persist an operation ID and exact payload; the daemon durably records committed/rejected status with inventory. Authoritative `not_started` permits exact-ID replay. Controller correlation binds operation ID/hash/target/fence; status/resolution can durably reject a never-accepted request and fence delayed delivery. Rejected selection intent restores previous persisted state. | Native/transport regressions cover rejection, delayed delivery, mismatched receipts and retained fences. The actual three-process scenario passes pre-send SIGKILL, lost post-commit acknowledgement and all-process restart with exact generation progression. Live traffic and legacy pre-operation journal migration remain separate limits. |
| **REV-4 — release blocker** | Device-group rules could be stored/compiled but native policy apply and the complete enrollment executor were unavailable. | Documentation now identifies missing implementation explicitly. Enrollment stays disabled. | **Open.** Implement complete policy assembly/application/recovery, independent guard, firewall/session coordination and client-path probes; then demonstrate one canary and one unaffected control device. |
| **REV-5 — P2** | Network qualification checked out moving `main` while attributing evidence to the dispatch SHA. | Checkout uses the immutable event SHA, asserts checked-out `HEAD` equals `GITHUB_SHA`, and passes that verified output to the harness and artifact name. | Workflow provenance regression/structural checks cover drift rejection. No live network qualification or hosted result is implied by this source change. |

## Actual native management-path acceptance

The final [continuous scenario receipt](../tests/integration/artifacts/review-native-cross-layer.json)
passed on `u25-code1` from **11:04:23 to 11:05:08 UTC, 8 October 2026**.
Independent readback matched all **260 repository hashes and 500 dae source
hashes**. The runner builds the real controller and gateway-agent binaries;
its source harness runs the patched dae Unix HTTP/control-plane code.

The scenario publishes a provider, edits and applies group membership without
changing that provider revision, and clicks a node in the actual browser.
Both TCP and UDP requests/readbacks converge. Injected agent termination before
send resolves the original daemon operation ID with one commit (`5 → 6`);
termination after commit resolves the lost acknowledgement with no second
mutation dispatch (`6 → 7`). Restarting controller, agent and daemon retains
generation 7 and the provider/group/selection state. Persistence remains
encrypted. The [rendered browser screenshot](../tests/integration/artifacts/native-shared-selection.png)
was inspected.

This passes the real management protocol and process-recovery boundary. It
does not attach eBPF, exercise OPNsense-enrolled clients, or establish live
traffic continuity or production enrollment acceptance.

## Focused regression evidence

- **REV-1:** `TestSharedSelectionScopedRevisionsConvergeLegacyIndependentSelections`,
  `TestSharedSelectionRejectsIncompleteOrAmbiguousScopedRevisions`,
  `TestOutboundGroupReadbackExposesSelectionScope`,
  `TestSharedSelectionSecondScopeCASConflictChangesNeitherScope`, plus definite
  preflight, rollback and replay cases. The focused API command passed 18
  checks on `agnet-test` (`rt-20261008-103916-k2tjj93c`).
  Frontend tests passed 79/79 (`rt-20261008-104216-u5qdkzsf`), and
  typecheck/Vite build passed (`rt-20261008-104231-54muxdl8`). The 14/14 local
  Chrome run includes shared browser selection followed by group edit/apply
  with unchanged provider inventory; its external gateway remains a fixture.
  The subsequent administrator-only group-apply UI correction passed 7/7
  focused ProxiesView tests and typecheck/build
  (`rt-20261008-105851-vdzps96w`); the earlier full-suite totals do not include
  that added authorization regression.
- **REV-2:** `TestGatewayGroupPublicationWithoutProviderRefresh`,
  `TestGatewayGroupPublicationRejectsSelectedRemovalAndStaleCAS`,
  `TestOutboundGroupApplyIdempotencyAndUnknownFence` and
  `TestGroupEditPreservesSelectionRevisionAndReadbackOwnership`. Controller,
  outbound and API package tests passed 510 checks
  (`rt-20261008-103806-5mag0r6e`); the later outbound/API run passed 264
  (`rt-20261008-103922-t9xd6st5`). These use a remote contract fixture rather
  than claiming live dae traffic.
- **REV-3:** `TestNativeCrashAfterPendingPersistBeforeSendRecovers`,
  `TestNativeAuthoritativeAbsenceSafelyRetriesSameOperation`,
  `TestNativeRejectedOperationAllowsFreshMutation`,
  `TestNativeResolvedAbsenceFencesDelayedControllerMutation`,
  `TestNativeControllerFenceSurvivesReceiptPruningAndRestart` and
  `TestNativeOperationReceiptMismatchRetainsPendingIntent`. Gateway package
  tests passed 169 checks on `agnet-test`
  (`rt-20261008-104043-e07e1u6i`). The public agent mutation contract uses
  explicit correlated receipts; the private daemon operation protocol is
  documented separately under [`engine/dae`](../engine/dae/README.md).
  `TestRuntimeReconciliationTerminatesRejectedSelectionAcrossControllerRestart`
  restarts encrypted controller state/journals and uses the real mTLS client
  against a gateway fixture to cover never-sent, rejected, committed,
  unavailable and wrong-identity outcomes. The focused controller/API/deployment
  race run first passed 82 checks
  (`rt-20261008-104504-l42ilayg`); a later recovery expansion passed 115
  targeted checks (`rt-20261008-105603-g8d1maxp`), including all-gateway exact
  rejection, mixed committed/rejected uncertainty, TCP/UDP compensation,
  encrypted restart, final-journal failure and no repeated terminal resolve.
  The final mutation/recovery lock boundary passed 7 targeted race checks
  (`rt-20261008-110143-s3hp3zo7`). Relevant controller/API/deployment vet passed
  (`rt-20261008-105703-8uvquiah`).
  Legacy pre-operation journal records remain a migration boundary: quiesce
  native mutations and drain/quarantine them with the old component before an
  upgrade; a new resolver cannot manufacture authoritative proof for a request
  that has no persisted operation identity. Such pending native legacy records
  prevent adapter startup with `upgrade_required`.
- **Contracts:** Redocly CLI `1.34.2` validated both
  [`api/openapi.yaml`](../api/openapi.yaml) and
  [`api/agent-contract.yaml`](../api/agent-contract.yaml), exit 0. Existing
  warnings remain: missing license metadata in both specs and the OIDC login
  route's redirect-only response. These checks validate the specifications;
  they do not execute the network workflow.
- **REV-5:** The workflow change passed YAML parsing, source-binding
  assertions, and shell checks that accept an identical event/checkout SHA
  and reject a mismatch. The network gate rejected a run without the required
  real qualification receipt, as intended. No hosted/network success is
  claimed.

## Remaining product scope

Native outbound groups still use predeclared operator mappings, contain nodes
from one provider and use manual selection shared by TCP/UDP. Group apply
requires the currently selected node to remain eligible. Automatic selection,
multi-provider groups, native latency probes, native connection/counter
telemetry and scheduled automatic provider publication remain unsupported.
The compiler's routing fragment does not assemble a complete daemon
configuration. None of these restrictions is removed by a successful group or
selection management response.

Use the updated [stuck-operation runbook](runbooks/stuck-operation.md) for
recovery semantics. Production acceptance still requires source-bound native
artifacts and the protected OPNsense/dae/client packet-path workflow, including
failure/restart and unaffected-traffic evidence.
