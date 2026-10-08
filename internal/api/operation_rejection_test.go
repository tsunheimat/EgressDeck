package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func rejectionSealOperation(t *testing.T, services *Services, op deployment.Operation) deployment.Operation {
	t.Helper()
	op.RequestHash = privateRequestHash(json.RawMessage(op.Views.Desired.Data))
	if err := services.Journal.Save(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	return op
}

func rejectionResult(t *testing.T, op deployment.Operation, gatewayIDs ...string) deployment.VerifyResult {
	t.Helper()
	proof := OperationRejectionReadback{Receipts: map[string]gateway.MutationReceipt{}}
	for _, id := range gatewayIDs {
		proof.Receipts[id] = gateway.MutationReceipt{Identity: OperationMutationIdentity(op), State: gateway.MutationRejected, ErrorCode: "never_accepted"}
	}
	return deployment.VerifyResult{NotApplied: true, Observed: &deployment.StateRecord{Data: completionJSON(t, proof)}}
}

func rejectionSelectionFixture(t *testing.T, services *Services) (deployment.Operation, deployment.VerifyResult, map[string]*outbounds.Selection) {
	t.Helper()
	group, err := services.Outbounds.Create(outbounds.Group{ID: "outbound-rejection", Name: "Prior selection", GatewayID: "gateway-a", NodeIDs: []string{"node-a", "node-b", "node-c"}})
	if err != nil {
		t.Fatal(err)
	}
	prior := map[string]*outbounds.Selection{}
	revisions := map[string]int64{}
	for index, transport := range []string{"tcp", "udp"} {
		scope := outbounds.Scope{GatewayID: group.GatewayID, Transport: transport}
		for revision := int64(0); revision <= int64(index); revision++ {
			if _, err := services.Outbounds.SetDesired(group.ID, scope, "node-a", revision); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := services.Outbounds.MarkApplied(group.ID, scope, "node-a", 5); err != nil {
			t.Fatal(err)
		}
		// Keep distinct observed state to catch compensation which overwrites
		// remote evidence with the historical desired selection.
		selection, err := services.Outbounds.Observe(group.ID, scope, "node-c", 7)
		if err != nil {
			t.Fatal(err)
		}
		prior[transport], revisions[transport] = &selection, selection.Revision
		if _, err := services.Outbounds.SetDesired(group.ID, scope, "node-b", selection.Revision); err != nil {
			t.Fatal(err)
		}
	}
	desired := selectionRequest{GatewayID: group.GatewayID, NodeID: "node-b", TransportScopes: []string{"tcp", "udp"}, ExpectedRevisions: revisions}
	op := completionOperation(t, services, "selection", deployment.Target{Kind: "outbound_group", ID: group.ID}, desired)
	op.Views.Previous = &deployment.StateRecord{Data: completionJSON(t, prior)}
	op = rejectionSealOperation(t, services, op)
	return op, rejectionResult(t, op, group.GatewayID), prior
}

func rejectionOutboundState(t *testing.T, services *Services) []byte {
	t.Helper()
	state, err := services.Outbounds.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func assertRejectedSelectionRestored(t *testing.T, services *Services, op deployment.Operation, prior map[string]*outbounds.Selection) {
	t.Helper()
	for transport, previous := range prior {
		current, err := services.Outbounds.GetSelection(op.Target.ID, previous.Scope)
		if err != nil {
			t.Fatal(err)
		}
		expected := *previous
		expected.Revision += 2 // Accepted intent and its compensation are separate CAS writes.
		expected.UpdatedAt = current.UpdatedAt
		if !reflect.DeepEqual(current, expected) {
			t.Fatalf("%s compensation changed remote evidence or failed to restore intent: got %+v want %+v", transport, current, expected)
		}
	}
}

func TestOperationRejectionRestoresBothSelectionsWithoutChangingRuntimeEvidence(t *testing.T) {
	services := NewServices()
	op, result, prior := rejectionSelectionFixture(t, services)
	if err := services.CompleteOperationReadback(context.Background(), op, result); err != nil {
		t.Fatal(err)
	}
	assertRejectedSelectionRestored(t, services, op, prior)
	before := rejectionOutboundState(t, services)
	if err := services.CompleteOperationReadback(context.Background(), op, result); err != nil {
		t.Fatalf("duplicate rejection completion failed: %v", err)
	}
	if !bytes.Equal(before, rejectionOutboundState(t, services)) {
		t.Fatal("duplicate completion changed compensated selections or their revisions")
	}
}

func TestOperationRejectionRequiresExactAuthoritativeReceiptWithoutMutation(t *testing.T) {
	for _, name := range []string{"request_hash", "target_id", "target_kind", "fence", "operation_id", "missing_gateway", "other_gateway", "extra_gateway", "committed", "pending", "unknown", "negative_generation", "changed_intent", "stale_fence", "contradictory_result", "missing_previous"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			services := NewServices()
			op, result, _ := rejectionSelectionFixture(t, services)
			documents := store.NewMemoryStore()
			if err := services.Load(ctx, documents, lifecycleTestVault(t, 12)); err != nil {
				t.Fatal(err)
			}
			if err := services.Persist(ctx); err != nil {
				t.Fatal(err)
			}
			var proof OperationRejectionReadback
			if err := json.Unmarshal(result.Observed.Data, &proof); err != nil {
				t.Fatal(err)
			}
			receipt := proof.Receipts["gateway-a"]
			switch name {
			case "request_hash":
				receipt.Identity.RequestHash = strings.Repeat("f", 64)
			case "target_id":
				receipt.Identity.TargetID = "other-group"
			case "target_kind":
				receipt.Identity.TargetKind = "provider"
			case "fence":
				receipt.Identity.FenceToken++
			case "operation_id":
				receipt.Identity.ID = "other-operation"
			case "committed":
				receipt.State = gateway.MutationCommitted
			case "pending":
				receipt.State = gateway.MutationPending
			case "unknown":
				receipt.State = gateway.MutationUnknown
			case "negative_generation":
				receipt.Generation = -1
			case "changed_intent":
				completionReplaceJSONField(t, op.Views.Desired, "node_id", "node-c")
			case "stale_fence":
				if _, err := services.Journal.NextFence(ctx, op.Target); err != nil {
					t.Fatal(err)
				}
			case "contradictory_result":
				result.VerifiedOK = true
			case "missing_previous":
				op.Views.Previous = nil
			}
			proof.Receipts["gateway-a"] = receipt
			switch name {
			case "missing_gateway":
				delete(proof.Receipts, "gateway-a")
			case "other_gateway":
				delete(proof.Receipts, "gateway-a")
				proof.Receipts["gateway-other"] = receipt
			case "extra_gateway":
				proof.Receipts["gateway-other"] = receipt
			}
			result.Observed.Data = completionJSON(t, proof)
			before := rejectionOutboundState(t, services)
			durableBefore, err := documents.LoadDocument(ctx, lifecycleDocumentKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := services.CompleteOperationReadback(ctx, op, result); err == nil {
				t.Fatal("uncorrelated or nonauthoritative rejection was accepted")
			}
			if !bytes.Equal(before, rejectionOutboundState(t, services)) {
				t.Fatal("invalid rejection changed selection state")
			}
			durableAfter, err := documents.LoadDocument(ctx, lifecycleDocumentKey)
			if err != nil || !bytes.Equal(durableBefore, durableAfter) {
				t.Fatalf("invalid rejection changed encrypted durable state: %v", err)
			}
		})
	}
}

func TestOperationRejectionValidatesEveryPriorScopeBeforeCompensation(t *testing.T) {
	for _, name := range []string{"prior_revision", "current_revision", "prior_node", "missing_scope"} {
		t.Run(name, func(t *testing.T) {
			services := NewServices()
			op, result, prior := rejectionSelectionFixture(t, services)
			switch name {
			case "prior_revision":
				prior["udp"].Revision++
			case "current_revision":
				if _, err := services.Outbounds.SetDesired(op.Target.ID, prior["udp"].Scope, "node-c", prior["udp"].Revision+1); err != nil {
					t.Fatal(err)
				}
			case "prior_node":
				prior["udp"].DesiredNodeID = "node-not-in-group"
			case "missing_scope":
				delete(prior, "udp")
			}
			op.Views.Previous.Data = completionJSON(t, prior)
			before := rejectionOutboundState(t, services)
			if err := services.CompleteOperationReadback(context.Background(), op, result); err == nil {
				t.Fatal("inconsistent UDP prior state was accepted")
			}
			if !bytes.Equal(before, rejectionOutboundState(t, services)) {
				t.Fatal("rejection on the second scope partially compensated the first scope")
			}
		})
	}
}

type rejectionCompletionReader struct {
	services *Services
	result   deployment.VerifyResult
	calls    int
}

func (r *rejectionCompletionReader) Readback(ctx context.Context, op deployment.Operation, _ deployment.Fence) (deployment.VerifyResult, error) {
	r.calls++
	return r.result, r.services.CompleteOperationReadback(ctx, op, r.result)
}

type rejectionFailTerminalJournal struct {
	deployment.Journal
	failure error
}

func (j *rejectionFailTerminalJournal) Save(ctx context.Context, op deployment.Operation) error {
	if op.Status == deployment.StatusFailed {
		return j.failure
	}
	return j.Journal.Save(ctx, op)
}

func TestOperationRejectionRecoversAfterLifecycleCommitAndFailedJournalCommit(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	lifecyclePath, journalPath := filepath.Join(directory, "controller.json"), filepath.Join(directory, "operations.json")
	vault := lifecycleTestVault(t, 13)
	documents, err := store.NewFileStore(lifecyclePath)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := deployment.OpenEncryptedFileJournal(journalPath, vault)
	if err != nil {
		t.Fatal(err)
	}
	services := NewServices()
	services.Journal = journal
	if err := services.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	op, result, prior := rejectionSelectionFixture(t, services)
	if err := services.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("terminal operation journal unavailable")
	services.Journal = &rejectionFailTerminalJournal{Journal: journal, failure: failure}
	reader := &rejectionCompletionReader{services: services, result: result}
	if _, err := deployment.NewRunner(services.Journal).InspectOutcome(ctx, op.ID, reader); !errors.Is(err, failure) {
		t.Fatalf("expected final journal failure after lifecycle compensation, got %v", err)
	}
	assertRejectedSelectionRestored(t, services, op, prior)
	saved, err := journal.Get(ctx, op.ID)
	if err != nil || saved.Status != deployment.StatusOutcomeUnknown {
		t.Fatalf("failed journal write changed durable operation status: %+v %v", saved, err)
	}
	compensatedState := rejectionOutboundState(t, services)
	for _, path := range []string{lifecyclePath, journalPath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, plaintext := range []string{"node-a", "node-b", "outbound-rejection"} {
			if bytes.Contains(raw, []byte(plaintext)) {
				t.Fatalf("private recovery state %q leaked into %s", plaintext, path)
			}
		}
	}
	// Restart both controller persistence boundaries after the independent
	// lifecycle commit. Recovery must recognize compensation already saved.
	reopenedDocuments, err := store.NewFileStore(lifecyclePath)
	if err != nil {
		t.Fatal(err)
	}
	reopenedJournal, err := deployment.OpenEncryptedFileJournal(journalPath, vault)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewServices()
	restarted.Journal = reopenedJournal
	if err := restarted.Load(ctx, reopenedDocuments, vault); err != nil {
		t.Fatal(err)
	}
	assertRejectedSelectionRestored(t, restarted, op, prior)
	if err := restarted.rejectUnknownTarget(ctx, op.Target); err == nil {
		t.Fatal("incomplete operation was not fenced before terminal recovery")
	}
	restartReader := &rejectionCompletionReader{services: restarted, result: result}
	runner := deployment.NewRunner(reopenedJournal)
	completed, err := runner.InspectOutcome(ctx, op.ID, restartReader)
	if err != nil || completed.Status != deployment.StatusFailed || completed.CompletedAt == nil || completed.Views.Applied != nil || completed.Views.Verified != nil {
		t.Fatalf("authoritative rejection did not terminate safely: %+v %v", completed, err)
	}
	if !bytes.Equal(compensatedState, rejectionOutboundState(t, restarted)) {
		t.Fatal("restart completion repeated compensation or changed runtime evidence")
	}
	if err := restarted.rejectUnknownTarget(ctx, op.Target); err != nil {
		t.Fatalf("terminal rejection continued to block management: %v", err)
	}
	if _, err := runner.InspectOutcome(ctx, op.ID, restartReader); err != nil || restartReader.calls != 1 {
		t.Fatalf("terminal recovery replay reentered readback: calls=%d err=%v", restartReader.calls, err)
	}
	finalJournal, err := deployment.OpenEncryptedFileJournal(journalPath, vault)
	if err != nil {
		t.Fatal(err)
	}
	final, err := finalJournal.Get(ctx, op.ID)
	if err != nil || final.Status != deployment.StatusFailed {
		t.Fatalf("terminal rejection was not durable: %+v %v", final, err)
	}
}

func TestOperationRejectionProviderRequiresAllGatewaysAndPreservesActiveRevision(t *testing.T) {
	for _, name := range []string{"all_rejected", "missing_gateway", "committed_gateway"} {
		t.Run(name, func(t *testing.T) {
			services := NewServices()
			active, _, err := services.Providers.Stage("provider-1", []byte("trojan://old-private@example.org:443#old"), providers.FormatLinks)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := services.Providers.Publish("provider-1", active.Number, 0); err != nil {
				t.Fatal(err)
			}
			staged, _, err := services.Providers.Stage("provider-1", []byte("trojan://new-private@example.org:443#new"), providers.FormatLinks)
			if err != nil {
				t.Fatal(err)
			}
			desired := map[string]any{"provider_id": "provider-1", "revision": staged.Number, "expected_active_revision": active.Number, "content_hash": staged.Hash, "gateway_ids": []string{"gateway-a", "gateway-b"}}
			op := completionOperation(t, services, "publish", deployment.Target{Kind: "provider", ID: "provider-1"}, desired)
			op = rejectionSealOperation(t, services, op)
			result := rejectionResult(t, op, "gateway-a", "gateway-b")
			var proof OperationRejectionReadback
			if err := json.Unmarshal(result.Observed.Data, &proof); err != nil {
				t.Fatal(err)
			}
			if name == "missing_gateway" {
				delete(proof.Receipts, "gateway-b")
			} else if name == "committed_gateway" {
				receipt := proof.Receipts["gateway-b"]
				receipt.State = gateway.MutationCommitted
				proof.Receipts["gateway-b"] = receipt
			}
			result.Observed.Data = completionJSON(t, proof)
			before, err := services.Providers.ExportState()
			if err != nil {
				t.Fatal(err)
			}
			err = services.CompleteOperationReadback(context.Background(), op, result)
			if (err == nil) != (name == "all_rejected") {
				t.Fatalf("wrong all-target rejection result: %v", err)
			}
			after, err := services.Providers.ExportState()
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("provider noncommit changed active or staged revisions: %v", err)
			}
		})
	}
}

func TestOperationRejectionGroupRetainsDesiredEditAndPreviousRuntimeConfiguration(t *testing.T) {
	services := NewServices()
	group, err := services.Outbounds.Create(outbounds.Group{ID: "group-rejection", Name: "Edited group", GatewayID: "gateway-a", NodeIDs: []string{"node-a", "node-b"}})
	if err != nil {
		t.Fatal(err)
	}
	group, err = services.Outbounds.ObserveConfiguration(group.ID, group.Revision, group.NodeIDs, 4)
	if err != nil {
		t.Fatal(err)
	}
	group.NodeIDs = []string{"node-a"}
	group, err = services.Outbounds.Update(group, group.Revision)
	if err != nil {
		t.Fatal(err)
	}
	op := completionOperation(t, services, "group_apply", deployment.Target{Kind: "outbound_group", ID: group.ID}, groupApplyIntent(group))
	op = rejectionSealOperation(t, services, op)
	before := rejectionOutboundState(t, services)
	if err := services.CompleteOperationReadback(context.Background(), op, rejectionResult(t, op, group.GatewayID)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, rejectionOutboundState(t, services)) {
		t.Fatal("rejected group apply discarded desired membership or advanced runtime configuration")
	}
	current, err := services.Outbounds.Get(group.ID)
	if err != nil || current.Revision != 2 || current.AppliedRevision != 1 || current.ObservedRevision != 1 || !reflect.DeepEqual(current.NodeIDs, []string{"node-a"}) || !reflect.DeepEqual(current.AppliedNodeIDs, []string{"node-a", "node-b"}) || !reflect.DeepEqual(current.ObservedNodeIDs, []string{"node-a", "node-b"}) {
		t.Fatalf("desired and runtime group state no longer distinguish rejected publication: %+v %v", current, err)
	}
}

func TestOperationCompletionProviderGroupsIsAtomicAcrossReadback(t *testing.T) {
	for _, name := range []string{"valid", "second_generation", "second_candidates"} {
		t.Run(name, func(t *testing.T) {
			services := NewServices()
			revision, _, err := services.Providers.Stage("provider-groups", []byte("trojan://first@example.org:443#first\ntrojan://second@example.org:443#second"), providers.FormatLinks)
			if err != nil || len(revision.Nodes) != 2 {
				t.Fatalf("stage provider fixture: nodes=%d err=%v", len(revision.Nodes), err)
			}
			groups := make([]outbounds.Group, 0, 2)
			for index, gatewayID := range []string{"gateway-a", "gateway-b"} {
				group, createErr := services.Outbounds.Create(outbounds.Group{ID: "provider-group-" + string(rune('1'+index)), Name: "Provider group", GatewayID: gatewayID, NodeIDs: []string{revision.Nodes[0].ID}, SourceFilters: &outbounds.SourceFilters{ProviderIDs: []string{"provider-groups"}}})
				if createErr != nil {
					t.Fatal(createErr)
				}
				group, err = services.Outbounds.ObserveConfiguration(group.ID, group.Revision, group.NodeIDs, 4)
				if err != nil {
					t.Fatal(err)
				}
				groups = append(groups, group)
			}
			desired := map[string]any{"provider_id": "provider-groups", "revision": revision.Number, "expected_active_revision": int64(0), "content_hash": revision.Hash, "gateway_ids": []string{"gateway-a", "gateway-b"}}
			op := completionOperation(t, services, "publish", deployment.Target{Kind: "provider", ID: "provider-groups"}, desired)
			op = rejectionSealOperation(t, services, op)
			observedGroups := []GroupApplyReadback{
				{GroupID: groups[0].ID, Revision: groups[0].Revision + 1, NodeIDs: []string{revision.Nodes[0].ID, revision.Nodes[1].ID}, Generation: 8},
				{GroupID: groups[1].ID, Revision: groups[1].Revision + 1, NodeIDs: []string{revision.Nodes[0].ID, revision.Nodes[1].ID}, Generation: 8},
			}
			switch name {
			case "second_generation":
				observedGroups[1].Generation = 3
			case "second_candidates":
				observedGroups[1].NodeIDs = []string{revision.Nodes[0].ID}
			}
			observed := map[string]any{"provider_id": "provider-groups", "revision": revision.Number, "content_hash": revision.Hash, "gateway_ids": []string{"gateway-b", "gateway-a"}, "groups": observedGroups}
			result := deployment.VerifyResult{VerifiedOK: true, Observed: &deployment.StateRecord{Data: completionJSON(t, observed)}}
			beforeProvider, err := services.Providers.ExportState()
			if err != nil {
				t.Fatal(err)
			}
			beforeGroups := rejectionOutboundState(t, services)
			err = services.CompleteOperationReadback(context.Background(), op, result)
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if services.Providers.Status("provider-groups").Active != revision.Number {
					t.Fatal("valid provider readback did not publish the exact staged revision")
				}
				for _, group := range groups {
					got, getErr := services.Outbounds.Get(group.ID)
					if getErr != nil || got.Revision != group.Revision+1 || got.AppliedRevision != group.Revision+1 || got.ObservedRevision != group.Revision+1 || got.AppliedGeneration != 8 || got.ObservedGeneration != 8 || !sameStringSet(got.NodeIDs, observedGroups[0].NodeIDs) || !sameStringSet(got.AppliedNodeIDs, got.NodeIDs) || !sameStringSet(got.ObservedNodeIDs, got.NodeIDs) {
						t.Fatalf("valid readback did not commit group %s: %+v %v", group.ID, got, getErr)
					}
				}
				return
			}
			if err == nil {
				t.Fatal("invalid second group readback was accepted")
			}
			afterProvider, exportErr := services.Providers.ExportState()
			afterGroups := rejectionOutboundState(t, services)
			if exportErr != nil || !bytes.Equal(beforeProvider, afterProvider) || !bytes.Equal(beforeGroups, afterGroups) || services.Providers.Status("provider-groups").Active != 0 {
				t.Fatalf("invalid group readback partially committed provider/groups: provider=%v groups=%v export=%v", !bytes.Equal(beforeProvider, afterProvider), !bytes.Equal(beforeGroups, afterGroups), exportErr)
			}
		})
	}
}
