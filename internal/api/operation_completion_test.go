package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func completionJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func completionOperation(t *testing.T, services *Services, action string, target deployment.Target, desired any) deployment.Operation {
	t.Helper()
	fence, err := services.Journal.NextFence(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := services.Journal.Create(context.Background(), deployment.Operation{
		Target: target, Action: action, FenceToken: fence.Token,
		Status: deployment.StatusOutcomeUnknown,
		Views:  deployment.StateViews{Desired: &deployment.StateRecord{Data: completionJSON(t, desired)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

func completionProviderFixture(t *testing.T) (*Services, deployment.Operation, deployment.VerifyResult) {
	t.Helper()
	services := NewServices()
	revision, _, err := services.Providers.Stage("provider-1", []byte("trojan://completion-private-secret@example.org:443#primary"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	desired := map[string]any{"provider_id": "provider-1", "revision": revision.Number, "expected_active_revision": 0, "content_hash": revision.Hash, "gateway_ids": []string{"gateway-a", "gateway-b"}}
	operation := completionOperation(t, services, "publish", deployment.Target{Kind: "provider", ID: "provider-1"}, desired)
	observed := map[string]any{"provider_id": "provider-1", "revision": revision.Number, "content_hash": revision.Hash, "gateway_ids": []string{"gateway-b", "gateway-a"}}
	return services, operation, deployment.VerifyResult{VerifiedOK: true, Observed: &deployment.StateRecord{Data: completionJSON(t, observed)}}
}

func completionSelectionFixture(t *testing.T) (*Services, deployment.Operation, deployment.VerifyResult) {
	t.Helper()
	services := NewServices()
	group, err := services.Outbounds.Create(outbounds.Group{ID: "outbound-1", Name: "Primary", GatewayID: "gateway-a", NodeIDs: []string{"node-a", "node-b"}})
	if err != nil {
		t.Fatal(err)
	}
	var observed []outbounds.Selection
	for _, transport := range []string{"tcp", "udp"} {
		scope := outbounds.Scope{GatewayID: group.GatewayID, Transport: transport}
		if _, err := services.Outbounds.SetDesired(group.ID, scope, "node-a", 0); err != nil {
			t.Fatal(err)
		}
		observed = append(observed, outbounds.Selection{GroupID: group.ID, Scope: scope, ObservedNodeID: "node-a", Generation: 7})
	}
	desired := selectionRequest{NodeID: "node-a", GatewayID: group.GatewayID, TransportScopes: []string{"tcp", "udp"}}
	operation := completionOperation(t, services, "selection", deployment.Target{Kind: "outbound_group", ID: group.ID}, desired)
	return services, operation, deployment.VerifyResult{VerifiedOK: true, Observed: &deployment.StateRecord{Data: completionJSON(t, observed)}}
}

func completionReplaceJSONField(t *testing.T, record *deployment.StateRecord, field string, value any) {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(record.Data, &document); err != nil {
		t.Fatal(err)
	}
	document[field] = value
	record.Data = completionJSON(t, document)
}

func TestOperationCompletionRequiresConfirmedReadbackAndCurrentNonzeroFence(t *testing.T) {
	for _, name := range []string{"unverified", "missing_observed", "missing_desired", "zero_fence", "stale_fence"} {
		t.Run(name, func(t *testing.T) {
			services, operation, result := completionProviderFixture(t)
			switch name {
			case "unverified":
				result.VerifiedOK = false
			case "missing_observed":
				result.Observed = nil
			case "missing_desired":
				operation.Views.Desired = nil
			case "zero_fence":
				operation.FenceToken = 0
			case "stale_fence":
				if _, err := services.Journal.NextFence(context.Background(), operation.Target); err != nil {
					t.Fatal(err)
				}
			}
			if err := services.CompleteOperationReadback(context.Background(), operation, result); err == nil {
				t.Fatal("unconfirmed or unfenced completion was accepted")
			}
			if services.Providers.Status("provider-1").Active != 0 {
				t.Fatal("rejected completion activated the staged revision")
			}
		})
	}
}

func TestOperationCompletionRejectsProviderReadbackIntentMismatch(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value any
	}{
		{"provider", "provider_id", "provider-other"},
		{"revision", "revision", 2},
		{"content", "content_hash", "wrong-hash"},
		{"missing_gateway", "gateway_ids", []string{"gateway-a"}},
		{"extra_gateway", "gateway_ids", []string{"gateway-a", "gateway-b", "gateway-c"}},
		{"duplicate_gateway", "gateway_ids", []string{"gateway-a", "gateway-a"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			services, operation, result := completionProviderFixture(t)
			completionReplaceJSONField(t, result.Observed, test.field, test.value)
			if err := services.CompleteOperationReadback(context.Background(), operation, result); err == nil {
				t.Fatal("provider readback mismatch was accepted")
			}
			if services.Providers.Status("provider-1").Active != 0 {
				t.Fatal("readback mismatch changed the active revision")
			}
		})
	}
}

func TestOperationCompletionProviderPublishesExactRevisionAndReplaysIdempotently(t *testing.T) {
	services, operation, result := completionProviderFixture(t)
	if err := services.CompleteOperationReadback(context.Background(), operation, result); err != nil {
		t.Fatal(err)
	}
	active, err := services.Providers.Active("provider-1")
	if err != nil || active.Number != 1 || active.PublishedAt == nil || active.Nodes[0].Definition.Password != "completion-private-secret" {
		t.Fatalf("readback did not commit the exact private provider revision: %v", err)
	}
	if err := services.CompleteOperationReadback(context.Background(), operation, result); err != nil {
		t.Fatalf("idempotent replay failed: %v", err)
	}
	replayed, err := services.Providers.Active("provider-1")
	if err != nil || !reflect.DeepEqual(active, replayed) {
		t.Fatalf("replayed provider completion changed the committed revision: %v", err)
	}
}

func TestOperationCompletionProviderRequiresRegistryHashAndTargetKind(t *testing.T) {
	for _, name := range []string{"wrong_registry_hash", "wrong_target_kind"} {
		t.Run(name, func(t *testing.T) {
			services, operation, result := completionProviderFixture(t)
			if name == "wrong_registry_hash" {
				completionReplaceJSONField(t, operation.Views.Desired, "content_hash", "not-the-staged-content")
				completionReplaceJSONField(t, result.Observed, "content_hash", "not-the-staged-content")
			} else {
				operation.Target.Kind = "outbound_group"
				fence, err := services.Journal.NextFence(context.Background(), operation.Target)
				if err != nil {
					t.Fatal(err)
				}
				operation.FenceToken = fence.Token
			}
			if err := services.CompleteOperationReadback(context.Background(), operation, result); err == nil {
				t.Fatal("provider completion accepted unrelated registry content or fencing scope")
			}
			if services.Providers.Status("provider-1").Active != 0 {
				t.Fatal("invalid completion published a provider revision")
			}
		})
	}
}

func TestOperationCompletionSelectionRequiresExactObservedScopesAndCurrentIntent(t *testing.T) {
	for _, name := range []string{"wrong_group", "wrong_gateway", "wrong_node", "wrong_scope", "missing_scope", "duplicate_scope", "negative_generation", "stale_desired", "stale_same_node_revision", "wrong_target_kind"} {
		t.Run(name, func(t *testing.T) {
			services, operation, result := completionSelectionFixture(t)
			var observed []outbounds.Selection
			if err := json.Unmarshal(result.Observed.Data, &observed); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "wrong_group":
				observed[1].GroupID = "other-group"
			case "wrong_gateway":
				observed[1].Scope.GatewayID = "other-gateway"
			case "wrong_node":
				observed[1].ObservedNodeID = "node-b"
			case "wrong_scope":
				observed[1].Scope.Transport = "quic"
			case "missing_scope":
				observed = observed[:1]
			case "duplicate_scope":
				observed[1].Scope = observed[0].Scope
			case "negative_generation":
				observed[1].Generation = -1
			case "stale_desired":
				if _, err := services.Outbounds.SetDesired("outbound-1", observed[1].Scope, "node-b", 1); err != nil {
					t.Fatal(err)
				}
			case "stale_same_node_revision":
				if _, err := services.Outbounds.SetDesired("outbound-1", observed[1].Scope, "node-b", 1); err != nil {
					t.Fatal(err)
				}
				if _, err := services.Outbounds.SetDesired("outbound-1", observed[1].Scope, "node-a", 2); err != nil {
					t.Fatal(err)
				}
			case "wrong_target_kind":
				operation.Target.Kind = "provider"
				fence, err := services.Journal.NextFence(context.Background(), operation.Target)
				if err != nil {
					t.Fatal(err)
				}
				operation.FenceToken = fence.Token
			}
			result.Observed.Data = completionJSON(t, observed)
			before, err := services.Outbounds.ExportState()
			if err != nil {
				t.Fatal(err)
			}
			if err := services.CompleteOperationReadback(context.Background(), operation, result); err == nil {
				t.Fatal("selection readback mismatch or stale desired state was accepted")
			}
			after, err := services.Outbounds.ExportState()
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected completion changed selection state: %v", err)
			}
		})
	}
}

func TestOperationCompletionCanceledContextDoesNotMutateOrFreezeWrites(t *testing.T) {
	services, operation, result := completionProviderFixture(t)
	documents := store.NewMemoryStore()
	if err := services.Load(context.Background(), documents, lifecycleTestVault(t, 8)); err != nil {
		t.Fatal(err)
	}
	if err := services.Persist(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := documents.LoadDocument(context.Background(), lifecycleDocumentKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := services.CompleteOperationReadback(ctx, operation, result); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled completion did not return cancellation: %v", err)
	}
	if services.mutationBlocked || services.Providers.Status("provider-1").Active != 0 {
		t.Fatal("canceled completion changed provider state or paused healthy storage")
	}
	after, err := documents.LoadDocument(context.Background(), lifecycleDocumentKey)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("canceled completion changed durable storage: %v", err)
	}
}

func TestOperationCompletionRuntimeTargetsCannotEnterGenericOperationRunner(t *testing.T) {
	for _, kind := range []string{"provider", "outbound_group"} {
		t.Run(kind, func(t *testing.T) {
			server := NewServer(store.NewMemoryStore(), nil)
			server.Services.PolicyApplyEnabled = true
			factoryCalled := false
			server.Services.ExecutorFactory = func(deployment.Target) deployment.Executor {
				factoryCalled = true
				return nil
			}
			request := completionJSON(t, deployment.Request{Target: deployment.Target{Kind: kind, ID: "target-1"}, Action: "publish", IdempotencyKey: "generic-must-not-submit"})
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/operations", bytes.NewReader(request)))
			if response.Code != http.StatusNotImplemented || factoryCalled {
				t.Fatalf("runtime target entered generic runner: status=%d factory=%v", response.Code, factoryCalled)
			}
			operations, err := server.Services.Journal.List(context.Background())
			if err != nil || len(operations) != 0 {
				t.Fatalf("rejected runtime target created generic operations: count=%d err=%v", len(operations), err)
			}
		})
	}
}

func TestOperationCompletionSelectionRejectsStaleGenerationWithoutPartialMutation(t *testing.T) {
	services, operation, result := completionSelectionFixture(t)
	udp := outbounds.Scope{GatewayID: "gateway-a", Transport: "udp"}
	if _, err := services.Outbounds.MarkApplied("outbound-1", udp, "node-a", 9); err != nil {
		t.Fatal(err)
	}
	if _, err := services.Outbounds.Observe("outbound-1", udp, "node-a", 9); err != nil {
		t.Fatal(err)
	}
	before, err := services.Outbounds.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if err := services.CompleteOperationReadback(context.Background(), operation, result); err == nil {
		t.Fatal("stale observed generation was accepted")
	}
	after, err := services.Outbounds.ExportState()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("later stale scope caused partial mutation of earlier scope: %v", err)
	}
}

func TestOperationCompletionPersistsProviderAndSelectionAcrossEncryptedRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.json")
	documents, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	vault := lifecycleTestVault(t, 6)
	services, providerOperation, providerResult := completionProviderFixture(t)
	selectionServices, selectionOperation, selectionResult := completionSelectionFixture(t)
	services.Outbounds = selectionServices.Outbounds
	selectionOperation = completionOperation(t, services, selectionOperation.Action, selectionOperation.Target, json.RawMessage(selectionOperation.Views.Desired.Data))
	if err := services.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	if err := services.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	if err := services.CompleteOperationReadback(ctx, providerOperation, providerResult); err != nil {
		t.Fatal(err)
	}
	if err := services.CompleteOperationReadback(ctx, selectionOperation, selectionResult); err != nil {
		t.Fatal(err)
	}
	if err := services.CompleteOperationReadback(ctx, selectionOperation, selectionResult); err != nil {
		t.Fatalf("selection replay failed: %v", err)
	}
	reopened, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewServices()
	if err := restored.Load(ctx, reopened, vault); err != nil {
		t.Fatal(err)
	}
	active, err := restored.Providers.Active("provider-1")
	if err != nil || active.Number != 1 || active.Nodes[0].Definition.Password != "completion-private-secret" {
		t.Fatalf("restart lost completed provider state or credentials: %v", err)
	}
	for _, transport := range []string{"tcp", "udp"} {
		selection, err := restored.Outbounds.GetSelection("outbound-1", outbounds.Scope{GatewayID: "gateway-a", Transport: transport})
		if err != nil || selection.AppliedNodeID != "node-a" || selection.ObservedNodeID != "node-a" || selection.AppliedGeneration != 7 || selection.ObservedGeneration != 7 {
			t.Fatalf("restart lost completed %s selection: %+v %v", transport, selection, err)
		}
	}
	raw, err := reopened.LoadDocument(ctx, lifecycleDocumentKey)
	if err != nil || bytes.Contains(raw, []byte("completion-private-secret")) || bytes.Contains(raw, []byte("node-a")) {
		t.Fatalf("completed state was not encrypted: %v", err)
	}
}

func TestOperationCompletionPersistenceFailureFreezesManagementWrites(t *testing.T) {
	ctx := context.Background()
	documents := store.NewMemoryStore()
	vault := lifecycleTestVault(t, 7)
	services, operation, result := completionProviderFixture(t)
	if err := services.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	if err := services.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := documents.LoadDocument(ctx, lifecycleDocumentKey)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("completion storage unavailable")
	services.persistence.documents = failingLifecycleDocuments{DocumentStore: documents, failure: failure}
	if err := services.CompleteOperationReadback(ctx, operation, result); !errors.Is(err, failure) {
		t.Fatalf("completion hid persistence failure: %v", err)
	}
	if !services.mutationBlocked {
		t.Fatal("persistence failure did not pause writes")
	}
	if err := services.CompleteOperationReadback(ctx, operation, result); err == nil {
		t.Fatal("completion continued after writes were paused")
	}
	server := NewServer(store.NewMemoryStore(), nil)
	server.Services = services
	handlerCalled := false
	handler := server.durableMutations(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { handlerCalled = true }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/policies", nil))
	if response.Code != http.StatusServiceUnavailable || handlerCalled {
		t.Fatalf("management mutation was not fenced after failure: code=%d called=%v", response.Code, handlerCalled)
	}
	after, err := documents.LoadDocument(ctx, lifecycleDocumentKey)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed completion replaced durable state: %v", err)
	}
	restored := NewServices()
	if err := restored.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	if restored.Providers.Status("provider-1").Active != 0 || restored.Providers.Status("provider-1").Staged != 1 {
		t.Fatal("restart treated failed completion as durable publication")
	}
}

type completionFenceJournal struct {
	deployment.Journal
	checked chan struct{}
	once    sync.Once
}

func (j *completionFenceJournal) FenceCurrent(ctx context.Context, target deployment.Target, token uint64) (bool, error) {
	current, err := j.Journal.FenceCurrent(ctx, target, token)
	j.once.Do(func() { close(j.checked) })
	return current, err
}

func TestOperationCompletionRechecksFenceAfterWaitingForMutationLock(t *testing.T) {
	services, operation, result := completionProviderFixture(t)
	journal := &completionFenceJournal{Journal: services.Journal, checked: make(chan struct{})}
	services.Journal = journal
	services.mutationMu.Lock()
	done := make(chan error, 1)
	go func() { done <- services.CompleteOperationReadback(context.Background(), operation, result) }()
	// A correct implementation waits for this lock before validating its fence.
	// The timeout supports that ordering; an early check exposes the old race.
	select {
	case <-journal.checked:
	case <-time.After(100 * time.Millisecond):
	}
	_, fenceErr := journal.NextFence(context.Background(), operation.Target)
	services.mutationMu.Unlock()
	if fenceErr != nil {
		t.Fatal(fenceErr)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("completion used a fence invalidated while waiting for the mutation lock")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("completion did not leave the mutation boundary")
	}
	if services.Providers.Status("provider-1").Active != 0 {
		t.Fatal("stale fenced completion activated a provider")
	}
}
