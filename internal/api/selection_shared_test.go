package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func sharedSelectionFixture(t *testing.T) *Server {
	t.Helper()
	server := NewServer(store.NewMemoryStore(), nil)
	if _, err := server.Services.Outbounds.Create(outbounds.Group{ID: "shared", Name: "Shared", GatewayID: "gateway", NodeIDs: []string{"first", "second"}}); err != nil {
		t.Fatal(err)
	}
	server.Services.SelectionScopeMode = func(outbounds.Group) string { return "shared" }
	return server
}

func requestSharedSelection(handler http.Handler, body, revision, key string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPut, "/api/v1/outbound-groups/shared/selection", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", revision)
	request.Header.Set("Idempotency-Key", key)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestSharedSelectionRequiresBothExplicitTransportScopes(t *testing.T) {
	for _, test := range []struct {
		body string
		code string
	}{
		{`{"node_id":"first"}`, "shared_transport_required"},
		{`{"node_id":"first","transport":"tcp"}`, "shared_transport_required"},
		{`{"node_id":"first","transport_scopes":["udp"]}`, "shared_transport_required"},
		{`{"node_id":"first","transport_scopes":["tcp","tcp"]}`, "invalid_transport_scope"},
	} {
		t.Run(test.body, func(t *testing.T) {
			server := sharedSelectionFixture(t)
			calls := 0
			server.Services.SelectionApplier = func(context.Context, outbounds.Group, outbounds.Selection) (outbounds.Selection, error) {
				calls++
				return outbounds.Selection{}, nil
			}
			before, err := server.Services.Outbounds.ExportState()
			if err != nil {
				t.Fatal(err)
			}
			response := requestSharedSelection(server.Handler(), test.body, "0", "single-scope")
			if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), test.code) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			after, err := server.Services.Outbounds.ExportState()
			if err != nil {
				t.Fatal(err)
			}
			if calls != 0 || !bytes.Equal(before, after) {
				t.Fatalf("invalid transport scope changed outbound state or called adapter: calls=%d", calls)
			}
			operations, err := server.Services.Journal.List(context.Background())
			if err != nil || len(operations) != 0 {
				t.Fatalf("invalid request left journal intent: operations=%+v err=%v", operations, err)
			}
		})
	}
}

func TestSharedSelectionPersistsBothIntentsCallsAdapterOnceAndReplays(t *testing.T) {
	ctx := context.Background()
	server := sharedSelectionFixture(t)
	documents := store.NewMemoryStore()
	vault := lifecycleTestVault(t, 1)
	if err := server.Services.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server.Services.SelectionApplier = func(_ context.Context, group outbounds.Group, selected outbounds.Selection) (outbounds.Selection, error) {
		calls++
		if group.ID != "shared" || selected.Scope.Transport != "tcp" {
			t.Fatalf("unexpected shared adapter target: group=%+v selected=%+v", group, selected)
		}
		// Re-open the durable snapshot at the exact remote mutation boundary.
		// Both intents must survive a controller restart before that mutation.
		restored := NewServices()
		if err := restored.Load(ctx, documents, vault); err != nil {
			t.Fatal(err)
		}
		pending := restored.Outbounds.Selections("shared")
		if len(pending) != 2 {
			t.Fatalf("remote mutation started before both intents were durable: %+v", pending)
		}
		for index, transport := range []string{"tcp", "udp"} {
			intent := pending[index]
			if intent.Scope != (outbounds.Scope{GatewayID: "gateway", Transport: transport}) || intent.DesiredNodeID != "first" || intent.Revision != 1 || intent.AppliedNodeID != "" || intent.ObservedNodeID != "" {
				t.Fatalf("invalid persisted %s intent: %+v", transport, intent)
			}
		}
		operations, err := server.Services.Journal.List(ctx)
		if err != nil || len(operations) != 1 || operations[0].FenceToken == 0 || operations[0].Status != deployment.StatusApplying {
			t.Fatalf("remote mutation has no fenced journal intent: operations=%+v err=%v", operations, err)
		}
		selected.AppliedNodeID, selected.ObservedNodeID, selected.Generation = "first", "first", 17
		return selected, nil
	}
	handler := server.Handler()
	body := `{"node_id":"first","transport_scopes":["udp","tcp"]}`
	response := requestSharedSelection(handler, body, "0", "shared-once")
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var accepted struct {
		OperationID string                `json:"operation_id"`
		Status      deployment.Status     `json:"status"`
		Items       []outbounds.Selection `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || accepted.OperationID == "" || accepted.Status != deployment.StatusApplied || len(accepted.Items) != 2 {
		t.Fatalf("shared operation result=%+v calls=%d", accepted, calls)
	}
	for index, transport := range []string{"tcp", "udp"} {
		selection, err := server.Services.Outbounds.GetSelection("shared", outbounds.Scope{GatewayID: "gateway", Transport: transport})
		if err != nil {
			t.Fatal(err)
		}
		if selection.DesiredNodeID != "first" || selection.AppliedNodeID != "first" || selection.ObservedNodeID != "first" || selection.Generation != 17 || selection.AppliedGeneration != 17 || selection.ObservedGeneration != 17 {
			t.Fatalf("%s did not mirror the verified shared generation: %+v", transport, selection)
		}
		if !reflect.DeepEqual(selection, accepted.Items[index]) {
			t.Fatalf("response does not describe saved %s state: response=%+v saved=%+v", transport, accepted.Items[index], selection)
		}
	}
	operation, err := server.Services.Journal.Get(ctx, accepted.OperationID)
	if err != nil || operation.FenceToken == 0 || operation.Status != deployment.StatusApplied || operation.Target != (deployment.Target{Kind: "outbound_group", ID: "shared"}) {
		t.Fatalf("final fenced operation=%+v err=%v", operation, err)
	}
	beforeReplay, err := server.Services.Outbounds.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	// The common expected revision is now stale; idempotent replay must still
	// return the original operation without repeating the gateway mutation.
	replay := requestSharedSelection(handler, `{"node_id":"first","transport_scopes":["tcp","udp"]}`, "0", "shared-once")
	var replayed struct {
		OperationID string            `json:"operation_id"`
		Status      deployment.Status `json:"status"`
	}
	if err := json.Unmarshal(replay.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if replay.Code != http.StatusAccepted || calls != 1 || replayed.OperationID != accepted.OperationID || replayed.Status != deployment.StatusApplied {
		t.Fatalf("replay status=%d calls=%d body=%s", replay.Code, calls, replay.Body.String())
	}
	afterReplay, err := server.Services.Outbounds.ExportState()
	if err != nil || !bytes.Equal(beforeReplay, afterReplay) {
		t.Fatalf("replay changed outbound state: %v", err)
	}
	operations, err := server.Services.Journal.List(ctx)
	if err != nil || len(operations) != 1 {
		t.Fatalf("replay created another operation: operations=%+v err=%v", operations, err)
	}
	restored := NewServices()
	if err := restored.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(server.Services.Outbounds.Selections("shared"), restored.Outbounds.Selections("shared")) {
		t.Fatal("verified shared selection did not survive restart")
	}
}

func TestSharedSelectionSecondScopeCASConflictChangesNeitherScope(t *testing.T) {
	server := sharedSelectionFixture(t)
	for _, transport := range []string{"tcp", "udp"} {
		if _, err := server.Services.Outbounds.SetDesired("shared", outbounds.Scope{GatewayID: "gateway", Transport: transport}, "first", 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server.Services.Outbounds.SetDesired("shared", outbounds.Scope{GatewayID: "gateway", Transport: "udp"}, "first", 1); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server.Services.SelectionApplier = func(context.Context, outbounds.Group, outbounds.Selection) (outbounds.Selection, error) {
		calls++
		return outbounds.Selection{}, nil
	}
	before, err := server.Services.Outbounds.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	response := requestSharedSelection(server.Handler(), `{"node_id":"second","transport_scopes":["tcp","udp"]}`, "1", "cas-conflict")
	if response.Code != http.StatusPreconditionFailed || !strings.Contains(response.Body.String(), "revision_conflict") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	after, err := server.Services.Outbounds.ExportState()
	if err != nil || calls != 0 || !bytes.Equal(before, after) {
		t.Fatalf("second-scope CAS failure mutated first scope: calls=%d err=%v", calls, err)
	}
	operations, err := server.Services.Journal.List(context.Background())
	if err != nil || len(operations) != 0 {
		t.Fatalf("CAS conflict left journal intent: operations=%+v err=%v", operations, err)
	}
}

func TestSharedSelectionScopedRevisionsConvergeLegacyIndependentSelections(t *testing.T) {
	server := sharedSelectionFixture(t)
	for _, transport := range []string{"tcp", "udp"} {
		if _, err := server.Services.Outbounds.SetDesired("shared", outbounds.Scope{GatewayID: "gateway", Transport: transport}, "first", 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server.Services.Outbounds.SetDesired("shared", outbounds.Scope{GatewayID: "gateway", Transport: "udp"}, "first", 1); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server.Services.SelectionApplier = func(_ context.Context, _ outbounds.Group, selection outbounds.Selection) (outbounds.Selection, error) {
		calls++
		selection.AppliedNodeID, selection.ObservedNodeID, selection.Generation = selection.DesiredNodeID, selection.DesiredNodeID, 10
		return selection, nil
	}
	before, _ := server.Services.Outbounds.ExportState()
	stale := requestSharedSelection(server.Handler(), `{"node_id":"second","transport_scopes":["tcp","udp"],"expected_revisions":{"tcp":1,"udp":1}}`, "1", "stale-scoped")
	after, _ := server.Services.Outbounds.ExportState()
	if stale.Code != http.StatusPreconditionFailed || calls != 0 || !bytes.Equal(before, after) {
		t.Fatalf("stale second scope must not change either scope: status=%d calls=%d body=%s", stale.Code, calls, stale.Body.String())
	}
	operations, err := server.Services.Journal.List(context.Background())
	if err != nil || len(operations) != 0 {
		t.Fatalf("stale request left intent: operations=%+v err=%v", operations, err)
	}
	body := `{"node_id":"second","transport_scopes":["tcp","udp"],"expected_revisions":{"tcp":1,"udp":2}}`
	response := requestSharedSelection(server.Handler(), body, "1", "merge-scoped")
	if response.Code != http.StatusAccepted || calls != 1 {
		t.Fatalf("valid unequal CAS failed: status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
	for index, transport := range []string{"tcp", "udp"} {
		selection, err := server.Services.Outbounds.GetSelection("shared", outbounds.Scope{GatewayID: "gateway", Transport: transport})
		if err != nil || selection.Revision != int64(index+2) || selection.DesiredNodeID != "second" || selection.AppliedNodeID != "second" || selection.ObservedNodeID != "second" || selection.Generation != 10 {
			t.Fatalf("scope %s did not converge: %+v err=%v", transport, selection, err)
		}
	}
	replay := requestSharedSelection(server.Handler(), body, "1", "merge-scoped")
	if replay.Code != http.StatusAccepted || calls != 1 {
		t.Fatalf("scoped replay mutated runtime: status=%d calls=%d body=%s", replay.Code, calls, replay.Body.String())
	}
}

func TestSharedSelectionRejectsIncompleteOrAmbiguousScopedRevisions(t *testing.T) {
	for _, revisions := range []string{`{}`, `{"tcp":0}`, `{"tcp":0,"udp":-1}`, `{"tcp":0,"other":0}`, `{"tcp":1,"udp":0}`} {
		t.Run(revisions, func(t *testing.T) {
			server := sharedSelectionFixture(t)
			server.Services.SelectionApplier = func(context.Context, outbounds.Group, outbounds.Selection) (outbounds.Selection, error) {
				t.Fatal("invalid CAS map reached adapter")
				return outbounds.Selection{}, nil
			}
			response := requestSharedSelection(server.Handler(), `{"node_id":"second","transport_scopes":["tcp","udp"],"expected_revisions":`+revisions+`}`, "0", "invalid-scoped")
			if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), "invalid_expected_revisions") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if len(server.Services.Outbounds.Selections("shared")) != 0 {
				t.Fatal("invalid CAS map changed desired state")
			}
			operations, err := server.Services.Journal.List(context.Background())
			if err != nil || len(operations) != 0 {
				t.Fatalf("invalid CAS map left intent: %+v %v", operations, err)
			}
		})
	}
}

func TestOutboundGroupReadbackExposesSelectionScope(t *testing.T) {
	for _, shared := range []bool{false, true} {
		server := sharedSelectionFixture(t)
		want := "shared_tcp_udp"
		if !shared {
			server.Services.SelectionScopeMode = nil
			want = "independent_transport"
		}
		for _, path := range []string{"/api/v1/outbound-groups", "/api/v1/outbound-groups/shared"} {
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"selection_scope":"`+want+`"`) {
				t.Fatalf("path=%s expected=%s status=%d body=%s", path, want, response.Code, response.Body.String())
			}
		}
	}
}

func TestSelectionPreflightRejectionLeavesNoIntent(t *testing.T) {
	server := sharedSelectionFixture(t)
	server.Services.SelectionPreflight = func(context.Context, outbounds.Group) error {
		return gateway.RejectBeforeMutation("group_configuration_not_applied", "apply group configuration first", nil)
	}
	server.Services.SelectionApplier = func(context.Context, outbounds.Group, outbounds.Selection) (outbounds.Selection, error) {
		t.Fatal("preflight rejection reached mutation")
		return outbounds.Selection{}, nil
	}
	before, _ := server.Services.Outbounds.ExportState()
	response := requestSharedSelection(server.Handler(), `{"node_id":"first","transport_scopes":["tcp","udp"]}`, "0", "preflight")
	after, _ := server.Services.Outbounds.ExportState()
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "group_configuration_not_applied") || !bytes.Equal(before, after) {
		t.Fatalf("status=%d body=%s desiredChanged=%v", response.Code, response.Body.String(), !bytes.Equal(before, after))
	}
	operations, err := server.Services.Journal.List(context.Background())
	if err != nil || len(operations) != 0 {
		t.Fatalf("preflight rejection left journal intent: %+v %v", operations, err)
	}
}

func TestSelectionDefiniteRejectionRestoresBothDurableIntents(t *testing.T) {
	ctx := context.Background()
	server := sharedSelectionFixture(t)
	documents := store.NewMemoryStore()
	vault := lifecycleTestVault(t, 1)
	if err := server.Services.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	server.Services.SelectionApplier = func(context.Context, outbounds.Group, outbounds.Selection) (outbounds.Selection, error) {
		return outbounds.Selection{}, gateway.RejectBeforeMutation("group_configuration_not_applied", "group changed before send", nil)
	}
	response := requestSharedSelection(server.Handler(), `{"node_id":"first","transport_scopes":["tcp","udp"]}`, "0", "rejected")
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	for _, selection := range server.Services.Outbounds.Selections("shared") {
		if selection.DesiredNodeID != "" || selection.AppliedNodeID != "" || selection.ObservedNodeID != "" || selection.Revision != 2 {
			t.Fatalf("rejected selection retained intent or lost monotonic CAS: %+v", selection)
		}
	}
	operations, err := server.Services.Journal.List(ctx)
	if err != nil || len(operations) != 1 || operations[0].Status != deployment.StatusFailed || operations[0].Views.Previous == nil || operations[0].RequestHash == "" {
		t.Fatalf("definite rejection did not retain terminal intent: %+v %v", operations, err)
	}
	restored := NewServices()
	if err := restored.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.Outbounds.Selections("shared"), server.Services.Outbounds.Selections("shared")) {
		t.Fatal("compensation was not durable across restart")
	}
}

func TestSelectionUnknownReplayReturnsExistingOperation(t *testing.T) {
	server := sharedSelectionFixture(t)
	calls := 0
	server.Services.SelectionApplier = func(context.Context, outbounds.Group, outbounds.Selection) (outbounds.Selection, error) {
		calls++
		return outbounds.Selection{}, context.DeadlineExceeded
	}
	body := `{"node_id":"first","transport_scopes":["tcp","udp"]}`
	first := requestSharedSelection(server.Handler(), body, "0", "lost-ack")
	replay := requestSharedSelection(server.Handler(), body, "0", "lost-ack")
	if first.Code != http.StatusAccepted || replay.Code != http.StatusAccepted || !bytes.Equal(first.Body.Bytes(), replay.Body.Bytes()) || calls != 1 {
		t.Fatalf("unknown replay first=%d %s replay=%d %s calls=%d", first.Code, first.Body.String(), replay.Code, replay.Body.String(), calls)
	}
}
