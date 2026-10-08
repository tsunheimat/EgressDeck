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
