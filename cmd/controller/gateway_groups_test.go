package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
)

func (h *runtimeTestHarness) groupRequest(t *testing.T, method, path, body string, revision int64) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", fmt.Sprint(revision))
	response := httptest.NewRecorder()
	h.controller.Handler().ServeHTTP(response, request)
	return response
}

func TestGatewayGroupPublicationWithoutProviderRefresh(t *testing.T) {
	h := newRuntimeTestHarness(t, 1)
	h.configure(t)
	if response := h.publish(t); response.Code != http.StatusAccepted || runtimeResponseStatus(t, response) != "applied" {
		t.Fatalf("publish: %d %s", response.Code, response.Body.String())
	}
	group, err := h.controller.Services.Outbounds.Get(h.groups[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if group.AppliedRevision != group.Revision {
		t.Fatalf("provider publication failed to mark applied group: %+v", group)
	}
	group.NodeIDs = []string{h.revision.Nodes[0].ID}
	body, _ := json.Marshal(group)
	path := "/api/v1/outbound-groups/" + group.ID
	response := h.groupRequest(t, http.MethodPut, path, string(body), group.Revision)
	if response.Code != http.StatusOK {
		t.Fatalf("edit: %d %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &group); err != nil {
		t.Fatal(err)
	}
	if group.AppliedRevision == group.Revision {
		t.Fatal("controller edit pretended gateway applied")
	}
	selectionBody := fmt.Sprintf(`{"gateway_id":%q,"node_id":%q,"transport_scopes":["tcp","udp"]}`, group.GatewayID, group.NodeIDs[0])
	response = h.groupRequest(t, http.MethodPost, path+"/selection", selectionBody, 0)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "group_configuration_not_applied") {
		t.Fatalf("selection before apply: %d %s", response.Code, response.Body.String())
	}
	if selections := h.controller.Services.Outbounds.Selections(group.ID); len(selections) != 0 {
		t.Fatalf("preflight rejection left desired selection: %+v", selections)
	}
	response = h.groupRequest(t, http.MethodPost, path+"/apply", `{}`, group.Revision)
	if response.Code != http.StatusAccepted || runtimeResponseStatus(t, response) != "applied" {
		t.Fatalf("apply: %d %s", response.Code, response.Body.String())
	}
	response = h.groupRequest(t, http.MethodPost, path+"/selection", selectionBody, 0)
	if response.Code != http.StatusAccepted || runtimeResponseStatus(t, response) != "applied" {
		t.Fatalf("selection after apply: %d %s", response.Code, response.Body.String())
	}
	for _, transport := range []string{"tcp", "udp"} {
		selected, err := h.controller.Services.Outbounds.GetSelection(group.ID, outbounds.Scope{GatewayID: group.GatewayID, Transport: transport})
		if err != nil || selected.ObservedNodeID != group.NodeIDs[0] {
			t.Fatalf("%s selection: %+v %v", transport, selected, err)
		}
	}
	engine := h.engines[0]
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.groupPublishCalls != 1 || engine.publishCalls != 1 || len(engine.received) != 1 || engine.state.Providers[h.provider.ID].Revision != h.revision.Number {
		t.Fatalf("group deployment changed provider lifecycle: group=%d publish=%d stage=%d", engine.groupPublishCalls, engine.publishCalls, len(engine.received))
	}
	if got := engine.state.Groups[group.ID]; got.Revision != group.Revision || !sameIDs(got.NodeIDs, group.NodeIDs) {
		t.Fatalf("runtime mismatch: %+v", got)
	}
	if h.controller.Services.Providers.Status(h.provider.ID).Active != h.revision.Number {
		t.Fatal("controller provider revision changed")
	}
	operations, err := h.controller.Services.Journal.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range operations {
		if string(op.Status) == "outcome_unknown" {
			t.Fatalf("definite mismatch leaked unresolved operation: %+v", op)
		}
	}
}

func TestGatewayGroupPublicationRejectsSelectedRemovalAndStaleCAS(t *testing.T) {
	h := newRuntimeTestHarness(t, 1)
	h.configure(t)
	if response := h.publish(t); response.Code != http.StatusAccepted || runtimeResponseStatus(t, response) != "applied" {
		t.Fatal(response.Body.String())
	}
	group, _ := h.controller.Services.Outbounds.Get(h.groups[0].ID)
	group.NodeIDs = []string{h.revision.Nodes[1].ID}
	group, err := h.controller.Services.Outbounds.Update(group, group.Revision)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/outbound-groups/" + group.ID + "/apply"
	response := h.groupRequest(t, http.MethodPost, path, `{}`, group.Revision-1)
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale CAS=%d %s", response.Code, response.Body.String())
	}
	response = h.groupRequest(t, http.MethodPost, path, `{}`, group.Revision)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "group_configuration_rejected") {
		t.Fatalf("selected removal=%d %s", response.Code, response.Body.String())
	}
	engine := h.engines[0]
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.groupPublishCalls != 0 || len(engine.state.Groups[group.ID].NodeIDs) != 2 {
		t.Fatal("rejected configuration changed runtime")
	}
}
