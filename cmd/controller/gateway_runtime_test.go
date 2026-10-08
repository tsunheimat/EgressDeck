package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

const runtimeTestImplementation = "qualified-runtime-contract-test"
const runtimeTestPassword = "private-node-password-92"

// This fixture implements only the runtime contract exercised below. Embedding
// the remaining interface makes an unexpected engine operation fail the test.
// It is a protocol fixture, not evidence of native dae qualification.
type runtimeTestEngine struct {
	gateway.Engine
	mu                    sync.Mutex
	id                    string
	caps                  gateway.Capabilities
	state                 gateway.Snapshot
	staged                map[string]gateway.ProviderRevision
	received              []gateway.ProviderRevision
	selectionRequests     []gateway.Selection
	publishCalls          int
	requestCount          int
	responses             []string
	rejectPublish         bool
	ignorePublish         bool
	unknownPublishAck     bool
	failPublishedReadback bool
	ignoreSelection       bool
	unknownSelectionAck   bool
}

var _ gateway.Engine = (*runtimeTestEngine)(nil)

func (e *runtimeTestEngine) Capabilities(context.Context) (gateway.Capabilities, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.caps, nil
}

func (e *runtimeTestEngine) Inventory(context.Context) (gateway.Snapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failPublishedReadback && e.publishCalls > 0 {
		return gateway.Snapshot{}, gateway.ErrUnavailable
	}
	return e.snapshotLocked(), nil
}

func (e *runtimeTestEngine) snapshotLocked() gateway.Snapshot {
	// The public inventory copy uses the same JSON boundary as the agent, so
	// private node connection material cannot escape through readback.
	data, _ := json.Marshal(e.state)
	var snapshot gateway.Snapshot
	_ = json.Unmarshal(data, &snapshot)
	return snapshot
}

func (e *runtimeTestEngine) StageProvider(_ context.Context, revision gateway.ProviderRevision, expected int64) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if expected != e.state.Generation {
		return "", gateway.ErrConflict
	}
	e.received = append(e.received, revision)
	id := fmt.Sprintf("stage-%d", len(e.received))
	e.staged[id] = revision
	return id, nil
}

func (e *runtimeTestEngine) PublishProvider(_ context.Context, id string) (gateway.Snapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.publishCalls++
	if e.rejectPublish {
		return gateway.Snapshot{}, gateway.ErrConflict
	}
	revision, ok := e.staged[id]
	if !ok {
		return gateway.Snapshot{}, gateway.ErrStageNotFound
	}
	if !e.ignorePublish {
		e.state.Generation++
		e.state.Providers[revision.ProviderID] = revision
		for _, group := range revision.Groups {
			e.state.Groups[group.ID] = gateway.OutboundGroup{ID: group.ID, Name: group.Name, Revision: group.Revision, ProviderIDs: []string{revision.ProviderID}, NodeIDs: append([]string(nil), group.CandidateIDs...), SelectionMode: "manual"}
			e.state.Selections[group.ID] = gateway.Selection{Scope: gateway.SelectionScope{GatewayID: e.id, GroupID: group.ID, Transport: "both"}, DesiredNodeID: group.SelectedNodeID, ObservedNodeID: group.SelectedNodeID, Revision: 1}
		}
	}
	return e.snapshotLocked(), nil
}

func (e *runtimeTestEngine) PersistSelection(_ context.Context, scope gateway.SelectionScope, node string, expected int64) (gateway.Selection, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	old := e.state.Selections[scope.GroupID]
	if old.Revision != expected {
		return gateway.Selection{}, gateway.ErrConflict
	}
	ack := gateway.Selection{Scope: scope, DesiredNodeID: node, ObservedNodeID: node, Revision: expected + 1}
	e.selectionRequests = append(e.selectionRequests, ack)
	if !e.ignoreSelection {
		e.state.Selections[scope.GroupID] = ack
	}
	return ack, nil
}

func (e *runtimeTestEngine) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 {
		t.Error("runtime operation did not use verified mutual TLS 1.3")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Authorization") != "Bearer runtime-private-token" {
		t.Error("runtime operation omitted configured bearer authentication")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	e.mu.Lock()
	e.requestCount++
	e.mu.Unlock()
	write := func(status int, value any) {
		data, err := json.Marshal(value)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		e.mu.Lock()
		e.responses = append(e.responses, string(data))
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(data)
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/capabilities":
		caps, _ := e.Capabilities(r.Context())
		write(http.StatusOK, caps)
	case "GET /v1/readback":
		snapshot, err := e.Inventory(r.Context())
		if err != nil {
			write(http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
			return
		}
		write(http.StatusOK, snapshot)
	case "POST /v1/providers/stage":
		var request gateway.ProviderStageRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id, err := e.StageProvider(r.Context(), request.ProviderRevision(), request.ExpectedGeneration)
		if err != nil {
			write(http.StatusConflict, map[string]string{"error": "conflict"})
			return
		}
		write(http.StatusCreated, map[string]any{"stage_id": id, "provider_id": request.ProviderID, "revision": request.Revision, "content_hash": request.ContentHash, "base_generation": request.ExpectedGeneration, "status": "staged"})
	case "POST /v1/providers/publish":
		var request struct {
			StageID            string `json:"stage_id"`
			ExpectedGeneration int64  `json:"expected_generation"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		e.mu.Lock()
		expected, unknown := e.state.Generation, e.unknownPublishAck
		e.mu.Unlock()
		if request.ExpectedGeneration != expected {
			write(http.StatusConflict, map[string]string{"error": "conflict"})
			return
		}
		snapshot, err := e.PublishProvider(r.Context(), request.StageID)
		if err != nil {
			write(http.StatusConflict, map[string]string{"error": "conflict"})
			return
		}
		if unknown {
			write(http.StatusOK, map[string]string{"status": "published"})
			return
		}
		write(http.StatusOK, map[string]any{"status": "published", "snapshot": snapshot})
	case "PUT /v1/selections":
		var request struct {
			Scope    gateway.SelectionScope `json:"scope"`
			Node     string                 `json:"desired_node_id"`
			Expected int64                  `json:"expected_revision"`
			Persist  bool                   `json:"persist_restart"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !request.Persist {
			t.Error("shared runtime selection omitted restart persistence")
		}
		selection, err := e.PersistSelection(r.Context(), request.Scope, request.Node, request.Expected)
		if err != nil {
			write(http.StatusConflict, map[string]string{"error": "conflict"})
			return
		}
		e.mu.Lock()
		unknown := e.unknownSelectionAck
		e.mu.Unlock()
		if unknown {
			write(http.StatusOK, map[string]string{"status": "applied"})
			return
		}
		write(http.StatusOK, selection)
	default:
		t.Errorf("unexpected runtime agent operation: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

type runtimeTestHarness struct {
	controller  *api.Server
	provider    domain.Provider
	revision    providers.Revision
	groups      []outbounds.Group
	engines     []*runtimeTestEngine
	connections []gatewayConnection
}

func newRuntimeTestHarness(t *testing.T, count int) *runtimeTestHarness {
	t.Helper()
	h := &runtimeTestHarness{controller: api.NewServer(store.NewMemoryStore(), nil)}
	var err error
	h.provider, err = h.controller.Store.CreateProvider(context.Background(), domain.Provider{ID: "runtime-provider", Name: "Runtime provider", Source: "inline", Format: "local"})
	if err != nil {
		t.Fatal(err)
	}
	h.revision, _, err = h.controller.Services.Providers.Stage(h.provider.ID, []byte("socks5://private-user:"+runtimeTestPassword+"@one.example:1080#First\nsocks5://private-user:"+runtimeTestPassword+"@two.example:1080#Second\n"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	root := newConfiguredTestIdentity(t, nil, 0)
	clientIdentity := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageClientAuth)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("gateway-%d", i+1)
		engine := &runtimeTestEngine{id: id, caps: gateway.DefaultCapabilities(runtimeTestImplementation, "contract-test"), staged: map[string]gateway.ProviderRevision{}, state: gateway.Snapshot{Generation: 11, Providers: map[string]gateway.ProviderRevision{}, Groups: map[string]gateway.OutboundGroup{}, Selections: map[string]gateway.Selection{}}}
		serverIdentity := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageServerAuth)
		serverTLS, err := gateway.LoadServerTLS(serverIdentity.certFile, serverIdentity.keyFile, root.certFile)
		if err != nil {
			t.Fatal(err)
		}
		agent := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { engine.serve(t, w, r) }))
		agent.TLS = serverTLS
		agent.StartTLS()
		t.Cleanup(agent.Close)
		if _, err := h.controller.Store.CreateGateway(context.Background(), domain.Gateway{ID: id, Name: id, Endpoint: agent.URL}); err != nil {
			t.Fatal(err)
		}
		group, err := h.controller.Services.Outbounds.Create(outbounds.Group{ID: fmt.Sprintf("outbound-%d", i+1), Name: "Provider candidates", GatewayID: id, NodeIDs: []string{h.revision.Nodes[0].ID, h.revision.Nodes[1].ID}, Mode: outbounds.SelectionManual})
		if err != nil {
			t.Fatal(err)
		}
		h.groups = append(h.groups, group)
		h.engines = append(h.engines, engine)
		h.connections = append(h.connections, gatewayConnection{ID: id, Endpoint: agent.URL, Token: "runtime-private-token", ClientCert: clientIdentity.certFile, ClientKey: clientIdentity.keyFile, CAFile: root.certFile, Runtime: gatewayRuntimeConfig{EnableProviderPublish: true, EnableSelection: true, ExpectedImplementation: runtimeTestImplementation, SharedTransportSelection: true, Groups: map[string]gatewayRuntimeGroup{group.ID: {Name: "native_exit", InitialNodeID: h.revision.Nodes[0].ID}}}})
	}
	return h
}

func (h *runtimeTestHarness) configure(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(gatewayConnections{Gateways: h.connections})
	if err != nil {
		t.Fatal(err)
	}
	closeClients, err := configureGateways(context.Background(), h.controller, writeGatewayConfigTestFile(t, 0o600, string(data)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeClients)
}

func (h *runtimeTestHarness) request(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", "0")
	response := httptest.NewRecorder()
	h.controller.Handler().ServeHTTP(response, request)
	return response
}

func (h *runtimeTestHarness) publish(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	return h.request(t, fmt.Sprintf("/api/v1/providers/%s/revisions/%d/apply", h.provider.ID, h.revision.Number), `{}`)
}

func runtimeResponseStatus(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var value struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	return value.Status
}

func TestGatewayRuntimeRejectsUnqualifiedMutations(t *testing.T) {
	for _, test := range []struct {
		name     string
		change   func(*runtimeTestHarness)
		disabled bool
	}{
		{"disabled", func(h *runtimeTestHarness) { h.connections[0].Runtime = gatewayRuntimeConfig{} }, true},
		{"stock agent", func(h *runtimeTestHarness) { h.engines[0].caps.Implementation = "dae-stock" }, false},
		{"different implementation", func(h *runtimeTestHarness) { h.engines[0].caps.Implementation = "unqualified-runtime" }, false},
		{"simulation", func(h *runtimeTestHarness) { h.engines[0].caps.Implementation = "fake-runtime" }, false},
		{"missing inventory", func(h *runtimeTestHarness) {
			disableRuntimeTestCapability(h.engines[0], gateway.CapabilityInventoryRead)
		}, false},
		{"missing stage", func(h *runtimeTestHarness) {
			disableRuntimeTestCapability(h.engines[0], gateway.CapabilityProviderStage)
		}, false},
		{"missing publish", func(h *runtimeTestHarness) {
			disableRuntimeTestCapability(h.engines[0], gateway.CapabilityProviderPublish)
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newRuntimeTestHarness(t, 1)
			test.change(h)
			h.configure(t)
			if test.disabled {
				if h.controller.Services.ProviderPublisher != nil || h.controller.Services.SelectionApplier != nil {
					t.Fatal("disabled configuration installed runtime mutation hooks")
				}
			} else if err := h.controller.Services.ProviderPublisher(context.Background(), h.provider, h.revision); !errors.Is(err, gateway.ErrUnsupported) {
				t.Fatalf("unqualified publication was not unsupported: %v", err)
			}
			engine := h.engines[0]
			engine.mu.Lock()
			defer engine.mu.Unlock()
			if len(engine.received) != 0 || engine.publishCalls != 0 || len(engine.selectionRequests) != 0 || engine.state.Generation != 11 || len(engine.state.Providers) != 0 {
				t.Fatal("qualification failure changed gateway runtime state")
			}
			if h.controller.Services.Providers.Status(h.provider.ID).Active != 0 {
				t.Fatal("qualification failure changed controller active revision")
			}
		})
	}
}

func disableRuntimeTestCapability(engine *runtimeTestEngine, name gateway.CapabilityName) {
	for i := range engine.caps.Items {
		if engine.caps.Items[i].Name == name {
			engine.caps.Items[i].Supported = false
		}
	}
}

func TestGatewayRuntimePublicationCarriesPrivateSourceBoundCandidates(t *testing.T) {
	h := newRuntimeTestHarness(t, 1)
	// An unrelated group must not be appended to this provider publication.
	if _, err := h.controller.Store.CreateProvider(context.Background(), domain.Provider{ID: "other-provider", Name: "Other provider", Source: "inline", Format: "local"}); err != nil {
		t.Fatal(err)
	}
	other, _, err := h.controller.Services.Providers.Stage("other-provider", []byte("socks5://other.example:1080#Other"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.controller.Services.Providers.Publish("other-provider", other.Number, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := h.controller.Services.Outbounds.Create(outbounds.Group{ID: "unrelated", Name: "Other provider", GatewayID: "gateway-1", NodeIDs: []string{other.Nodes[0].ID}}); err != nil {
		t.Fatal(err)
	}
	h.configure(t)
	response := h.publish(t)
	if response.Code != http.StatusAccepted || runtimeResponseStatus(t, response) != "applied" {
		t.Fatalf("provider publication was not applied: %d %s", response.Code, response.Body.String())
	}
	if got := h.controller.Services.Providers.Status(h.provider.ID).Active; got != h.revision.Number {
		t.Fatalf("active revision=%d", got)
	}
	engine := h.engines[0]
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if len(engine.received) != 1 || engine.publishCalls != 1 {
		t.Fatalf("unexpected stage/publish attempts: %d/%d", len(engine.received), engine.publishCalls)
	}
	received := engine.received[0]
	if received.ProviderID != h.provider.ID || received.Revision != h.revision.Number || received.ContentHash != revisionIdentity(h.provider.ID, h.revision.Number) {
		t.Fatalf("publication was not bound to provider revision: %+v", received)
	}
	if len(received.Groups) != 1 || received.Groups[0].ID != h.groups[0].ID || received.Groups[0].Revision != h.groups[0].Revision || received.Groups[0].Name != "native_exit" || !sameIDs(received.Groups[0].CandidateIDs, h.groups[0].NodeIDs) || received.Groups[0].SelectedNodeID != h.revision.Nodes[0].ID {
		t.Fatalf("publication lost affected group identity/revision: %+v", received.Groups)
	}
	for i, node := range received.Nodes {
		link, err := url.Parse(node.Connection)
		if err != nil {
			t.Fatal(err)
		}
		password, ok := link.User.Password()
		if node.ID != h.revision.Nodes[i].ID || node.ProviderID != h.provider.ID || link.Scheme != "socks5" || link.Fragment != node.ID || !ok || password != runtimeTestPassword {
			t.Fatal("private stage body lost immutable node identity or credential")
		}
	}
	for _, public := range append(engine.responses, response.Body.String()) {
		if strings.Contains(public, runtimeTestPassword) || strings.Contains(public, "private-user") || strings.Contains(public, "socks5://") {
			t.Fatal("private connection material appeared in an agent/controller response")
		}
	}
	if len(engine.selectionRequests) != 0 {
		t.Fatal("provider publication made a separate implicit selection mutation")
	}
}

func TestGatewayRuntimePublicationRequiresExplicitSelection(t *testing.T) {
	h := newRuntimeTestHarness(t, 1)
	binding := h.connections[0].Runtime.Groups[h.groups[0].ID]
	binding.InitialNodeID = ""
	h.connections[0].Runtime.Groups[h.groups[0].ID] = binding
	h.configure(t)
	if err := h.controller.Services.ProviderPublisher(context.Background(), h.provider, h.revision); err == nil {
		t.Fatal("publication silently chose a candidate without operator/desired/readback selection")
	}
	engine := h.engines[0]
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if len(engine.received) != 0 || engine.publishCalls != 0 || engine.state.Generation != 11 {
		t.Fatal("missing explicit selection changed remote state")
	}
}

func TestGatewayRuntimeProviderRefreshReconcilesFilteredCandidates(t *testing.T) {
	h := newRuntimeTestHarness(t, 1)
	group := h.groups[0]
	group.SourceFilters = &outbounds.SourceFilters{ProviderIDs: []string{h.provider.ID}}
	var err error
	group, err = h.controller.Services.Outbounds.Update(group, group.Revision)
	if err != nil {
		t.Fatal(err)
	}
	h.groups[0] = group
	h.configure(t)
	if response := h.publish(t); runtimeResponseStatus(t, response) != "applied" {
		t.Fatalf("initial publication: %s", response.Body.String())
	}
	oldNumber := h.revision.Number
	h.revision, _, err = h.controller.Services.Providers.Stage(h.provider.ID, []byte("socks5://private-user:"+runtimeTestPassword+"@one.example:1080#First\nsocks5://private-user:"+runtimeTestPassword+"@two.example:1080#Second\nsocks5://private-user:"+runtimeTestPassword+"@three.example:1080#Third\n"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/providers/%s/revisions/%d/apply", h.provider.ID, h.revision.Number), strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", fmt.Sprint(oldNumber))
	response := httptest.NewRecorder()
	h.controller.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || runtimeResponseStatus(t, response) != "applied" {
		t.Fatalf("filtered candidate refresh was not applied: %d %s", response.Code, response.Body.String())
	}
	after, err := h.controller.Services.Outbounds.Get(group.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{}
	for _, node := range h.revision.Nodes {
		wantIDs = append(wantIDs, node.ID)
	}
	if !sameIDs(after.NodeIDs, wantIDs) || after.Revision != group.Revision+1 {
		t.Fatalf("controller candidates did not follow published revision: %+v", after)
	}
	engine := h.engines[0]
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if len(engine.received) != 2 || engine.publishCalls != 2 {
		t.Fatal("refresh did not perform exactly one additional stage/publication")
	}
	staged := engine.received[1]
	if len(staged.Groups) != 1 || staged.Groups[0].ID != group.ID || staged.Groups[0].Revision != after.Revision || !sameIDs(staged.Groups[0].CandidateIDs, wantIDs) || staged.Groups[0].SelectedNodeID != engine.received[0].Groups[0].SelectedNodeID {
		t.Fatalf("native refresh lost group identity/revision or changed surviving selection: %+v", staged.Groups)
	}
}

func TestGatewayRuntimePublicationRequiresReadbackConfirmation(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*runtimeTestEngine)
		applied   bool
	}{
		{"lost acknowledgement confirmed", func(e *runtimeTestEngine) { e.unknownPublishAck = true }, true},
		{"rejected publication", func(e *runtimeTestEngine) { e.rejectPublish = true }, false},
		{"successful acknowledgement stale inventory", func(e *runtimeTestEngine) { e.ignorePublish = true }, false},
		{"unknown acknowledgement stale inventory", func(e *runtimeTestEngine) { e.ignorePublish = true; e.unknownPublishAck = true }, false},
		{"readback unavailable", func(e *runtimeTestEngine) { e.failPublishedReadback = true }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newRuntimeTestHarness(t, 1)
			test.configure(h.engines[0])
			h.configure(t)
			response := h.publish(t)
			wantStatus, wantActive := "outcome_unknown", int64(0)
			if test.applied {
				wantStatus, wantActive = "applied", h.revision.Number
			}
			if response.Code != http.StatusAccepted || runtimeResponseStatus(t, response) != wantStatus {
				t.Fatalf("status=%d body=%s, want %s", response.Code, response.Body.String(), wantStatus)
			}
			if active := h.controller.Services.Providers.Status(h.provider.ID).Active; active != wantActive {
				t.Fatalf("active=%d, want %d", active, wantActive)
			}
			engine := h.engines[0]
			engine.mu.Lock()
			defer engine.mu.Unlock()
			if engine.publishCalls != 1 || len(engine.received) != 1 {
				t.Fatal("ambiguous publication was automatically retried")
			}
		})
	}
}

func TestGatewayRuntimePartialMultiGatewayPublicationIsNotGloballyActive(t *testing.T) {
	h := newRuntimeTestHarness(t, 2)
	h.engines[1].rejectPublish = true
	h.configure(t)
	response := h.publish(t)
	if response.Code != http.StatusAccepted || runtimeResponseStatus(t, response) != "outcome_unknown" {
		t.Fatalf("partial publish reported success: %d %s", response.Code, response.Body.String())
	}
	if h.controller.Services.Providers.Status(h.provider.ID).Active != 0 {
		t.Fatal("partial gateway publication advanced global active revision")
	}
	for i, engine := range h.engines {
		engine.mu.Lock()
		_, published := engine.state.Providers[h.provider.ID]
		calls := engine.publishCalls
		engine.mu.Unlock()
		if published != (i == 0) || calls != 1 {
			t.Fatalf("gateway %d publication=%v calls=%d", i, published, calls)
		}
	}
	if _, err := h.controller.Services.ProviderReadback(context.Background(), h.provider); err == nil {
		t.Fatal("one gateway's applied revision satisfied global readback")
	}
}

func TestGatewayRuntimeSharedSelectionRequiresMatchingReadback(t *testing.T) {
	for _, test := range []struct {
		name                     string
		ignore, unknown, applied bool
	}{
		{"confirmed", false, false, true},
		{"lost acknowledgement confirmed", false, true, true},
		{"success acknowledgement stale readback", true, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newRuntimeTestHarness(t, 1)
			h.configure(t)
			if response := h.publish(t); runtimeResponseStatus(t, response) != "applied" {
				t.Fatalf("setup publication: %s", response.Body.String())
			}
			engine := h.engines[0]
			engine.mu.Lock()
			engine.ignoreSelection, engine.unknownSelectionAck = test.ignore, test.unknown
			engine.mu.Unlock()
			node := h.revision.Nodes[1].ID
			body, _ := json.Marshal(map[string]any{"node_id": node, "gateway_id": "gateway-1", "transport_scopes": []string{"tcp", "udp"}})
			response := h.request(t, "/api/v1/outbound-groups/"+h.groups[0].ID+"/selection", string(body))
			want := "outcome_unknown"
			if test.applied {
				want = "applied"
			}
			if response.Code != http.StatusAccepted || runtimeResponseStatus(t, response) != want {
				t.Fatalf("selection status=%d body=%s", response.Code, response.Body.String())
			}
			selections := h.controller.Services.Outbounds.Selections(h.groups[0].ID)
			if test.applied && len(selections) != 2 {
				t.Fatalf("shared selection omitted local transport state: %+v", selections)
			}
			for _, selection := range selections {
				if test.applied {
					if selection.DesiredNodeID != node || selection.AppliedNodeID != node || selection.ObservedNodeID != node || selection.AppliedGeneration != 12 || selection.ObservedGeneration != 12 {
						t.Fatalf("confirmed shared selection not recorded: %+v", selection)
					}
				} else if selection.AppliedNodeID != "" || selection.ObservedNodeID != "" || selection.AppliedGeneration != 0 || selection.ObservedGeneration != 0 {
					t.Fatalf("unconfirmed selection claimed applied/observed state: %+v", selection)
				}
			}
			engine.mu.Lock()
			defer engine.mu.Unlock()
			if len(engine.selectionRequests) != 1 || engine.selectionRequests[0].Scope.Transport != "both" || engine.selectionRequests[0].Scope.GatewayID != "gateway-1" {
				t.Fatalf("selection was not one shared persisted mutation: %+v", engine.selectionRequests)
			}
		})
	}
}

func TestGatewayRuntimeSelectionCapabilityAndScopeGates(t *testing.T) {
	for _, test := range []struct {
		name        string
		capability  gateway.CapabilityName
		singleScope bool
	}{
		{"runtime capability absent", gateway.CapabilitySelectionRuntime, false},
		{"persistence capability absent", gateway.CapabilitySelectionPersist, false},
		{"single transport rejected", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newRuntimeTestHarness(t, 1)
			if test.capability != "" {
				disableRuntimeTestCapability(h.engines[0], test.capability)
			}
			h.configure(t)
			if test.singleScope {
				body, _ := json.Marshal(map[string]string{"node_id": h.revision.Nodes[1].ID, "gateway_id": "gateway-1", "transport": "tcp"})
				response := h.request(t, "/api/v1/outbound-groups/"+h.groups[0].ID+"/selection", string(body))
				if response.Code != http.StatusUnprocessableEntity {
					t.Fatalf("single transport accepted: %d %s", response.Code, response.Body.String())
				}
				if len(h.controller.Services.Outbounds.Selections(h.groups[0].ID)) != 0 {
					t.Fatal("rejected single transport persisted selection intent")
				}
			} else {
				desired, err := h.controller.Services.Outbounds.SetDesired(h.groups[0].ID, outbounds.Scope{GatewayID: "gateway-1", Transport: "tcp"}, h.revision.Nodes[1].ID, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := h.controller.Services.SelectionApplier(context.Background(), h.groups[0], desired); !errors.Is(err, gateway.ErrUnsupported) {
					t.Fatalf("unqualified selection: %v", err)
				}
			}
			engine := h.engines[0]
			engine.mu.Lock()
			defer engine.mu.Unlock()
			if len(engine.selectionRequests) != 0 || engine.state.Generation != 11 || len(engine.state.Selections) != 0 {
				t.Fatal("selection gate changed native state")
			}
		})
	}
}

type runtimeEndpointDriftStore struct{ store.Store }

func (s runtimeEndpointDriftStore) GetGateway(ctx context.Context, id string) (domain.Gateway, error) {
	value, err := s.Store.GetGateway(ctx, id)
	value.Endpoint = "https://unexpected-gateway.invalid"
	return value, err
}

func TestGatewayRuntimeEndpointDriftPreventsCredentialBearingRequests(t *testing.T) {
	h := newRuntimeTestHarness(t, 1)
	h.configure(t)
	h.controller.Store = runtimeEndpointDriftStore{h.controller.Store}
	if err := h.controller.Services.ProviderPublisher(context.Background(), h.provider, h.revision); err == nil {
		t.Fatal("endpoint drift accepted for publication")
	}
	desired, err := h.controller.Services.Outbounds.SetDesired(h.groups[0].ID, outbounds.Scope{GatewayID: "gateway-1", Transport: "tcp"}, h.revision.Nodes[0].ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.controller.Services.SelectionApplier(context.Background(), h.groups[0], desired); err == nil {
		t.Fatal("endpoint drift accepted for selection")
	}
	engine := h.engines[0]
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.requestCount != 0 || len(engine.received) != 0 || len(engine.selectionRequests) != 0 {
		t.Fatal("endpoint drift sent credentials or changed remote state")
	}
}
