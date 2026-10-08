package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

const diagnosticsTestToken = "diagnostics-operator-private-token"

type diagnosticsRemoteFixture struct {
	controller *api.Server
	registered domain.Gateway
	observed   time.Time
	mu         sync.Mutex
	requests   map[string]int
	disabled   map[gateway.CapabilityName]bool
	rejectAuth bool
}

func newDiagnosticsRemoteFixture(t *testing.T) *diagnosticsRemoteFixture {
	t.Helper()
	root := newConfiguredTestIdentity(t, nil, 0)
	clientIdentity := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageClientAuth)
	serverIdentity := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageServerAuth)
	serverTLS, err := gateway.LoadServerTLS(serverIdentity.certFile, serverIdentity.keyFile, root.certFile)
	if err != nil {
		t.Fatal(err)
	}
	f := &diagnosticsRemoteFixture{
		controller: api.NewServer(store.NewMemoryStore(), nil),
		observed:   time.Date(2026, time.October, 8, 7, 0, 0, 0, time.UTC),
		requests:   map[string]int{}, disabled: map[gateway.CapabilityName]bool{},
	}
	agent := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests[r.URL.Path]++
		reject := f.rejectAuth
		caps := gateway.Capabilities{Implementation: "diagnostics-test-agent", Version: "1"}
		for _, name := range []gateway.CapabilityName{gateway.CapabilityProbeNode, gateway.CapabilityProbeGroup, gateway.CapabilityConnectionsObserve, gateway.CapabilityProxyCounters, gateway.CapabilityDirectCounters} {
			caps.Items = append(caps.Items, gateway.Capability{Name: name, Supported: !f.disabled[name]})
		}
		f.mu.Unlock()
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 {
			t.Error("diagnostic request did not authenticate the controller with TLS 1.3")
		}
		if r.Header.Get("Authorization") != "Bearer "+diagnosticsTestToken {
			t.Error("diagnostic request omitted operator bearer authentication")
			reject = true
		}
		w.Header().Set("Content-Type", "application/json")
		if reject {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintf(w, `{"error":{"code":"unauthorized","message":"%s remote-private-diagnostic-secret"}}`, diagnosticsTestToken)
			return
		}
		switch r.URL.Path {
		case "/v1/capabilities":
			if r.Method != http.MethodGet {
				t.Errorf("capabilities method = %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(caps)
		case "/v1/probes/node", "/v1/probes/group":
			if r.Method != http.MethodPost {
				t.Errorf("probe method = %s", r.Method)
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode probe request: %v", err)
			}
			key, target := "node_id", "node-1"
			if r.URL.Path == "/v1/probes/group" {
				key, target = "group_id", "group-1"
			}
			if !reflect.DeepEqual(body, map[string]string{key: target}) {
				t.Errorf("incorrect remote probe request: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(gateway.ProbeResult{Target: target, OK: true, Latency: 2250 * time.Microsecond, Observed: f.observed})
		case "/v1/connections":
			if r.Method != http.MethodGet {
				t.Errorf("connections method = %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode([]gateway.Connection{{ID: "connection-1", GroupID: "group-1", NodeID: "node-1", Transport: "tcp", State: "open", OpenedAt: f.observed}})
		case "/v1/counters":
			if r.Method != http.MethodGet {
				t.Errorf("counters method = %s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(gateway.Counters{ProxyBytes: ^uint64(0), ProxyPackets: 42, DirectBytes: 0, DirectPackets: 0})
		default:
			t.Errorf("unexpected diagnostic agent request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	agent.TLS = serverTLS
	agent.StartTLS()
	t.Cleanup(agent.Close)
	connection := gatewayConnection{ID: "gateway-1", Endpoint: agent.URL, Token: diagnosticsTestToken, ClientCert: clientIdentity.certFile, ClientKey: clientIdentity.keyFile, CAFile: root.certFile}
	config, err := json.Marshal(gatewayConnections{Gateways: []gatewayConnection{connection}})
	if err != nil {
		t.Fatal(err)
	}
	closeClients, err := configureGateways(context.Background(), f.controller, writeGatewayConfigTestFile(t, 0o600, string(config)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeClients)
	f.registered, err = f.controller.Store.CreateGateway(context.Background(), domain.Gateway{ID: connection.ID, Name: "Living room gateway", Endpoint: agent.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.controller.Services.Outbounds.Create(outbounds.Group{ID: "group-1", Name: "Main group", GatewayID: f.registered.ID, NodeIDs: []string{"node-1"}}); err != nil {
		t.Fatal(err)
	}
	if calls := f.calls(); len(calls) != 0 {
		t.Fatalf("configuring diagnostics contacted the agent: %#v", calls)
	}
	return f
}

func (f *diagnosticsRemoteFixture) calls() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int, len(f.requests))
	for path, count := range f.requests {
		out[path] = count
	}
	return out
}

func diagnosticsRequest(t *testing.T, controller *api.Server, method, path, body string, wantStatus int) map[string]any {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	controller.Handler().ServeHTTP(w, r)
	if w.Code != wantStatus {
		t.Fatalf("%s %s: status=%d, want=%d, body=%s", method, path, w.Code, wantStatus, w.Body.String())
	}
	for _, secret := range []string{diagnosticsTestToken, "remote-private-diagnostic-secret"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("diagnostic response disclosed private remote error data")
		}
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode diagnostic response: %v; body=%s", err, w.Body.String())
	}
	return result
}

func assertDiagnosticsScope(t *testing.T, result map[string]any, registered domain.Gateway) {
	t.Helper()
	if result["gateway_id"] != registered.ID || result["gateway_name"] != registered.Name {
		t.Fatalf("diagnostic observation lost gateway identity: %#v", result)
	}
	observed, ok := result["observed_at"].(string)
	if !ok {
		t.Fatalf("diagnostic observation has no timestamp: %#v", result)
	}
	if parsed, err := time.Parse(time.RFC3339Nano, observed); err != nil || parsed.IsZero() {
		t.Fatalf("invalid diagnostic timestamp %q: %v", observed, err)
	}
}

func TestConfiguredGatewayDiagnosticsAuthenticatedRemoteBoundary(t *testing.T) {
	f := newDiagnosticsRemoteFixture(t)
	for _, target := range []struct{ kind, plural, id, body string }{{"node", "nodes", "node-1", ""}, {"group", "groups", "group-1", "{}"}} {
		result := diagnosticsRequest(t, f.controller, http.MethodPost, "/api/v1/gateways/gateway-1/probes/"+target.plural+"/"+target.id, target.body, http.StatusOK)
		assertDiagnosticsScope(t, result, f.registered)
		if result["target_kind"] != target.kind || result["target_id"] != target.id {
			t.Fatalf("incorrect probe scope: %#v", result)
		}
		probe, ok := result["probe"].(map[string]any)
		if !ok || probe["target"] != target.id || probe["ok"] != true || probe["latency_ms"] != 2.25 || probe["observed_at"] != f.observed.Format(time.RFC3339Nano) {
			t.Fatalf("remote probe observation was not preserved with millisecond latency: %#v", result)
		}
		if _, present := probe["latency"]; present {
			t.Fatal("controller returned ambiguous nanosecond latency")
		}
	}
	connections := diagnosticsRequest(t, f.controller, http.MethodGet, "/api/v1/gateways/gateway-1/connections", "", http.StatusOK)
	assertDiagnosticsScope(t, connections, f.registered)
	items, ok := connections["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("incorrect connection observation: %#v", connections)
	}
	connection, ok := items[0].(map[string]any)
	if !ok || connection["id"] != "connection-1" || connection["node_id"] != "node-1" || connection["group_id"] != "group-1" || connection["transport"] != "tcp" {
		t.Fatalf("remote connection was not preserved: %#v", connection)
	}
	counters := diagnosticsRequest(t, f.controller, http.MethodGet, "/api/v1/gateways/gateway-1/counters", "", http.StatusOK)
	assertDiagnosticsScope(t, counters, f.registered)
	for key, expected := range map[string]map[string]any{
		"proxy":          {"available": true, "bytes": "18446744073709551615", "packets": "42"},
		"direct":         {"available": true, "bytes": "0", "packets": "0"},
		"provider_quota": {"available": false},
	} {
		if !reflect.DeepEqual(counters[key], expected) {
			t.Fatalf("incorrect %s counter observation: got=%#v want=%#v", key, counters[key], expected)
		}
	}
	if got, want := f.calls(), (map[string]int{"/v1/capabilities": 4, "/v1/probes/node": 1, "/v1/probes/group": 1, "/v1/connections": 1, "/v1/counters": 1}); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected remote calls: got=%#v want=%#v", got, want)
	}
}

func TestConfiguredGatewayDiagnosticsCapabilitiesGateRemoteCalls(t *testing.T) {
	for _, test := range []struct {
		name, method, path string
		disabled           []gateway.CapabilityName
	}{
		{"node", http.MethodPost, "/probes/nodes/node-1", []gateway.CapabilityName{gateway.CapabilityProbeNode}},
		{"group", http.MethodPost, "/probes/groups/group-1", []gateway.CapabilityName{gateway.CapabilityProbeGroup}},
		{"connections", http.MethodGet, "/connections", []gateway.CapabilityName{gateway.CapabilityConnectionsObserve}},
		{"counters", http.MethodGet, "/counters", []gateway.CapabilityName{gateway.CapabilityProxyCounters, gateway.CapabilityDirectCounters}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newDiagnosticsRemoteFixture(t)
			f.mu.Lock()
			for _, cap := range test.disabled {
				f.disabled[cap] = true
			}
			f.mu.Unlock()
			result := diagnosticsRequest(t, f.controller, test.method, "/api/v1/gateways/gateway-1"+test.path, "", http.StatusNotImplemented)
			encoded, _ := json.Marshal(result)
			if !strings.Contains(string(encoded), `"unsupported_capability"`) {
				t.Fatalf("missing typed capability refusal: %s", encoded)
			}
			if got, want := f.calls(), (map[string]int{"/v1/capabilities": 1}); !reflect.DeepEqual(got, want) {
				t.Fatalf("unsupported diagnostic contacted operation endpoint: %#v", got)
			}
		})
	}
}

func TestConfiguredGatewayDiagnosticsPartialCountersAreExplicitlyUnavailable(t *testing.T) {
	f := newDiagnosticsRemoteFixture(t)
	f.mu.Lock()
	f.disabled[gateway.CapabilityDirectCounters] = true
	f.mu.Unlock()
	result := diagnosticsRequest(t, f.controller, http.MethodGet, "/api/v1/gateways/gateway-1/counters", "", http.StatusOK)
	if !reflect.DeepEqual(result["direct"], map[string]any{"available": false}) || !reflect.DeepEqual(result["provider_quota"], map[string]any{"available": false}) {
		t.Fatalf("unavailable counters were represented as observed zeros: %#v", result)
	}
	proxy, ok := result["proxy"].(map[string]any)
	if !ok || proxy["available"] != true || proxy["bytes"] != "18446744073709551615" {
		t.Fatalf("available proxy counter was lost: %#v", result)
	}
	if got, want := f.calls(), (map[string]int{"/v1/capabilities": 1, "/v1/counters": 1}); !reflect.DeepEqual(got, want) {
		t.Fatalf("incorrect partial-counter remote requests: %#v", got)
	}
}

func TestConfiguredGatewayDiagnosticsRejectWrongTargetsBeforeRemoteCalls(t *testing.T) {
	f := newDiagnosticsRemoteFixture(t)
	if _, err := f.controller.Store.CreateGateway(context.Background(), domain.Gateway{ID: "other-gateway", Name: "Other gateway", Endpoint: f.registered.Endpoint}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.controller.Services.Outbounds.Create(outbounds.Group{ID: "other-group", Name: "Other group", GatewayID: "other-gateway", NodeIDs: []string{"other-node"}}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/probes/nodes/other-node", "/probes/nodes/missing-node", "/probes/groups/other-group", "/probes/groups/missing-group"} {
		diagnosticsRequest(t, f.controller, http.MethodPost, "/api/v1/gateways/gateway-1"+path, "", http.StatusNotFound)
	}
	if calls := f.calls(); len(calls) != 0 {
		t.Fatalf("wrong-target diagnostics contacted remote gateway: %#v", calls)
	}
}

func TestConfiguredGatewayDiagnosticsRejectUnconfiguredAndRemoteAuthentication(t *testing.T) {
	f := newDiagnosticsRemoteFixture(t)
	if _, err := f.controller.Store.CreateGateway(context.Background(), domain.Gateway{ID: "unconfigured", Name: "Unconfigured", Endpoint: f.registered.Endpoint}); err != nil {
		t.Fatal(err)
	}
	result := diagnosticsRequest(t, f.controller, http.MethodGet, "/api/v1/gateways/unconfigured/counters", "", http.StatusNotImplemented)
	encoded, _ := json.Marshal(result)
	if !strings.Contains(string(encoded), `"unsupported_capability"`) {
		t.Fatalf("unconfigured gateway did not give typed refusal: %s", encoded)
	}
	if calls := f.calls(); len(calls) != 0 {
		t.Fatalf("unconfigured gateway contacted remote agent: %#v", calls)
	}
	f.mu.Lock()
	f.rejectAuth = true
	f.mu.Unlock()
	for _, route := range []struct{ method, path string }{{http.MethodPost, "/probes/nodes/node-1"}, {http.MethodPost, "/probes/groups/group-1"}, {http.MethodGet, "/connections"}, {http.MethodGet, "/counters"}} {
		diagnosticsRequest(t, f.controller, route.method, "/api/v1/gateways/gateway-1"+route.path, "", http.StatusBadGateway)
	}
	if got, want := f.calls(), (map[string]int{"/v1/capabilities": 4}); !reflect.DeepEqual(got, want) {
		t.Fatalf("unauthorized capabilities led to diagnostic operation calls: %#v", got)
	}
}

type diagnosticsEndpointDriftStore struct{ store.Store }

func (s diagnosticsEndpointDriftStore) GetGateway(ctx context.Context, id string) (domain.Gateway, error) {
	registered, err := s.Store.GetGateway(ctx, id)
	if err == nil {
		registered.Endpoint = "https://untrusted-diagnostic-endpoint.invalid"
	}
	return registered, err
}

func TestConfiguredGatewayDiagnosticsRecheckEndpointBeforeEveryOperation(t *testing.T) {
	f := newDiagnosticsRemoteFixture(t)
	if f.controller.Services.GatewayDiagnostics == nil {
		t.Fatal("configured gateway did not install diagnostics resolver")
	}
	diagnostics, err := f.controller.Services.GatewayDiagnostics(context.Background(), f.registered)
	if err != nil {
		t.Fatal(err)
	}
	f.controller.Store = diagnosticsEndpointDriftStore{Store: f.controller.Store}
	for _, operation := range []struct {
		name string
		call func() error
	}{
		{"capabilities", func() error { _, err := diagnostics.Capabilities(context.Background()); return err }},
		{"probe node", func() error { _, err := diagnostics.ProbeNode(context.Background(), "node-1"); return err }},
		{"probe group", func() error { _, err := diagnostics.ProbeGroup(context.Background(), "group-1"); return err }},
		{"connections", func() error { _, err := diagnostics.ObserveConnections(context.Background()); return err }},
		{"counters", func() error { _, err := diagnostics.Counters(context.Background()); return err }},
	} {
		if err := operation.call(); err == nil {
			t.Errorf("retained diagnostics client ignored endpoint drift for %s", operation.name)
		}
	}
	for _, route := range []struct{ method, path string }{{http.MethodPost, "/probes/nodes/node-1"}, {http.MethodPost, "/probes/groups/group-1"}, {http.MethodGet, "/connections"}, {http.MethodGet, "/counters"}} {
		diagnosticsRequest(t, f.controller, route.method, "/api/v1/gateways/gateway-1"+route.path, "", http.StatusBadGateway)
	}
	if calls := f.calls(); len(calls) != 0 {
		t.Fatalf("endpoint tampering allowed credential-bearing remote requests: %#v", calls)
	}
}
