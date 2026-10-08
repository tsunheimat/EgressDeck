package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/auth"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/opnsense"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

const testFirewallAttach = `{"id":"binding-1","gateway_id":"gw","alias":"managed","family":"ipv4","interface_scope":"lan","rule_ids":["rule-1"]}`

func firewallTestServer(t *testing.T) (*Server, *opnsense.FakeClient, *httptest.Server) {
	t.Helper()
	s := NewServer(store.NewMemoryStore(), nil)
	if _, err := s.Store.CreateGateway(context.Background(), domain.Gateway{ID: "gw", Name: "Gateway", Endpoint: "https://gateway.example.invalid", Adapter: "dae"}); err != nil {
		t.Fatal(err)
	}
	client := opnsense.NewFakeClient(opnsense.AliasRecord{Name: "managed", UUID: "alias-1", Type: opnsense.HostAlias, Addresses: []string{"192.0.2.1"}})
	adapter, err := opnsense.NewAdapter(client)
	if err != nil {
		t.Fatal(err)
	}
	s.Services.Firewall = adapter
	server := httptest.NewServer(s.Handler())
	t.Cleanup(server.Close)
	return s, client, server
}

func getFirewallJSON(t *testing.T, endpoint string, output any) {
	t.Helper()
	response, err := http.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("GET %s = %d: %s", endpoint, response.StatusCode, body)
	}
	if err := json.NewDecoder(response.Body).Decode(output); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallListOverviewAndDetailsShareActualReadback(t *testing.T) {
	_, client, server := firewallTestServer(t)
	body := postJSON(t, server.URL+"/api/v1/firewall-bindings", testFirewallAttach, http.StatusCreated)
	var attached struct {
		View     FirewallBindingView `json:"view"`
		Verified bool                `json:"verified"`
	}
	if err := json.Unmarshal(body, &attached); err != nil {
		t.Fatal(err)
	}
	if attached.View.ActiveCount == nil || *attached.View.ActiveCount != 1 || attached.View.PersistedCount == nil || *attached.View.PersistedCount != 1 || attached.View.Drift == nil || *attached.View.Drift || attached.View.State != "observed" || attached.View.ObservationStatus != "fresh" || attached.View.ObservedAt == nil || attached.Verified || attached.View.Verified {
		t.Fatalf("attach projection=%+v", attached)
	}
	var listed struct {
		Items []FirewallBindingView `json:"items"`
	}
	getFirewallJSON(t, server.URL+"/api/v1/firewall-bindings", &listed)
	if len(listed.Items) != 1 || listed.Items[0].DesiredCount != 1 || listed.Items[0].Alias != "managed" {
		t.Fatalf("list=%+v", listed)
	}
	var detail FirewallBindingView
	getFirewallJSON(t, server.URL+"/api/v1/firewall-bindings/binding-1", &detail)
	if detail.ID != "binding-1" || detail.ActiveCount == nil || *detail.ActiveCount != 1 {
		t.Fatalf("detail=%+v", detail)
	}
	var overview struct {
		Bindings []FirewallBindingView `json:"bindings"`
	}
	getFirewallJSON(t, server.URL+"/api/v1/overview", &overview)
	if len(overview.Bindings) != 1 || overview.Bindings[0].ObservedAt == nil || !overview.Bindings[0].ObservedAt.Equal(*attached.View.ObservedAt) {
		t.Fatalf("overview=%+v", overview)
	}
	if len(client.Calls()) != 0 {
		t.Fatalf("attach/readback mutated firewall: %#v", client.Calls())
	}
}

func TestFirewallReadbackCachesDriftAndRetainsLastObservationOnError(t *testing.T) {
	_, client, server := firewallTestServer(t)
	postJSON(t, server.URL+"/api/v1/firewall-bindings", testFirewallAttach, http.StatusCreated)
	if err := client.SetActive("managed", opnsense.AliasRecord{Name: "managed", UUID: "alias-1", Type: opnsense.HostAlias, Addresses: []string{}}); err != nil {
		t.Fatal(err)
	}
	var readback struct {
		View     FirewallBindingView `json:"view"`
		Verified bool                `json:"verified"`
	}
	getFirewallJSON(t, server.URL+"/api/v1/firewall-bindings/binding-1/readback", &readback)
	if readback.View.ActiveCount == nil || *readback.View.ActiveCount != 0 || readback.View.PersistedCount == nil || *readback.View.PersistedCount != 1 || readback.View.Drift == nil || !*readback.View.Drift || readback.Verified {
		t.Fatalf("drift projection=%+v", readback)
	}
	client.ReadActiveErr = errors.New("transport failure with private api-secret/token")
	response, err := http.Get(server.URL + "/api/v1/firewall-bindings/binding-1/readback")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway || bytes.Contains(body, []byte("api-secret")) {
		t.Fatalf("failure=%d %s", response.StatusCode, body)
	}
	var detail FirewallBindingView
	getFirewallJSON(t, server.URL+"/api/v1/firewall-bindings/binding-1", &detail)
	if detail.ObservationStatus != "error" || detail.ObservationError == "" || detail.ActiveCount == nil || *detail.ActiveCount != 0 || detail.ObservedAt == nil || !detail.ObservedAt.Equal(*readback.View.ObservedAt) || detail.LastAttemptAt == nil || detail.Verified {
		t.Fatalf("cached failure=%+v", detail)
	}
	client.ReadActiveErr = nil
	getFirewallJSON(t, server.URL+"/api/v1/firewall-bindings/binding-1/readback", &readback)
	if readback.View.ObservationStatus != "fresh" || readback.View.ObservationError != "" {
		t.Fatalf("recovered=%+v", readback)
	}
	if len(client.Calls()) != 0 {
		t.Fatal("readback mutated firewall")
	}
}

func TestFirewallUnknownAndStaleObservationsAreExplicit(t *testing.T) {
	s, _, server := firewallTestServer(t)
	binding := opnsense.Binding{ID: "restored", GatewayID: "gw", Alias: opnsense.AliasShape{Name: "managed", Type: opnsense.HostAlias}, Family: opnsense.IPv4Family, InterfaceScope: "lan"}
	s.Services.mu.Lock()
	s.Services.bindings[binding.ID] = binding
	s.Services.mu.Unlock()
	var raw map[string]any
	getFirewallJSON(t, server.URL+"/api/v1/firewall-bindings/restored", &raw)
	for _, field := range []string{"active_count", "persisted_count", "drift", "observed_at"} {
		if _, ok := raw[field]; ok {
			t.Fatalf("unobserved binding invented %s: %v", field, raw)
		}
	}
	if raw["observation_status"] != "never_read" || raw["state"] != "desired" || raw["verified"] != false {
		t.Fatalf("unobserved=%v", raw)
	}
	observedAt := time.Now().UTC().Add(-firewallObservationTTL - time.Second)
	view := firewallView(binding, firewallObservation{Readback: &opnsense.Readback{ReadAt: observedAt}}, time.Now().UTC())
	if view.ObservationStatus != "stale" || view.ActiveCount == nil || *view.ActiveCount != 0 || view.Verified {
		t.Fatalf("stale=%+v", view)
	}
}

func TestFirewallDuplicateAttachCannotReplaceIntent(t *testing.T) {
	s, client, server := firewallTestServer(t)
	if _, err := s.Store.CreateGateway(context.Background(), domain.Gateway{ID: "other-gateway", Name: "Other gateway", Endpoint: "https://other.example.invalid", Adapter: "dae"}); err != nil {
		t.Fatal(err)
	}
	postJSON(t, server.URL+"/api/v1/firewall-bindings", testFirewallAttach, http.StatusCreated)
	postJSON(t, server.URL+"/api/v1/firewall-bindings", strings.Replace(testFirewallAttach, `"gw"`, `"other-gateway"`, 1), http.StatusConflict)
	postJSON(t, server.URL+"/api/v1/firewall-bindings", strings.Replace(testFirewallAttach, `"binding-1"`, `"binding-2"`, 1), http.StatusConflict)
	s.Services.mu.RLock()
	defer s.Services.mu.RUnlock()
	if len(s.Services.bindings) != 1 || s.Services.bindings["binding-1"].GatewayID != "gw" || len(client.Calls()) != 0 {
		t.Fatalf("duplicate replaced binding or mutated alias")
	}
}

func TestFirewallAttachRequiresRegisteredGateway(t *testing.T) {
	s, client, server := firewallTestServer(t)
	postJSON(t, server.URL+"/api/v1/firewall-bindings", strings.Replace(testFirewallAttach, `"gw"`, `"missing-gateway"`, 1), http.StatusUnprocessableEntity)
	s.Services.mu.RLock()
	defer s.Services.mu.RUnlock()
	if len(s.Services.bindings) != 0 || len(client.Calls()) != 0 {
		t.Fatal("unknown gateway was attached or firewall was mutated")
	}
}

type delayedFirewallReadback struct {
	started, release chan struct{}
	reads            atomic.Int32
}

func (c *delayedFirewallReadback) ReadPersistedAlias(context.Context, string) (opnsense.AliasRecord, error) {
	return opnsense.AliasRecord{Name: "managed", Type: opnsense.HostAlias, Addresses: []string{"192.0.2.1"}}, nil
}
func (c *delayedFirewallReadback) ReadActiveAlias(context.Context, string) (opnsense.AliasRecord, error) {
	if c.reads.Add(1) == 1 {
		close(c.started)
		<-c.release
		return opnsense.AliasRecord{Name: "managed", Type: opnsense.HostAlias, Addresses: []string{"192.0.2.1"}}, nil
	}
	return opnsense.AliasRecord{Name: "managed", Type: opnsense.HostAlias, Addresses: []string{"192.0.2.1", "192.0.2.2"}}, nil
}
func (c *delayedFirewallReadback) AddAliasAddresses(context.Context, string, []string) error {
	panic("readback must not mutate")
}
func (c *delayedFirewallReadback) DeleteAliasAddresses(context.Context, string, []string) error {
	panic("readback must not mutate")
}

func TestFirewallLateReadbackCannotReplaceNewerObservation(t *testing.T) {
	s := NewServer(store.NewMemoryStore(), nil)
	client := &delayedFirewallReadback{started: make(chan struct{}), release: make(chan struct{})}
	s.Services.Firewall, _ = opnsense.NewAdapter(client)
	s.Services.bindings["binding-1"] = opnsense.Binding{ID: "binding-1", GatewayID: "gw", Alias: opnsense.AliasShape{Name: "managed", Type: opnsense.HostAlias}, Family: opnsense.IPv4Family, InterfaceScope: "lan", ManagedAddresses: []string{"192.0.2.1"}}
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		response, err := http.Get(server.URL + "/api/v1/firewall-bindings/binding-1/readback")
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-client.started:
	case <-time.After(time.Second):
		t.Fatal("first readback did not start")
	}
	var latest struct {
		View FirewallBindingView `json:"view"`
	}
	getFirewallJSON(t, server.URL+"/api/v1/firewall-bindings/binding-1/readback", &latest)
	close(client.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var detail FirewallBindingView
	getFirewallJSON(t, server.URL+"/api/v1/firewall-bindings/binding-1", &detail)
	if detail.ActiveCount == nil || *detail.ActiveCount != 2 || detail.Drift == nil || !*detail.Drift || !detail.ObservedAt.Equal(*latest.View.ObservedAt) {
		t.Fatalf("late response replaced newest observation: %+v", detail)
	}
}

func TestFirewallRolesAtAuthenticatedBoundary(t *testing.T) {
	s := NewServer(store.NewMemoryStore(), nil)
	if _, err := s.Store.CreateGateway(context.Background(), domain.Gateway{ID: "gw", Name: "Gateway", Endpoint: "https://gateway.example.invalid", Adapter: "dae"}); err != nil {
		t.Fatal(err)
	}
	client := opnsense.NewFakeClient(opnsense.AliasRecord{Name: "managed", Type: opnsense.HostAlias})
	s.Services.Firewall, _ = opnsense.NewAdapter(client)
	manager := auth.NewSessionManager(bytes.Repeat([]byte{3}, 32), auth.WithSecureCookies(false))
	middleware := auth.NewMiddleware(manager)
	handler := s.Handler()
	authenticated := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.Require(auth.RequiredRole(r))(middleware.CSRF(handler)).ServeHTTP(w, r)
	})
	request := func(role auth.Role, method, path, body string, csrf bool) *httptest.ResponseRecorder {
		session, err := manager.Issue("test-"+string(role), role)
		if err != nil {
			t.Fatal(err)
		}
		login := httptest.NewRecorder()
		if err := manager.SetSession(login, session); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for _, cookie := range login.Result().Cookies() {
			req.AddCookie(cookie)
		}
		if csrf {
			req.Header.Set("X-CSRF-Token", session.CSRFToken)
		}
		recorder := httptest.NewRecorder()
		authenticated.ServeHTTP(recorder, req)
		return recorder
	}
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator} {
		if response := request(role, "POST", "/api/v1/firewall-bindings", testFirewallAttach, true); response.Code != 403 {
			t.Fatalf("role %s attach=%d", role, response.Code)
		}
	}
	if response := request(auth.RoleAdmin, "POST", "/api/v1/firewall-bindings", testFirewallAttach, false); response.Code != 403 {
		t.Fatalf("no CSRF attach=%d", response.Code)
	}
	if response := request(auth.RoleAdmin, "POST", "/api/v1/firewall-bindings", testFirewallAttach, true); response.Code != 201 {
		t.Fatalf("admin attach=%d %s", response.Code, response.Body.String())
	}
	if response := request(auth.RoleViewer, "GET", "/api/v1/firewall-bindings/binding-1/readback", "", false); response.Code != 200 {
		t.Fatalf("viewer readback=%d %s", response.Code, response.Body.String())
	}
	if len(client.Calls()) != 0 {
		t.Fatal("attach or readback mutated firewall")
	}
}
