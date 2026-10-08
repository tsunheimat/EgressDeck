package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

// This fixture uses the real gateway Client across authenticated TLS and the
// repository agent wire contract. FakeEngine supplies runtime state; no dae
// packet path or external gateway is modified by the test.
func TestConfiguredPolicyExecutorAndRestartReconciliationUseAuthenticatedReadback(t *testing.T) {
	root := newConfiguredTestIdentity(t, nil, 0)
	clientIdentity := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageClientAuth)
	serverIdentity := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageServerAuth)
	serverTLS, err := gateway.LoadServerTLS(serverIdentity.certFile, serverIdentity.keyFile, root.certFile)
	if err != nil {
		t.Fatal(err)
	}
	engine := gateway.NewFakeEngine()
	var mu sync.Mutex
	paths := []string{}
	agent := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || r.Header.Get("Authorization") != "Bearer policy-token" {
			t.Error("missing authenticated TLS identity")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var output any
		switch r.URL.Path {
		case "/v1/capabilities":
			caps, _ := engine.Capabilities(r.Context())
			caps.Implementation = "qualified-protocol-fixture"
			output = caps
		case "/v1/inventory":
			output, _ = engine.Inventory(r.Context())
		case "/v1/policies/validate":
			var p gateway.Policy
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Error(err)
			}
			if err := engine.ValidatePolicy(r.Context(), p); err != nil {
				t.Error(err)
			}
			output = map[string]bool{"valid": true}
		case "/v1/policies/apply":
			var input struct {
				Policy             gateway.Policy `json:"policy"`
				ExpectedGeneration int64          `json:"expected_generation"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			var err error
			output, err = engine.ApplyPolicyGeneration(r.Context(), input.Policy, input.ExpectedGeneration)
			if err != nil {
				t.Error(err)
			}
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(output)
	}))
	agent.TLS = serverTLS
	agent.StartTLS()
	defer agent.Close()
	controller := api.NewServer(store.NewMemoryStore(), nil)
	if _, err := controller.Store.CreateGateway(context.Background(), domain.Gateway{ID: "g1", Name: "fixture", Endpoint: agent.URL}); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "operations.json")
	journal, err := deployment.OpenFileJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	controller.Services.Journal = journal
	controller.Services.Runner = deployment.NewRunner(journal)
	connection := gatewayConnection{ID: "g1", Endpoint: agent.URL, Token: "policy-token", ClientCert: clientIdentity.certFile, ClientKey: clientIdentity.keyFile, CAFile: root.certFile, EnablePolicyApply: true, PolicyFormat: deployment.NativeDAEPolicyFormat}
	config, _ := json.Marshal(gatewayConnections{Gateways: []gatewayConnection{connection}})
	cleanup, err := configureGateways(context.Background(), controller, writeGatewayConfigTestFile(t, 0o600, string(config)))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	manifest := deployment.GatewayPolicyManifest{GatewayID: "g1", Format: deployment.NativeDAEPolicyFormat, Policy: gateway.Policy{ID: "native-artifact", Generation: 4, Payload: json.RawMessage(`{"native_config":"routing { fallback: block }"}`)}}
	req, err := deployment.GatewayPolicyRequest("apply", manifest)
	if err != nil {
		t.Fatal(err)
	}
	executor := controller.Services.ExecutorFactory(req.Target)
	if executor == nil {
		t.Fatal("operator policy configuration did not wire executor")
	}
	op, err := controller.Services.Runner.Submit(context.Background(), req, executor)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != deployment.StatusApplied || op.Views.Verified != nil {
		t.Fatalf("configuration readback improperly classified: %+v", op)
	}
	mu.Lock()
	mutationCount := 0
	for _, path := range paths {
		if path == "POST /v1/policies/apply" {
			mutationCount++
		}
	}
	mu.Unlock()
	if mutationCount != 1 {
		t.Fatalf("policy mutations=%d", mutationCount)
	}
	// Simulate a controller that persisted the request but lost its final ack.
	op.Status = deployment.StatusOutcomeUnknown
	op.Views.Applied = nil
	op.Views.Observed = nil
	op.Views.Verified = nil
	if err := journal.Save(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	reopened, err := deployment.OpenFileJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	restarted := api.NewServer(controller.Store, nil)
	restarted.Services.Journal = reopened
	restarted.Services.Runner = deployment.NewRunner(reopened)
	cleanup2, err := configureGateways(context.Background(), restarted, writeGatewayConfigTestFile(t, 0o600, string(config)))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup2()
	mu.Lock()
	before := len(paths)
	mu.Unlock()
	worker := newOperationReconciler(reopened, restarted.Services.ExecutorFactory, nil, reconciliationOptions{})
	worker.runner = restarted.Services.Runner
	if err := worker.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := reopened.Get(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != deployment.StatusApplied || recovered.Views.Observed == nil || recovered.Views.Verified != nil {
		t.Fatalf("restart result=%+v", recovered)
	}
	mu.Lock()
	after := append([]string(nil), paths[before:]...)
	mu.Unlock()
	if len(after) != 1 || after[0] != "GET /v1/inventory" {
		t.Fatalf("restart issued mutation or unneeded validation: %v", after)
	}
	// A policy-only executor cannot accidentally turn on strict enrollment.
	invalid := req
	invalid.Action = "enable"
	invalid.IdempotencyKey = "enrollment"
	_, err = restarted.Services.Runner.Submit(context.Background(), invalid, restarted.Services.ExecutorFactory(req.Target))
	if !errors.Is(err, gateway.ErrUnsupported) {
		t.Fatalf("native policy bridge accepted enrollment: %v", err)
	}
}
