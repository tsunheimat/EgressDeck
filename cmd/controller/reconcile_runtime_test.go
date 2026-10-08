package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func TestRuntimeReconciliationUsesOnlyTLSReadbackAndPersistsLocalCompletion(t *testing.T) {
	for _, action := range []string{"publish", "selection"} {
		t.Run(action, func(t *testing.T) {
			ctx := context.Background()
			root := newConfiguredTestIdentity(t, nil, 0)
			clientIdentity := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageClientAuth)
			serverIdentity := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageServerAuth)
			serverTLS, err := gateway.LoadServerTLS(serverIdentity.certFile, serverIdentity.keyFile, root.certFile)
			if err != nil {
				t.Fatal(err)
			}
			var snapshot gateway.Snapshot
			var calls []string
			var callsMu sync.Mutex
			remote := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callsMu.Lock()
				calls = append(calls, r.Method+" "+r.URL.Path)
				callsMu.Unlock()
				if r.Method != "GET" || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || r.Header.Get("Authorization") != "Bearer recovery-token" {
					t.Errorf("unsafe remote call %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/capabilities":
					_ = json.NewEncoder(w).Encode(gateway.DefaultCapabilities("qualified-fixture", "1"))
				case "/v1/readback":
					_ = json.NewEncoder(w).Encode(snapshot)
				default:
					t.Errorf("unexpected route %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			remote.TLS = serverTLS
			remote.StartTLS()
			defer remote.Close()
			storage, err := store.NewFileStore(filepath.Join(t.TempDir(), "store.json"))
			if err != nil {
				t.Fatal(err)
			}
			controller := api.NewServer(storage, nil)
			vault, err := secrets.New("test", bytes.Repeat([]byte{7}, 32))
			if err != nil {
				t.Fatal(err)
			}
			if err := controller.Services.Load(ctx, storage, vault); err != nil {
				t.Fatal(err)
			}
			j, err := deployment.OpenEncryptedFileJournal(filepath.Join(t.TempDir(), "operations.json"), vault)
			if err != nil {
				t.Fatal(err)
			}
			controller.Services.Journal = j
			controller.Services.Runner = deployment.NewRunner(j)
			if _, err := storage.CreateGateway(ctx, domain.Gateway{ID: "g1", Name: "gateway", Endpoint: remote.URL}); err != nil {
				t.Fatal(err)
			}
			revision, _, err := controller.Services.Providers.Stage("p1", []byte("trojan://private-test-password@node.example:443#test"), providers.FormatLinks)
			if err != nil {
				t.Fatal(err)
			}
			nodeID := revision.Nodes[0].ID
			if _, err := controller.Services.Outbounds.Create(outbounds.Group{ID: "group1", Name: "group", GatewayID: "g1", NodeIDs: []string{nodeID}, Mode: outbounds.SelectionManual, Replacement: outbounds.ReplacementBlock}); err != nil {
				t.Fatal(err)
			}
			if _, err := controller.Services.Outbounds.SetDesired("group1", outbounds.Scope{GatewayID: "g1", Transport: "tcp"}, nodeID, 0); err != nil {
				t.Fatal(err)
			}
			snapshot = gateway.Snapshot{Generation: 3, Providers: map[string]gateway.ProviderRevision{"p1": {ProviderID: "p1", Revision: revision.Number, ContentHash: revisionIdentity("p1", revision.Number), Nodes: []gateway.Node{{ID: nodeID, ProviderID: "p1"}}}}, Groups: map[string]gateway.OutboundGroup{"group1": {ID: "group1", Name: "native-group", Revision: 1, NodeIDs: []string{nodeID}}}, Selections: map[string]gateway.Selection{"both": {Scope: gateway.SelectionScope{GatewayID: "g1", GroupID: "group1", Transport: "both"}, DesiredNodeID: nodeID, ObservedNodeID: nodeID, Revision: 2}}}
			clientTLS, err := gateway.LoadClientTLS(clientIdentity.certFile, clientIdentity.keyFile, root.certFile, "")
			if err != nil {
				t.Fatal(err)
			}
			client, err := gateway.NewClient(gateway.ClientOptions{Endpoint: remote.URL, Token: "recovery-token", TLSConfig: clientTLS})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			connections := map[string]configuredGateway{"g1": {endpoint: remote.URL, client: client, runtime: gatewayRuntimeConfig{EnableProviderPublish: true, EnableSelection: true, ExpectedImplementation: "qualified-fixture", SharedTransportSelection: true, Groups: map[string]gatewayRuntimeGroup{"group1": {Name: "native-group", InitialNodeID: nodeID}}}}}
			if err := configurePolicyExecutors(controller, connections); err != nil {
				t.Fatal(err)
			}
			target := deployment.Target{Kind: "provider", ID: "p1"}
			intent, _ := json.Marshal(providerRecoveryIntent{ProviderID: "p1", Revision: revision.Number, ContentHash: revision.Hash, GatewayIDs: []string{"g1"}})
			if action == "selection" {
				target = deployment.Target{Kind: "outbound_group", ID: "group1"}
				intent, _ = json.Marshal(selectionRecoveryIntent{NodeID: nodeID, GatewayID: "g1", TransportScopes: []string{"tcp"}})
			}
			f, err := j.NextFence(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			op, err := j.Create(ctx, deployment.Operation{ID: "uncertain", Target: target, Action: action, FenceToken: f.Token, Status: deployment.StatusOutcomeUnknown, Views: deployment.StateViews{Desired: &deployment.StateRecord{Revision: "1", Data: intent}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := controller.Services.Persist(ctx); err != nil {
				t.Fatal(err)
			}
			worker := newOperationReconciler(j, controller.Services.ExecutorFactory, nil, reconciliationOptions{})
			worker.runner = controller.Services.Runner
			worker.complete = controller.Services.CompleteOperationReadback
			if err := worker.Sweep(ctx); err != nil {
				t.Fatal(err)
			}
			completed, err := j.Get(ctx, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			if completed.Status != deployment.StatusApplied || completed.Views.Verified != nil {
				t.Fatalf("recovery outcome=%+v", completed)
			}
			restored := api.NewServices()
			if err := restored.Load(ctx, storage, vault); err != nil {
				t.Fatal(err)
			}
			if action == "publish" {
				if restored.Providers.Status("p1").Active != revision.Number {
					t.Fatal("observed provider not durably active")
				}
			} else {
				selected, err := restored.Outbounds.GetSelection("group1", outbounds.Scope{GatewayID: "g1", Transport: "tcp"})
				if err != nil || selected.AppliedNodeID != nodeID || selected.ObservedNodeID != nodeID {
					t.Fatalf("observed selection not durable: %+v %v", selected, err)
				}
			}
			callsMu.Lock()
			defer callsMu.Unlock()
			if len(calls) != 2 || calls[0] != "GET /v1/capabilities" || calls[1] != "GET /v1/readback" {
				t.Fatalf("reconciliation called mutation path: %v", calls)
			}
		})
	}
}
