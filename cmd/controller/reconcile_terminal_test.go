package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

// This exercises controller journal -> authenticated gateway resolution ->
// lifecycle persistence -> terminal journal ordering. The fixture models an
// authoritative gateway receipt, never an unchanged generation heuristic.
func TestRuntimeReconciliationTerminatesRejectedSelectionAcrossControllerRestart(t *testing.T) {
	for _, fault := range []string{"before_controller_state", "before_send", "before_commit", "lost_ack", "unknown", "wrong_identity"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			root := newConfiguredTestIdentity(t, nil, 0)
			clientID := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageClientAuth)
			serverID := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageServerAuth)
			serverTLS, err := gateway.LoadServerTLS(serverID.certFile, serverID.keyFile, root.certFile)
			if err != nil {
				t.Fatal(err)
			}
			var expected gateway.MutationIdentity
			var calls []string
			var mu sync.Mutex
			remote := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				calls = append(calls, r.Method+" "+r.URL.Path)
				if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || r.Header.Get("Authorization") != "Bearer recovery-token" {
					t.Error("unauthenticated recovery")
					w.WriteHeader(403)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/resolve"):
					if r.Method != http.MethodPost || r.URL.Path != "/v1/mutations/"+expected.ID+"/resolve" || r.Header.Get("X-EgressDeck-Mutation-Hash") != expected.RequestHash || r.Header.Get("X-EgressDeck-Mutation-Fence") != strconv.FormatUint(expected.FenceToken, 10) {
						t.Error("operation correlation lost")
						w.WriteHeader(400)
						return
					}
					receipt := gateway.MutationReceipt{Identity: expected, State: gateway.MutationRejected}
					if fault == "lost_ack" {
						receipt.State = gateway.MutationCommitted
						receipt.Generation = 8
					}
					if fault == "unknown" {
						receipt.State = gateway.MutationUnknown
					}
					if fault == "wrong_identity" {
						receipt.Identity.FenceToken++
					}
					_ = json.NewEncoder(w).Encode(receipt)
				case r.URL.Path == "/v1/capabilities":
					_ = json.NewEncoder(w).Encode(gateway.DefaultCapabilities("recovery-native", "1"))
				case r.URL.Path == "/v1/readback":
					_ = json.NewEncoder(w).Encode(gateway.Snapshot{Generation: 8, Groups: map[string]gateway.OutboundGroup{"g": {ID: "g", Name: "native-group", Revision: 1, NodeIDs: []string{"a", "b"}}}, Selections: map[string]gateway.Selection{"both": {Scope: gateway.SelectionScope{GatewayID: "gw", GroupID: "g", Transport: "both"}, DesiredNodeID: "b", ObservedNodeID: "b", Revision: 3}}})
				default:
					t.Errorf("unexpected mutation %s %s", r.Method, r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			remote.TLS = serverTLS
			remote.StartTLS()
			defer remote.Close()
			storagePath, journalPath := filepath.Join(t.TempDir(), "store.json"), filepath.Join(t.TempDir(), "journal.json")
			storage, err := store.NewFileStore(storagePath)
			if err != nil {
				t.Fatal(err)
			}
			vault, _ := secrets.New("test", bytes.Repeat([]byte{7}, 32))
			server := api.NewServer(storage, nil)
			if err := server.Services.Load(ctx, storage, vault); err != nil {
				t.Fatal(err)
			}
			journal, err := deployment.OpenEncryptedFileJournal(journalPath, vault)
			if err != nil {
				t.Fatal(err)
			}
			server.Services.Journal, server.Services.Runner = journal, deployment.NewRunner(journal)
			if _, err := storage.CreateGateway(ctx, domain.Gateway{ID: "gw", Name: "gateway", Endpoint: remote.URL}); err != nil {
				t.Fatal(err)
			}
			if _, err := server.Services.Outbounds.Create(outbounds.Group{ID: "g", Name: "group", GatewayID: "gw", NodeIDs: []string{"a", "b"}}); err != nil {
				t.Fatal(err)
			}
			prior := map[string]*outbounds.Selection{}
			for _, transport := range []string{"tcp", "udp"} {
				scope := outbounds.Scope{GatewayID: "gw", Transport: transport}
				old, err := server.Services.Outbounds.SetDesired("g", scope, "a", 0)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = server.Services.Outbounds.MarkApplied("g", scope, "a", 7)
				old, _ = server.Services.Outbounds.Observe("g", scope, "a", 7)
				prior[transport] = &old
			}
			if err := server.Services.Persist(ctx); err != nil {
				t.Fatal(err)
			}
			intentData, _ := json.Marshal(selectionRecoveryIntent{NodeID: "b", GatewayID: "gw", TransportScopes: []string{"tcp", "udp"}, ExpectedRevision: 1})
			previousData, _ := json.Marshal(prior)
			digest := sha256.Sum256(intentData)
			target := deployment.Target{Kind: "outbound_group", ID: "g"}
			fence, _ := journal.NextFence(ctx, target)
			op, err := journal.Create(ctx, deployment.Operation{ID: "selection-recovery", Target: target, Action: "selection", FenceToken: fence.Token, RequestHash: hex.EncodeToString(digest[:]), Status: deployment.StatusOutcomeUnknown, Views: deployment.StateViews{Desired: &deployment.StateRecord{Data: intentData}, Previous: &deployment.StateRecord{Data: previousData}}})
			if err != nil {
				t.Fatal(err)
			}
			expected = api.OperationMutationIdentity(op)
			if fault != "before_controller_state" {
				for _, transport := range []string{"tcp", "udp"} {
					if _, err := server.Services.Outbounds.SetDesired("g", outbounds.Scope{GatewayID: "gw", Transport: transport}, "b", 1); err != nil {
						t.Fatal(err)
					}
				}
				if err := server.Services.Persist(ctx); err != nil {
					t.Fatal(err)
				}
			}
			// Restart both durable controller stores before recovery.
			storage, err = store.NewFileStore(storagePath)
			if err != nil {
				t.Fatal(err)
			}
			journal, err = deployment.OpenEncryptedFileJournal(journalPath, vault)
			if err != nil {
				t.Fatal(err)
			}
			server = api.NewServer(storage, nil)
			if err := server.Services.Load(ctx, storage, vault); err != nil {
				t.Fatal(err)
			}
			server.Services.Journal, server.Services.Runner = journal, deployment.NewRunner(journal)
			clientTLS, _ := gateway.LoadClientTLS(clientID.certFile, clientID.keyFile, root.certFile, "")
			client, err := gateway.NewClient(gateway.ClientOptions{Endpoint: remote.URL, Token: "recovery-token", TLSConfig: clientTLS})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			connections := map[string]configuredGateway{"gw": {endpoint: remote.URL, client: client, runtime: gatewayRuntimeConfig{EnableSelection: true, ExpectedImplementation: "recovery-native", SharedTransportSelection: true, Groups: map[string]gatewayRuntimeGroup{"g": {Name: "native-group"}}}}}
			if err := configurePolicyExecutors(server, connections); err != nil {
				t.Fatal(err)
			}
			worker := newOperationReconciler(journal, server.Services.ExecutorFactory, nil, reconciliationOptions{})
			worker.runner, worker.complete = server.Services.Runner, server.Services.CompleteOperationReadback
			worker.guard = server.Services.OperationReadback
			sweepErr := worker.Sweep(ctx)
			unresolved := fault == "unknown" || fault == "wrong_identity"
			if (sweepErr != nil) != unresolved {
				t.Fatalf("sweep=%v", sweepErr)
			}
			result, _ := journal.Get(ctx, op.ID)
			wantStatus := deployment.StatusFailed
			if unresolved {
				wantStatus = deployment.StatusOutcomeUnknown
			}
			if fault == "lost_ack" {
				wantStatus = deployment.StatusApplied
			}
			if result.Status != wantStatus {
				t.Fatalf("status=%s want=%s", result.Status, wantStatus)
			}
			restored := api.NewServices()
			if err := restored.Load(ctx, storage, vault); err != nil {
				t.Fatal(err)
			}
			for _, transport := range []string{"tcp", "udp"} {
				selection, err := restored.Outbounds.GetSelection("g", outbounds.Scope{GatewayID: "gw", Transport: transport})
				if err != nil {
					t.Fatal(err)
				}
				wantNode, wantApplied := "a", "a"
				if unresolved || fault == "lost_ack" {
					wantNode = "b"
				}
				if fault == "lost_ack" {
					wantApplied = "b"
				}
				if selection.DesiredNodeID != wantNode || selection.AppliedNodeID != wantApplied || selection.ObservedNodeID != wantApplied {
					t.Fatalf("selection not durable: %+v", selection)
				}
			}
			mu.Lock()
			callCount := len(calls)
			mu.Unlock()
			if !unresolved {
				if err := worker.Sweep(ctx); err != nil {
					t.Fatal(err)
				}
				mu.Lock()
				if len(calls) != callCount {
					t.Error("terminal recovery repeated remote request")
				}
				mu.Unlock()
			}
		})
	}
}
