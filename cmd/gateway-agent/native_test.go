package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

func TestNativeStageWirePreservesPrivateConnection(t *testing.T) {
	for _, body := range []string{
		`{"provider_id":"p","revision":2,"expected_generation":4,"nodes":[{"id":"n","connection":"socks5://private-password@192.0.2.1:1080"}],"groups":[{"id":"g","name":"native-g","candidate_ids":["n"],"selected_node_id":"n"}]}`,
		`{"revision":{"provider_id":"p","revision":2,"nodes":[{"id":"n","connection":"socks5://private-password@192.0.2.1:1080"}],"groups":[{"id":"g","name":"native-g","candidate_ids":["n"],"selected_node_id":"n"}]},"expected_generation":4}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/v1/providers/stage", strings.NewReader(body))
		got, err := decodeStageRequest(req)
		if err != nil || got.ExpectedGeneration != 4 || got.Revision.Nodes[0].Connection != "socks5://private-password@192.0.2.1:1080" || got.Revision.Groups[0].Name != "native-g" {
			t.Fatalf("private wire decode failed: %v", err)
		}
		encoded, _ := json.Marshal(got.Revision)
		if strings.Contains(string(encoded), "private-password") {
			t.Fatal("public revision serialized private connection")
		}
	}
}
func TestNativeJournalEndpointWithholdsRecoveryMaterial(t *testing.T) {
	journal := gateway.NewMemoryJournal()
	_ = journal.Append(context.Background(), gateway.JournalEntry{Operation: "native.state", Status: "staged", State: json.RawMessage(`{"ciphertext":"sensitive-recovery-material"}`)})
	a := &agent{engine: gateway.NewFakeEngine(), journal: journal, token: "token"}
	req := httptest.NewRequest(http.MethodGet, "/v1/journal", nil)
	req.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	a.routes().ServeHTTP(response, req)
	if response.Code != 200 || strings.Contains(response.Body.String(), "sensitive-recovery-material") || strings.Contains(response.Body.String(), "ciphertext") {
		t.Fatalf("recovery material leaked: %s", response.Body.String())
	}
	entries, _ := journal.Entries(context.Background())
	if len(entries[0].State) == 0 {
		t.Fatal("response redaction erased recoverable state")
	}
}
