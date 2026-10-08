package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/opnsense"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func TestOPNsenseExternalConfiguration(t *testing.T) {
	var reads atomic.Int32
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if r.Method != http.MethodGet || r.URL.Path != "/api/core/firmware/info" || !ok || user != "fixture-key" || password != "fixture-secret" {
			t.Errorf("unexpected OPNsense request: %s %s basic_auth=%v", r.Method, r.URL.Path, ok)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		reads.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"product_id": "opnsense", "product_version": opnsense.SupportedRelease})
	}))
	defer fixture.Close()
	root := t.TempDir()
	caPath := filepath.Join(root, "opnsense-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := opnsenseFileConfig{BaseURL: fixture.URL, APIKey: "fixture-key", APISecret: "fixture-secret", Release: opnsense.SupportedRelease, RootCAFile: caPath}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "opnsense.json")
	if err := os.WriteFile(configPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	server := api.NewServer(store.NewMemoryStore(), nil)
	cleanup, err := configureOPNsense(context.Background(), server, configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if server.Services.Firewall == nil || reads.Load() != 0 {
		t.Fatal("startup must install the adapter without contacting or mutating the appliance")
	}
	client, ok := server.Services.Firewall.Client().(*opnsense.HTTPClient)
	if !ok {
		t.Fatal("configured client is not the real native OPNsense HTTP adapter")
	}
	if err := client.VerifyConnection(context.Background()); err != nil {
		t.Fatalf("configured CA/credentials did not reach TLS fixture: %v", err)
	}
	if reads.Load() != 1 {
		t.Fatalf("connection read count=%d", reads.Load())
	}
}

func TestOPNsenseDisabledAndInvalidConfigurations(t *testing.T) {
	server := api.NewServer(store.NewMemoryStore(), nil)
	cleanup, err := configureOPNsense(context.Background(), server, "")
	if err != nil || cleanup == nil || server.Services.Firewall != nil {
		t.Fatalf("empty config should leave integration disabled: %v", err)
	}
	cleanup()
	for _, tc := range []struct {
		name, body string
		mode       os.FileMode
	}{
		{"public mode", `{}`, 0o644},
		{"group access", `{}`, 0o640},
		{"no version", `{"base_url":"https://opnsense.example","api_key":"test-key","api_secret":"test-secret"}`, 0o600},
		{"wrong version", `{"base_url":"https://opnsense.example","api_key":"test-key","api_secret":"test-secret","release":"wrong"}`, 0o600},
		{"plaintext http", `{"base_url":"http://opnsense.example","api_key":"test-key","api_secret":"test-secret","release":"26.7"}`, 0o600},
		{"unknown field", `{"insecure_skip_verify":true}`, 0o600},
		{"trailing json", `{} {}`, 0o600},
		{"trailing malformed", `{} trailing-secret`, 0o600},
		{"null", `null`, 0o600},
		{"array", `[]`, 0o600},
		{"oversized", `{"api_secret":"` + strings.Repeat("s", 1<<20) + `"}`, 0o600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "opnsense.json")
			if err := os.WriteFile(path, []byte(tc.body), tc.mode); err != nil {
				t.Fatal(err)
			}
			server := api.NewServer(store.NewMemoryStore(), nil)
			cleanup, err := configureOPNsense(context.Background(), server, path)
			if cleanup != nil {
				cleanup()
			}
			if err == nil || server.Services.Firewall != nil || strings.Contains(err.Error(), "test-secret") || strings.Contains(err.Error(), "trailing-secret") {
				t.Fatalf("invalid config accepted or leaked: err=%v configured=%v", err, server.Services.Firewall != nil)
			}
		})
	}
}
