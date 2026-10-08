package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func writeGatewayConfigTestFile(t *testing.T, mode os.FileMode, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateways.json")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadGatewayConnectionsRejectsUnsafeFiles(t *testing.T) {
	tests := []struct {
		name string
		mode os.FileMode
		body string
	}{
		{name: "group readable", mode: 0o640, body: `{"gateways":[]}`},
		{name: "world readable", mode: 0o604, body: `{"gateways":[]}`},
		{name: "group writable", mode: 0o620, body: `{"gateways":[]}`},
		{name: "unknown field", mode: 0o600, body: `{"gateways":[],"secret":"x"}`},
		{name: "trailing JSON", mode: 0o600, body: `{"gateways":[]} {}`},
		{name: "invalid JSON", mode: 0o600, body: `{"token":"operator-private-token`},
		{name: "missing array", mode: 0o600, body: `{}`},
		{name: "null", mode: 0o600, body: `null`},
		{name: "oversized", mode: 0o600, body: strings.Repeat(" ", gatewayConfigLimit+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := readGatewayConnections(writeGatewayConfigTestFile(t, test.mode, test.body))
			if err == nil {
				t.Fatal("unsafe configuration was accepted")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("configuration error disclosed a secret field")
			}
		})
	}
}

type configuredTestIdentity struct {
	certFile string
	keyFile  string
	cert     *x509.Certificate
	key      ed25519.PrivateKey
}

func newConfiguredTestIdentity(t *testing.T, parent *configuredTestIdentity, usage x509.ExtKeyUsage) configuredTestIdentity {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "configured gateway test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	issuer, signingKey := template, private
	if parent == nil {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		issuer, signingKey = parent.cert, parent.key
		template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, public, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	identity := configuredTestIdentity{certFile: filepath.Join(dir, "cert.pem"), keyFile: filepath.Join(dir, "key.pem"), cert: cert, key: private}
	if err := os.WriteFile(identity.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity.keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestConfiguredGatewayReadsAuthenticatedLiveState(t *testing.T) {
	root := newConfiguredTestIdentity(t, nil, 0)
	clientIdentity := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageClientAuth)
	serverIdentity := newConfiguredTestIdentity(t, &root, x509.ExtKeyUsageServerAuth)
	serverTLS, err := gateway.LoadServerTLS(serverIdentity.certFile, serverIdentity.keyFile, root.certFile)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	wantCaps := gateway.Capabilities{Implementation: "qualified-test-agent", Version: "1", Items: []gateway.Capability{{Name: gateway.CapabilityProviderPublish, Supported: false}}}
	wantHealth := gateway.Health{Status: "degraded", Implementation: "qualified-test-agent", ObservedAt: time.Now().UTC()}
	agent := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 {
			t.Error("gateway read did not authenticate controller over TLS 1.3")
		}
		if r.Header.Get("Authorization") != "Bearer operator-private-token" {
			t.Error("gateway read omitted bearer authentication")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/capabilities":
			_ = json.NewEncoder(w).Encode(wantCaps)
		case "/v1/health":
			_ = json.NewEncoder(w).Encode(wantHealth)
		default:
			t.Errorf("unexpected agent request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	agent.TLS = serverTLS
	agent.StartTLS()
	defer agent.Close()
	connection := gatewayConnection{ID: "gateway-1", Endpoint: agent.URL, Token: "operator-private-token", ClientCert: clientIdentity.certFile, ClientKey: clientIdentity.keyFile, CAFile: root.certFile}
	data, err := json.Marshal(gatewayConnections{Gateways: []gatewayConnection{connection}})
	if err != nil {
		t.Fatal(err)
	}
	configPath := writeGatewayConfigTestFile(t, 0o600, string(data))
	controller := api.NewServer(store.NewMemoryStore(), nil)
	closeClients, err := configureGateways(context.Background(), controller, configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClients()
	if requests.Load() != 0 {
		t.Fatal("startup contacted a gateway before an observation was requested")
	}
	registered, err := controller.Store.CreateGateway(context.Background(), domain.Gateway{ID: connection.ID, Name: "Test gateway", Endpoint: agent.URL})
	if err != nil {
		t.Fatal(err)
	}
	caps, health, err := controller.Services.GatewayObserver(context.Background(), registered)
	if err != nil || caps.Implementation != wantCaps.Implementation || caps.Has(gateway.CapabilityProviderPublish) || health.Status != wantHealth.Status || !health.ObservedAt.Equal(wantHealth.ObservedAt) || requests.Load() != 2 {
		t.Fatalf("incorrect live observation: caps=%+v health=%+v err=%v requests=%d", caps, health, err, requests.Load())
	}
	if controller.Services.ProviderPublisher != nil || controller.Services.SelectionApplier != nil || controller.Services.ExecutorFactory != nil {
		t.Fatal("observation configuration enabled unqualified gateway mutations")
	}
	registered.Endpoint = "https://unexpected.test"
	_, _, err = controller.Services.GatewayObserver(context.Background(), registered)
	if err == nil || requests.Load() != 2 {
		t.Fatal("registered endpoint drift did not prevent credential-bearing requests")
	}
	registered.ID = "another-gateway"
	_, _, err = controller.Services.GatewayObserver(context.Background(), registered)
	if !errors.Is(err, gateway.ErrUnsupported) || requests.Load() != 2 {
		t.Fatal("unconfigured gateway did not remain unsupported")
	}
	for _, test := range []struct {
		name   string
		mutate func(*gatewayConnections)
	}{
		{"duplicate id", func(c *gatewayConnections) { c.Gateways = append(c.Gateways, connection) }},
		{"registered endpoint mismatch", func(c *gatewayConnections) { c.Gateways[0].Endpoint = "https://unexpected.test" }},
		{"missing id", func(c *gatewayConnections) { c.Gateways[0].ID = "" }},
		{"invalid bearer", func(c *gatewayConnections) { c.Gateways[0].Token += "\r\nprivate-secret" }},
		{"invalid TLS", func(c *gatewayConnections) { c.Gateways[0].ClientKey = "/missing/private-secret" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := gatewayConnections{Gateways: []gatewayConnection{connection}}
			test.mutate(&config)
			data, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			candidate := api.NewServer(controller.Store, nil)
			closeClients, err := configureGateways(context.Background(), candidate, writeGatewayConfigTestFile(t, 0o600, string(data)))
			if err == nil || closeClients != nil || candidate.Services.GatewayObserver != nil || requests.Load() != 2 {
				t.Fatalf("invalid registry partially installed or made requests: err=%v", err)
			}
			if strings.Contains(err.Error(), "operator-private-token") || strings.Contains(err.Error(), "private-secret") {
				t.Fatal("configuration error disclosed credentials")
			}
		})
	}
}

func TestConfigureGatewaysWithoutFileKeepsIntegrationDisabled(t *testing.T) {
	controller := api.NewServer(store.NewMemoryStore(), nil)
	closeClients, err := configureGateways(context.Background(), controller, "")
	if err != nil || closeClients == nil || controller.Services.GatewayObserver != nil {
		t.Fatalf("absent configuration did not leave integration disabled: %v", err)
	}
	closeClients()
}

func TestReadGatewayConnectionsRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "gateways.json")
	if err := os.WriteFile(target, []byte(`{"gateways":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readGatewayConnections(link); err == nil {
		t.Fatal("symlinked configuration was accepted")
	}
}
