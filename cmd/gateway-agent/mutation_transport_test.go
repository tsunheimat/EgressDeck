package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

func mutationTransportTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mutation test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "mutation peer"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	if err != nil {
		t.Fatal(err)
	}
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	client := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: pool}
	return server, client
}

// Real gateway.Client -> agent routes over mutually authenticated TLS. The
// optional engine double records context identity; it does not emulate native
// daemon transaction recovery, which has separate process-boundary tests.
func TestAgentMutationClientRoundTripUsesProductionTransport(t *testing.T) {
	engine := &mutationAgentEngine{Engine: gateway.NewFakeEngine(), state: gateway.MutationUnknown}
	a := &agent{engine: engine, token: "mutation-test-token"}
	serverTLS, clientTLS := mutationTransportTLS(t)
	routes := a.routes()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 {
			t.Error("unverified client transport")
		}
		routes.ServeHTTP(w, r)
	}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	client, err := gateway.NewClient(gateway.ClientOptions{Endpoint: server.URL, Token: "mutation-test-token", TLSConfig: clientTLS})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	identity := agentMutationIdentity()
	ctx := gateway.WithMutationIdentity(context.Background(), identity)
	receipt, err := client.MutationStatus(ctx, identity)
	if err != nil || receipt.State != gateway.MutationUnknown || engine.seen != identity {
		t.Fatalf("status receipt=%+v err=%v identity=%+v", receipt, err, engine.seen)
	}
	engine.state = gateway.MutationRejected
	receipt, err = client.ResolveMutation(ctx, identity)
	if err != nil || receipt.State != gateway.MutationRejected || engine.seen != identity {
		t.Fatalf("resolution receipt=%+v err=%v identity=%+v", receipt, err, engine.seen)
	}
	engine.err = gateway.RejectBeforeMutation("group_not_applied", "private adapter details", gateway.ErrConflict)
	_, err = client.SetRuntimeSelection(ctx, gateway.SelectionScope{GroupID: "group-1", Transport: "tcp"}, "node-1", 0)
	if !gateway.IsDefiniteRejection(err) || !errors.Is(err, gateway.ErrConflict) || engine.seen != identity {
		t.Fatalf("typed rejection lost over HTTP: %v, seen=%+v", err, engine.seen)
	}
	engine.err = gateway.ErrConflict
	_, err = client.SetRuntimeSelection(ctx, gateway.SelectionScope{GroupID: "group-1", Transport: "tcp"}, "node-1", 0)
	if gateway.IsDefiniteRejection(err) || !errors.Is(err, gateway.ErrConflict) {
		t.Fatalf("generic conflict was upgraded: %v", err)
	}
}
