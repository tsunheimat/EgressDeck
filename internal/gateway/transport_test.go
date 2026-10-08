package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type transportTestIdentity struct {
	certFile    string
	keyFile     string
	certificate *x509.Certificate
	key         ed25519.PrivateKey
	pem         []byte
}

func newTransportIdentity(t *testing.T, parent *transportTestIdentity, usage x509.ExtKeyUsage) transportTestIdentity {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "gateway transport test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	issuer, signingKey := template, privateKey
	if parent == nil {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		issuer, signingKey = parent.certificate, parent.key
		template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		if usage == x509.ExtKeyUsageServerAuth {
			template.DNSNames = []string{"gateway.test"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, publicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	identity := transportTestIdentity{
		certFile:    filepath.Join(dir, "cert.pem"),
		keyFile:     filepath.Join(dir, "key.pem"),
		certificate: certificate,
		key:         privateKey,
		pem:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
	if err := os.WriteFile(identity.certFile, identity.pem, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity.keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return identity
}

func TestGatewayMutualTLS(t *testing.T) {
	root := newTransportIdentity(t, nil, 0)
	serverIdentity := newTransportIdentity(t, &root, x509.ExtKeyUsageServerAuth)
	clientIdentity := newTransportIdentity(t, &root, x509.ExtKeyUsageClientAuth)
	untrustedRoot := newTransportIdentity(t, nil, 0)
	untrustedClient := newTransportIdentity(t, &untrustedRoot, x509.ExtKeyUsageClientAuth)
	untrustedCertificate, err := tls.LoadX509KeyPair(untrustedClient.certFile, untrustedClient.keyFile)
	if err != nil {
		t.Fatal(err)
	}

	serverTLS, err := LoadServerTLS(serverIdentity.certFile, serverIdentity.keyFile, root.certFile)
	if err != nil {
		t.Fatal(err)
	}
	if serverTLS.MinVersion != tls.VersionTLS13 || serverTLS.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("server configuration did not require TLS 1.3 with client verification")
	}
	var requests atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 {
			t.Error("request did not have a verified TLS 1.3 client")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	for _, test := range []struct {
		name        string
		mutate      func(*tls.Config)
		wantSuccess bool
	}{
		{name: "trusted peers", wantSuccess: true},
		{name: "URL hostname verification", wantSuccess: true, mutate: func(config *tls.Config) { config.ServerName = "" }},
		{name: "missing client certificate", mutate: func(config *tls.Config) { config.Certificates = nil }},
		{name: "untrusted client", mutate: func(config *tls.Config) {
			// Force presentation even though the server advertises another CA.
			config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &untrustedCertificate, nil }
		}},
		{name: "untrusted server", mutate: func(config *tls.Config) {
			config.RootCAs = x509.NewCertPool()
			config.RootCAs.AddCert(untrustedRoot.certificate)
		}},
		{name: "wrong server hostname", mutate: func(config *tls.Config) { config.ServerName = "another-gateway.test" }},
		{name: "TLS 1.2 client", mutate: func(config *tls.Config) {
			config.MinVersion = tls.VersionTLS12
			config.MaxVersion = tls.VersionTLS12
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := LoadClientTLS(clientIdentity.certFile, clientIdentity.keyFile, root.certFile, "gateway.test")
			if err != nil {
				t.Fatal(err)
			}
			if config.MinVersion != tls.VersionTLS13 || config.InsecureSkipVerify {
				t.Fatal("client configuration did not require verified TLS 1.3")
			}
			if test.mutate != nil {
				test.mutate(config)
			}
			transport := &http.Transport{TLSClientConfig: config}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			before := requests.Load()
			response, err := client.Get(server.URL)
			if response != nil {
				defer response.Body.Close()
			}
			if test.wantSuccess {
				if err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != http.StatusNoContent || requests.Load() != before+1 {
					t.Fatalf("unexpected response: status %d, request count %d", response.StatusCode, requests.Load())
				}
				if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
					t.Fatal("client did not verify the gateway server")
				}
			} else {
				if err == nil {
					t.Fatal("unauthenticated or obsolete TLS connection succeeded")
				}
				if requests.Load() != before {
					t.Fatal("rejected connection reached the HTTP handler")
				}
			}
		})
	}
}

func TestGatewayTLSRejectsInvalidCAFiles(t *testing.T) {
	root := newTransportIdentity(t, nil, 0)
	identity := newTransportIdentity(t, &root, x509.ExtKeyUsageClientAuth)
	loaders := []struct {
		name string
		load func(string) (*tls.Config, error)
	}{
		{"server", func(path string) (*tls.Config, error) {
			return LoadServerTLS(identity.certFile, identity.keyFile, path)
		}},
		{"client", func(path string) (*tls.Config, error) {
			return LoadClientTLS(identity.certFile, identity.keyFile, path, "gateway.test")
		}},
	}
	for _, test := range []struct {
		name     string
		contents []byte
	}{
		{"empty", nil},
		{"whitespace", []byte(" \n\t")},
		{"malformed PEM", []byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n")},
		{"malformed DER", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")})},
		{"malformed PEM followed by valid CA", append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), root.pem...)},
		{"valid CA followed by garbage", append(append([]byte(nil), root.pem...), []byte("invalid")...)},
		{"leaf certificate", identity.pem},
	} {
		for _, loader := range loaders {
			t.Run(loader.name+"/"+test.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "ca.pem")
				if err := os.WriteFile(path, test.contents, 0600); err != nil {
					t.Fatal(err)
				}
				if config, err := loader.load(path); err == nil || config != nil {
					t.Fatal("invalid CA produced a TLS configuration")
				}
			})
		}
	}
	for _, loader := range loaders {
		t.Run(loader.name+"/missing CA file", func(t *testing.T) {
			if config, err := loader.load(filepath.Join(t.TempDir(), "missing.pem")); err == nil || config != nil {
				t.Fatal("missing CA produced a TLS configuration")
			}
		})
	}
}
