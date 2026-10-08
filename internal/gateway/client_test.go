package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const clientTestToken = "private-controller-bearer-token"

// These fixtures exercise real authenticated TLS requests and the gateway-agent
// wire contract. They do not qualify a dae runtime or packet-processing path.
func newClientTestServer(t *testing.T, handler http.Handler) (*httptest.Server, ClientOptions) {
	t.Helper()
	root := newTransportIdentity(t, nil, 0)
	serverIdentity := newTransportIdentity(t, &root, x509.ExtKeyUsageServerAuth)
	clientIdentity := newTransportIdentity(t, &root, x509.ExtKeyUsageClientAuth)
	serverTLS, err := LoadServerTLS(serverIdentity.certFile, serverIdentity.keyFile, root.certFile)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := LoadClientTLS(clientIdentity.certFile, clientIdentity.keyFile, root.certFile, "")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 {
			t.Error("request lacked a verified TLS 1.3 client identity")
		}
		if r.Header.Get("Authorization") != "Bearer "+clientTestToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Error("request did not accept JSON")
		}
		handler.ServeHTTP(w, r)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = serverTLS
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, ClientOptions{Endpoint: server.URL, Token: clientTestToken, TLSConfig: clientTLS}
}

func clientTestClient(t *testing.T, options ClientOptions) *Client {
	t.Helper()
	client, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func clientTestJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Error(err)
	}
}

func clientTestRequest(t *testing.T, r *http.Request, method, path string, want any) {
	t.Helper()
	if r.Method != method || r.URL.Path != path {
		t.Errorf("request = %s %s, want %s %s", r.Method, r.URL.Path, method, path)
	}
	if want == nil {
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		t.Error("request body was not identified as JSON")
	}
	var gotValue, wantValue any
	if err := json.NewDecoder(r.Body).Decode(&gotValue); err != nil {
		t.Error(err)
		return
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wantJSON, &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("request body = %#v, want %#v", gotValue, wantValue)
	}
}

func TestClientRequiresHTTPSIdentityAndBearer(t *testing.T) {
	_, valid := newClientTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, test := range []struct {
		name   string
		mutate func(*ClientOptions)
	}{
		{"HTTP", func(o *ClientOptions) { o.Endpoint = "http://gateway.test" }},
		{"missing host", func(o *ClientOptions) { o.Endpoint = "https:///gateway" }},
		{"URL credentials", func(o *ClientOptions) { o.Endpoint = "https://user:private-password@gateway.test" }},
		{"URL query", func(o *ClientOptions) { o.Endpoint += "?token=private-password" }},
		{"URL fragment", func(o *ClientOptions) { o.Endpoint += "#private-password" }},
		{"missing token", func(o *ClientOptions) { o.Token = "" }},
		{"blank token", func(o *ClientOptions) { o.Token = " \t" }},
		{"header injection", func(o *ClientOptions) { o.Token += "\r\nX-Injected: true" }},
		{"missing TLS", func(o *ClientOptions) { o.TLSConfig = nil }},
		{"missing roots", func(o *ClientOptions) { o.TLSConfig.RootCAs = nil }},
		{"missing identity", func(o *ClientOptions) { o.TLSConfig.Certificates = nil }},
		{"insecure verification", func(o *ClientOptions) { o.TLSConfig.InsecureSkipVerify = true }},
		{"obsolete TLS", func(o *ClientOptions) { o.TLSConfig.MaxVersion = tls.VersionTLS12 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := valid
			options.TLSConfig = valid.TLSConfig.Clone()
			test.mutate(&options)
			client, err := NewClient(options)
			if client != nil || err == nil {
				t.Fatalf("unsafe client configuration accepted: client=%v err=%v", client, err)
			}
			if strings.Contains(err.Error(), clientTestToken) || strings.Contains(err.Error(), "private-password") {
				t.Fatal("configuration error disclosed credentials")
			}
		})
	}
	client := clientTestClient(t, valid)
	if client.http.Timeout != 20*time.Second {
		t.Fatalf("default timeout = %s, want 20s", client.http.Timeout)
	}
}

func TestClientReadsAuthenticatedAgentRoutes(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	wantHealth := Health{Status: "simulation", Implementation: "test-agent", ObservedAt: now}
	wantCapabilities := DefaultCapabilities("test-agent", "1")
	wantInventory := Snapshot{Generation: 8, Providers: map[string]ProviderRevision{"provider": {ProviderID: "provider", Revision: 2}}}
	wantReadback := Snapshot{Generation: 9}
	wantJournal := []JournalEntry{{ID: "operation-1", Status: "published", Generation: 9}}
	wantConnections := []Connection{{ID: "connection-1", NodeID: "node", Transport: "tcp"}}
	wantCounters := Counters{ProxyBytes: 101, DirectBytes: 202, ProxyPackets: 3, DirectPackets: 4}
	wantEvents := []Event{{ID: 12, Type: "published", Generation: 9}}
	responses := map[string]any{
		"/v1/health": wantHealth, "/v1/capabilities": wantCapabilities,
		"/v1/inventory": wantInventory, "/v1/readback": wantReadback,
		"/v1/journal": wantJournal, "/v1/connections": wantConnections,
		"/v1/counters": wantCounters, "/v1/events": wantEvents,
	}
	var requests atomic.Int64
	_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		clientTestRequest(t, r, http.MethodGet, r.URL.Path, nil)
		value, ok := responses[r.URL.Path]
		if !ok {
			t.Errorf("unexpected route %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/v1/events" && r.URL.Query().Get("after") != "11" {
			t.Errorf("event cursor = %q", r.URL.RawQuery)
		}
		clientTestJSON(t, w, http.StatusOK, value)
	}))
	client := clientTestClient(t, options)
	for _, test := range []struct {
		name string
		read func() (any, error)
		want any
	}{
		{"health", func() (any, error) { return client.Health(ctx) }, wantHealth},
		{"capabilities", func() (any, error) { return client.Capabilities(ctx) }, wantCapabilities},
		{"inventory", func() (any, error) { return client.Inventory(ctx) }, wantInventory},
		{"readback", func() (any, error) { return client.Readback(ctx) }, wantReadback},
		{"journal", func() (any, error) { return client.JournalEntries(ctx) }, wantJournal},
		{"connections", func() (any, error) { return client.ObserveConnections(ctx) }, wantConnections},
		{"counters", func() (any, error) { return client.Counters(ctx) }, wantCounters},
		{"events", func() (any, error) { return client.ResumeEvents(ctx, 11) }, wantEvents},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.read()
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("result = %#v, err = %v, want %#v", got, err, test.want)
			}
		})
	}
	if requests.Load() != int64(len(responses)) {
		t.Fatalf("request count = %d, want %d", requests.Load(), len(responses))
	}
}

func TestClientStagePublicationPreservesGenerationFence(t *testing.T) {
	ctx := context.Background()
	revision := ProviderRevision{ProviderID: "provider", Revision: 6, ContentHash: "hash-6", Nodes: []Node{{ID: "node", Name: "one"}}}
	var publications atomic.Int64
	_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/providers/stage":
			clientTestRequest(t, r, http.MethodPost, "/v1/providers/stage", map[string]any{
				"provider_id": "provider", "revision": 6, "content_hash": "hash-6", "nodes": revision.Nodes, "expected_generation": 41,
			})
			clientTestJSON(t, w, http.StatusCreated, map[string]any{"stage_id": "stage-1", "provider_id": "provider", "revision": 6, "content_hash": "hash-6", "base_generation": 41, "status": "staged"})
		case "/v1/providers/publish":
			publications.Add(1)
			clientTestRequest(t, r, http.MethodPost, "/v1/providers/publish", map[string]any{"stage_id": "stage-1", "expected_generation": 41})
			clientTestJSON(t, w, http.StatusOK, map[string]any{"status": "published", "snapshot": Snapshot{Generation: 42, Providers: map[string]ProviderRevision{"provider": revision}}})
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	client := clientTestClient(t, options)
	if _, err := client.PublishProvider(ctx, "unknown"); !errors.Is(err, ErrStageNotFound) || publications.Load() != 0 {
		t.Fatalf("unknown stage reached publication: err=%v requests=%d", err, publications.Load())
	}
	id, err := client.StageProvider(ctx, revision, 41)
	if err != nil || id != "stage-1" {
		t.Fatalf("stage = %q, %v", id, err)
	}
	snapshot, err := client.PublishProvider(ctx, id)
	if err != nil || snapshot.Generation != 42 || !reflect.DeepEqual(snapshot.Providers["provider"], revision) {
		t.Fatalf("publication = %#v, %v", snapshot, err)
	}
	if _, err := client.PublishProvider(ctx, id); !errors.Is(err, ErrStageNotFound) || publications.Load() != 1 {
		t.Fatalf("consumed stage was replayed: err=%v requests=%d", err, publications.Load())
	}
}

func TestClientRejectsUnmatchedStageAcknowledgement(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"provider", func(ack map[string]any) { ack["provider_id"] = "other-provider" }},
		{"revision", func(ack map[string]any) { ack["revision"] = 7 }},
		{"content hash", func(ack map[string]any) { ack["content_hash"] = "other-hash" }},
		{"generation", func(ack map[string]any) { ack["base_generation"] = 42 }},
		{"status", func(ack map[string]any) { ack["status"] = "published" }},
		{"missing stage ID", func(ack map[string]any) { delete(ack, "stage_id") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			ack := map[string]any{"stage_id": "stage-1", "provider_id": "provider", "revision": 6, "content_hash": "hash-6", "base_generation": 41, "status": "staged"}
			test.mutate(ack)
			_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				clientTestJSON(t, w, http.StatusCreated, ack)
			}))
			client := clientTestClient(t, options)
			id, err := client.StageProvider(context.Background(), ProviderRevision{ProviderID: "provider", Revision: 6, ContentHash: "hash-6"}, 41)
			if id != "" || !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("unmatched staging acknowledgement accepted: id=%q err=%v", id, err)
			}
			if _, err := client.PublishProvider(context.Background(), "stage-1"); !errors.Is(err, ErrStageNotFound) {
				t.Fatalf("unmatched stage became publishable: %v", err)
			}
		})
	}
}

func TestClientMutationAndProbeRoutes(t *testing.T) {
	ctx := context.Background()
	scope := SelectionScope{GatewayID: "gateway", GroupID: "group", Transport: "tcp"}
	selection := Selection{Scope: scope, DesiredNodeID: "node", ObservedNodeID: "node", Revision: 5}
	policy := Policy{ID: "policy", Generation: 7, Payload: json.RawMessage(`{"native_config":"global{}"}`)}
	filter := ConnectionFilter{GroupID: "group", ProviderID: "provider", NodeID: "node", Transport: "udp"}
	for _, test := range []struct {
		name, method, path string
		request, response  any
		invoke             func(*Client) (any, error)
		want               any
	}{
		{"runtime selection", http.MethodPut, "/v1/selections", map[string]any{"scope": scope, "desired_node_id": "node", "expected_revision": 4, "persist_restart": false}, selection, func(c *Client) (any, error) { return c.SetRuntimeSelection(ctx, scope, "node", 4) }, selection},
		{"persistent selection", http.MethodPut, "/v1/selections", map[string]any{"scope": scope, "desired_node_id": "node", "expected_revision": 4, "persist_restart": true}, selection, func(c *Client) (any, error) { return c.PersistSelection(ctx, scope, "node", 4) }, selection},
		{"validate policy", http.MethodPost, "/v1/policies/validate", policy, map[string]bool{"valid": true}, func(c *Client) (any, error) { return nil, c.ValidatePolicy(ctx, policy) }, nil},
		{"apply policy", http.MethodPost, "/v1/policies/apply", map[string]any{"policy": policy, "expected_generation": 6}, Snapshot{Generation: 7, Policy: policy}, func(c *Client) (any, error) { return c.ApplyPolicyGeneration(ctx, policy, 6) }, Snapshot{Generation: 7, Policy: policy}},
		{"probe node", http.MethodPost, "/v1/probes/node", map[string]string{"node_id": "node/with?punctuation"}, ProbeResult{Target: "node/with?punctuation", OK: true}, func(c *Client) (any, error) { return c.ProbeNode(ctx, "node/with?punctuation") }, ProbeResult{Target: "node/with?punctuation", OK: true}},
		{"probe group", http.MethodPost, "/v1/probes/group", map[string]string{"group_id": "group"}, ProbeResult{Target: "group", OK: true}, func(c *Client) (any, error) { return c.ProbeGroup(ctx, "group") }, ProbeResult{Target: "group", OK: true}},
		{"close filtered", http.MethodPost, "/v1/connections/close", filter, map[string]int{"closed": 3}, func(c *Client) (any, error) { return c.CloseFiltered(ctx, filter) }, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int64
			_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				clientTestRequest(t, r, test.method, test.path, test.request)
				clientTestJSON(t, w, http.StatusOK, test.response)
			}))
			got, err := test.invoke(clientTestClient(t, options))
			if err != nil || !reflect.DeepEqual(got, test.want) || requests.Load() != 1 {
				t.Fatalf("result=%#v err=%v requests=%d, want %#v", got, err, requests.Load(), test.want)
			}
		})
	}
}

func TestClientStockUnsupportedAndHealth(t *testing.T) {
	stock := NewStockEngine(StockOptions{Executable: filepath.Join(t.TempDir(), "missing-dae")})
	_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var value any
		var err error
		switch r.URL.Path {
		case "/v1/health":
			value, err = stock.Health(r.Context())
		case "/v1/capabilities":
			value, err = stock.Capabilities(r.Context())
		case "/v1/inventory":
			value, err = stock.Inventory(r.Context())
		case "/v1/providers/stage":
			value, err = stock.StageProvider(r.Context(), ProviderRevision{}, 0)
		default:
			http.NotFound(w, r)
			return
		}
		if err != nil {
			if !errors.Is(err, ErrUnsupported) {
				t.Errorf("unexpected stock error: %v", err)
			}
			clientTestJSON(t, w, http.StatusNotImplemented, map[string]any{"error": err})
			return
		}
		clientTestJSON(t, w, http.StatusOK, value)
	}))
	client := clientTestClient(t, options)
	health, err := client.Health(context.Background())
	if err != nil || health.Status != "unavailable" || health.Implementation != "dae-stock" || health.ExecutableAvailable {
		t.Fatalf("stock health=%#v err=%v", health, err)
	}
	capabilities, err := client.Capabilities(context.Background())
	if err != nil || capabilities.Implementation != "dae-stock" {
		t.Fatalf("stock capabilities=%#v err=%v", capabilities, err)
	}
	for _, capability := range capabilities.Items {
		if capability.Supported {
			t.Errorf("missing stock runtime advertised %s", capability.Name)
		}
	}
	if _, err := client.Inventory(context.Background()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("stock inventory error=%v", err)
	}
	if _, err := client.StageProvider(context.Background(), ProviderRevision{}, 0); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("stock staging error=%v", err)
	}
}

func TestClientRejectsUntrustedPeersAndWrongBearer(t *testing.T) {
	var requests atomic.Int64
	_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		clientTestJSON(t, w, http.StatusOK, Snapshot{Generation: 1})
	}))
	otherRoot := newTransportIdentity(t, nil, 0)
	otherIdentity := newTransportIdentity(t, &otherRoot, x509.ExtKeyUsageClientAuth)
	otherCertificate, err := tls.LoadX509KeyPair(otherIdentity.certFile, otherIdentity.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ClientOptions)
		want   error
	}{
		{"untrusted server", func(o *ClientOptions) {
			o.TLSConfig.RootCAs = x509.NewCertPool()
			o.TLSConfig.RootCAs.AddCert(otherRoot.certificate)
		}, ErrUnavailable},
		{"wrong server hostname", func(o *ClientOptions) { o.TLSConfig.ServerName = "wrong-gateway.test" }, ErrUnavailable},
		{"untrusted client", func(o *ClientOptions) {
			o.TLSConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &otherCertificate, nil }
		}, ErrUnavailable},
		{"wrong bearer", func(o *ClientOptions) { o.Token = "wrong-token" }, ErrUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := options
			config.TLSConfig = options.TLSConfig.Clone()
			test.mutate(&config)
			_, err := clientTestClient(t, config).Inventory(context.Background())
			if !errors.Is(err, test.want) || requests.Load() != 0 {
				t.Fatalf("untrusted request: err=%v requests=%d", err, requests.Load())
			}
		})
	}
}

func TestClientStatusErrorsAreTypedAndRedacted(t *testing.T) {
	for _, test := range []struct {
		status int
		want   error
	}{
		{http.StatusNotImplemented, ErrUnsupported},
		{http.StatusConflict, ErrConflict},
		{http.StatusUnauthorized, ErrUnauthorized},
		{http.StatusUnprocessableEntity, ErrValidation},
		{http.StatusTooManyRequests, ErrBusy},
		{http.StatusNotFound, ErrStageNotFound},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				clientTestJSON(t, w, test.status, map[string]any{"error": map[string]string{"code": "untrusted-code", "operation": "untrusted-operation", "detail": "private-subscription " + clientTestToken}})
			}))
			_, err := clientTestClient(t, options).Inventory(context.Background())
			var typed *Error
			if !errors.Is(err, test.want) || !errors.As(err, &typed) {
				t.Fatalf("status %d error=%v, want typed %v", test.status, err, test.want)
			}
			for _, secret := range []string{clientTestToken, "private-subscription", "untrusted-code", "untrusted-operation", options.Endpoint} {
				if strings.Contains(err.Error(), secret) || strings.Contains(typed.Detail, secret) || strings.Contains(typed.Operation, secret) {
					t.Fatalf("remote response or credentials appeared in error: %v", err)
				}
			}
		})
	}
}

func TestClientRejectsMalformedAndOversizedResponses(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{"invalid JSON", `{"generation": private-subscription`},
		{"trailing JSON", `{"generation":1}{"generation":2}`},
		{"oversized body", strings.Repeat("private-subscription", 100)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, test.body) }))
			options.MaxResponseBytes = 128
			_, err := clientTestClient(t, options).Inventory(context.Background())
			if !errors.Is(err, ErrProtocol) || strings.Contains(err.Error(), "private-subscription") {
				t.Fatalf("invalid response error=%v", err)
			}
		})
	}
}

func TestClientRejectsMissingReadbackState(t *testing.T) {
	for _, body := range []string{"null", "{}", `{"generation":null}`} {
		t.Run(body, func(t *testing.T) {
			_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				clientTestRequest(t, r, http.MethodGet, "/v1/readback", nil)
				_, _ = io.WriteString(w, body)
			}))
			if _, err := clientTestClient(t, options).Readback(context.Background()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("missing readback state was accepted: body=%s err=%v", body, err)
			}
		})
	}
}

func TestClientTimeoutAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "client timeout"
		if canceled {
			name = "caller cancellation"
		}
		t.Run(name, func(t *testing.T) {
			arrived := make(chan struct{})
			release := make(chan struct{})
			_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(arrived)
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			defer close(release)
			options.Timeout = 100 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if canceled {
				options.Timeout = 5 * time.Second
				go func() {
					select {
					case <-arrived:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			started := time.Now()
			_, err := clientTestClient(t, options).Inventory(ctx)
			if err == nil || time.Since(started) > 2*time.Second {
				t.Fatalf("deadline was not enforced: err=%v duration=%s", err, time.Since(started))
			}
			if canceled && !errors.Is(err, context.Canceled) {
				t.Fatalf("caller cancellation was lost: %v", err)
			}
		})
	}
}

func TestClientLostMutationResponseRequiresReadbackWithoutRetry(t *testing.T) {
	var applied atomic.Int64
	_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/readback" {
			clientTestJSON(t, w, http.StatusOK, Snapshot{Generation: applied.Load()})
			return
		}
		clientTestRequest(t, r, http.MethodPost, "/v1/policies/apply", map[string]any{"policy": Policy{ID: "policy"}, "expected_generation": 0})
		applied.Add(1) // The operation commits before the response connection disappears.
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	}))
	client := clientTestClient(t, options)
	_, err := client.ApplyPolicyGeneration(context.Background(), Policy{ID: "policy"}, 0)
	var typed *Error
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.As(err, &typed) || typed.Code != "outcome_unknown" {
		t.Fatalf("lost acknowledgement error=%v", err)
	}
	if applied.Load() != 1 {
		t.Fatalf("mutation ran %d times", applied.Load())
	}
	observed, err := client.Readback(context.Background())
	if err != nil || observed.Generation != 1 || applied.Load() != 1 {
		t.Fatalf("readback after uncertain mutation=%#v err=%v applications=%d", observed, err, applied.Load())
	}
}

func TestClientUncertainMutationAcknowledgementsNeverRetry(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{"server failure", http.StatusInternalServerError, `{"error":"private-subscription"}`},
		{"malformed response", http.StatusOK, `{"generation":private-subscription}`},
		{"oversized response", http.StatusOK, strings.Repeat("private-subscription", 100)},
		{"stale acknowledgement", http.StatusOK, `{"generation":0}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var applied atomic.Int64
			_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				applied.Add(1)
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			options.MaxResponseBytes = 128
			_, err := clientTestClient(t, options).ApplyPolicyGeneration(context.Background(), Policy{ID: "policy"}, 0)
			if !errors.Is(err, ErrOutcomeUnknown) || applied.Load() != 1 || strings.Contains(err.Error(), "private-subscription") {
				t.Fatalf("uncertain mutation err=%v applications=%d", err, applied.Load())
			}
		})
	}
}

func TestClientDoesNotFollowRedirectsOrLeakAuthorization(t *testing.T) {
	var redirected atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("authorization leaked to redirect destination")
		}
		clientTestJSON(t, w, http.StatusOK, Snapshot{Generation: 1})
	}))
	defer destination.Close()
	var requests atomic.Int64
	_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, destination.URL+"/private-subscription", http.StatusTemporaryRedirect)
	}))
	client := clientTestClient(t, options)
	if _, err := client.Inventory(context.Background()); err == nil || strings.Contains(err.Error(), "private-subscription") {
		t.Fatalf("redirect read error=%v", err)
	}
	if _, err := client.ApplyPolicyGeneration(context.Background(), Policy{ID: "policy"}, 0); err == nil {
		t.Fatal("redirected mutation was reported successful")
	}
	if redirected.Load() != 0 || requests.Load() != 2 {
		t.Fatalf("redirect requests=%d, origin requests=%d", redirected.Load(), requests.Load())
	}
}
