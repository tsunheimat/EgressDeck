package providers

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func localHTTPServer(handler http.Handler) (*httptest.Server, SourceAllowlistEntry) {
	s := httptest.NewServer(handler)
	portText := strings.TrimPrefix(s.URL, "http://127.0.0.1:")
	port, _ := strconv.Atoi(portText)
	return s, SourceAllowlistEntry{Host: "127.0.0.1", Ports: []int{port}, CIDRs: []string{"127.0.0.0/8"}}
}

func TestFetcherRejectsPrivateAddressWithoutExplicitAllowlist(t *testing.T) {
	server, _ := localHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	_, err := (&Fetcher{Limits: Limits{AllowHTTP: true}}).Fetch(context.Background(), server.URL+"/secret?token=do-not-print")
	if !errors.Is(err, ErrFetchPrivate) {
		t.Fatalf("error = %v, want private-address error", err)
	}
	if strings.Contains(err.Error(), "token=do-not-print") || strings.Contains(err.Error(), "/secret") {
		t.Fatalf("error leaked source credentials: %v", err)
	}
}

func TestFetcherAllowsExplicitPrivateSourceAndEnforcesWireLimit(t *testing.T) {
	server, allow := localHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "12345") }))
	defer server.Close()
	f := &Fetcher{Limits: Limits{AllowHTTP: true, MaxBodyBytes: 5, MaxDecodedBytes: 5}, Allowlist: []SourceAllowlistEntry{allow}}
	result, err := f.Fetch(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if string(result.Content) != "12345" || result.Route != "direct" || result.RedactedSource != server.URL {
		t.Fatalf("unexpected result: %+v", result)
	}

	f.Limits.MaxBodyBytes = 4
	if _, err := f.Fetch(context.Background(), server.URL); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("oversized response error = %v, want body limit", err)
	}
}

func TestFetcherEnforcesDecompressedLimit(t *testing.T) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = zw.Write(bytes.Repeat([]byte("x"), 1024))
	_ = zw.Close()
	server, allow := localHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	}))
	defer server.Close()
	f := &Fetcher{Limits: Limits{AllowHTTP: true, MaxBodyBytes: int64(compressed.Len()), MaxDecodedBytes: 128}, Allowlist: []SourceAllowlistEntry{allow}}
	if _, err := f.Fetch(context.Background(), server.URL); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("gzip expansion error = %v, want decoded limit", err)
	}
}

func TestFetcherRevalidatesRedirectDestination(t *testing.T) {
	target, _ := localHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "target") }))
	defer target.Close()
	source, sourceAllow := localHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	f := &Fetcher{Limits: Limits{AllowHTTP: true}, Allowlist: []SourceAllowlistEntry{sourceAllow}}
	if _, err := f.Fetch(context.Background(), source.URL); !errors.Is(err, ErrFetchPrivate) {
		t.Fatalf("redirect error = %v, want private-address error", err)
	}
}

type sequenceResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
}

func (r *sequenceResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.answers) == 0 {
		return nil, fmt.Errorf("no answer")
	}
	answer := r.answers[0]
	if len(r.answers) > 1 {
		r.answers = r.answers[1:]
	}
	return answer, nil
}

func TestFetcherRejectsDNSRebindingAtDial(t *testing.T) {
	r := &sequenceResolver{answers: [][]netip.Addr{{netip.MustParseAddr("93.184.216.34")}, {netip.MustParseAddr("127.0.0.1")}}}
	f := &Fetcher{Limits: Limits{AllowHTTP: true, RequestTimeout: time.Second}, Resolver: r}
	_, err := f.Fetch(context.Background(), "http://provider.example.invalid/subscription")
	if !errors.Is(err, ErrFetchPrivate) {
		t.Fatalf("rebinding error = %v, want private-address error", err)
	}
}

func TestFetcherAlternateRouteMustBeVerified(t *testing.T) {
	server, allow := localHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	called := false
	f := &Fetcher{Limits: Limits{AllowHTTP: true}, Route: "missing-route", Allowlist: []SourceAllowlistEntry{allow}}
	if _, err := f.Fetch(context.Background(), server.URL); !errors.Is(err, ErrFetchRoute) {
		t.Fatalf("unverified route error = %v", err)
	}
	f.RouteVerify = RouteVerifierFunc(func(_ context.Context, route string) (DialContextFunc, error) {
		called = route == "verified-route"
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}, nil
	})
	f.Route = "verified-route"
	if result, err := f.Fetch(context.Background(), server.URL); err != nil || string(result.Content) != "ok" || !called {
		t.Fatalf("verified route result=%+v err=%v called=%v", result, err, called)
	}
}

func TestFetchErrorsNeverExposeRemoteTextOrSourceSecrets(t *testing.T) {
	err := fetchError("https://user:password@example.org/private?token=secret", errors.New("header echoed raw-secret outside a URL"))
	if strings.Contains(err.Error(), "raw-secret") || strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "token") {
		t.Fatalf("error leaks secret: %v", err)
	}
	raw, _ := json.Marshal(err)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "password") {
		t.Fatalf("error JSON leaks private data: %s", raw)
	}
}

func TestAlternateFetchRouteReceivesOnlyValidatedLiteralAndRebindingIsRejected(t *testing.T) {
	r := &sequenceResolver{answers: [][]netip.Addr{{netip.MustParseAddr("93.184.216.34")}, {netip.MustParseAddr("127.0.0.1")}}}
	calls := 0
	f := &Fetcher{Limits: Limits{AllowHTTP: true}, Route: "verified", Resolver: r, RouteVerify: RouteVerifierFunc(func(context.Context, string) (DialContextFunc, error) {
		return func(context.Context, string, string) (net.Conn, error) {
			calls++
			return nil, errors.New("unexpected route dial")
		}, nil
	})}
	if _, err := f.Fetch(context.Background(), "http://provider.example/subscription"); !errors.Is(err, ErrFetchPrivate) {
		t.Fatalf("rebinding error=%v", err)
	}
	if calls != 0 {
		t.Fatal("unvalidated route dial occurred")
	}
}

func TestPartialPrivateAllowlistDoesNotBypassValidation(t *testing.T) {
	server, _ := localHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected connection") }))
	defer server.Close()
	for _, entry := range []SourceAllowlistEntry{{Host: "127.0.0.1"}, {Host: "127.0.0.1", CIDRs: []string{"127.0.0.0/8"}}} {
		f := &Fetcher{Limits: Limits{AllowHTTP: true}, Allowlist: []SourceAllowlistEntry{entry}}
		if _, err := f.Fetch(context.Background(), server.URL); !errors.Is(err, ErrFetchPrivate) {
			t.Fatalf("incomplete allowlist accepted: %v", err)
		}
	}
}
