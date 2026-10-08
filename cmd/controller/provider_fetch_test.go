package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
)

func writeProviderFetchTestConfig(t *testing.T, config providerFetchConfig) string {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "provider-fetch.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A fresh subprocess ensures crypto/x509's process-wide system-root cache has
// not been initialized by another test. The actual fetcher still verifies TLS
// through the operating-system trust boundary; no test-only bypass is wired.
func TestProviderFetchHTTPSBoundary(t *testing.T) {
	const childEnv = "EGRESSDECK_PROVIDER_TLS_TEST_CHILD"
	if os.Getenv(childEnv) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command(executable, "-test.run=^TestProviderFetchHTTPSBoundary$", "-test.v")
		child.Env = append(os.Environ(), childEnv+"=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("HTTPS boundary subprocess failed: %v\n%s", err, output)
		}
		return
	}

	var targetRequests, sourceRequests atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		_, _ = io.WriteString(w, "unexpected target request")
	}))
	defer target.Close()
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		_, _ = io.WriteString(w, "unexpected plaintext request")
	}))
	defer plaintext.Close()
	const subscription = "trojan://private-credential@node.example:443#one"
	var source *httptest.Server
	source = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceRequests.Add(1)
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, source.URL+"/subscription", http.StatusFound)
		case "/target":
			http.Redirect(w, r, target.URL+"/subscription", http.StatusFound)
		case "/plaintext":
			http.Redirect(w, r, plaintext.URL+"/subscription", http.StatusFound)
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			compressed := gzip.NewWriter(w)
			_, _ = io.WriteString(compressed, strings.Repeat(subscription+"\n", 20))
			_ = compressed.Close()
		case "/two":
			_, _ = io.WriteString(w, subscription+"\ntrojan://second-credential@second.example:443#two")
		case "/slow":
			<-r.Context().Done()
		default:
			_, _ = io.WriteString(w, subscription)
		}
	}))
	source.StartTLS()
	defer source.Close()
	trustPath := filepath.Join(t.TempDir(), "source-ca.pem")
	if err := os.WriteFile(trustPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: source.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", trustPath)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	sourceURL, err := url.Parse(source.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(sourceURL.Port())
	base := providerSourceConfig{Host: "127.0.0.1", Ports: []int{port}, CIDRs: []string{"127.0.0.1/32"}}
	registry, err := newProviderRegistry(writeProviderFetchTestConfig(t, providerFetchConfig{Allowlist: []providerSourceConfig{base}}))
	if err != nil {
		t.Fatal(err)
	}
	revision, _, err := registry.Refresh(context.Background(), domain.Provider{ID: "private", Source: source.URL + "/subscription"}, providers.FormatLinks)
	if err != nil || len(revision.Nodes) != 1 || sourceRequests.Load() != 1 {
		t.Fatalf("approved HTTPS refresh failed: nodes=%d requests=%d err=%v", len(revision.Nodes), sourceRequests.Load(), err)
	}
	if encoded, err := json.Marshal(revision); err != nil || strings.Contains(string(encoded), "private-credential") {
		t.Fatal("fetched revision exposed provider credentials")
	}
	defaultRegistry, err := newProviderRegistry("")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := defaultRegistry.Refresh(context.Background(), domain.Provider{ID: "denied", Source: source.URL}, providers.FormatLinks); !errors.Is(err, providers.ErrFetch) {
		t.Fatalf("default private denial: %v", err)
	}
	if sourceRequests.Load() != 1 {
		t.Fatal("default private denial contacted source")
	}
	zero, one, small, line := 0, 1, int64(8), 8
	decoded, timeout := int64(64), int64(100)
	for i, test := range []struct {
		name   string
		source providerSourceConfig
		limits providerLimitsConfig
		path   string
		route  string
		want   error
		hits   int64
	}{
		{name: "wrong host", source: providerSourceConfig{Host: "localhost", Ports: []int{port}, CIDRs: base.CIDRs}, path: "/subscription", want: providers.ErrFetch},
		{name: "wrong port", source: providerSourceConfig{Host: base.Host, Ports: []int{1}, CIDRs: base.CIDRs}, path: "/subscription", want: providers.ErrFetch},
		{name: "non-direct has no fallback", source: base, path: "/subscription", route: "unqualified-outbound", want: providers.ErrFetch},
		{name: "private redirect", source: base, path: "/target", want: providers.ErrFetch, hits: 1},
		{name: "plaintext redirect", source: base, path: "/plaintext", want: providers.ErrFetch, hits: 1},
		{name: "redirect disabled", source: base, limits: providerLimitsConfig{MaxRedirects: &zero}, path: "/redirect", want: providers.ErrFetch, hits: 1},
		{name: "wire limit", source: base, limits: providerLimitsConfig{MaxBodyBytes: &small}, path: "/subscription", want: providers.ErrFetch, hits: 1},
		{name: "decoded limit", source: base, limits: providerLimitsConfig{MaxDecodedBytes: &decoded}, path: "/gzip", want: providers.ErrFetch, hits: 1},
		{name: "node limit", source: base, limits: providerLimitsConfig{MaxNodes: &one}, path: "/two", hits: 1},
		{name: "line limit", source: base, limits: providerLimitsConfig{MaxLineBytes: &line}, path: "/subscription", hits: 1},
		{name: "request timeout", source: base, limits: providerLimitsConfig{RequestTimeout: &timeout}, path: "/slow", want: providers.ErrFetch, hits: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry, err := newProviderRegistry(writeProviderFetchTestConfig(t, providerFetchConfig{Allowlist: []providerSourceConfig{test.source}, Limits: test.limits}))
			if err != nil {
				t.Fatal(err)
			}
			before := sourceRequests.Load()
			_, _, err = registry.Refresh(context.Background(), domain.Provider{ID: fmt.Sprintf("test-%d", i), Source: source.URL + test.path, FetchRoute: test.route}, providers.FormatLinks)
			if err == nil || (test.want != nil && !errors.Is(err, test.want)) {
				t.Fatalf("error=%v, expected %v", err, test.want)
			}
			if actual := sourceRequests.Load() - before; actual != test.hits || targetRequests.Load() != 0 {
				t.Fatalf("request boundary violated: source=%d expected=%d target=%d", actual, test.hits, targetRequests.Load())
			}
		})
	}
}
