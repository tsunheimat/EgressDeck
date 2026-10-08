package contract_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
)

func fixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller unavailable")
	}
	path := filepath.Join(append([]string{filepath.Dir(file), "..", "fixtures"}, parts...)...)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return b
}

func TestProviderFixturesNormalizeSupportedNodesDeterministically(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		provider string
		format   providers.Format
		count    int
		first    string
	}{
		{name: "sip008", path: "sip008.json", provider: "provider-sip008", format: providers.FormatSIP008, count: 2, first: "alpha"},
		{name: "clash node subset", path: "clash.yaml", provider: "provider-clash", format: providers.FormatClash, count: 2, first: "gamma"},
		{name: "native links", path: "links.txt", provider: "provider-links", format: providers.FormatLinks, count: 2, first: "epsilon"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := fixture(t, "provider", tc.path)
			limits := providers.DefaultLimits()
			got, err := providers.Parse(tc.provider, content, tc.format, limits)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got.Report.Format != tc.format {
				t.Fatalf("format = %q, want %q", got.Report.Format, tc.format)
			}
			if len(got.Nodes) != tc.count {
				t.Fatalf("nodes = %d, want %d (report=%+v)", len(got.Nodes), tc.count, got.Report)
			}
			if got.Nodes[0].Name != tc.first {
				t.Fatalf("first node = %q, want %q", got.Nodes[0].Name, tc.first)
			}

			// Parsing the same bytes twice is the provider revision identity
			// contract: content hashes and node identities must not depend on
			// map iteration or generated IDs.
			again, err := providers.Parse(tc.provider, content, tc.format, limits)
			if err != nil {
				t.Fatalf("second Parse: %v", err)
			}
			if got.ContentHash != again.ContentHash {
				t.Fatalf("content hash changed: %q != %q", got.ContentHash, again.ContentHash)
			}
			for i := range got.Nodes {
				if got.Nodes[i].Identity != again.Nodes[i].Identity || got.Nodes[i].ContentHash != again.Nodes[i].ContentHash {
					t.Fatalf("node %d normalized identity or connection revision changed", i)
				}
				if got.Nodes[i].ID == again.Nodes[i].ID {
					t.Fatalf("node %d public ID must be opaque; lifecycle reconciliation owns stable IDs", i)
				}
			}
		})
	}
}

func TestProviderParserDoesNotExposeNodeSecrets(t *testing.T) {
	parsed, err := providers.Parse("provider-secret-check", fixture(t, "provider", "sip008.json"), providers.FormatSIP008, providers.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(parsed.Nodes)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("alpha-secret")) || bytes.Contains(encoded, []byte("beta-secret")) {
		t.Fatalf("serialized nodes contain credentials: %s", encoded)
	}
}

func TestProviderParserRejectsEmptyAndMalformedFixtures(t *testing.T) {
	for _, name := range []string{"empty.txt", "malformed.txt"} {
		_, err := providers.Parse("provider-invalid", fixture(t, "provider", name), providers.FormatAuto, providers.DefaultLimits())
		if !errors.Is(err, providers.ErrNoNodes) {
			t.Errorf("%s error = %v, want ErrNoNodes", name, err)
		}
	}
}
