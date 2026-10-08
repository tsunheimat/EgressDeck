package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
)

func writeProviderFetchConfigFixture(t *testing.T, mode os.FileMode, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "operator-private-source-policy.json")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProviderFetchConfigRejectsUnsafeFiles(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o620, 0o602, 0o610, 0o601} {
		t.Run(fmt.Sprintf("permissions_%04o", mode), func(t *testing.T) {
			if _, err := newProviderRegistry(writeProviderFetchConfigFixture(t, mode, `{"allowlist":[]}`)); err == nil {
				t.Fatal("nonprivate policy was accepted")
			}
		})
	}
	for name, path := range map[string]string{
		"missing":   filepath.Join(t.TempDir(), "missing-private-policy.json"),
		"directory": t.TempDir(),
		"oversized": writeProviderFetchConfigFixture(t, 0o600, strings.Repeat(" ", providerFetchConfigLimit+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newProviderRegistry(path); err == nil {
				t.Fatal("unsafe policy file was accepted")
			}
		})
	}
}

func TestProviderFetchConfigRejectsSymlinkComponents(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(realDir, "policy.json")
	if err := os.WriteFile(target, []byte(`{"allowlist":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(root, "policy-link.json")
	dirLink := filepath.Join(root, "directory-link")
	if err := os.Symlink(target, fileLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, dirLink); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"file": fileLink, "parent_directory": filepath.Join(dirLink, "policy.json")} {
		t.Run(name, func(t *testing.T) {
			if _, err := newProviderRegistry(path); err == nil {
				t.Fatal("symlinked policy path was accepted")
			}
		})
	}
}

func TestProviderFetchConfigRejectsAmbiguousJSON(t *testing.T) {
	for name, body := range map[string]string{
		"missing_allowlist":    `{}`,
		"root_null":            `null`,
		"root_array":           `[]`,
		"allowlist_null":       `{"allowlist":null}`,
		"entry_null":           `{"allowlist":[null]}`,
		"ports_null":           `{"allowlist":[{"host":"source.internal","ports":null,"cidrs":["10.0.0.0/8"]}]}`,
		"port_null":            `{"allowlist":[{"host":"source.internal","ports":[null],"cidrs":["10.0.0.0/8"]}]}`,
		"limits_null":          `{"allowlist":[],"limits":null}`,
		"limit_null":           `{"allowlist":[],"limits":{"max_redirects":null}}`,
		"duplicate_root":       `{"allowlist":[],"allowlist":[]}`,
		"duplicate_case":       `{"allowlist":[],"ALLOWLIST":[]}`,
		"duplicate_escaped":    `{"allowlist":[],"allowl\u0069st":[]}`,
		"duplicate_entry":      `{"allowlist":[{"host":"source.internal","host":"other.internal","ports":[443],"cidrs":["10.0.0.0/8"]}]}`,
		"duplicate_limit":      `{"allowlist":[],"limits":{"max_redirects":0,"max_redirects":5}}`,
		"unknown_root":         `{"allowlist":[],"operator-private-value":"do-not-disclose"}`,
		"unknown_entry":        `{"allowlist":[{"host":"source.internal","ports":[443],"cidrs":["10.0.0.0/8"],"insecure_skip_verify":true}]}`,
		"plaintext_switch":     `{"allowlist":[],"limits":{"allow_http":true}}`,
		"unverified_route":     `{"allowlist":[],"route":"unqualified"}`,
		"trailing_object":      `{"allowlist":[]} {}`,
		"trailing_null":        `{"allowlist":[]} null`,
		"trailing_junk":        `{"allowlist":[]} operator-private-value`,
		"invalid_json":         `{"allowlist":[],"operator-private-value":"`,
		"excessive_nesting":    `{"allowlist":[[[[[[[[[[]]]]]]]]]]}`,
		"fractional_port":      `{"allowlist":[{"host":"source.internal","ports":[443.5],"cidrs":["10.0.0.0/8"]}]}`,
		"overflowing_duration": `{"allowlist":[],"limits":{"request_timeout_ms":9223372036854775808}}`,
	} {
		t.Run(name, func(t *testing.T) {
			registry, err := newProviderRegistry(writeProviderFetchConfigFixture(t, 0o600, body))
			if err == nil || registry != nil {
				t.Fatal("invalid policy installed a registry")
			}
			if strings.Contains(err.Error(), "operator-private-value") || strings.Contains(err.Error(), "do-not-disclose") {
				t.Fatal("configuration error disclosed file contents")
			}
		})
	}
}

func TestProviderFetchConfigValidatesExactSources(t *testing.T) {
	valid := providerSourceConfig{Host: "source.internal", Ports: []int{443}, CIDRs: []string{"10.2.0.0/16"}}
	tests := []struct {
		name   string
		mutate func(*providerSourceConfig)
	}{
		{"empty_host", func(s *providerSourceConfig) { s.Host = "" }},
		{"whitespace", func(s *providerSourceConfig) { s.Host = " source.internal" }},
		{"wildcard", func(s *providerSourceConfig) { s.Host = "*.internal" }},
		{"scheme", func(s *providerSourceConfig) { s.Host = "https://source.internal" }},
		{"userinfo", func(s *providerSourceConfig) { s.Host = "secret@source.internal" }},
		{"host_port", func(s *providerSourceConfig) { s.Host = "source.internal:443" }},
		{"path", func(s *providerSourceConfig) { s.Host = "source.internal/private" }},
		{"query", func(s *providerSourceConfig) { s.Host = "source.internal?token=secret" }},
		{"unicode", func(s *providerSourceConfig) { s.Host = "sourcé.internal" }},
		{"empty_label", func(s *providerSourceConfig) { s.Host = "source..internal" }},
		{"long_label", func(s *providerSourceConfig) { s.Host = strings.Repeat("x", 64) + ".internal" }},
		{"label_hyphen", func(s *providerSourceConfig) { s.Host = "-source.internal" }},
		{"ipv6_zone", func(s *providerSourceConfig) { s.Host = "fe80::1%eth0" }},
		{"mapped_ipv4", func(s *providerSourceConfig) { s.Host = "::ffff:10.2.0.1" }},
		{"ip_outside_cidrs", func(s *providerSourceConfig) { s.Host = "10.3.0.1" }},
		{"empty_ports", func(s *providerSourceConfig) { s.Ports = nil }},
		{"zero_port", func(s *providerSourceConfig) { s.Ports = []int{0} }},
		{"negative_port", func(s *providerSourceConfig) { s.Ports = []int{-1} }},
		{"large_port", func(s *providerSourceConfig) { s.Ports = []int{65536} }},
		{"duplicate_port", func(s *providerSourceConfig) { s.Ports = []int{443, 443} }},
		{"many_ports", func(s *providerSourceConfig) {
			s.Ports = make([]int, 17)
			for i := range s.Ports {
				s.Ports[i] = i + 1
			}
		}},
		{"empty_cidrs", func(s *providerSourceConfig) { s.CIDRs = nil }},
		{"bare_ip", func(s *providerSourceConfig) { s.CIDRs = []string{"10.2.0.1"} }},
		{"host_bits", func(s *providerSourceConfig) { s.CIDRs = []string{"10.2.0.1/24"} }},
		{"public_cidr", func(s *providerSourceConfig) { s.CIDRs = []string{"8.8.8.0/24"} }},
		{"blanket_ipv4", func(s *providerSourceConfig) { s.CIDRs = []string{"0.0.0.0/0"} }},
		{"blanket_ipv6", func(s *providerSourceConfig) { s.CIDRs = []string{"::/0"} }},
		{"metadata_range", func(s *providerSourceConfig) { s.CIDRs = []string{"169.254.0.0/16"} }},
		{"overbroad_private_range", func(s *providerSourceConfig) { s.CIDRs = []string{"172.0.0.0/8"} }},
		{"duplicate_cidr", func(s *providerSourceConfig) { s.CIDRs = []string{"10.2.0.0/16", "10.2.0.0/16"} }},
		{"many_cidrs", func(s *providerSourceConfig) {
			s.CIDRs = make([]string, 17)
			for i := range s.CIDRs {
				s.CIDRs[i] = fmt.Sprintf("10.2.0.%d/32", i+1)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := valid
			test.mutate(&source)
			body, err := json.Marshal(providerFetchConfig{Allowlist: []providerSourceConfig{source}})
			if err != nil {
				t.Fatal(err)
			}
			if registry, err := newProviderRegistry(writeProviderFetchConfigFixture(t, 0o600, string(body))); err == nil || registry != nil {
				t.Fatal("unsafe source installed a registry")
			}
		})
	}
	for name, sources := range map[string][]providerSourceConfig{
		"duplicate_normalized_host": {valid, {Host: "SOURCE.INTERNAL.", Ports: []int{8443}, CIDRs: []string{"10.3.0.0/16"}}},
		"too_many_sources":          make([]providerSourceConfig, 65),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "too_many_sources" {
				for i := range sources {
					sources[i] = providerSourceConfig{Host: fmt.Sprintf("source%d.internal", i), Ports: []int{443}, CIDRs: []string{"10.2.0.0/16"}}
				}
			}
			body, _ := json.Marshal(providerFetchConfig{Allowlist: sources})
			if registry, err := newProviderRegistry(writeProviderFetchConfigFixture(t, 0o600, string(body))); err == nil || registry != nil {
				t.Fatal("ambiguous or oversized allowlist installed a registry")
			}
		})
	}
}

func TestProviderFetchConfigDefaultsAndLimits(t *testing.T) {
	config, err := readProviderFetchConfig(writeProviderFetchConfigFixture(t, 0o400, `{"allowlist":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	limits, options, err := config.fetchOptions()
	if err != nil || limits != providers.DefaultLimits() || options.DisableRedirects || len(options.Allowlist) != 0 || limits.AllowHTTP || options.RouteVerify != nil {
		t.Fatalf("secure defaults changed: limits=%+v options=%+v err=%v", limits, options, err)
	}
	defaults := providers.DefaultLimits()
	for field, maximum := range map[string]int64{
		"max_body_bytes": defaults.MaxBodyBytes, "max_decoded_bytes": defaults.MaxDecodedBytes,
		"max_nodes": int64(defaults.MaxNodes), "max_line_bytes": int64(defaults.MaxLineBytes),
		"max_parser_depth": int64(defaults.MaxParserDepth), "request_timeout_ms": defaults.RequestTimeout.Milliseconds(),
		"max_redirects": int64(defaults.MaxRedirects),
	} {
		for _, value := range []int64{-1, 0, maximum + 1} {
			if field == "max_redirects" && value == 0 {
				continue
			}
			t.Run(fmt.Sprintf("%s_%d", field, value), func(t *testing.T) {
				body := fmt.Sprintf(`{"allowlist":[],"limits":{%q:%d}}`, field, value)
				if registry, err := newProviderRegistry(writeProviderFetchConfigFixture(t, 0o600, body)); err == nil || registry != nil {
					t.Fatal("unbounded or invalid limit installed a registry")
				}
			})
		}
	}
	body := `{"allowlist":[{"host":"SOURCE.INTERNAL.","ports":[443,8443],"cidrs":["10.2.0.0/16","fc00::/7"]},{"host":"fd00:0000::1","ports":[443],"cidrs":["fd00::/8"]}],"limits":{"max_body_bytes":1024,"max_decoded_bytes":2048,"max_nodes":7,"max_line_bytes":256,"max_parser_depth":4,"max_redirects":0,"request_timeout_ms":1234}}`
	config, err = readProviderFetchConfig(writeProviderFetchConfigFixture(t, 0o600, body))
	if err != nil {
		t.Fatal(err)
	}
	limits, options, err = config.fetchOptions()
	wantLimits := providers.Limits{MaxBodyBytes: 1024, MaxDecodedBytes: 2048, MaxNodes: 7, MaxLineBytes: 256, MaxParserDepth: 4, MaxRedirects: 0, RequestTimeout: 1234 * time.Millisecond}
	wantAllowlist := []providers.SourceAllowlistEntry{{Host: "source.internal", Ports: []int{443, 8443}, CIDRs: []string{"10.2.0.0/16", "fc00::/7"}}, {Host: "fd00::1", Ports: []int{443}, CIDRs: []string{"fd00::/8"}}}
	if err != nil || limits != wantLimits || !options.DisableRedirects || !reflect.DeepEqual(options.Allowlist, wantAllowlist) || options.Limits != (providers.Limits{}) || options.RouteVerify != nil {
		t.Fatalf("bounded policy was not preserved: limits=%+v options=%+v err=%v", limits, options, err)
	}
}
