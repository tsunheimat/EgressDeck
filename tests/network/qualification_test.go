//go:build network

package network_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// This is an evidence gate, not a substitute for the topology harness. It
// fails closed when the protected runner has not produced real artifacts.
func TestNetworkQualificationEvidence(t *testing.T) {
	path := os.Getenv("NETWORK_QUALIFICATION_EVIDENCE")
	if path == "" {
		t.Fatal("NETWORK_QUALIFICATION_EVIDENCE must name a fresh real-network receipt; simulated tests do not qualify")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read network receipt: %v", err)
	}
	var receipt struct {
		SourceCommit string            `json:"source_commit"`
		RunID        string            `json:"run_id"`
		StartedAt    time.Time         `json:"started_at"`
		EngineSHA    string            `json:"engine_artifact_sha256"`
		TopologySHA  string            `json:"topology_sha256"`
		Checks       map[string]string `json:"checks"`
		Artifacts    []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatalf("decode network receipt: %v", err)
	}
	sha := os.Getenv("GITHUB_SHA")
	if sha == "" || receipt.SourceCommit != sha {
		t.Fatal("receipt must match GITHUB_SHA for the checked-out source")
	}
	if receipt.RunID == "" || receipt.StartedAt.IsZero() || time.Since(receipt.StartedAt) < 0 || time.Since(receipt.StartedAt) > 24*time.Hour {
		t.Fatal("receipt must identify a fresh run within the last 24 hours")
	}
	hexSHA := regexp.MustCompile(`^[0-9a-f]{64}$`)
	if !hexSHA.MatchString(receipt.EngineSHA) || !hexSHA.MatchString(receipt.TopologySHA) {
		t.Fatal("engine artifact and topology SHA-256 hashes are required")
	}
	for _, name := range []string{"source_identity", "direct_tcp_udp", "proxy_tcp_udp", "blocked_traffic", "deny_preservation", "hot_provider_publication", "unrelated_tcp_udp_survival", "selection_restart", "dns", "ipv6_coverage", "failure_guard", "restore", "bounded_retained_resources"} {
		if receipt.Checks[name] != "PASS" {
			t.Errorf("required real-network check %q did not pass", name)
		}
	}
	if len(receipt.Artifacts) == 0 {
		t.Fatal("receipt must reference independently readable redacted network artifacts")
	}
	base := filepath.Dir(path)
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatalf("resolve receipt directory: %v", err)
	}
	for _, artifact := range receipt.Artifacts {
		clean := filepath.Clean(artifact.Path)
		if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			t.Errorf("artifact path must remain inside receipt directory: %q", artifact.Path)
			continue
		}
		artifactPath, err := filepath.EvalSymlinks(filepath.Join(base, clean))
		if err != nil {
			t.Errorf("resolve artifact %q: %v", artifact.Path, err)
			continue
		}
		relative, err := filepath.Rel(resolvedBase, artifactPath)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			t.Errorf("artifact symlink escapes receipt directory: %q", artifact.Path)
			continue
		}
		content, err := os.ReadFile(artifactPath)
		if err != nil {
			t.Errorf("read artifact %q: %v", artifact.Path, err)
			continue
		}
		sum := sha256.Sum256(content)
		if hex.EncodeToString(sum[:]) != artifact.SHA256 {
			t.Errorf("artifact %q hash mismatch", artifact.Path)
		}
	}
}
