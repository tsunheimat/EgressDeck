package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDAEPinnedNativeValidation uses the actual upstream CLI config parser and
// run-path routing lowering. It is opt-in because the controller intentionally
// does not link dae or download/build an engine during ordinary unit tests.
func TestDAEPinnedNativeValidation(t *testing.T) {
	validator := os.Getenv("DAE_POLICY_VALIDATOR")
	if validator == "" {
		t.Skip("set DAE_POLICY_VALIDATOR and DAE_POLICY_VALIDATOR_SHA256 to run pinned native parser validation")
	}
	expected := os.Getenv("DAE_POLICY_VALIDATOR_SHA256")
	if len(expected) != 64 {
		t.Fatal("native validation requires an explicit binary SHA-256 receipt")
	}
	binary, err := os.ReadFile(validator)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binary)
	if hex.EncodeToString(digest[:]) != expected {
		t.Fatal("native validator binary differs from expected receipt")
	}
	t.Logf("native dae base=%s validator_sha256=%s", DAEBaseRevision, expected)
	validate := func(t *testing.T, configuration string, wantOK bool) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.dae")
		if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, validator, "validate", "--config", path).CombinedOutput()
		if (err == nil) != wantOK {
			t.Fatalf("native validation want success=%t, err=%v, output=%s", wantOK, err, output)
		}
	}
	for _, scenario := range []struct {
		name  string
		input CompileInput
	}{
		{"all-matchers-ipv4", daeFixture()},
		{"ipv6", daeIPv6Fixture()},
		{"domain-set-conjunction", daeDomainSetFixture()},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			artifact, err := RenderDAE(scenario.input)
			if err != nil {
				t.Fatal(err)
			}
			configuration := daeNativeValidationConfig(artifact)
			validate(t, configuration, true)
			// A native-negative case ensures this executable is checking routing
			// operands, rather than merely accepting the outer file grammar.
			invalid := strings.Replace(configuration, "fallback: block", "l4proto(quic) -> block\n  fallback: block", 1)
			validate(t, invalid, false)
			missing := strings.Replace(configuration, "fallback: block", "fallback: missing_group", 1)
			validate(t, missing, false)
		})
	}
}

func daeIPv6Fixture() CompileInput {
	in := daeFixture()
	in.Devices = in.Devices[:1]
	in.DeviceGroups[0].DeviceIDs = []string{"dev-a"}
	in.Devices[0].Addresses = []DeviceAddress{{Address: "2001:db8::1", Family: FamilyIPv6}}
	in.Policies[0].Rules[0].Match.DestinationCIDRs = []string{"2001:db8:1::/48"}
	in.Policies[0].Rules[0].Match.AddressFamilies = []AddressFamily{FamilyIPv6}
	return in
}

func daeDomainSetFixture() CompileInput {
	in := daeFixture()
	in.DomainSets = []DomainSet{{ID: "immutable", Domains: []string{"selected.example.com", "other.example.com"}}}
	in.Policies[0].Rules[0].Match.DomainSets = []string{"immutable"}
	return in
}

// These native group declarations exist only to resolve the exact configured
// outbound names in the parser test. They do not establish candidate, selection,
// connectivity, DNS, ingress or runtime qualification.
func daeNativeValidationConfig(artifact DAEArtifact) string {
	var config strings.Builder
	config.WriteString("global {\n  dial_mode: ip\n  auto_sniff_punt: false\n}\n")
	if len(artifact.OutboundBindings) > 0 {
		config.WriteString("group {\n")
		for _, binding := range artifact.OutboundBindings {
			config.WriteString("  " + binding.EngineName + " {\n    policy: fixed(0)\n  }\n")
		}
		config.WriteString("}\n")
	}
	config.WriteString(artifact.RoutingConfig)
	return config.String()
}
