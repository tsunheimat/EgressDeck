package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func daeFixture() CompileInput {
	in := baselineInput()
	in.OutboundGroups = []OutboundGroup{{ID: "shared-exit", NodeIDs: []string{"node-1"}}}
	in.Policies[0].DefaultAction = Block()
	in.Policies[0].UnknownDomainAction = Block()
	in.Policies[0].ProxyFailureAction = Block()
	in.Policies[0].MandatoryRules = []Rule{{ID: "mandatory", Enabled: true, Match: Match{DomainSuffix: []string{"malware.example"}}, Action: Block()}}
	in.Devices[0].Exceptions = []Rule{{ID: "local", Enabled: true, Match: Match{DestinationCIDRs: []string{"198.51.100.1/32"}}, Action: Direct()}}
	in.Policies[0].Rules = []Rule{{ID: "all-matchers", Enabled: true, Match: Match{
		DomainExact: []string{"api.example.com"}, DomainSuffix: []string{"example.org"},
		DestinationCIDRs: []string{"203.0.113.0/24"}, DestinationPorts: []PortRange{Port(443), Ports(8000, 8080)},
		Transport: []Transport{TransportTCP, TransportUDP}, AddressFamilies: []AddressFamily{FamilyIPv4},
	}, Action: Outbound("shared-exit")}}
	return in
}

func TestDAERendersTypedRulesWithIndividualSourcesAndLineMaps(t *testing.T) {
	artifact, err := RenderDAE(daeFixture())
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Format != "dae-routing-v1" || artifact.DAEBase != DAEBaseRevision || artifact.RequiredGlobals.DialMode != "ip" || artifact.RequiredGlobals.AutoSniffPunt {
		t.Fatalf("wrong artifact contract: %+v", artifact)
	}
	want := []string{
		"sip('192.0.2.10/32') && domain(suffix: 'malware.example') -> block",
		"sip('192.0.2.11/32') && domain(suffix: 'malware.example') -> block",
		"sip('192.0.2.10/32') && dip('198.51.100.1/32') -> direct",
		"domain(full: 'api.example.com', suffix: 'example.org') && dip('203.0.113.0/24') && dport(443, 8000-8080) && l4proto(tcp, udp) && ipversion(4)",
		"sip('192.0.2.10/32') -> block", "sip('192.0.2.11/32') -> block", "fallback: block",
	}
	for _, fragment := range want {
		if !strings.Contains(artifact.RoutingConfig, fragment) {
			t.Fatalf("missing %q in:\n%s", fragment, artifact.RoutingConfig)
		}
	}
	if strings.Contains(artifact.RoutingConfig, "sip('192.0.2.10/32',") {
		t.Fatal("source aggregation changed source/domain semantics")
	}
	if len(artifact.OutboundBindings) != 1 || artifact.OutboundBindings[0].OutboundGroupID != "shared-exit" || !strings.HasPrefix(artifact.OutboundBindings[0].EngineName, "eg_") {
		t.Fatalf("outbound binding mismatch: %+v", artifact.OutboundBindings)
	}
	lines := strings.Split(artifact.RoutingConfig, "\n")
	if len(artifact.SourceMap) != 7 {
		t.Fatalf("line map count = %d", len(artifact.SourceMap))
	}
	for _, mapping := range artifact.SourceMap {
		if !strings.Contains(lines[mapping.Line-1], "sip('"+mapping.SourceSelector+"')") {
			t.Fatalf("wrong source line map: %+v", mapping)
		}
	}
	digest := sha256.Sum256([]byte(artifact.RoutingConfig))
	if artifact.RoutingSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("artifact hash does not bind exact native bytes")
	}
	if strings.Index(artifact.RoutingConfig, "malware.example") > strings.Index(artifact.RoutingConfig, "198.51.100.1") {
		t.Fatal("mandatory restrictions lost precedence")
	}
}

func TestDAERejectsUnrepresentableIntent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*CompileInput)
		code   string
	}{
		{"unknown differs", func(in *CompileInput) { in.Policies[0].UnknownDomainAction = Direct() }, "unsupported_unknown_domain"},
		{"generic proxy", func(in *CompileInput) { in.Policies[0].Rules[0].Action = Proxy() }, "unsupported_dae_action"},
		{"QUIC", func(in *CompileInput) {
			in.Gateway.SupportedTransports = append(in.Gateway.SupportedTransports, TransportQUIC)
			in.Policies[0].Rules[0].Match.Transport = []Transport{TransportQUIC}
		}, "unsupported_dae_transport"},
		{"source subnet", func(in *CompileInput) {
			in.Gateway.DistinguishesNetworks = true
			in.Devices[0].Addresses[0].Address = "198.51.100.0/24"
		}, "unsupported_source_scope"},
		{"domain quote", func(in *CompileInput) { in.Policies[0].Rules[0].Match.DomainExact = []string{"bad'example.com"} }, "unsupported_domain"},
		{"domain wildcard", func(in *CompileInput) { in.Policies[0].Rules[0].Match.DomainExact = []string{"*.example.com"} }, "unsupported_domain"},
		{"empty domain set", func(in *CompileInput) {
			in.DomainSets = []DomainSet{{ID: "empty"}}
			in.Policies[0].Rules[0].Match.DomainSets = []string{"empty"}
		}, "unresolved_domain_set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := daeFixture()
			tc.change(&in)
			artifact, err := RenderDAE(in)
			validation, ok := err.(*ValidationError)
			if !ok || !validation.HasCode(tc.code) {
				t.Fatalf("expected %s, got %v", tc.code, err)
			}
			if artifact.RoutingConfig != "" {
				t.Fatal("failed rendering returned applicable partial configuration")
			}
		})
	}
}

func TestDAEStableNamesAreIndependentOfInventoryAndSafeForArbitraryIDs(t *testing.T) {
	in := daeFixture()
	first, err := RenderDAE(in)
	if err != nil {
		t.Fatal(err)
	}
	in.OutboundGroups[0].NodeIDs = []string{"node-2", "node-3"}
	in.Devices[0], in.Devices[1] = in.Devices[1], in.Devices[0]
	second, err := RenderDAE(in)
	if err != nil {
		t.Fatal(err)
	}
	if first.RoutingConfig != second.RoutingConfig {
		t.Fatal("inventory refresh or entity order changed native routing")
	}
	in.OutboundGroups[0].ID = "exit'\n} routing { fallback: direct }"
	in.Policies[0].Rules[0].Action = Outbound(in.OutboundGroups[0].ID)
	third, err := RenderDAE(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(third.RoutingConfig, "fallback: direct") || strings.Contains(third.RoutingConfig, "exit'") {
		t.Fatal("logical outbound ID was injected into native syntax")
	}
}

func TestDAEDomainSetsKeepANDWithOtherDomainDimension(t *testing.T) {
	in := daeFixture()
	in.DomainSets = []DomainSet{{ID: "selected", Domains: []string{"selected.example.com"}}}
	in.Policies[0].Rules[0].Match.DomainSets = []string{"selected"}
	artifact, err := RenderDAE(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(artifact.RoutingConfig, "domain(full: 'api.example.com', suffix: 'example.org') && domain(suffix: 'selected.example.com')") {
		t.Fatalf("domain set AND was changed:\n%s", artifact.RoutingConfig)
	}
}

func TestDAEBoundsExpansionAndUsesBlockForEmptyInventory(t *testing.T) {
	in := daeFixture()
	for i := 0; i < 200; i++ {
		in.Policies[0].Rules = append(in.Policies[0].Rules, in.Policies[0].Rules[0])
	}
	if _, err := RenderDAE(in); err == nil {
		t.Fatal("unbounded source/rule expansion accepted")
	}
	in = daeFixture()
	in.Devices[0].Enabled = false
	in.Devices[1].Enabled = false
	artifact, err := RenderDAE(in)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.RoutingConfig != "routing {\n  fallback: block\n}\n" {
		t.Fatalf("empty inventory became permissive: %s", artifact.RoutingConfig)
	}
}

func TestDAEArtifactBindsStrictGuardRequirement(t *testing.T) {
	in := daeFixture()
	ordinary, err := RenderDAE(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Policies[0].Strict = true
	strict, err := RenderDAE(in)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.RequiresGuard || !strict.RequiresGuard {
		t.Fatal("strict policy lost the independent guard requirement")
	}
	if ordinary.ContentHash == strict.ContentHash || ordinary.RoutingSHA256 != strict.RoutingSHA256 {
		t.Fatal("artifact identity must bind guard requirement independently of routing bytes")
	}
}
