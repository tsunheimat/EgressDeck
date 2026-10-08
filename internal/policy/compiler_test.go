package policy

import (
	"strings"
	"testing"
)

func baselineInput() CompileInput {
	return CompileInput{
		Gateway: Gateway{ID: "gw-1", SupportedTransports: []Transport{TransportTCP, TransportUDP}, SupportsIPv6: true},
		Devices: []Device{
			{ID: "dev-a", Name: "A", Addresses: []DeviceAddress{{Address: "192.0.2.10"}}, Enabled: true},
			{ID: "dev-b", Name: "B", Addresses: []DeviceAddress{{Address: "192.0.2.11"}}, Enabled: true},
		},
		DeviceGroups: []DeviceGroup{{ID: "group-a", GatewayID: "gw-1", PolicyID: "policy-a", DeviceIDs: []string{"dev-a", "dev-b"}, Enabled: true}},
		Policies:     []Policy{{ID: "policy-a", DefaultAction: Direct(), Rules: []Rule{{ID: "block-tracker", Name: "block tracker", Match: Match{DomainSuffix: []string{"tracker.example"}}, Action: Block(), Enabled: true}}}},
	}
}

func TestCompileIsDeterministicAndSourceScoped(t *testing.T) {
	in := baselineInput()
	a, err := Compile(in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	in.Devices[0], in.Devices[1] = in.Devices[1], in.Devices[0]
	in.DeviceGroups[0].DeviceIDs = []string{"dev-b", "dev-a"}
	b, err := Compile(in)
	if err != nil {
		t.Fatalf("reordered compile: %v", err)
	}
	if a.Manifest.ContentHash != b.Manifest.ContentHash {
		t.Fatalf("reordering changed hash: %s != %s", a.Manifest.ContentHash, b.Manifest.ContentHash)
	}
	if got := a.Manifest.Groups[0].Rules[0].SourceSelector; len(got) != 2 || got[0] != "192.0.2.10/32" || got[1] != "192.0.2.11/32" {
		t.Fatalf("source selector = %#v", got)
	}
	if len(a.SourceMap) != 1 || a.SourceMap[0].Source.RuleID != "block-tracker" {
		t.Fatalf("source map = %#v", a.SourceMap)
	}
}

func TestRuleSetExpansionPreservesOrderAndSource(t *testing.T) {
	in := baselineInput()
	in.Policies[0].Entries = []PolicyEntry{{RuleSetID: "mandatory-set"}}
	in.Policies[0].Rules = nil
	in.RuleSets = []RuleSet{{ID: "mandatory-set", Rules: []Rule{{ID: "first", Match: Match{Transport: []Transport{TransportTCP}}, Action: Block(), Enabled: true}, {ID: "second", Match: Match{DestinationPorts: []PortRange{Port(443)}}, Action: Direct(), Enabled: true}}}}
	result, err := Compile(in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(result.Manifest.Groups[0].Rules) != 2 {
		t.Fatalf("rules = %#v", result.Manifest.Groups[0].Rules)
	}
	if got := result.Manifest.Groups[0].Rules[0].Source.RuleSetID; got != "mandatory-set" {
		t.Fatalf("source rule set = %q", got)
	}
	if !strings.Contains(result.Manifest.Groups[0].Rules[0].Expression, "transport=tcp") {
		t.Fatalf("expression = %q", result.Manifest.Groups[0].Rules[0].Expression)
	}
}

func TestMandatoryRulePrecedesDeviceException(t *testing.T) {
	in := baselineInput()
	in.Policies[0].MandatoryRules = []Rule{{ID: "mandatory-block", Match: Match{DomainSuffix: []string{"example"}}, Action: Block(), Enabled: true}}
	in.Devices[0].Exceptions = []Rule{{ID: "exception-direct", Match: Match{DomainExact: []string{"safe.example"}}, Action: Direct(), Enabled: true}}
	result, err := Compile(in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	explanation := result.Explain(Packet{SourceIP: "192.0.2.10", DestinationIP: "198.51.100.2", Domain: "safe.example", Transport: TransportTCP})
	if explanation.Action.Kind != ActionBlock || explanation.Source.Phase != "mandatory" {
		t.Fatalf("explanation = %#v", explanation)
	}
	// The other device is not widened by dev-a's exception.
	explanation = result.Explain(Packet{SourceIP: "192.0.2.11", DestinationIP: "198.51.100.2", Domain: "safe.example", Transport: TransportTCP})
	if explanation.Action.Kind != ActionBlock || explanation.Source.Phase != "mandatory" {
		t.Fatalf("other device explanation = %#v", explanation)
	}
}

func TestExplainDefaultAndDomainMatch(t *testing.T) {
	result, err := Compile(baselineInput())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := result.Explain(Packet{SourceIP: "192.0.2.10", DestinationIP: "198.51.100.2", Domain: "cdn.tracker.example.", Transport: TransportTCP})
	if got.Action.Kind != ActionBlock || got.MatchedRuleID != "block-tracker" || !got.Predicted {
		t.Fatalf("blocked explanation = %#v", got)
	}
	got = result.Explain(Packet{SourceIP: "192.0.2.10", DestinationIP: "198.51.100.2", Domain: "other.example", Transport: TransportTCP})
	if got.Action.Kind != ActionDirect || got.MatchedRuleID != "" {
		t.Fatalf("default explanation = %#v", got)
	}
	got = result.Explain(Packet{SourceIP: "192.0.2.99", DestinationIP: "198.51.100.2", Domain: "tracker.example", Transport: TransportTCP})
	if got.Predicted {
		t.Fatalf("unmanaged source should not match: %#v", got)
	}
}

func TestCompileValidationDiagnostics(t *testing.T) {
	in := baselineInput()
	in.Devices = append(in.Devices, Device{ID: "dev-c", Addresses: []DeviceAddress{{Address: "192.0.2.10"}}})
	in.Policies[0].DefaultAction = Outbound("missing")
	in.Policies[0].Rules[0].Match.DestinationCIDRs = []string{"not-a-cidr"}
	in.Policies[0].Rules[0].Match.Transport = []Transport{TransportQUIC}
	in.Options.SupportedTransports = map[Transport]bool{TransportTCP: true}
	_, err := Compile(in)
	if err == nil {
		t.Fatal("expected validation error")
	}
	validation, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	for _, code := range []string{"unknown_outbound_group", "invalid_cidr", "unsupported_transport", "duplicate_address_ownership"} {
		if !validation.HasCode(code) {
			t.Fatalf("missing diagnostic %q: %#v", code, validation.Problems)
		}
	}
}

func TestStrictUncontrolledIPv6Rejected(t *testing.T) {
	in := baselineInput()
	in.Policies[0].Strict = true
	in.Options.UncontrolledIPv6 = true
	_, err := Compile(in)
	if err == nil {
		t.Fatal("expected strict IPv6 validation error")
	}
	if !strings.Contains(err.Error(), "uncontrolled_ipv6") {
		t.Fatalf("error = %v", err)
	}
}
