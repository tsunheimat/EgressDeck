package policy

import (
	"encoding/json"
	"reflect"
	"testing"
)

func requireDiagnostic(t *testing.T, input CompileInput, code string) {
	t.Helper()
	_, err := Compile(input)
	validation, ok := err.(*ValidationError)
	if !ok || !validation.HasCode(code) {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}

func TestStrictUnknownAndFailureActions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		unknown Action
		failure Action
		code    string
	}{
		{"missing unknown", Action{}, Block(), "unsafe_unknown_domain"},
		{"direct unknown", Direct(), Block(), "unsafe_unknown_domain"},
		{"missing failure", Block(), Action{}, "unsafe_proxy_failure"},
		{"direct failure", Block(), Direct(), "unsafe_proxy_failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := baselineInput()
			in.Policies[0].Strict = true
			in.Policies[0].UnknownDomainAction = tc.unknown
			in.Policies[0].ProxyFailureAction = tc.failure
			requireDiagnostic(t, in, tc.code)
		})
	}
	in := baselineInput()
	in.Policies[0].Strict = true
	in.Policies[0].UnknownDomainAction = Block()
	in.Policies[0].ProxyFailureAction = Block()
	result, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	got := result.Explain(Packet{SourceIP: "192.0.2.10", DestinationIP: "198.51.100.1", Transport: TransportTCP})
	if got.Action.Kind != ActionBlock {
		t.Fatalf("unknown domain leaked to default: %+v", got)
	}
}

func TestEntryChoiceAndRawConfigAreRejected(t *testing.T) {
	in := baselineInput()
	rule := in.Policies[0].Rules[0]
	in.Policies[0].Rules = nil
	in.RuleSets = []RuleSet{{ID: "set", Rules: []Rule{rule}}}
	in.Policies[0].Entries = []PolicyEntry{{Rule: &rule, RuleSetID: "set"}}
	requireDiagnostic(t, in, "ambiguous_entry")
	in.Policies[0].Entries = []PolicyEntry{{}}
	requireDiagnostic(t, in, "invalid_entry")
	in = baselineInput()
	in.Policies[0].Entries = []PolicyEntry{{Rule: &rule}}
	requireDiagnostic(t, in, "ambiguous_policy_entries")
	in = baselineInput()
	in.Policies[0].RawConfigOverride = "unmanaged expression"
	in.Options.AllowUnsafeRawConfig = true
	requireDiagnostic(t, in, "unsafe_raw_config")
}

func TestDisabledDevicesAndEmptySourcesAreNeverEmitted(t *testing.T) {
	in := baselineInput()
	in.Devices[0].Enabled = false
	in.Devices[0].Exceptions = []Rule{{ID: "disabled-direct", Enabled: true, Action: Direct()}}
	result, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	group := result.Manifest.Groups[0]
	if !reflect.DeepEqual(group.SourceSelector, []string{"192.0.2.11/32"}) {
		t.Fatalf("disabled device included: %+v", group.SourceSelector)
	}
	for _, rule := range group.Rules {
		if len(rule.SourceSelector) == 0 || rule.Source.DeviceID == "dev-a" {
			t.Fatalf("disabled/empty rule emitted: %+v", rule)
		}
	}
	in.Devices[1].Enabled = false
	result, err = Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Manifest.Groups) != 0 || len(result.Manifest.Enrollments) != 0 || len(result.SourceMap) != 0 {
		t.Fatalf("empty source group emitted: %+v", result.Manifest)
	}
	in.Devices[1].Enabled = true
	in.Devices[1].Addresses = nil
	requireDiagnostic(t, in, "missing_source_address")
}

func TestGatewayCapabilitiesCannotBeExpandedByOptions(t *testing.T) {
	in := baselineInput()
	in.Gateway.SupportedTransports = []Transport{TransportTCP}
	in.Options.SupportedTransports = map[Transport]bool{TransportTCP: true, TransportQUIC: true}
	in.Policies[0].Rules[0].Match.Transport = []Transport{TransportQUIC}
	requireDiagnostic(t, in, "unsupported_transport")
	in.Gateway.SupportedTransports = []Transport{TransportTCP}
	in.Policies[0].Rules[0].Match.Transport = []Transport{TransportUDP}
	requireDiagnostic(t, in, "unsupported_transport")
	in = baselineInput()
	in.Gateway.SupportsIPv6 = false
	in.Options.SupportsIPv6 = true
	in.Devices[0].Addresses = []DeviceAddress{{Address: "2001:db8::1"}}
	requireDiagnostic(t, in, "unsupported_ipv6")
	in = baselineInput()
	in.Options.DistinguishesNetworks = true
	in.Devices[0].Addresses = []DeviceAddress{{Address: "192.0.2.0/25"}}
	requireDiagnostic(t, in, "indistinguishable_overlap")
}

func TestOverlappingSourcesCannotSelectCompetingPolicies(t *testing.T) {
	in := baselineInput()
	in.Gateway.DistinguishesNetworks = true
	in.Devices[0].Addresses = []DeviceAddress{{Address: "192.0.2.0/24"}}
	in.Devices[1].Addresses = []DeviceAddress{{Address: "192.0.2.128/25"}}
	requireDiagnostic(t, in, "overlapping_source_ownership")
	in.Devices[1].Addresses[0].Address = "192.0.2.240"
	requireDiagnostic(t, in, "overlapping_source_ownership")
	in.Devices[1].Addresses[0].Address = "198.51.100.10"
	if _, err := Compile(in); err != nil {
		t.Fatalf("non-overlapping sources rejected: %v", err)
	}
}

func TestImpactNoOpRemovalAndSameGatewayMove(t *testing.T) {
	in := baselineInput()
	first, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Previous = &first.Manifest
	unchanged, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Impact.RequiresPolicyApply || unchanged.Impact.EnrollmentChanged || len(unchanged.Impact.ChangedGroups) != 0 {
		t.Fatalf("no-op requires apply: %+v", unchanged.Impact)
	}
	in.DeviceGroups[0].Enabled = false
	removed, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if !removed.Impact.RequiresPolicyApply || !removed.Impact.EnrollmentChanged || !reflect.DeepEqual(removed.Impact.ChangedGroups, []string{"group-a"}) {
		t.Fatalf("removal not applied: %+v", removed.Impact)
	}
	in = baselineInput()
	in.Previous = &first.Manifest
	in.DeviceGroups[0].DeviceIDs = []string{"dev-a"}
	in.DeviceGroups = append(in.DeviceGroups, DeviceGroup{ID: "group-b", GatewayID: "gw-1", PolicyID: "policy-a", DeviceIDs: []string{"dev-b"}, Enabled: true})
	moved, err := Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if !moved.Impact.RequiresPolicyApply || moved.Impact.EnrollmentChanged {
		t.Fatalf("same-gateway move requires wrong mutations: %+v", moved.Impact)
	}
}

func TestCompileDoesNotMutateIntent(t *testing.T) {
	in := baselineInput()
	in.Policies[0].MandatoryRules = []Rule{{ID: " block ", Action: Block(), Enabled: true}}
	before, _ := json.Marshal(in)
	if _, err := Compile(in); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(in)
	if string(before) != string(after) {
		t.Fatal("compiler mutated the caller's policy slices")
	}
}
