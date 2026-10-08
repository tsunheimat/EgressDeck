package contract_test

import (
	"encoding/json"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/policy"
)

func TestPolicyFixturePreservesSourceIdentityAndOrderedIntent(t *testing.T) {
	var input policy.CompileInput
	if err := json.Unmarshal(fixture(t, "policy", "contract.json"), &input); err != nil {
		t.Fatalf("decode policy fixture: %v", err)
	}
	if input.Gateway.ID != "gateway-home" || input.Options.GatewayID != input.Gateway.ID {
		t.Fatalf("gateway/options mismatch: gateway=%+v options=%+v", input.Gateway, input.Options)
	}
	if len(input.Devices) != 2 || len(input.DeviceGroups) != 1 || len(input.Policies) != 1 {
		t.Fatalf("fixture cardinality changed: devices=%d groups=%d policies=%d", len(input.Devices), len(input.DeviceGroups), len(input.Policies))
	}
	group := input.DeviceGroups[0]
	if group.ID != "group-development" || group.PolicyID != "policy-development" || len(group.DeviceIDs) != 2 {
		t.Fatalf("invalid device-group fixture: %+v", group)
	}
	policyValue := input.Policies[0]
	if len(policyValue.MandatoryRules) != 1 || len(policyValue.Entries) != 2 {
		t.Fatalf("ordered policy entries changed: mandatory=%d entries=%d", len(policyValue.MandatoryRules), len(policyValue.Entries))
	}
	if policyValue.Entries[0].Rule == nil || policyValue.Entries[0].Rule.ID != "rule-ai" {
		t.Fatalf("first policy entry lost direct rule identity: %+v", policyValue.Entries[0])
	}
	if policyValue.Entries[1].RuleSetID != "ruleset-standard" {
		t.Fatalf("second policy entry lost reusable ruleset reference: %+v", policyValue.Entries[1])
	}
	if policyValue.DefaultAction.Kind != policy.ActionDirect || policyValue.ProxyFailureAction.Kind != policy.ActionBlock {
		t.Fatalf("policy defaults changed: default=%s failure=%s", policyValue.DefaultAction, policyValue.ProxyFailureAction)
	}
}

func TestPolicyMatchJSONMergesCompatibilityAliases(t *testing.T) {
	m := policy.Match{
		DomainSuffix:  []string{"Example.com", "example.com"},
		DestinationIP: []string{"192.0.2.0/24"},
		Ports:         []policy.PortRange{{From: 443}},
		Transports:    []policy.Transport{policy.TransportTCP},
		Families:      []policy.AddressFamily{policy.FamilyIPv4},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	// Aliases are accepted at the API boundary and merged into canonical
	// dimensions before compilation. The fixture test guards that this
	// compatibility behavior remains visible in the wire contract.
	if _, ok := wire["destination_cidrs"]; !ok {
		t.Fatalf("canonical destination_cidrs missing from %s", b)
	}
	if _, ok := wire["destination_ports"]; !ok {
		t.Fatalf("canonical destination_ports missing from %s", b)
	}
	if _, ok := wire["transport"]; !ok {
		t.Fatalf("canonical transport missing from %s", b)
	}
	if _, ok := wire["address_families"]; !ok {
		t.Fatalf("canonical address_families missing from %s", b)
	}
}
