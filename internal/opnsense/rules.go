package opnsense

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ManagedAlias is an explicit mutation allowlist entry. Shape binds the alias
// name to its UUID/type/description; Rules bind that alias to reviewed modern
// steering rules. A tag or matching name alone never authorizes mutation.
type ManagedAlias struct {
	Shape          AliasShape        `json:"shape"`
	GatewayID      string            `json:"gateway_id"`
	InterfaceScope string            `json:"interface_scope"`
	Family         AddressFamily     `json:"family"`
	Rules          []RuleExpectation `json:"rules"`
	Review         PolicyReview      `json:"review"`
}

// PolicyReview captures installation evidence the selected-rule API cannot
// establish. A declaration is not an automated packet-path test. The caller
// must store the evidence and invalidate/review it when the topology changes.
type PolicyReview struct {
	Reviewer                string    `json:"reviewer"`
	ReviewedAt              time.Time `json:"reviewed_at"`
	EvidenceReference       string    `json:"evidence_reference"`
	PacketPathEvidence      string    `json:"packet_path_evidence"`
	ExistingDeniesPreserved bool      `json:"existing_denies_preserved"`
	ManagementExcluded      bool      `json:"management_excluded"`
	TransitExcluded         bool      `json:"transit_excluded"`
}

// RuleExpectation pins the normalized complete modern-rule settings, including
// sequence, quick, exclusions, ports, and advanced fields. ReadSteeringRule
// provides a hash to show in an attach preview; only a reviewed hash may be
// registered as expected. Legacy rules have no supported read endpoint here.
type RuleExpectation struct {
	UUID           string `json:"uuid"`
	SnapshotHash   string `json:"snapshot_hash"`
	Gateway        string `json:"gateway"`
	Destination    string `json:"destination"`
	DestinationNot bool   `json:"destination_not"`
}

type SteeringRule struct {
	UUID         string                     `json:"uuid"`
	SnapshotHash string                     `json:"snapshot_hash"`
	Fields       map[string]json.RawMessage `json:"fields"`
}

func (m ManagedAlias) Validate() error {
	if !validAliasName(m.Shape.Name) || !uuidPattern.MatchString(m.Shape.UUID) || m.Shape.Disabled || (m.Shape.Type != HostAlias && m.Shape.Type != NetworkAlias) || m.Shape.OwnerTag != "" {
		return fmt.Errorf("%w: enabled alias UUID/type/description required; native aliases have no owner-tag field", ErrScope)
	}
	if m.GatewayID == "" || m.InterfaceScope == "" || strings.ContainsAny(m.InterfaceScope, ", \t\n") || (m.Family != IPv4Family && m.Family != IPv6Family) {
		return fmt.Errorf("%w: gateway, single client interface, and single address family required", ErrScope)
	}
	if len(m.Rules) == 0 {
		return fmt.Errorf("%w: reviewed modern steering rules required", ErrScope)
	}
	seen := map[string]bool{}
	for _, rule := range m.Rules {
		hash, err := hex.DecodeString(rule.SnapshotHash)
		if !uuidPattern.MatchString(rule.UUID) || seen[rule.UUID] || err != nil || len(hash) != sha256.Size || rule.Gateway == "" || strings.TrimSpace(rule.Destination) == "" {
			return fmt.Errorf("%w: invalid rule UUID, hash, or gateway", ErrScope)
		}
		seen[rule.UUID] = true
	}
	r := m.Review
	if strings.TrimSpace(r.Reviewer) == "" || r.ReviewedAt.IsZero() || r.EvidenceReference == "" || r.PacketPathEvidence == "" || !r.ExistingDeniesPreserved || !r.ManagementExcluded || !r.TransitExcluded {
		return fmt.Errorf("%w: deny ordering, management/transit exclusions and packet-path review required", ErrScope)
	}
	return nil
}

// ReadSteeringRule inspects only API-backed rules. Missing UUIDs and legacy
// rule identifiers are rejected rather than converted to new-rule defaults.
func (c *HTTPClient) ReadSteeringRule(ctx context.Context, uuid string) (SteeringRule, error) {
	if !uuidPattern.MatchString(uuid) {
		return SteeringRule{}, fmt.Errorf("%w: modern rule UUID required", ErrUnsupported)
	}
	var rawResponse json.RawMessage
	if err := c.request(ctx, "GET", "/api/firewall/filter/get_rule/"+uuid, nil, &rawResponse); err != nil {
		return SteeringRule{}, err
	}
	if bytes.Equal(bytes.TrimSpace(rawResponse), []byte("[]")) {
		return SteeringRule{}, ErrNotFound
	}
	var response struct {
		Rule map[string]json.RawMessage `json:"rule"`
	}
	if json.Unmarshal(rawResponse, &response) != nil {
		return SteeringRule{}, ErrProtocol
	}
	if len(response.Rule) == 0 {
		return SteeringRule{}, ErrNotFound
	}
	// Discard unselected UI menu entries and display labels, preserving all
	// settings values. Unrelated menu choices do not create spurious drift.
	normalized := map[string]json.RawMessage{}
	for key, raw := range response.Rule {
		// BaseField adds %-prefixed localized placeholder descriptions for
		// scalar fields. They are presentation data, not rule configuration.
		if strings.HasPrefix(key, "%") {
			continue
		}
		if ignoredRuleField[key] {
			continue
		}
		var scalar string
		if json.Unmarshal(raw, &scalar) == nil && string(raw) != "null" {
			normalized[key], _ = json.Marshal(scalar)
			continue
		}
		selected, err := selectedOptions(raw)
		if err != nil {
			return SteeringRule{}, ErrProtocol
		}
		normalized[key], _ = json.Marshal(selected)
	}
	encoded, _ := json.Marshal(normalized)
	hash := sha256.Sum256(encoded)
	return SteeringRule{UUID: uuid, SnapshotHash: hex.EncodeToString(hash[:]), Fields: normalized}, nil
}

var ignoredRuleField = map[string]bool{
	// Volatile ordering/telemetry fields: sequence and prio_group remain in
	// the snapshot and are validated as part of the narrow steering contract.
	"sort_order": true, "current_items": true, "last_updated": true,
	"eval_nomatch": true, "eval_match": true, "in_block_p": true,
	"in_block_b": true, "in_pass_p": true, "in_pass_b": true,
	"out_block_p": true, "out_block_b": true, "out_pass_p": true,
	"out_pass_b": true,
}

// ValidateBinding is an additional adapter gate: a binding cannot substitute
// a different gateway, source scope, or rule set for its registered allowlist.
func (c *HTTPClient) ValidateBinding(ctx context.Context, binding Binding) error {
	managed, ok := c.managed[binding.Alias.Name]
	if !ok || managed.Shape != binding.Alias || managed.GatewayID != binding.GatewayID || managed.Family != binding.Family || managed.InterfaceScope != binding.InterfaceScope {
		return ErrScope
	}
	expected := make([]string, 0, len(managed.Rules))
	for _, rule := range managed.Rules {
		expected = append(expected, rule.UUID)
	}
	observed := append([]string(nil), binding.RuleIDs...)
	sort.Strings(expected)
	sort.Strings(observed)
	if !equalStrings(expected, observed) {
		return ErrScope
	}
	_, err := c.authorize(ctx, managed)
	return err
}

func (c *HTTPClient) authorize(ctx context.Context, managed ManagedAlias) (AliasRecord, error) {
	persisted, err := c.ReadPersistedAlias(ctx, managed.Shape.Name)
	if err != nil {
		return AliasRecord{}, err
	}
	active, err := c.ReadActiveAlias(ctx, managed.Shape.Name)
	if err != nil {
		return AliasRecord{}, err
	}
	if !shapeMatches(managed.Shape, persisted) || !shapeMatches(managed.Shape, active) || !equalStrings(persisted.Addresses, active.Addresses) {
		return AliasRecord{}, ErrDrift
	}
	if err := validateFamily(managed.Family, persisted.Addresses); err != nil {
		return AliasRecord{}, err
	}
	for _, expected := range managed.Rules {
		rule, err := c.ReadSteeringRule(ctx, expected.UUID)
		if err != nil {
			return AliasRecord{}, err
		}
		if rule.SnapshotHash != expected.SnapshotHash {
			return AliasRecord{}, fmt.Errorf("%w: steering rule snapshot changed", ErrDrift)
		}
		family := "inet"
		if managed.Family == IPv6Family {
			family = "inet6"
		}
		destinationNot := "0"
		if expected.DestinationNot {
			destinationNot = "1"
		}
		scalars := map[string]string{"enabled": "1", "quick": "1", "source_not": "0", "interfacenot": "0", "source_net": managed.Shape.Name, "source_port": "", "destination_port": "", "destination_net": expected.Destination, "destination_not": destinationNot, "tagged": "", "prio_group": "400000"}
		for key, expected := range scalars {
			var actual string
			if json.Unmarshal(rule.Fields[key], &actual) != nil || actual != expected {
				return AliasRecord{}, fmt.Errorf("%w: unsupported steering rule shape", ErrScope)
			}
		}
		options := map[string][]string{"action": {"pass"}, "direction": {"in"}, "ipprotocol": {family}, "interface": {managed.InterfaceScope}, "gateway": {expected.Gateway}, "protocol": {"any"}, "statetype": {"keep"}, "sched": {""}, "divert-to": {""}, "replyto": {""}, "prio": {""}, "tos": {""}}
		for key, expected := range options {
			var actual []string
			if json.Unmarshal(rule.Fields[key], &actual) != nil || !equalStrings(actual, expected) {
				return AliasRecord{}, fmt.Errorf("%w: unsupported steering rule shape", ErrScope)
			}
		}
	}
	return persisted, nil
}
