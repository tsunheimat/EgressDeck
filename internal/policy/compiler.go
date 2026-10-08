package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Compiler is stateless. Keeping it as a type allows adapter-specific options
// to be added later without changing the CompileInput contract.
type Compiler struct{}

func NewCompiler() *Compiler { return &Compiler{} }

// Compile produces a deterministic immutable snapshot. A result is returned
// alongside validation errors so callers can render all diagnostics at once;
// callers must not apply a result when err is non-nil.
func Compile(in CompileInput) (CompileResult, error) { return (&Compiler{}).Compile(in) }

// CompilePolicy is a descriptive alias for integrations that expose policy as
// a first-class API resource.
func CompilePolicy(in CompileInput) (CompileResult, error) { return Compile(in) }

// CompileManifest returns only the immutable gateway manifest.
func CompileManifest(in CompileInput) (Manifest, error) {
	result, err := Compile(in)
	return result.Manifest, err
}

// Validate performs the same deterministic checks as Compile without
// constructing a deployment snapshot.
func Validate(in CompileInput) []Diagnostic { return validateInput(normalizeInput(in)) }

func (c *Compiler) Compile(in CompileInput) (CompileResult, error) {
	n := normalizeInput(in)
	diagnostics := validateInput(n)
	if hasErrors(diagnostics) {
		return CompileResult{Diagnostics: sortDiagnostics(diagnostics)}, &ValidationError{Problems: sortDiagnostics(diagnostics)}
	}

	groups := make([]CompiledGroup, 0, len(n.groups))
	sourceMap := make([]SourceMapEntry, 0)
	enrollments := make([]EnrollmentSet, 0, len(n.groups))
	generatedIDs := map[string]int{}
	for _, group := range n.groups {
		if !group.Enabled {
			continue
		}
		p := n.policies[group.PolicyID]
		members := append([]string(nil), group.DeviceIDs...)
		sort.Strings(members)
		groupSources := make([]string, 0)
		for _, id := range members {
			if !n.devices[id].Enabled {
				continue
			}
			for _, address := range n.devices[id].Addresses {
				if source, ok := canonicalSource(address.Address); ok {
					groupSources = append(groupSources, source)
				}
			}
		}
		groupSources = uniqueSorted(groupSources)
		if len(groupSources) == 0 {
			continue
		}
		cg := CompiledGroup{
			DeviceGroupID:       group.ID,
			GatewayID:           group.GatewayID,
			SourceSelector:      groupSources,
			DefaultAction:       normalizeAction(p.DefaultAction),
			UnknownDomainAction: normalizeAction(p.UnknownDomainAction),
			ProxyFailureAction:  normalizeAction(p.ProxyFailureAction),
		}
		if cg.UnknownDomainAction.Kind == "" {
			cg.UnknownDomainAction = cg.DefaultAction
		}
		if cg.ProxyFailureAction.Kind == "" {
			cg.ProxyFailureAction = Block()
		}

		// Mandatory restrictions are emitted for the complete group source list.
		for i, rule := range orderedRules(append(append([]Rule(nil), p.mandatoryRules()...), nil...)) {
			if !rule.Enabled {
				continue
			}
			nr, ds := normalizedRule(rule, i, "mandatory", SourceRef{PolicyID: p.ID, DeviceGroupID: group.ID, RuleID: rule.ID, Phase: "mandatory"})
			if len(ds) > 0 {
				// Input was validated above, so this is defensive only.
				return CompileResult{Diagnostics: ds}, &ValidationError{Problems: ds}
			}
			nr.SourceSelector = groupSources
			nr.ID = uniqueGeneratedID(nr.ID, generatedIDs)
			cg.Rules = append(cg.Rules, nr)
			sourceMap = append(sourceMap, SourceMapEntry{GeneratedID: nr.ID, Source: nr.Source})
		}
		// Policy-level exceptions apply to the group source set. Device-level
		// exceptions below are narrowed to one source selector per device.
		for i, rule := range orderedRules(p.Exceptions) {
			if !rule.Enabled {
				continue
			}
			nr, ds := normalizedRule(rule, i, "exception", SourceRef{PolicyID: p.ID, DeviceGroupID: group.ID, RuleID: rule.ID, Phase: "exception"})
			if len(ds) > 0 {
				return CompileResult{Diagnostics: ds}, &ValidationError{Problems: ds}
			}
			nr.SourceSelector = groupSources
			nr.ID = uniqueGeneratedID(nr.ID, generatedIDs)
			cg.Rules = append(cg.Rules, nr)
			sourceMap = append(sourceMap, SourceMapEntry{GeneratedID: nr.ID, Source: nr.Source})
		}

		// Per-device exceptions must retain an individual source selector. This
		// prevents one member's exception from widening another member's policy.
		for _, deviceID := range members {
			device := n.devices[deviceID]
			if !device.Enabled {
				continue
			}
			for i, rule := range orderedRules(device.Exceptions) {
				if !rule.Enabled {
					continue
				}
				nr, ds := normalizedRule(rule, i, "exception", SourceRef{PolicyID: p.ID, DeviceGroupID: group.ID, DeviceID: device.ID, RuleID: rule.ID, Phase: "exception"})
				if len(ds) > 0 {
					return CompileResult{Diagnostics: ds}, &ValidationError{Problems: ds}
				}
				nr.SourceSelector = addressesForDevice(device)
				nr.ID = uniqueGeneratedID(nr.ID, generatedIDs)
				cg.Rules = append(cg.Rules, nr)
				sourceMap = append(sourceMap, SourceMapEntry{GeneratedID: nr.ID, Source: nr.Source})
			}
		}

		entries := expandEntries(p, n.ruleSets)
		for i, entry := range entries {
			if !entry.Rule.Enabled {
				continue
			}
			source := SourceRef{PolicyID: p.ID, DeviceGroupID: group.ID, RuleID: entry.Rule.ID, RuleSetID: entry.RuleSetID, Phase: "group"}
			nr, ds := normalizedRule(entry.Rule, i, "group", source)
			if len(ds) > 0 {
				return CompileResult{Diagnostics: ds}, &ValidationError{Problems: ds}
			}
			nr.SourceSelector = groupSources
			nr.ID = uniqueGeneratedID(nr.ID, generatedIDs)
			cg.Rules = append(cg.Rules, nr)
			sourceMap = append(sourceMap, SourceMapEntry{GeneratedID: nr.ID, Source: nr.Source})
		}
		groups = append(groups, cg)
		enrollments = append(enrollments, EnrollmentSet{GatewayID: group.GatewayID, GroupID: group.ID, Addresses: groupSources})
	}

	sort.Slice(groups, func(i, j int) bool { return groups[i].DeviceGroupID < groups[j].DeviceGroupID })
	sort.Slice(enrollments, func(i, j int) bool {
		if enrollments[i].GatewayID == enrollments[j].GatewayID {
			return enrollments[i].GroupID < enrollments[j].GroupID
		}
		return enrollments[i].GatewayID < enrollments[j].GatewayID
	})
	sort.Slice(sourceMap, func(i, j int) bool { return sourceMap[i].GeneratedID < sourceMap[j].GeneratedID })
	manifest := Manifest{Version: 1, GatewayID: n.gatewayID, Groups: groups, Enrollments: enrollments, SourceMap: sourceMap, DomainSets: normalizedDomainSets(n.domainSets)}
	manifest.ContentHash = manifestHash(manifest)
	impact := impactReport(manifest, n.previous)
	result := CompileResult{Manifest: manifest, Normalized: groups, SourceMap: sourceMap, Impact: impact}
	return result, nil
}

func uniqueGeneratedID(base string, seen map[string]int) string {
	count := seen[base]
	seen[base] = count + 1
	if count == 0 {
		return base
	}
	return fmt.Sprintf("%s~%d", base, count+1)
}

type normalizedInput struct {
	gatewayID  string
	devices    map[string]Device
	groups     []DeviceGroup
	policies   map[string]Policy
	ruleSets   map[string]RuleSet
	domainSets map[string]DomainSet
	outbounds  map[string]OutboundGroup
	options    CompileOptions
	previous   *Manifest
	preflight  []Diagnostic
}

func normalizeInput(in CompileInput) normalizedInput {
	n := normalizedInput{gatewayID: strings.TrimSpace(in.Gateway.ID), devices: map[string]Device{}, groups: nil, policies: map[string]Policy{}, ruleSets: map[string]RuleSet{}, domainSets: map[string]DomainSet{}, outbounds: map[string]OutboundGroup{}, options: in.Options, previous: in.Previous}
	if in.Options.GatewayID != "" && in.Gateway.ID != "" && strings.TrimSpace(in.Options.GatewayID) != strings.TrimSpace(in.Gateway.ID) {
		n.preflight = append(n.preflight, Diagnostic{Severity: SeverityError, Code: "gateway_mismatch", Path: "options.gateway_id", Message: "options gateway id does not match gateway id"})
	}
	if in.Gateway.ID != "" {
		n.options.SupportedTransports = map[Transport]bool{}
		for _, transport := range in.Gateway.SupportedTransports {
			transport = normalizeTransport(transport)
			if in.Options.SupportedTransports == nil || in.Options.SupportedTransports[transport] {
				n.options.SupportedTransports[transport] = true
			}
		}
	}
	if in.Gateway.ID != "" {
		n.options.SupportsIPv6 = in.Gateway.SupportsIPv6
		n.options.DistinguishesNetworks = in.Gateway.DistinguishesNetworks
	}
	seenIDs := map[string]map[string]bool{"device": {}, "group": {}, "policy": {}, "ruleset": {}, "domain_set": {}, "outbound": {}}
	checkID := func(kind, id string) {
		if id == "" {
			return
		}
		if seenIDs[kind][id] {
			n.preflight = append(n.preflight, Diagnostic{Severity: SeverityError, Code: "duplicate_id", Path: kind + "." + id, Message: "duplicate " + kind + " id"})
		}
		seenIDs[kind][id] = true
	}
	if n.gatewayID == "" {
		n.gatewayID = strings.TrimSpace(in.Options.GatewayID)
	}
	for _, d := range in.Devices {
		d.ID = strings.TrimSpace(d.ID)
		checkID("device", d.ID)
		d.GroupID = strings.TrimSpace(d.GroupID)
		d.Addresses = append([]DeviceAddress(nil), d.Addresses...)
		for i := range d.Addresses {
			d.Addresses[i].Address = strings.TrimSpace(d.Addresses[i].Address)
			d.Addresses[i].Family = normalizeFamily(d.Addresses[i].Family)
		}
		d.Exceptions = append([]Rule(nil), d.Exceptions...)
		n.devices[d.ID] = d
	}
	for _, g := range in.DeviceGroups {
		g.ID = strings.TrimSpace(g.ID)
		checkID("group", g.ID)
		g.GatewayID = strings.TrimSpace(g.GatewayID)
		g.PolicyID = strings.TrimSpace(g.PolicyID)
		g.DeviceIDs = uniqueSorted(append(append([]string(nil), g.DeviceIDs...), g.Members...))
		n.groups = append(n.groups, g)
	}
	sort.Slice(n.groups, func(i, j int) bool { return n.groups[i].ID < n.groups[j].ID })
	for _, set := range in.DomainSets {
		set.ID = strings.TrimSpace(set.ID)
		checkID("domain_set", set.ID)
		set.Domains = normalizeDomainValues(set.Domains)
		n.domainSets[set.ID] = set
	}
	for _, p := range in.Policies {
		p.ID = strings.TrimSpace(p.ID)
		checkID("policy", p.ID)
		p.Entries = append([]PolicyEntry(nil), p.Entries...)
		p.MandatoryRules = append([]Rule(nil), p.MandatoryRules...)
		p.Mandatory = append([]Rule(nil), p.Mandatory...)
		p.Exceptions = append([]Rule(nil), p.Exceptions...)
		p.Rules = append([]Rule(nil), p.Rules...)
		p.RuleSetIDs = uniquePreserve(p.RuleSetIDs)
		p.DefaultAction = normalizeAction(p.DefaultAction)
		p.UnknownDomainAction = normalizeAction(p.UnknownDomainAction)
		p.ProxyFailureAction = normalizeAction(p.ProxyFailureAction)
		for i := range p.MandatoryRules {
			p.MandatoryRules[i] = normalizeRuleShape(p.MandatoryRules[i])
		}
		for i := range p.Mandatory {
			p.Mandatory[i] = normalizeRuleShape(p.Mandatory[i])
		}
		for i := range p.Exceptions {
			p.Exceptions[i] = normalizeRuleShape(p.Exceptions[i])
		}
		for i := range p.Rules {
			p.Rules[i] = normalizeRuleShape(p.Rules[i])
		}
		n.policies[p.ID] = p
	}
	for _, r := range in.RuleSets {
		r.ID = strings.TrimSpace(r.ID)
		checkID("ruleset", r.ID)
		r.Rules = append([]Rule(nil), r.Rules...)
		for i := range r.Rules {
			r.Rules[i] = normalizeRuleShape(r.Rules[i])
		}
		n.ruleSets[r.ID] = r
	}
	for _, o := range in.OutboundGroups {
		o.ID = strings.TrimSpace(o.ID)
		checkID("outbound", o.ID)
		o.NodeIDs = uniqueSorted(append(append([]string(nil), o.NodeIDs...), o.CandidateNodeIDs...))
		n.outbounds[o.ID] = o
	}
	// A device's primary group is authoritative even when a caller omits the
	// redundant group member list. Explicit members are merged deterministically.
	for id, d := range n.devices {
		if d.GroupID == "" {
			continue
		}
		for i := range n.groups {
			if n.groups[i].ID == d.GroupID {
				n.groups[i].DeviceIDs = uniqueSorted(append(n.groups[i].DeviceIDs, id))
			}
		}
	}
	return n
}

func normalizeDomainValues(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniquePreserve(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func normalizedDomainSets(sets map[string]DomainSet) []DomainSet {
	out := make([]DomainSet, 0, len(sets))
	for _, set := range sets {
		out = append(out, set)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func normalizeRuleShape(r Rule) Rule {
	r.ID = strings.TrimSpace(r.ID)
	r.Name = strings.TrimSpace(r.Name)
	r.Action = normalizeAction(r.Action)
	return r
}

func (p Policy) mandatoryRules() []Rule {
	return append(append([]Rule(nil), p.MandatoryRules...), p.Mandatory...)
}

func orderedRules(in []Rule) []Rule {
	type item struct {
		rule  Rule
		order int
		index int
	}
	items := make([]item, len(in))
	for i, rule := range in {
		order := rule.Order
		if order == 0 {
			order = i + 1
		}
		items[i] = item{rule: rule, order: order, index: i}
	}
	// Explicit orders sort numerically. A zero order means the source position,
	// so mixed legacy lists remain stable instead of moving every zero-order rule
	// to the end of the list.
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].order == items[j].order {
			return items[i].index < items[j].index
		}
		return items[i].order < items[j].order
	})
	out := make([]Rule, len(items))
	for i, item := range items {
		out[i] = item.rule
	}
	return out
}

type expandedRule struct {
	Rule      Rule
	RuleSetID string
}

func expandEntries(p Policy, sets map[string]RuleSet) []expandedRule {
	var out []expandedRule
	if len(p.Entries) > 0 {
		for _, e := range p.Entries {
			if e.Rule != nil {
				out = append(out, expandedRule{Rule: normalizeRuleShape(*e.Rule)})
			}
			if e.RuleSetID != "" {
				if rs, ok := sets[e.RuleSetID]; ok {
					for _, r := range orderedRules(rs.Rules) {
						out = append(out, expandedRule{Rule: r, RuleSetID: rs.ID})
					}
				}
			}
		}
	} else {
		for _, r := range orderedRules(p.Rules) {
			out = append(out, expandedRule{Rule: r})
		}
		for _, id := range p.RuleSetIDs {
			if rs, ok := sets[id]; ok {
				for _, r := range orderedRules(rs.Rules) {
					out = append(out, expandedRule{Rule: r, RuleSetID: rs.ID})
				}
			}
		}
	}
	return out
}

func normalizedRule(r Rule, index int, phase string, source SourceRef) (EngineRule, []Diagnostic) {
	m, ds := r.Match.normalized()
	r.Action = normalizeAction(r.Action)
	if r.ID == "" {
		r.ID = fmt.Sprintf("%s-%03d", phase, index+1)
	}
	id := r.ID
	if source.DeviceID != "" {
		id = source.DeviceID + ":" + id
	}
	if source.RuleSetID != "" {
		id = source.RuleSetID + ":" + id
	}
	id = source.DeviceGroupID + ":" + phase + ":" + id
	expression := renderExpression(m, r.Action)
	return EngineRule{ID: id, Name: r.Name, Match: m, Action: r.Action, Expression: expression, Source: source}, ds
}

func addressesForDevice(d Device) []string {
	out := make([]string, 0, len(d.Addresses))
	for _, a := range d.Addresses {
		if s, ok := canonicalSource(a.Address); ok {
			out = append(out, s)
		}
	}
	return uniqueSorted(out)
}

func canonicalSource(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if ip := net.ParseIP(raw); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String() + "/32", true
		}
		return ip.String() + "/128", true
	}
	_, n, err := net.ParseCIDR(raw)
	if err != nil {
		return "", false
	}
	return n.String(), true
}

func renderExpression(m Match, action Action) string {
	parts := []string{}
	if len(m.DomainExact) > 0 {
		parts = append(parts, "domain_exact="+strings.Join(m.DomainExact, ","))
	}
	if len(m.DomainSuffix) > 0 {
		parts = append(parts, "domain_suffix="+strings.Join(m.DomainSuffix, ","))
	}
	if len(m.DomainSets) > 0 {
		parts = append(parts, "domain_set="+strings.Join(m.DomainSets, ","))
	}
	if len(m.DestinationCIDRs) > 0 {
		parts = append(parts, "dst_cidr="+strings.Join(m.DestinationCIDRs, ","))
	}
	if len(m.DestinationPorts) > 0 {
		vals := make([]string, len(m.DestinationPorts))
		for i, p := range m.DestinationPorts {
			vals[i] = strconv.Itoa(p.From)
			if p.To != p.From {
				vals[i] += "-" + strconv.Itoa(p.To)
			}
		}
		parts = append(parts, "dst_port="+strings.Join(vals, ","))
	}
	if len(m.Transport) > 0 {
		vals := make([]string, len(m.Transport))
		for i, t := range m.Transport {
			vals[i] = string(t)
		}
		parts = append(parts, "transport="+strings.Join(vals, ","))
	}
	if len(m.AddressFamilies) > 0 {
		vals := make([]string, len(m.AddressFamilies))
		for i, f := range m.AddressFamilies {
			vals[i] = string(f)
		}
		parts = append(parts, "family="+strings.Join(vals, ","))
	}
	if len(parts) == 0 {
		parts = append(parts, "any")
	}
	return strings.Join(parts, " ") + " => " + action.String()
}

func manifestHash(m Manifest) string {
	m.ContentHash = ""
	b, _ := json.Marshal(m)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func impactReport(m Manifest, previous *Manifest) ImpactReport {
	r := ImpactReport{RequiresPolicyApply: len(m.Groups) > 0}
	if previous == nil {
		for _, g := range m.Groups {
			r.ChangedGroups = append(r.ChangedGroups, g.DeviceGroupID)
		}
		r.EnrollmentChanged = len(m.Enrollments) > 0
		return r
	}
	old := map[string]CompiledGroup{}
	for _, g := range previous.Groups {
		old[g.DeviceGroupID] = g
	}
	for _, g := range m.Groups {
		if p, ok := old[g.DeviceGroupID]; ok {
			a, _ := json.Marshal(p)
			b, _ := json.Marshal(g)
			if string(a) == string(b) {
				r.UnchangedGroups = append(r.UnchangedGroups, g.DeviceGroupID)
			} else {
				r.ChangedGroups = append(r.ChangedGroups, g.DeviceGroupID)
			}
		} else {
			r.ChangedGroups = append(r.ChangedGroups, g.DeviceGroupID)
		}
		delete(old, g.DeviceGroupID)
	}
	for id := range old {
		r.ChangedGroups = append(r.ChangedGroups, id)
	}
	sort.Strings(r.ChangedGroups)
	oldE, _ := json.Marshal(flattenEnrollments(previous.Enrollments))
	newE, _ := json.Marshal(flattenEnrollments(m.Enrollments))
	r.EnrollmentChanged = string(oldE) != string(newE)
	r.RequiresPolicyApply = manifestHash(m) != manifestHash(*previous)
	return r
}

// Firewall membership is the gateway-wide union. Moving a device between
// groups on the same gateway changes its policy without touching enrollment.
func flattenEnrollments(sets []EnrollmentSet) map[string][]string {
	out := map[string][]string{}
	for _, set := range sets {
		out[set.GatewayID] = append(out[set.GatewayID], set.Addresses...)
	}
	for gatewayID, addresses := range out {
		out[gatewayID] = uniqueSorted(addresses)
	}
	return out
}

func validateInput(n normalizedInput) []Diagnostic {
	ds := append([]Diagnostic(nil), n.preflight...)
	if n.gatewayID == "" {
		ds = append(ds, Diagnostic{Severity: SeverityError, Code: "missing_gateway", Path: "gateway.id", Message: "gateway id is required"})
	}
	for _, p := range n.policies {
		if p.ID == "" {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "missing_policy_id", Message: "policy id is required"})
		}
		if len(p.Entries) > 0 && (len(p.Rules) > 0 || len(p.RuleSetIDs) > 0) {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "ambiguous_policy_entries", Path: "policies." + p.ID, Message: "entries cannot be combined with rules or rule_set_ids"})
		}
		if p.DefaultAction.Kind == "" {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "invalid_default", Path: "policies." + p.ID + ".default_action", Message: "default action is required"})
		} else {
			ds = append(ds, validateAction(p.DefaultAction, n.outbounds, "policies."+p.ID+".default_action")...)
		}
		if p.UnknownDomainAction.Kind != "" {
			ds = append(ds, validateAction(p.UnknownDomainAction, n.outbounds, "policies."+p.ID+".unknown_domain_action")...)
		}
		if p.ProxyFailureAction.Kind != "" {
			ds = append(ds, validateAction(p.ProxyFailureAction, n.outbounds, "policies."+p.ID+".proxy_failure_action")...)
			if p.ProxyFailureAction.Kind != ActionBlock {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unsafe_proxy_failure", Path: "policies." + p.ID + ".proxy_failure_action", Message: "required proxy failure must block matching traffic"})
			}
		}
		if p.RawConfigOverride != "" {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unsafe_raw_config", Path: "policies." + p.ID, Message: "raw configuration overrides are not allowed"})
		}
		if p.Strict || p.StrictMode || n.options.Strict {
			if p.UnknownDomainAction.Kind != ActionBlock && p.UnknownDomainAction.Kind != ActionOutboundGroup && p.UnknownDomainAction.Kind != ActionProxy {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unsafe_unknown_domain", Path: "policies." + p.ID + ".unknown_domain_action", Message: "strict protection requires an explicit proxy or block action for unknown domains"})
			}
			if p.ProxyFailureAction.Kind == "" {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unsafe_proxy_failure", Path: "policies." + p.ID + ".proxy_failure_action", Message: "strict protection requires an explicit block action for required proxy failure"})
			}
		}
		if (p.Strict || p.StrictMode || n.options.Strict) && n.options.UncontrolledIPv6 {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "uncontrolled_ipv6", Path: "policies." + p.ID, Message: "strict protection cannot be claimed with uncontrolled IPv6"})
		}
		for _, r := range append(append(append([]Rule(nil), p.mandatoryRules()...), p.Exceptions...), p.Rules...) {
			ds = append(ds, validateRule(r, n.outbounds, n.options, "policies."+p.ID+".rule")...)
			for _, id := range r.Match.DomainSets {
				if _, ok := n.domainSets[strings.TrimSpace(id)]; !ok {
					ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unresolved_domain_set", Path: "policies." + p.ID, Message: "domain set " + id + " was not found"})
				}
			}
		}
		for _, e := range p.Entries {
			if e.Rule != nil && e.RuleSetID != "" {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "ambiguous_entry", Path: "policies." + p.ID, Message: "policy entry must contain exactly one rule or rule_set_id"})
			}
			if e.Rule == nil && e.RuleSetID == "" {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "invalid_entry", Path: "policies." + p.ID, Message: "policy entry must contain a rule or rule_set_id"})
			}
			if e.Rule != nil {
				ds = append(ds, validateRule(*e.Rule, n.outbounds, n.options, "policies."+p.ID+".entry")...)
				for _, id := range e.Rule.Match.DomainSets {
					if _, ok := n.domainSets[strings.TrimSpace(id)]; !ok {
						ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unresolved_domain_set", Path: "policies." + p.ID, Message: "domain set " + id + " was not found"})
					}
				}
			}
			if e.RuleSetID != "" {
				if _, ok := n.ruleSets[e.RuleSetID]; !ok {
					ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unresolved_rule_set", Path: "policies." + p.ID, Message: "rule set " + e.RuleSetID + " was not found"})
				}
			}
		}
		for _, id := range p.RuleSetIDs {
			if _, ok := n.ruleSets[id]; !ok {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unresolved_rule_set", Path: "policies." + p.ID, Message: "rule set " + id + " was not found"})
			}
		}
	}
	owners := map[string]string{}
	type ownedNetwork struct {
		owner   string
		source  string
		network *net.IPNet
	}
	var networks []ownedNetwork
	deviceIDs := make([]string, 0, len(n.devices))
	for id := range n.devices {
		deviceIDs = append(deviceIDs, id)
	}
	sort.Strings(deviceIDs)
	for _, deviceID := range deviceIDs {
		d := n.devices[deviceID]
		if d.ID == "" {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "missing_device_id", Message: "device id is required"})
		}
		for _, a := range d.Addresses {
			source, ok := canonicalSource(a.Address)
			if !ok {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "invalid_address", Path: "devices." + d.ID, Message: "invalid device address " + a.Address})
				continue
			}
			if a.Family != FamilyAny {
				parsed := net.ParseIP(strings.TrimSpace(strings.Split(a.Address, "/")[0]))
				actual := FamilyIPv6
				if parsed != nil && parsed.To4() != nil {
					actual = FamilyIPv4
				}
				if actual != a.Family {
					ds = append(ds, Diagnostic{Severity: SeverityError, Code: "address_family_mismatch", Path: "devices." + d.ID, Message: "address " + a.Address + " does not match declared family " + string(a.Family)})
				}
			}
			if strings.Contains(a.Address, ":") && !n.options.SupportsIPv6 {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unsupported_ipv6", Path: "devices." + d.ID, Message: "gateway does not support IPv6 source enforcement"})
			}
			if previous, exists := owners[source]; exists && previous != d.ID {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "duplicate_address_ownership", Path: "devices." + d.ID, Message: "address " + source + " is also owned by " + previous})
			} else {
				owners[source] = d.ID
			}
			_, network, _ := net.ParseCIDR(source)
			for _, previous := range networks {
				if previous.owner != d.ID && previous.source != source && (previous.network.Contains(network.IP) || network.Contains(previous.network.IP)) {
					ds = append(ds, Diagnostic{Severity: SeverityError, Code: "overlapping_source_ownership", Path: "devices." + d.ID, Message: "source " + source + " overlaps " + previous.source + " owned by " + previous.owner})
				}
			}
			networks = append(networks, ownedNetwork{owner: d.ID, source: source, network: network})
			if strings.Contains(a.Address, "/") && !n.options.DistinguishesNetworks {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "indistinguishable_overlap", Path: "devices." + d.ID, Message: "network source scope cannot be distinguished by this gateway"})
			}
		}
		for _, rule := range d.Exceptions {
			ds = append(ds, validateRule(rule, n.outbounds, n.options, "devices."+d.ID+".exceptions")...)
			for _, id := range rule.Match.DomainSets {
				if _, ok := n.domainSets[strings.TrimSpace(id)]; !ok {
					ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unresolved_domain_set", Path: "devices." + d.ID, Message: "domain set " + id + " was not found"})
				}
			}
		}
	}
	groups := map[string]struct{}{}
	deviceGroups := map[string]string{}
	for _, g := range n.groups {
		if g.ID == "" {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "missing_group_id", Message: "device group id is required"})
		}
		if g.GatewayID == "" {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "missing_gateway", Path: "groups." + g.ID + ".gateway_id", Message: "device group gateway is required"})
		}
		if _, ok := n.policies[g.PolicyID]; !ok {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unknown_policy", Path: "groups." + g.ID, Message: "policy " + g.PolicyID + " was not found"})
		}
		if g.GatewayID != "" && n.gatewayID != "" && g.GatewayID != n.gatewayID {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "gateway_mismatch", Path: "groups." + g.ID, Message: "group belongs to gateway " + g.GatewayID})
		}
		groups[g.ID] = struct{}{}
		for _, id := range g.DeviceIDs {
			d, ok := n.devices[id]
			if !ok {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unknown_device", Path: "groups." + g.ID, Message: "device " + id + " was not found"})
				continue
			}
			if g.Enabled && d.Enabled && len(d.Addresses) == 0 {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "missing_source_address", Path: "devices." + id, Message: "enabled group member requires a source address"})
			}
			if d.GroupID != "" && d.GroupID != g.ID {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "device_group_conflict", Path: "devices." + id, Message: "device declares a different primary group"})
			}
			if previous, exists := deviceGroups[id]; exists && previous != g.ID {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "multiple_primary_groups", Path: "devices." + id, Message: "device is assigned to both " + previous + " and " + g.ID})
			} else {
				deviceGroups[id] = g.ID
			}
		}
	}
	for _, d := range n.devices {
		if d.GroupID != "" {
			if _, ok := groups[d.GroupID]; !ok {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unknown_group", Path: "devices." + d.ID, Message: "primary group " + d.GroupID + " was not found"})
			}
		}
	}
	for _, rs := range n.ruleSets {
		for _, r := range rs.Rules {
			ds = append(ds, validateRule(r, n.outbounds, n.options, "rule_sets."+rs.ID+".rule")...)
			for _, id := range r.Match.DomainSets {
				if _, ok := n.domainSets[strings.TrimSpace(id)]; !ok {
					ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unresolved_domain_set", Path: "rule_sets." + rs.ID, Message: "domain set " + id + " was not found"})
				}
			}
		}
	}
	if n.options.SupportedTransports != nil {
		for _, p := range n.policies {
			for _, r := range allPolicyRules(p, n.ruleSets) {
				for _, t := range append(r.Match.Transport, r.Match.Transports...) {
					t = normalizeTransport(t)
					if !n.options.SupportedTransports[t] {
						ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unsupported_transport", Path: "policies." + p.ID, Message: "gateway does not support transport " + string(t)})
					}
				}
			}
		}
	}
	return sortDiagnostics(ds)
}

func allPolicyRules(p Policy, sets map[string]RuleSet) []Rule {
	out := append(append(append([]Rule(nil), p.mandatoryRules()...), p.Exceptions...), p.Rules...)
	for _, e := range p.Entries {
		if e.Rule != nil {
			out = append(out, *e.Rule)
		}
		if rs, ok := sets[e.RuleSetID]; ok {
			out = append(out, rs.Rules...)
		}
	}
	for _, id := range p.RuleSetIDs {
		if rs, ok := sets[id]; ok {
			out = append(out, rs.Rules...)
		}
	}
	return out
}

func validateAction(a Action, outbounds map[string]OutboundGroup, path string) []Diagnostic {
	a = normalizeAction(a)
	switch a.Kind {
	case ActionDirect, ActionProxy, ActionBlock:
		if a.OutboundGroupID != "" {
			return []Diagnostic{{Severity: SeverityError, Code: "invalid_action", Path: path, Message: "this action cannot include an outbound group"}}
		}
	case ActionOutboundGroup:
		if a.OutboundGroupID == "" {
			return []Diagnostic{{Severity: SeverityError, Code: "unknown_outbound_group", Path: path, Message: "outbound group id is required"}}
		}
		o, ok := outbounds[a.OutboundGroupID]
		if !ok {
			return []Diagnostic{{Severity: SeverityError, Code: "unknown_outbound_group", Path: path, Message: "outbound group " + a.OutboundGroupID + " was not found"}}
		}
		if len(o.NodeIDs) == 0 && !o.AllowEmpty {
			return []Diagnostic{{Severity: SeverityError, Code: "empty_outbound_group", Path: path, Message: "outbound group " + a.OutboundGroupID + " has no candidates"}}
		}
	default:
		return []Diagnostic{{Severity: SeverityError, Code: "invalid_action", Path: path, Message: "unknown action " + string(a.Kind)}}
	}
	return nil
}

func validateRule(r Rule, outbounds map[string]OutboundGroup, options CompileOptions, path string) []Diagnostic {
	var ds []Diagnostic
	ds = append(ds, validateAction(r.Action, outbounds, path+"."+r.ID+".action")...)
	_, md := r.Match.normalized()
	ds = append(ds, md...)
	// Domain set references are checked by validateInput, where the set index is
	// available. This function handles only match syntax and adapter support.
	if options.SupportedTransports != nil {
		for _, t := range append(r.Match.Transport, r.Match.Transports...) {
			if !options.SupportedTransports[normalizeTransport(t)] {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unsupported_transport", Path: path + "." + r.ID, Message: "gateway does not support transport " + string(t)})
			}
		}
	}
	return ds
}

func hasErrors(ds []Diagnostic) bool {
	for _, d := range ds {
		if d.Severity == SeverityError {
			return true
		}
	}
	return false
}
func sortDiagnostics(ds []Diagnostic) []Diagnostic {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].Path == ds[j].Path {
			if ds[i].Code == ds[j].Code {
				return ds[i].Message < ds[j].Message
			}
			return ds[i].Code < ds[j].Code
		}
		return ds[i].Path < ds[j].Path
	})
	return ds
}
