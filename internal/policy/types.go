// Package policy contains the typed policy model and deterministic compiler used
// to turn device-group intent into gateway policy snapshots.
package policy

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// ActionKind is the terminal decision for a matching rule.
type ActionKind string

const (
	ActionDirect        ActionKind = "direct"
	ActionProxy         ActionKind = "proxy"
	ActionBlock         ActionKind = "block"
	ActionOutboundGroup ActionKind = "outbound_group"
)

// Action is deliberately typed: an outbound group action must name the group
// rather than relying on a free-form engine expression.
type Action struct {
	Kind            ActionKind `json:"kind"`
	OutboundGroupID string     `json:"outbound_group_id,omitempty"`
}

func Direct() Action { return Action{Kind: ActionDirect} }
func Proxy() Action  { return Action{Kind: ActionProxy} }
func Block() Action  { return Action{Kind: ActionBlock} }
func Outbound(id string) Action {
	return Action{Kind: ActionOutboundGroup, OutboundGroupID: id}
}

// NewOutboundGroupAction is the explicit constructor when callers prefer a
// name that cannot be confused with the OutboundGroup model.
func NewOutboundGroupAction(id string) Action { return Outbound(id) }

func (a Action) String() string {
	if a.Kind == ActionOutboundGroup {
		return string(a.Kind) + ":" + a.OutboundGroupID
	}
	return string(a.Kind)
}

// AddressFamily identifies the IP family of a source or destination match.
type AddressFamily string

const (
	FamilyAny  AddressFamily = ""
	FamilyIPv4 AddressFamily = "ipv4"
	FamilyIPv6 AddressFamily = "ipv6"
)

// Transport is intentionally a small set until an adapter advertises support.
type Transport string

const (
	TransportTCP  Transport = "tcp"
	TransportUDP  Transport = "udp"
	TransportQUIC Transport = "quic"
)

// PortRange is inclusive at both ends. From and To are required to be in the
// 1..65535 range; a zero To means the same port as From for ergonomic literals.
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

func Port(port int) PortRange      { return PortRange{From: port, To: port} }
func Ports(from, to int) PortRange { return PortRange{From: from, To: to} }

// Match is an AND of its populated dimensions. Values within one dimension are
// ORed. Empty Match matches every packet.
type Match struct {
	DomainExact      []string        `json:"domain_exact,omitempty"`
	DomainSuffix     []string        `json:"domain_suffix,omitempty"`
	DomainSets       []string        `json:"domain_sets,omitempty"`
	DestinationCIDRs []string        `json:"destination_cidrs,omitempty"`
	DestinationIP    []string        `json:"destination_ip,omitempty"` // alias accepted for API callers
	DestinationPorts []PortRange     `json:"destination_ports,omitempty"`
	Ports            []PortRange     `json:"ports,omitempty"` // alias accepted for API callers
	Transport        []Transport     `json:"transport,omitempty"`
	Transports       []Transport     `json:"transports,omitempty"` // alias accepted for API callers
	AddressFamilies  []AddressFamily `json:"address_families,omitempty"`
	Families         []AddressFamily `json:"families,omitempty"` // alias accepted for API callers
}

// Rule is an ordered typed match/action pair. Order is relative within its
// containing list. A zero Order uses the source list order.
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Match   Match  `json:"match"`
	Action  Action `json:"action"`
	Enabled bool   `json:"enabled"`
	Order   int    `json:"order,omitempty"`
}

// RuleSet is reusable and has no terminal default. It can safely fall through
// to the next policy entry.
type RuleSet struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Rules    []Rule `json:"rules"`
	Revision int64  `json:"revision,omitempty"`
}

// DomainSet is a named, tested set of domains referenced by Match.DomainSets.
// It is copied into a manifest so explain can use the same immutable snapshot.
type DomainSet struct {
	ID      string   `json:"id"`
	Name    string   `json:"name,omitempty"`
	Domains []string `json:"domains"`
}

// PolicyEntry preserves interleaving of direct rules and reusable rule sets.
// Exactly one of Rule and RuleSetID should be populated.
type PolicyEntry struct {
	Rule      *Rule  `json:"rule,omitempty"`
	RuleSetID string `json:"rule_set_id,omitempty"`
}

// Policy describes a group's ordered policy. MandatoryRules are evaluated
// first, then device Exceptions, then Entries/Rules, then the default action.
type Policy struct {
	ID                  string        `json:"id"`
	Name                string        `json:"name,omitempty"`
	MandatoryRules      []Rule        `json:"mandatory_rules,omitempty"`
	Mandatory           []Rule        `json:"mandatory,omitempty"` // alias
	Exceptions          []Rule        `json:"exceptions,omitempty"`
	Entries             []PolicyEntry `json:"entries,omitempty"`
	Rules               []Rule        `json:"rules,omitempty"` // convenient direct-rule form
	RuleSetIDs          []string      `json:"rule_set_ids,omitempty"`
	DefaultAction       Action        `json:"default_action"`
	UnknownDomainAction Action        `json:"unknown_domain_action"`
	ProxyFailureAction  Action        `json:"proxy_failure_action"`
	Strict              bool          `json:"strict,omitempty"`
	StrictMode          bool          `json:"strict_mode,omitempty"` // alias
	RawConfigOverride   string        `json:"raw_config_override,omitempty"`
	Revision            int64         `json:"revision,omitempty"`
}

// DeviceAddress is an explicit address visible at the selected enforcement
// point. Address may be an IP or a CIDR; CIDRs are accepted only when the
// gateway can distinguish their source scope.
type DeviceAddress struct {
	Address    string        `json:"address"`
	Family     AddressFamily `json:"family,omitempty"`
	Provenance string        `json:"provenance,omitempty"`
}

type Device struct {
	ID         string          `json:"id"`
	Name       string          `json:"name,omitempty"`
	Addresses  []DeviceAddress `json:"addresses"`
	GroupID    string          `json:"group_id,omitempty"`
	Exceptions []Rule          `json:"exceptions,omitempty"`
	Enabled    bool            `json:"enabled"`
}

type DeviceGroup struct {
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"`
	GatewayID string   `json:"gateway_id"`
	PolicyID  string   `json:"policy_id"`
	DeviceIDs []string `json:"device_ids,omitempty"`
	Members   []string `json:"members,omitempty"` // alias
	Enabled   bool     `json:"enabled"`
}

type OutboundGroup struct {
	ID               string   `json:"id"`
	Name             string   `json:"name,omitempty"`
	NodeIDs          []string `json:"node_ids,omitempty"`
	CandidateNodeIDs []string `json:"candidate_node_ids,omitempty"` // alias
	AllowEmpty       bool     `json:"allow_empty,omitempty"`
}

type Gateway struct {
	ID                    string      `json:"id"`
	Name                  string      `json:"name,omitempty"`
	SupportedTransports   []Transport `json:"supported_transports,omitempty"`
	SupportsIPv6          bool        `json:"supports_ipv6,omitempty"`
	DistinguishesNetworks bool        `json:"distinguishes_networks,omitempty"`
}

type CompileOptions struct {
	GatewayID             string             `json:"gateway_id,omitempty"`
	SupportedTransports   map[Transport]bool `json:"supported_transports,omitempty"`
	SupportsIPv6          bool               `json:"supports_ipv6,omitempty"`
	DistinguishesNetworks bool               `json:"distinguishes_networks,omitempty"`
	UncontrolledIPv6      bool               `json:"uncontrolled_ipv6,omitempty"`
	AllowUnsafeRawConfig  bool               `json:"allow_unsafe_raw_config,omitempty"`
	Strict                bool               `json:"strict,omitempty"`
}

type CompileInput struct {
	Gateway        Gateway         `json:"gateway"`
	Devices        []Device        `json:"devices"`
	DeviceGroups   []DeviceGroup   `json:"device_groups"`
	Policies       []Policy        `json:"policies"`
	RuleSets       []RuleSet       `json:"rule_sets,omitempty"`
	DomainSets     []DomainSet     `json:"domain_sets,omitempty"`
	OutboundGroups []OutboundGroup `json:"outbound_groups,omitempty"`
	Options        CompileOptions  `json:"options,omitempty"`
	Previous       *Manifest       `json:"previous,omitempty"`
}

// CompileRequest is a descriptive alias retained for API callers.
type CompileRequest = CompileInput

// NormalizedRule is the immutable rule representation emitted by normalization.
type NormalizedRule struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Match  Match  `json:"match"`
	Action Action `json:"action"`
	Order  int    `json:"order"`
	Source string `json:"source"`
}

type SourceRef struct {
	PolicyID      string `json:"policy_id,omitempty"`
	RuleSetID     string `json:"rule_set_id,omitempty"`
	RuleID        string `json:"rule_id,omitempty"`
	DeviceGroupID string `json:"device_group_id,omitempty"`
	DeviceID      string `json:"device_id,omitempty"`
	Phase         string `json:"phase"`
}

type SourceMapEntry struct {
	GeneratedID string    `json:"generated_id"`
	Source      SourceRef `json:"source"`
}

type EngineRule struct {
	ID             string    `json:"id"`
	Name           string    `json:"name,omitempty"`
	SourceSelector []string  `json:"source_selector"`
	Match          Match     `json:"match"`
	Action         Action    `json:"action"`
	Expression     string    `json:"expression"`
	Source         SourceRef `json:"source"`
}

type CompiledGroup struct {
	DeviceGroupID       string       `json:"device_group_id"`
	GatewayID           string       `json:"gateway_id"`
	SourceSelector      []string     `json:"source_selector"`
	Rules               []EngineRule `json:"rules"`
	DefaultAction       Action       `json:"default_action"`
	UnknownDomainAction Action       `json:"unknown_domain_action"`
	ProxyFailureAction  Action       `json:"proxy_failure_action"`
}

type EnrollmentSet struct {
	GatewayID string   `json:"gateway_id"`
	GroupID   string   `json:"group_id"`
	Addresses []string `json:"addresses"`
}

type Manifest struct {
	Version     int              `json:"version"`
	GatewayID   string           `json:"gateway_id"`
	Groups      []CompiledGroup  `json:"groups"`
	Enrollments []EnrollmentSet  `json:"enrollments"`
	SourceMap   []SourceMapEntry `json:"source_map"`
	DomainSets  []DomainSet      `json:"domain_sets,omitempty"`
	ContentHash string           `json:"content_hash"`
}

type ImpactReport struct {
	ChangedGroups       []string `json:"changed_groups,omitempty"`
	UnchangedGroups     []string `json:"unchanged_groups,omitempty"`
	EnrollmentChanged   bool     `json:"enrollment_changed"`
	RequiresPolicyApply bool     `json:"requires_policy_apply"`
}

type DiagnosticSeverity string

const (
	SeverityError   DiagnosticSeverity = "error"
	SeverityWarning DiagnosticSeverity = "warning"
)

type Diagnostic struct {
	Severity DiagnosticSeverity `json:"severity"`
	Code     string             `json:"code"`
	Path     string             `json:"path,omitempty"`
	Message  string             `json:"message"`
}

// ValidationError contains stable, machine-readable problems. Errors are
// ordered by path/code/message, making API responses and tests deterministic.
type ValidationError struct{ Problems []Diagnostic }

func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Problems))
	for _, p := range e.Problems {
		parts = append(parts, p.Code+": "+p.Message)
	}
	return strings.Join(parts, "; ")
}

func (e *ValidationError) HasCode(code string) bool {
	for _, p := range e.Problems {
		if p.Code == code {
			return true
		}
	}
	return false
}

type CompileResult struct {
	Manifest    Manifest         `json:"manifest"`
	Normalized  []CompiledGroup  `json:"normalized"`
	SourceMap   []SourceMapEntry `json:"source_map"`
	Impact      ImpactReport     `json:"impact"`
	Diagnostics []Diagnostic     `json:"diagnostics,omitempty"`
}

type Compilation = CompileResult

// Packet is the input to Explain. Domain is optional because packet routing
// can occur before a name is sniffed.
type Packet struct {
	SourceIP        string        `json:"source_ip"`
	DestinationIP   string        `json:"destination_ip"`
	DestinationPort int           `json:"destination_port"`
	Transport       Transport     `json:"transport"`
	Family          AddressFamily `json:"family,omitempty"`
	Domain          string        `json:"domain,omitempty"`
}

type Explanation struct {
	Predicted       bool      `json:"predicted"`
	Action          Action    `json:"action"`
	DeviceGroupID   string    `json:"device_group_id,omitempty"`
	MatchedRuleID   string    `json:"matched_rule_id,omitempty"`
	MatchedRuleName string    `json:"matched_rule_name,omitempty"`
	Source          SourceRef `json:"source,omitempty"`
	Reason          string    `json:"reason"`
	Candidates      []string  `json:"candidates,omitempty"`
}

func cloneStrings(in []string) []string { return append([]string(nil), in...) }

func normalizeAction(a Action) Action {
	a.Kind = ActionKind(strings.ToLower(strings.TrimSpace(string(a.Kind))))
	a.OutboundGroupID = strings.TrimSpace(a.OutboundGroupID)
	return a
}

func normalizeFamily(f AddressFamily) AddressFamily {
	return AddressFamily(strings.ToLower(strings.TrimSpace(string(f))))
}
func normalizeTransport(t Transport) Transport {
	return Transport(strings.ToLower(strings.TrimSpace(string(t))))
}

func (m Match) merged() Match {
	out := m
	out.DomainExact = cloneStrings(m.DomainExact)
	out.DomainSuffix = cloneStrings(m.DomainSuffix)
	out.DomainSets = cloneStrings(m.DomainSets)
	out.DestinationCIDRs = append(cloneStrings(m.DestinationCIDRs), m.DestinationIP...)
	out.DestinationPorts = append(append([]PortRange(nil), m.DestinationPorts...), m.Ports...)
	out.Transport = append(append([]Transport(nil), m.Transport...), m.Transports...)
	out.AddressFamilies = append(append([]AddressFamily(nil), m.AddressFamilies...), m.Families...)
	return out
}

func (m Match) normalized() (Match, []Diagnostic) {
	m = m.merged()
	var ds []Diagnostic
	normDomain := func(vals []string, suffix bool) []string {
		set := map[string]struct{}{}
		for _, raw := range vals {
			v := strings.ToLower(strings.TrimSpace(raw))
			v = strings.TrimSuffix(v, ".")
			if v == "" || strings.ContainsAny(v, " /\\") {
				ds = append(ds, Diagnostic{Severity: SeverityError, Code: "invalid_domain", Message: fmt.Sprintf("invalid domain %q", raw)})
				continue
			}
			if suffix {
				v = strings.TrimPrefix(v, ".")
			}
			set[v] = struct{}{}
		}
		out := make([]string, 0, len(set))
		for v := range set {
			out = append(out, v)
		}
		sort.Strings(out)
		return out
	}
	m.DomainExact = normDomain(m.DomainExact, false)
	m.DomainSuffix = normDomain(m.DomainSuffix, true)
	m.DomainSets = uniqueSorted(m.DomainSets)
	m.DestinationIP = nil
	m.Ports = nil
	m.Transports = nil
	m.Families = nil
	cidrs := append([]string(nil), m.DestinationCIDRs...)
	m.DestinationCIDRs = nil
	for _, raw := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "invalid_cidr", Message: fmt.Sprintf("invalid destination CIDR %q", raw)})
			continue
		}
		m.DestinationCIDRs = append(m.DestinationCIDRs, n.String())
	}
	sort.Strings(m.DestinationCIDRs)
	ports := make([]PortRange, 0, len(m.DestinationPorts))
	seenPorts := map[string]struct{}{}
	for _, p := range m.DestinationPorts {
		if p.To == 0 {
			p.To = p.From
		}
		if p.From < 1 || p.From > 65535 || p.To < p.From || p.To > 65535 {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "invalid_port_range", Message: fmt.Sprintf("invalid port range %d-%d", p.From, p.To)})
			continue
		}
		key := strconv.Itoa(p.From) + ":" + strconv.Itoa(p.To)
		if _, ok := seenPorts[key]; !ok {
			seenPorts[key] = struct{}{}
			ports = append(ports, p)
		}
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].From == ports[j].From {
			return ports[i].To < ports[j].To
		}
		return ports[i].From < ports[j].From
	})
	m.DestinationPorts = ports
	transports := make([]Transport, 0, len(m.Transport))
	seenT := map[Transport]struct{}{}
	for _, t := range m.Transport {
		t = normalizeTransport(t)
		if t != TransportTCP && t != TransportUDP && t != TransportQUIC {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "unsupported_transport", Message: fmt.Sprintf("unsupported transport %q", t)})
			continue
		}
		if _, ok := seenT[t]; !ok {
			seenT[t] = struct{}{}
			transports = append(transports, t)
		}
	}
	sort.Slice(transports, func(i, j int) bool { return transports[i] < transports[j] })
	m.Transport = transports
	families := make([]AddressFamily, 0, len(m.AddressFamilies))
	seenF := map[AddressFamily]struct{}{}
	for _, f := range m.AddressFamilies {
		f = normalizeFamily(f)
		if f != FamilyIPv4 && f != FamilyIPv6 {
			ds = append(ds, Diagnostic{Severity: SeverityError, Code: "invalid_address_family", Message: fmt.Sprintf("invalid address family %q", f)})
			continue
		}
		if _, ok := seenF[f]; !ok {
			seenF[f] = struct{}{}
			families = append(families, f)
		}
	}
	sort.Slice(families, func(i, j int) bool { return families[i] < families[j] })
	m.AddressFamilies = families
	return m, ds
}

func uniqueSorted(in []string) []string {
	set := map[string]struct{}{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			set[v] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func (m Match) MarshalJSON() ([]byte, error) {
	type alias Match
	normalized, _ := m.normalized()
	return json.Marshal(alias(normalized))
}
