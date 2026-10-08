package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// DAEBaseRevision is the exact upstream source whose routing parser and
// semantics are used by this renderer. It is not a runtime qualification claim.
const DAEBaseRevision = "e3fee8fbc68a65167af13b685ab0b958757e20ee"

const daeMaxRoutingBytes = 1 << 20
const daeMaxMatchTerms = 512 // Leaves headroom below the pinned 1024 match-set limit.

// DAEArtifact is an immutable routing-only artifact. It must not be passed as
// a complete dae configuration: the gateway owns global, DNS, node and group
// configuration, and must validate the complete assembled configuration.
type DAEArtifact struct {
	Format           string               `json:"format"`
	DAEBase          string               `json:"dae_base"`
	GatewayID        string               `json:"gateway_id"`
	Manifest         Manifest             `json:"manifest"`
	RoutingConfig    string               `json:"routing_config"`
	RoutingSHA256    string               `json:"routing_sha256"`
	ContentHash      string               `json:"content_hash"`
	RequiresGuard    bool                 `json:"requires_guard"`
	OutboundBindings []DAEOutboundBinding `json:"outbound_bindings"`
	SourceMap        []DAESourceMapEntry  `json:"source_map"`
	RequiredGlobals  DAERequiredGlobals   `json:"required_globals"`
}

type DAEOutboundBinding struct {
	OutboundGroupID string `json:"outbound_group_id"`
	EngineName      string `json:"engine_name"`
}

// DAERequiredGlobals restrict routing-affecting options. Domain matching uses
// the gateway's shared DNS classification. Sniffing and automatic injected
// rules are disabled so the assembly cannot silently change the ordered rules.
type DAERequiredGlobals struct {
	DialMode      string `json:"dial_mode"`
	AutoSniffPunt bool   `json:"auto_sniff_punt"`
}

type DAESourceMapEntry struct {
	Line           int       `json:"line"`
	GeneratedID    string    `json:"generated_id,omitempty"`
	SourceSelector string    `json:"source_selector"`
	Source         SourceRef `json:"source"`
}

// RenderDAE compiles typed intent and emits only the representable subset of
// pinned dae routing syntax. Unsupported semantics return validation errors;
// they never silently widen a rule or substitute a direct route.
func RenderDAE(input CompileInput) (DAEArtifact, error) {
	compiled, err := Compile(input)
	if err != nil {
		return DAEArtifact{}, err
	}
	artifact, err := renderDAEManifest(compiled.Manifest)
	if err != nil {
		return DAEArtifact{}, err
	}
	artifact.RequiresGuard = input.Options.Strict
	for _, p := range input.Policies {
		artifact.RequiresGuard = artifact.RequiresGuard || p.Strict || p.StrictMode
	}
	bytes, err := json.Marshal(artifact)
	if err != nil {
		return DAEArtifact{}, err
	}
	digest := sha256.Sum256(bytes)
	artifact.ContentHash = hex.EncodeToString(digest[:])
	return artifact, nil
}

func renderDAEManifest(manifest Manifest) (DAEArtifact, error) {
	artifact := DAEArtifact{
		Format: "dae-routing-v1", DAEBase: DAEBaseRevision, GatewayID: manifest.GatewayID,
		Manifest: manifest, OutboundBindings: []DAEOutboundBinding{}, SourceMap: []DAESourceMapEntry{},
		RequiredGlobals: DAERequiredGlobals{DialMode: "ip", AutoSniffPunt: false},
	}
	var lines = []string{"routing {"}
	bindings := map[string]string{}
	domainSets := map[string][]string{}
	for _, set := range manifest.DomainSets {
		domainSets[set.ID] = set.Domains
	}
	terms := 1 // global fallback
	appendRule := func(selector, generatedID string, source SourceRef, match Match, action Action) error {
		prefix, err := netip.ParsePrefix(selector)
		if err != nil || prefix.Bits() != prefix.Addr().BitLen() {
			return daeError("unsupported_source_scope", "dae renderer requires a host /32 or /128 source selector")
		}
		functions, err := daeMatchFunctions(match, domainSets)
		if err != nil {
			return err
		}
		functions = append([]string{"sip('" + prefix.Masked().String() + "')"}, functions...)
		terms += len(functions) * 2 // Conservative bound including logical lowering.
		if terms > daeMaxMatchTerms {
			return daeError("dae_rule_limit", "expanded policy exceeds the bounded dae match budget")
		}
		outbound, err := daeAction(action, bindings)
		if err != nil {
			return err
		}
		lines = append(lines, "  "+strings.Join(functions, " && ")+" -> "+outbound)
		artifact.SourceMap = append(artifact.SourceMap, DAESourceMapEntry{Line: len(lines), GeneratedID: generatedID, SourceSelector: selector, Source: source})
		return nil
	}
	for _, group := range manifest.Groups {
		if normalizeAction(group.UnknownDomainAction) != normalizeAction(group.DefaultAction) {
			return DAEArtifact{}, daeError("unsupported_unknown_domain", "pinned dae cannot distinguish an unknown domain from ordinary default traffic")
		}
		if group.ProxyFailureAction != Block() {
			return DAEArtifact{}, daeError("unsupported_proxy_failure", "dae artifact requires block on required proxy failure")
		}
		for _, rule := range group.Rules {
			// Expand each source independently. Native source-list/domain
			// aggregation is deliberately not an optimization of this format.
			for _, source := range rule.SourceSelector {
				if err := appendRule(source, rule.ID, rule.Source, rule.Match, rule.Action); err != nil {
					return DAEArtifact{}, err
				}
			}
		}
		for _, source := range group.SourceSelector {
			ref := SourceRef{DeviceGroupID: group.DeviceGroupID, Phase: "default"}
			if err := appendRule(source, "", ref, Match{}, group.DefaultAction); err != nil {
				return DAEArtifact{}, err
			}
		}
	}
	// This is a dedicated managed-ingress routing artifact. Unmatched sources
	// must never inherit a permissive gateway-wide default.
	lines = append(lines, "  fallback: block", "}")
	artifact.RoutingConfig = strings.Join(lines, "\n") + "\n"
	if len(artifact.RoutingConfig) > daeMaxRoutingBytes {
		return DAEArtifact{}, daeError("dae_size_limit", "generated routing exceeds 1 MiB")
	}
	digest := sha256.Sum256([]byte(artifact.RoutingConfig))
	artifact.RoutingSHA256 = hex.EncodeToString(digest[:])
	for id, name := range bindings {
		artifact.OutboundBindings = append(artifact.OutboundBindings, DAEOutboundBinding{OutboundGroupID: id, EngineName: name})
	}
	sort.Slice(artifact.OutboundBindings, func(i, j int) bool {
		return artifact.OutboundBindings[i].OutboundGroupID < artifact.OutboundBindings[j].OutboundGroupID
	})
	return artifact, nil
}

func daeError(code, message string) error {
	return &ValidationError{Problems: []Diagnostic{{Severity: SeverityError, Code: code, Path: "dae", Message: message}}}
}

func daeAction(action Action, bindings map[string]string) (string, error) {
	action = normalizeAction(action)
	switch action.Kind {
	case ActionDirect, ActionBlock:
		if action.OutboundGroupID != "" {
			return "", daeError("invalid_action", "built-in action cannot name an outbound group")
		}
		return string(action.Kind), nil
	case ActionOutboundGroup:
		if action.OutboundGroupID == "" {
			return "", daeError("invalid_action", "outbound group id is required")
		}
		digest := sha256.Sum256([]byte(action.OutboundGroupID))
		// Hash the logical ID rather than placing names or arbitrary IDs in
		// native configuration. The complete digest avoids name collisions.
		name := "eg_" + hex.EncodeToString(digest[:])
		bindings[action.OutboundGroupID] = name
		return name, nil
	default:
		return "", daeError("unsupported_dae_action", "pinned dae requires direct, block or an explicitly named outbound group")
	}
}

func daeMatchFunctions(match Match, sets map[string][]string) ([]string, error) {
	match, diagnostics := match.normalized()
	if len(diagnostics) > 0 {
		return nil, &ValidationError{Problems: diagnostics}
	}
	var functions []string
	domains := make([]string, 0, len(match.DomainExact)+len(match.DomainSuffix))
	for _, domain := range match.DomainExact {
		if !daeDomain(domain) {
			return nil, daeError("unsupported_domain", "domain must use bounded ASCII DNS labels")
		}
		domains = append(domains, "full: '"+domain+"'")
	}
	for _, domain := range match.DomainSuffix {
		if !daeDomain(domain) {
			return nil, daeError("unsupported_domain", "domain suffix must use bounded ASCII DNS labels")
		}
		domains = append(domains, "suffix: '"+domain+"'")
	}
	if len(domains) > 0 {
		functions = append(functions, "domain("+strings.Join(domains, ", ")+")")
	}
	if len(match.DomainSets) > 0 {
		var values []string
		for _, id := range match.DomainSets {
			members, ok := sets[id]
			if !ok || len(members) == 0 {
				return nil, daeError("unresolved_domain_set", "domain set must contain an immutable nonempty snapshot")
			}
			values = append(values, members...)
		}
		values = uniqueSorted(values)
		params := make([]string, 0, len(values))
		for _, domain := range values {
			if !daeDomain(domain) {
				return nil, daeError("unsupported_domain", "domain set must use bounded ASCII DNS labels")
			}
			params = append(params, "suffix: '"+domain+"'")
		}
		functions = append(functions, "domain("+strings.Join(params, ", ")+")")
	}
	if len(match.DestinationCIDRs) > 0 {
		values := make([]string, 0, len(match.DestinationCIDRs))
		for _, cidr := range match.DestinationCIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, daeError("invalid_cidr", "destination CIDR is invalid")
			}
			values = append(values, "'"+prefix.Masked().String()+"'")
		}
		functions = append(functions, "dip("+strings.Join(values, ", ")+")")
	}
	if len(match.DestinationPorts) > 0 {
		values := make([]string, 0, len(match.DestinationPorts))
		for _, ports := range match.DestinationPorts {
			value := strconv.Itoa(ports.From)
			if ports.From != ports.To {
				value += "-" + strconv.Itoa(ports.To)
			}
			values = append(values, value)
		}
		functions = append(functions, "dport("+strings.Join(values, ", ")+")")
	}
	if len(match.Transport) > 0 {
		values := make([]string, 0, len(match.Transport))
		for _, transport := range match.Transport {
			if transport != TransportTCP && transport != TransportUDP {
				return nil, daeError("unsupported_dae_transport", "pinned dae cannot distinguish QUIC from other UDP in an l4proto match")
			}
			values = append(values, string(transport))
		}
		functions = append(functions, "l4proto("+strings.Join(values, ", ")+")")
	}
	if len(match.AddressFamilies) > 0 {
		values := make([]string, 0, len(match.AddressFamilies))
		for _, family := range match.AddressFamilies {
			switch family {
			case FamilyIPv4:
				values = append(values, "4")
			case FamilyIPv6:
				values = append(values, "6")
			default:
				return nil, daeError("invalid_address_family", "unsupported address family")
			}
		}
		functions = append(functions, "ipversion("+strings.Join(values, ", ")+")")
	}
	return functions, nil
}

func daeDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

func (artifact DAEArtifact) String() string {
	return fmt.Sprintf("dae routing %s on %s", artifact.RoutingSHA256, artifact.GatewayID)
}
