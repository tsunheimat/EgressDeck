package policy

import (
	"fmt"
	"net"
	"strings"
)

// Explain predicts the first matching generated rule for a packet. It is a
// compiler explanation, not traffic evidence: a returned match does not prove
// that the gateway observed the domain or that a packet traversed the route.
func Explain(manifest Manifest, packet Packet) Explanation {
	packet.SourceIP = strings.TrimSpace(packet.SourceIP)
	packet.DestinationIP = strings.TrimSpace(packet.DestinationIP)
	packet.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(packet.Domain), "."))
	packet.Transport = normalizeTransport(packet.Transport)
	packet.Family = normalizeFamily(packet.Family)
	if packet.Family == FamilyAny {
		if ip := net.ParseIP(packet.DestinationIP); ip != nil {
			if ip.To4() != nil {
				packet.Family = FamilyIPv4
			} else {
				packet.Family = FamilyIPv6
			}
		}
	}
	source := canonicalPacketSource(packet.SourceIP)
	for _, group := range manifest.Groups {
		if !contains(group.SourceSelector, source) {
			continue
		}
		for _, rule := range group.Rules {
			if !contains(groupSource(rule), source) || !matchPacket(rule.Match, packet, manifest.DomainSets) {
				continue
			}
			return Explanation{
				Predicted: true, Action: rule.Action, DeviceGroupID: group.DeviceGroupID,
				MatchedRuleID: rule.Source.RuleID, MatchedRuleName: rule.Name,
				Source: rule.Source, Reason: "predicted first matching rule",
			}
		}
		if packet.Domain == "" && group.UnknownDomainAction.Kind != "" {
			return Explanation{Predicted: true, Action: group.UnknownDomainAction, DeviceGroupID: group.DeviceGroupID, Reason: "predicted unknown-domain action (domain was not supplied)"}
		}
		return Explanation{Predicted: true, Action: group.DefaultAction, DeviceGroupID: group.DeviceGroupID, Reason: "predicted policy default"}
	}
	return Explanation{Predicted: false, Action: Action{Kind: ActionBlock}, Reason: "no generated device-group source selector matched"}
}

// Explain is also available as a method for callers holding a CompileResult.
func (r CompileResult) Explain(packet Packet) Explanation { return Explain(r.Manifest, packet) }
func (m Manifest) Explain(packet Packet) Explanation      { return Explain(m, packet) }

func groupSource(rule EngineRule) []string { return rule.SourceSelector }

func canonicalPacketSource(raw string) string {
	if source, ok := canonicalSource(raw); ok {
		return source
	}
	return strings.TrimSpace(raw)
}

func matchPacket(m Match, p Packet, domainSets []DomainSet) bool {
	if len(m.AddressFamilies) > 0 && !containsFamily(m.AddressFamilies, p.Family) {
		return false
	}
	if len(m.Transport) > 0 && !containsTransport(m.Transport, p.Transport) {
		return false
	}
	if len(m.DestinationPorts) > 0 && !containsPort(m.DestinationPorts, p.DestinationPort) {
		return false
	}
	if len(m.DestinationCIDRs) > 0 && !containsCIDR(m.DestinationCIDRs, p.DestinationIP) {
		return false
	}
	if len(m.DomainExact) > 0 || len(m.DomainSuffix) > 0 {
		if p.Domain == "" {
			return false
		}
		matched := false
		for _, d := range m.DomainExact {
			if p.Domain == strings.ToLower(strings.TrimSuffix(d, ".")) {
				matched = true
				break
			}
		}
		if !matched {
			for _, suffix := range m.DomainSuffix {
				suffix = strings.TrimPrefix(strings.ToLower(strings.TrimSuffix(suffix, ".")), ".")
				if p.Domain == suffix || strings.HasSuffix(p.Domain, "."+suffix) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	if len(m.DomainSets) > 0 {
		matchedSet := false
		for _, id := range m.DomainSets {
			for _, set := range domainSets {
				if id != set.ID {
					continue
				}
				for _, domain := range set.Domains {
					if p.Domain == domain || strings.HasSuffix(p.Domain, "."+domain) {
						matchedSet = true
						break
					}
				}
			}
			if matchedSet {
				break
			}
		}
		if !matchedSet {
			return false
		}
	}
	return true
}

func containsCIDR(cidrs []string, raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	for _, value := range cidrs {
		_, n, err := net.ParseCIDR(value)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
func containsPort(ranges []PortRange, port int) bool {
	for _, r := range ranges {
		if r.To == 0 {
			r.To = r.From
		}
		if port >= r.From && port <= r.To {
			return true
		}
	}
	return false
}
func containsFamily(values []AddressFamily, family AddressFamily) bool {
	for _, v := range values {
		if normalizeFamily(v) == family {
			return true
		}
	}
	return false
}
func containsTransport(values []Transport, t Transport) bool {
	for _, v := range values {
		if normalizeTransport(v) == t {
			return true
		}
	}
	return false
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// ExplainPacket is a descriptive alias suitable for HTTP handlers.
func ExplainPacket(manifest Manifest, packet Packet) Explanation { return Explain(manifest, packet) }

func (e Explanation) String() string { return fmt.Sprintf("%s (%s)", e.Action.String(), e.Reason) }
