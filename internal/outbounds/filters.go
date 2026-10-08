package outbounds

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
)

const maxFilterValues = 1024

// SourceFilters is a persisted rule for candidate membership. ProviderIDs and
// Protocols constrain the source independently. If either inclusion list is
// present, a node must match an included ID OR an included name. Exclusions
// always win. Names are exact and case-sensitive; they are never interpreted as
// regular expressions. At least one positive source constraint is required.
type SourceFilters struct {
	ProviderIDs        []string         `json:"provider_ids,omitempty"`
	Protocols          []nodes.Protocol `json:"protocols,omitempty"`
	ExcludeProviderIDs []string         `json:"exclude_provider_ids,omitempty"`
	ExcludeProtocols   []nodes.Protocol `json:"exclude_protocols,omitempty"`
	IncludeNodeIDs     []string         `json:"include_node_ids,omitempty"`
	ExcludeNodeIDs     []string         `json:"exclude_node_ids,omitempty"`
	IncludeNames       []string         `json:"include_names,omitempty"`
	ExcludeNames       []string         `json:"exclude_names,omitempty"`
}

func cloneSourceFilters(f SourceFilters) SourceFilters {
	f.ProviderIDs = slices.Clone(f.ProviderIDs)
	f.Protocols = slices.Clone(f.Protocols)
	f.ExcludeProviderIDs = slices.Clone(f.ExcludeProviderIDs)
	f.ExcludeProtocols = slices.Clone(f.ExcludeProtocols)
	f.IncludeNodeIDs = slices.Clone(f.IncludeNodeIDs)
	f.ExcludeNodeIDs = slices.Clone(f.ExcludeNodeIDs)
	f.IncludeNames = slices.Clone(f.IncludeNames)
	f.ExcludeNames = slices.Clone(f.ExcludeNames)
	return f
}

func normalizeSourceFilters(f SourceFilters) SourceFilters {
	f = cloneSourceFilters(f)
	for _, values := range [][]string{f.ProviderIDs, f.ExcludeProviderIDs, f.IncludeNodeIDs, f.ExcludeNodeIDs, f.IncludeNames, f.ExcludeNames} {
		for i := range values {
			values[i] = strings.TrimSpace(values[i])
		}
		sort.Strings(values)
	}
	for _, protocols := range [][]nodes.Protocol{f.Protocols, f.ExcludeProtocols} {
		for i, protocol := range protocols {
			protocols[i] = nodes.Protocol(strings.ToLower(strings.TrimSpace(string(protocol))))
		}
		slices.Sort(protocols)
	}
	return f
}

func validateSourceFilters(f SourceFilters) []string {
	var problems []string
	if len(f.ProviderIDs)+len(f.Protocols)+len(f.IncludeNodeIDs)+len(f.IncludeNames) == 0 {
		problems = append(problems, "source_filters requires a provider, protocol, included node ID, or included name")
	}
	fields := []struct {
		name   string
		values []string
		isName bool
	}{
		{"provider_ids", f.ProviderIDs, false},
		{"exclude_provider_ids", f.ExcludeProviderIDs, false},
		{"include_node_ids", f.IncludeNodeIDs, false},
		{"exclude_node_ids", f.ExcludeNodeIDs, false},
		{"include_names", f.IncludeNames, true},
		{"exclude_names", f.ExcludeNames, true},
	}
	for _, field := range fields {
		if len(field.values) > maxFilterValues {
			problems = append(problems, "source_filters."+field.name+" exceeds 1024 values")
			continue
		}
		seen := map[string]bool{}
		for _, value := range field.values {
			valid := validID(value)
			if field.isName {
				valid = value != "" && value == strings.TrimSpace(value) && len(value) <= 512 && strings.IndexFunc(value, unicode.IsControl) < 0
			}
			if !valid || seen[value] {
				problems = append(problems, "source_filters."+field.name+" contains an invalid or duplicate value")
				break
			}
			seen[value] = true
		}
	}
	for _, field := range []struct {
		name   string
		values []nodes.Protocol
	}{
		{"protocols", f.Protocols},
		{"exclude_protocols", f.ExcludeProtocols},
	} {
		if len(field.values) > maxFilterValues {
			problems = append(problems, "source_filters."+field.name+" exceeds 1024 values")
			continue
		}
		seen := map[nodes.Protocol]bool{}
		for _, protocol := range field.values {
			if !validProtocolFilter(string(protocol)) || seen[protocol] {
				problems = append(problems, "source_filters."+field.name+" contains an invalid or duplicate value")
				break
			}
			seen[protocol] = true
		}
	}
	return problems
}

// Protocol names remain extensible like nodes.Protocol. Unknown canonical
// names match no nodes until the inventory supports that protocol.
func validProtocolFilter(protocol string) bool {
	if protocol == "" || len(protocol) > 32 {
		return false
	}
	for _, r := range protocol {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '+' || r == '.') {
			return false
		}
	}
	return true
}

// ResolveCandidates evaluates a group against a complete normalized inventory.
// Only supported nodes can be candidates. With no SourceFilters the existing
// explicit NodeIDs are intersected with inventory; with filters NodeIDs is a
// cache and does not expand the filter. IDs are sorted and never include an
// implicit Direct fallback. An empty result is valid for impact preview.
func ResolveCandidates(group Group, inventory []nodes.Node) ([]string, error) {
	group = normalizeGroup(group)
	if err := ValidateGroup(group); err != nil {
		return nil, err
	}
	index, err := inventoryIndex(inventory)
	if err != nil {
		return nil, err
	}
	return resolveCandidates(group, index), nil
}

func inventoryIndex(inventory []nodes.Node) (map[string]nodes.Node, error) {
	index := make(map[string]nodes.Node, len(inventory))
	for _, node := range inventory {
		if !validID(node.ID) || !validID(node.ProviderID) {
			return nil, &domain.ValidationError{Problems: []string{"candidate inventory contains an invalid node or provider identifier"}}
		}
		if _, exists := index[node.ID]; exists {
			return nil, &domain.ValidationError{Problems: []string{"candidate inventory contains duplicate node identifiers"}}
		}
		index[node.ID] = node
	}
	return index, nil
}

func resolveCandidates(group Group, index map[string]nodes.Node) []string {
	out := []string{}
	if group.SourceFilters == nil {
		for _, id := range group.NodeIDs {
			if node, exists := index[id]; exists && node.Supported {
				out = append(out, id)
			}
		}
	} else {
		f := group.SourceFilters
		providers, includedIDs, excludedIDs := stringSet(f.ProviderIDs), stringSet(f.IncludeNodeIDs), stringSet(f.ExcludeNodeIDs)
		excludedProviders := stringSet(f.ExcludeProviderIDs)
		includedNames, excludedNames := stringSet(f.IncludeNames), stringSet(f.ExcludeNames)
		protocols := make(map[nodes.Protocol]bool, len(f.Protocols))
		for _, protocol := range f.Protocols {
			protocols[protocol] = true
		}
		excludedProtocols := make(map[nodes.Protocol]bool, len(f.ExcludeProtocols))
		for _, protocol := range f.ExcludeProtocols {
			excludedProtocols[protocol] = true
		}
		for id, node := range index {
			if !node.Supported || len(providers) > 0 && !providers[node.ProviderID] || len(protocols) > 0 && !protocols[node.Definition.Protocol] {
				continue
			}
			if len(includedIDs)+len(includedNames) > 0 && !includedIDs[id] && !includedNames[node.Name] {
				continue
			}
			if excludedIDs[id] || excludedNames[node.Name] || excludedProviders[node.ProviderID] || excludedProtocols[node.Definition.Protocol] {
				continue
			}
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

// CandidateImpact describes one changed group without claiming that a gateway
// has applied it. MissingSelections retain runtime evidence; Unavailable is
// computed from the prospective membership. RemovalPrevented means the group's
// ReplacementNone policy rejects this change. RequiresBlock requests fail-closed
// behavior for an empty group or an unavailable intended selection.
type CandidateImpact struct {
	GroupID           string      `json:"group_id"`
	ExpectedRevision  int64       `json:"expected_revision"`
	CandidateIDs      []string    `json:"candidate_ids"`
	AddedNodeIDs      []string    `json:"added_node_ids"`
	RemovedNodeIDs    []string    `json:"removed_node_ids"`
	MissingSelections []Selection `json:"missing_selections"`
	RequiresBlock     bool        `json:"requires_block"`
	RemovalPrevented  bool        `json:"removal_prevented"`
}

// PreviewInventory reports only groups whose membership changes. The inventory
// must include all providers, including unchanged providers' last working nodes.
// Staged provider data must replace that provider's old entries, not append them.
func (s *Service) PreviewInventory(inventory []nodes.Node) ([]CandidateImpact, error) {
	index, err := inventoryIndex(inventory)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.previewInventoryLocked(index), nil
}

func (s *Service) previewInventoryLocked(index map[string]nodes.Node) []CandidateImpact {
	return s.previewGroupsLocked(index, nil)
}

func (s *Service) previewGroupsLocked(index map[string]nodes.Node, only map[string]int64) []CandidateImpact {
	impacts := []CandidateImpact{}
	for _, group := range s.groups {
		if only != nil {
			if _, included := only[group.ID]; !included {
				continue
			}
		}
		candidates := resolveCandidates(group, index)
		previous, next := stringSet(group.NodeIDs), stringSet(candidates)
		impact := CandidateImpact{GroupID: group.ID, ExpectedRevision: group.Revision, CandidateIDs: candidates, AddedNodeIDs: []string{}, RemovedNodeIDs: []string{}, MissingSelections: []Selection{}}
		for _, id := range candidates {
			if !previous[id] {
				impact.AddedNodeIDs = append(impact.AddedNodeIDs, id)
			}
		}
		for _, id := range group.NodeIDs {
			if !next[id] {
				impact.RemovedNodeIDs = append(impact.RemovedNodeIDs, id)
			}
		}
		if len(impact.AddedNodeIDs)+len(impact.RemovedNodeIDs) == 0 {
			continue
		}
		sort.Strings(impact.RemovedNodeIDs)
		group.NodeIDs = candidates
		impact.RequiresBlock = len(candidates) == 0
		for _, selection := range s.selections {
			if selection.GroupID != group.ID || !referencesMissingNode(group, selection) {
				continue
			}
			selection.Unavailable = selectionUnavailable(group, selection)
			impact.MissingSelections = append(impact.MissingSelections, selection)
			impact.RequiresBlock = impact.RequiresBlock || selection.Unavailable
			impact.RemovalPrevented = impact.RemovalPrevented || group.Replacement == ReplacementNone
		}
		sort.Slice(impact.MissingSelections, func(i, j int) bool {
			return impact.MissingSelections[i].Scope.Key() < impact.MissingSelections[j].Scope.Key()
		})
		impacts = append(impacts, impact)
	}
	sort.Slice(impacts, func(i, j int) bool { return impacts[i].GroupID < impacts[j].GroupID })
	return impacts
}

// ReconcileInventory atomically updates candidate snapshots and selection
// availability. expectedRevisions must cover every affected group and may also
// fence unchanged groups. Callers must serialize provider publication and pass
// a complete approved inventory. This records controller membership only, not
// engine success. Explicit groups without filters retain only surviving IDs;
// use SourceFilters.IncludeNodeIDs to retain intent for reappearing candidates.
func (s *Service) ReconcileInventory(inventory []nodes.Node, expectedRevisions map[string]int64) ([]CandidateImpact, error) {
	return s.reconcileGroups(inventory, expectedRevisions, false)
}

// ReconcileGroups recomputes only the named group identities, with an exact
// precondition on each. An empty map is a no-op. This is the commit boundary for
// a single provider publication: unrelated groups, including pending groups,
// never lose candidates because those providers were absent from the input.
// The input must still contain every provider used by the named groups.
func (s *Service) ReconcileGroups(inventory []nodes.Node, expectedRevisions map[string]int64) ([]CandidateImpact, error) {
	return s.reconcileGroups(inventory, expectedRevisions, true)
}

func (s *Service) reconcileGroups(inventory []nodes.Node, expectedRevisions map[string]int64, scoped bool) ([]CandidateImpact, error) {
	index, err := inventoryIndex(inventory)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var impacts []CandidateImpact
	if scoped {
		if expectedRevisions == nil {
			expectedRevisions = map[string]int64{}
		}
		impacts = s.previewGroupsLocked(index, expectedRevisions)
	} else {
		impacts = s.previewInventoryLocked(index)
	}
	for id, revision := range expectedRevisions {
		group, exists := s.groups[id]
		if !exists || revision <= 0 || group.Revision != revision {
			return impacts, ErrSelectionConflict
		}
	}
	for _, impact := range impacts {
		if expectedRevisions[impact.GroupID] != impact.ExpectedRevision {
			return impacts, ErrSelectionConflict
		}
		if impact.RemovalPrevented {
			return impacts, &domain.ValidationError{Problems: []string{fmt.Sprintf("outbound group %s: replacement_policy none prevents removal of selected nodes", impact.GroupID)}}
		}
	}
	now := time.Now().UTC()
	for _, impact := range impacts {
		group := s.groups[impact.GroupID]
		group.NodeIDs = slices.Clone(impact.CandidateIDs)
		group.Revision++
		group.UpdatedAt = now
		s.groups[group.ID] = group
		for key, selection := range s.selections {
			if selection.GroupID == group.ID {
				unavailable := selectionUnavailable(group, selection)
				if selection.Unavailable != unavailable {
					selection.Unavailable = unavailable
					selection.Revision++
					selection.UpdatedAt = now
					s.selections[key] = selection
				}
			}
		}
	}
	return impacts, nil
}
