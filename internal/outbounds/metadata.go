package outbounds

import (
	"slices"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
)

// ProviderMetadataImpact is suitable for Registry.SetMetadataImpactEvaluator.
// Other providers are deliberately irrelevant here: their contributions to
// candidate sets are unchanged. Matching public IDs must already have been
// reconciled by the provider registry before this comparison.
func (s *Service) ProviderMetadataImpact(providerID string, before, after []nodes.Node) (bool, error) {
	for _, inventory := range [][]nodes.Node{before, after} {
		for _, node := range inventory {
			if node.ProviderID != providerID {
				return false, &domain.ValidationError{Problems: []string{"metadata inventory contains another provider"}}
			}
		}
	}
	previous, err := inventoryIndex(before)
	if err != nil {
		return false, err
	}
	next, err := inventoryIndex(after)
	if err != nil {
		return false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, group := range s.groups {
		if group.SourceFilters == nil || len(group.SourceFilters.IncludeNames)+len(group.SourceFilters.ExcludeNames) == 0 {
			continue
		}
		if !slices.Equal(resolveCandidates(group, previous), resolveCandidates(group, next)) {
			return true, nil
		}
	}
	return false, nil
}
