package outbounds

import (
	"errors"
	"sort"
	"time"
)

// ObserveConfiguration records an independently read-back configuration only
// when it matches the current desired revision and its exact candidate set.
// Selection state and provider inventory remain untouched.
func (s *Service) ObserveConfiguration(id string, revision int64, candidates []string, generation int64) (Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, ok := s.groups[id]
	if !ok {
		return Group{}, ErrGroupNotFound
	}
	if revision != group.Revision || revision <= 0 || generation < group.AppliedGeneration || generation < group.ObservedGeneration || generation < 0 || !sameCandidateIDs(candidates, group.NodeIDs) {
		return Group{}, ErrSelectionConflict
	}
	for _, selection := range s.selections {
		if selection.GroupID == id && referencesMissingNode(group, selection) {
			return Group{}, ErrSelectionConflict
		}
	}
	group.AppliedRevision, group.ObservedRevision = revision, revision
	group.AppliedNodeIDs = append([]string(nil), candidates...)
	group.ObservedNodeIDs = append([]string(nil), candidates...)
	group.AppliedGeneration, group.ObservedGeneration = generation, generation
	group.UpdatedAt = time.Now().UTC()
	s.groups[id] = cloneGroup(group)
	return cloneGroup(group), nil
}

func sameCandidateIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validateConfigurationState(group Group) error {
	for _, state := range []struct {
		revision, generation int64
		ids                  []string
	}{{group.AppliedRevision, group.AppliedGeneration, group.AppliedNodeIDs}, {group.ObservedRevision, group.ObservedGeneration, group.ObservedNodeIDs}} {
		if state.revision < 0 || state.revision > group.Revision || state.generation < 0 || (state.revision == 0 && (state.generation != 0 || len(state.ids) != 0)) {
			return errors.New("invalid outbound group configuration state")
		}
		seen := map[string]bool{}
		for _, id := range state.ids {
			if !validID(id) || seen[id] {
				return errors.New("invalid outbound group configuration members")
			}
			seen[id] = true
		}
		if state.revision > 0 && len(state.ids) == 0 {
			return errors.New("empty applied outbound group configuration")
		}
		if state.revision == group.Revision && !sameCandidateIDs(state.ids, group.NodeIDs) {
			return errors.New("outbound group configuration revision differs from candidates")
		}
	}
	return nil
}
