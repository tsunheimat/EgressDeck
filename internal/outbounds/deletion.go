package outbounds

import (
	"errors"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

var (
	ErrGroupReferenced = errors.New("outbound group is referenced by policy")
	ErrGroupInUse      = errors.New("outbound group still has desired or runtime selections")
)

// Delete removes an unreferenced group with an exact revision precondition.
// The API owns policy/rule-set records and must pass the references found under
// its serialized persistence boundary; an empty list is an explicit assertion
// that all references were checked. Runtime choices also prevent deletion:
// deleting their metadata is not equivalent to retiring the gateway policy.
func (s *Service) Delete(id string, expectedRevision int64, referencedBy []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	group, exists := s.groups[id]
	if !exists {
		return ErrGroupNotFound
	}
	if expectedRevision <= 0 || group.Revision != expectedRevision {
		return domain.ErrConflict
	}
	if len(referencedBy) > 0 {
		return ErrGroupReferenced
	}
	if group.AppliedRevision > 0 || group.ObservedRevision > 0 {
		return ErrGroupInUse
	}
	for _, selection := range s.selections {
		if selection.GroupID == id && (selection.DesiredNodeID != "" || selection.AppliedNodeID != "" || selection.ObservedNodeID != "") {
			return ErrGroupInUse
		}
	}
	for key, selection := range s.selections {
		if selection.GroupID == id {
			delete(s.selections, key)
		}
	}
	delete(s.groups, id)
	return nil
}
