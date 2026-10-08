package providers

import "errors"

// ForgetUnpublished drops only inventory that has never reached a gateway.
// Callers must additionally prove there are no group, selection or operation
// references and serialize this action with controller mutations.
func (r *Registry) ForgetUnpublished(providerID string) error {
	r.boundary.Lock()
	defer r.boundary.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.providers[providerID]
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.Active != 0 || s.refresh != nil {
		return errors.New("provider remains active or refreshing")
	}
	for _, revision := range s.revisions {
		if revision.PublishedAt != nil {
			return errors.New("published provider revisions cannot be forgotten")
		}
	}
	delete(r.providers, providerID)
	return nil
}
