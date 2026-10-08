package store

import (
	"encoding/json"
	"fmt"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

// cloneState and replaceState are intentionally package-private. They let the
// durable adapter take a rollback snapshot without exposing MemoryStore's
// implementation to API callers.
func (s *MemoryStore) cloneState() fileStoreState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := fileStoreState{
		Version:   fileStoreVersion,
		Devices:   make(map[string]domain.Device, len(s.devices)),
		Groups:    make(map[string]domain.DeviceGroup, len(s.groups)),
		Providers: make(map[string]domain.Provider, len(s.providers)),
		Gateways:  make(map[string]domain.Gateway, len(s.gateways)),
		Policies:  make(map[string]domain.Policy, len(s.policies)),
		Documents: make(map[string]json.RawMessage, len(s.documents)),
	}
	for id, d := range s.devices {
		state.Devices[id] = cloneDevice(d)
	}
	for id, g := range s.groups {
		state.Groups[id] = g
	}
	for id, p := range s.providers {
		state.Providers[id] = p
	}
	for id, g := range s.gateways {
		state.Gateways[id] = g
	}
	for id, p := range s.policies {
		state.Policies[id] = clonePolicy(p)
	}
	for key, document := range s.documents {
		state.Documents[key] = append(json.RawMessage(nil), document...)
	}
	return state
}

func (s *MemoryStore) replaceState(state fileStoreState) error {
	devices := make(map[string]domain.Device, len(state.Devices))
	groups := make(map[string]domain.DeviceGroup, len(state.Groups))
	providers := make(map[string]domain.Provider, len(state.Providers))
	gateways := make(map[string]domain.Gateway, len(state.Gateways))
	policies := make(map[string]domain.Policy, len(state.Policies))
	addresses := make(map[string]string)
	documents := make(map[string]json.RawMessage, len(state.Documents))
	for id, d := range state.Devices {
		if id == "" || d.ID != id {
			return fmt.Errorf("device map key %q does not match id %q", id, d.ID)
		}
		d = cloneDevice(d)
		if err := d.Validate(); err != nil || d.Revision < 1 {
			return fmt.Errorf("device %q has invalid persisted state", id)
		}
		for _, address := range d.Addresses {
			if owner := addresses[address.Address]; owner != "" && owner != id {
				return fmt.Errorf("address %q is owned by both %q and %q", address.Address, owner, id)
			}
			addresses[address.Address] = id
		}
		devices[id] = cloneDevice(d)
	}
	for id, g := range state.Groups {
		if id == "" || g.ID != id {
			return fmt.Errorf("device group map key %q does not match id %q", id, g.ID)
		}
		if err := g.Validate(); err != nil || g.Revision < 1 {
			return fmt.Errorf("device group %q has invalid persisted state", id)
		}
		groups[id] = g
	}
	for id, p := range state.Providers {
		if id == "" || p.ID != id {
			return fmt.Errorf("provider map key %q does not match id %q", id, p.ID)
		}
		if err := p.Validate(); err != nil || p.Revision < 1 {
			return fmt.Errorf("provider %q has invalid persisted state", id)
		}
		providers[id] = p
	}
	for id, g := range state.Gateways {
		if id == "" || g.ID != id {
			return fmt.Errorf("gateway map key %q does not match id %q", id, g.ID)
		}
		if err := g.Validate(); err != nil || g.Revision < 1 {
			return fmt.Errorf("gateway %q has invalid persisted state", id)
		}
		gateways[id] = g
	}
	for id, p := range state.Policies {
		if id == "" || p.ID != id || p.Name == "" || p.Revision < 1 {
			return fmt.Errorf("policy %q has invalid persisted state", id)
		}
		policies[id] = clonePolicy(p)
	}
	for key, document := range state.Documents {
		if key == "" || !json.Valid(document) {
			return fmt.Errorf("invalid persisted document %q", key)
		}
		documents[key] = append(json.RawMessage(nil), document...)
	}
	s.mu.Lock()
	s.devices, s.groups, s.providers, s.gateways, s.policies, s.addresses = devices, groups, providers, gateways, policies, addresses
	s.documents = documents
	s.mu.Unlock()
	return nil
}
