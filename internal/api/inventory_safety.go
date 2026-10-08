package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
)

func preserveDeviceObservations(old domain.Device, desired *domain.Device) {
	desired.EnrollmentState = old.EnrollmentState
	for i := range desired.Addresses {
		address, family, err := domain.NormalizeAddress(desired.Addresses[i].Address)
		if err != nil {
			continue
		}
		for _, observed := range old.Addresses {
			prior, priorFamily, err := domain.NormalizeAddress(observed.Address)
			if err == nil && prior == address && priorFamily == family && observed.VerifiedAt != nil {
				stamp := *observed.VerifiedAt
				desired.Addresses[i].VerifiedAt = &stamp
				break
			}
		}
	}
}

func (s *Server) validateOutboundInventory(ctx context.Context, group *outbounds.Group) error {
	if group.Mode == outbounds.SelectionAutomatic {
		return &domain.ValidationError{Problems: []string{"automatic selection is unavailable until a qualified chooser is configured"}}
	}
	if _, err := s.Store.GetGateway(ctx, group.GatewayID); err != nil {
		return &domain.ValidationError{Problems: []string{"gateway_id must reference a registered gateway"}}
	}
	providers, err := s.Store.ListProviders(ctx)
	if err != nil {
		return err
	}
	available := map[string]bool{}
	knownProviders := map[string]bool{}
	inventory := []nodes.Node{}
	services := s.servicesOrDefault()
	for _, provider := range providers {
		knownProviders[provider.ID] = true
		status := services.Providers.Status(provider.ID)
		// Match /nodes: a staged revision replaces its provider's active
		// inventory in the editor, so renamed or removed active entries cannot
		// satisfy a filter against the prospective inventory.
		number := status.Staged
		if number == 0 {
			number = status.Active
		}
		if number == 0 {
			continue
		}
		revision, err := services.Providers.Get(provider.ID, number)
		if err != nil {
			return err
		}
		for _, node := range revision.Nodes {
			inventory = append(inventory, node)
			if node.Supported {
				available[node.ID] = true
			}
		}
	}
	if group.SourceFilters != nil {
		for _, ids := range [][]string{group.SourceFilters.ProviderIDs, group.SourceFilters.ExcludeProviderIDs} {
			for _, id := range ids {
				if !knownProviders[strings.TrimSpace(id)] {
					return &domain.ValidationError{Problems: []string{"source_filters must reference existing providers"}}
				}
			}
		}
		resolved, err := outbounds.ResolveCandidates(*group, inventory)
		if err != nil {
			return err
		}
		// NodeIDs is a cache when filters are present. Only the server's
		// materialized result may be stored or returned as current candidates.
		group.NodeIDs = resolved
	}
	if len(group.NodeIDs) == 0 {
		return &domain.ValidationError{Problems: []string{"node_ids must contain at least one supported staged or active node"}}
	}
	for _, id := range group.NodeIDs {
		if !available[id] {
			return &domain.ValidationError{Problems: []string{"node_ids contains an unknown or unsupported node"}}
		}
	}
	return nil
}

func (s *Server) checkOutboundInventory(w http.ResponseWriter, r *http.Request, group *outbounds.Group) bool {
	if err := s.validateOutboundInventory(r.Context(), group); err != nil {
		writeServiceError(w, err)
		return false
	}
	return true
}
