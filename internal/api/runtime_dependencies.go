package api

import (
	"context"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
)

// Provider publication includes affected group membership. Recovery must keep
// these dependencies stable until the prior exact operation is resolved.
func (s *Services) runtimeTargetsOverlap(left, right deployment.Target) bool {
	if left == right {
		return true
	}
	if left.Kind == "outbound_group" && right.Kind == "provider" {
		left, right = right, left
	}
	if left.Kind != "provider" || right.Kind != "outbound_group" {
		return false
	}
	group, err := s.Outbounds.Get(right.ID)
	return err == nil && s.groupReferencesProvider(group, left.ID)
}

func (s *Services) groupReferencesProvider(group outbounds.Group, providerID string) bool {
	owned := map[string]bool{}
	for _, revision := range s.Providers.List(providerID) {
		for _, node := range revision.Nodes {
			owned[node.ID] = true
		}
	}
	for _, ids := range [][]string{group.NodeIDs, group.AppliedNodeIDs, group.ObservedNodeIDs} {
		for _, id := range ids {
			if owned[id] {
				return true
			}
		}
	}
	for _, selected := range s.Outbounds.Selections(group.ID) {
		if owned[selected.DesiredNodeID] || owned[selected.AppliedNodeID] || owned[selected.ObservedNodeID] {
			return true
		}
	}
	if filters := group.SourceFilters; filters != nil {
		for _, id := range filters.ExcludeProviderIDs {
			if id == providerID {
				return false
			}
		}
		if len(filters.ProviderIDs) == 0 {
			return true
		}
		for _, id := range filters.ProviderIDs {
			if id == providerID {
				return true
			}
		}
	}
	return false
}

// Check prospective membership too: a new group or a group previously owned
// by another provider must not enter a publication's recovery target set.
func (s *Services) rejectPendingProviderForGroup(ctx context.Context, group outbounds.Group) error {
	operations, err := s.Journal.List(ctx)
	if err != nil {
		return err
	}
	for _, op := range operations {
		if op.Target.Kind == "provider" && (op.Status == deployment.StatusOutcomeUnknown || op.Status == deployment.StatusApplying || op.Status == deployment.StatusVerifying) && s.groupReferencesProvider(group, op.Target.ID) {
			return s.rejectUnknownTarget(ctx, op.Target)
		}
	}
	return nil
}
