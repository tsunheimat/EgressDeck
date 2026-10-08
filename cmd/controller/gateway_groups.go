package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
)

func groupUnapplied() error {
	return gateway.RejectBeforeMutation("group_configuration_not_applied", "apply the desired group configuration before selecting a node", domain.ErrConflict)
}

func (b *gatewayRuntimeBridge) selectionPreflight(ctx context.Context, group outbounds.Group) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	connection, before, err := b.connection(ctx, group.GatewayID, gateway.CapabilitySelectionRuntime)
	if err != nil {
		return gateway.RejectBeforeMutation("selection_preflight_failed", err.Error(), err)
	}
	binding, bound := connection.runtime.Groups[group.ID]
	remote, found := before.Groups[group.ID]
	if !bound || !found || remote.Name != binding.Name || remote.Revision != group.Revision || !sameIDs(remote.NodeIDs, group.NodeIDs) {
		return groupUnapplied()
	}
	// This readback also fills lifecycle state imported from older controllers.
	_, err = b.server.Services.Outbounds.ObserveConfiguration(group.ID, group.Revision, remote.NodeIDs, before.Generation)
	if err != nil {
		return gateway.RejectBeforeMutation("selection_preflight_failed", err.Error(), err)
	}
	return nil
}

// groupPublication joins desired membership with existing active connection
// definitions. It never stages or increments a provider revision.
func (b *gatewayRuntimeBridge) groupPublication(ctx context.Context, group outbounds.Group, connection configuredGateway, before gateway.Snapshot) (gateway.GroupPublication, error) {
	binding, bound := connection.runtime.Groups[group.ID]
	if !bound || group.Mode != outbounds.SelectionManual {
		return gateway.GroupPublication{}, errors.New("group requires an existing manual native binding")
	}
	remote, found := before.Groups[group.ID]
	if !found || remote.Name != binding.Name {
		return gateway.GroupPublication{}, errors.New("publish the provider before applying this group")
	}
	if remote.Revision > group.Revision {
		return gateway.GroupPublication{}, domain.ErrConflict
	}
	if len(group.NodeIDs) == 0 {
		return gateway.GroupPublication{}, outbounds.ErrNoCandidates
	}
	providerID := ""
	providerRevision := int64(0)
	for _, nodeID := range group.NodeIDs {
		owner := ""
		for id, provider := range before.Providers {
			for _, node := range provider.Nodes {
				if node.ID == nodeID {
					if owner != "" {
						return gateway.GroupPublication{}, errors.New("runtime node ownership is ambiguous")
					}
					owner = id
				}
			}
		}
		if owner == "" {
			return gateway.GroupPublication{}, errors.New("candidate node has not been published")
		}
		if providerID != "" && owner != providerID {
			return gateway.GroupPublication{}, errors.New("native outbound groups may reference only one provider")
		}
		providerID = owner
		providerRevision = before.Providers[owner].Revision
	}
	active, err := b.server.Services.Providers.Active(providerID)
	if err != nil || active.Number != providerRevision || before.Providers[providerID].ContentHash != revisionIdentity(providerID, providerRevision) {
		return gateway.GroupPublication{}, errors.New("provider inventory is not synchronized; reconcile provider publication first")
	}
	for _, nodeID := range group.NodeIDs {
		found := false
		for _, node := range active.Nodes {
			if node.ID == nodeID {
				found = true
				break
			}
		}
		if !found {
			return gateway.GroupPublication{}, errors.New("candidate is outside the active provider revision")
		}
	}
	selection, exists := remoteSelection(before, group.GatewayID, group.ID)
	if !exists || selection.DesiredNodeID == "" || selection.DesiredNodeID != selection.ObservedNodeID || !containsID(group.NodeIDs, selection.DesiredNodeID) {
		return gateway.GroupPublication{}, errors.New("group publication must preserve its current selected node; restore it to candidates before applying")
	}
	for _, desired := range b.server.Services.Outbounds.Selections(group.ID) {
		if desired.DesiredNodeID != "" && desired.DesiredNodeID != selection.DesiredNodeID {
			return gateway.GroupPublication{}, errors.New("group has an unresolved selection intent")
		}
	}
	return gateway.GroupPublication{ProviderID: providerID, ProviderRevision: providerRevision, Group: gateway.PublicationGroup{ID: group.ID, Name: binding.Name, Revision: group.Revision, CandidateIDs: append([]string(nil), group.NodeIDs...), SelectedNodeID: selection.DesiredNodeID}}, nil
}

func groupPublicationMatches(snapshot gateway.Snapshot, want gateway.GroupPublication) bool {
	provider, found := snapshot.Providers[want.ProviderID]
	if !found || provider.Revision != want.ProviderRevision || provider.ContentHash != revisionIdentity(want.ProviderID, want.ProviderRevision) {
		return false
	}
	actual, found := snapshot.Groups[want.Group.ID]
	if !found || actual.Name != want.Group.Name || actual.Revision != want.Group.Revision || !sameIDs(actual.NodeIDs, want.Group.CandidateIDs) || len(actual.ProviderIDs) != 1 || actual.ProviderIDs[0] != want.ProviderID {
		return false
	}
	selected, found := remoteSelection(snapshot, "", want.Group.ID)
	if !found {
		for _, value := range snapshot.Selections {
			if value.Scope.GroupID == want.Group.ID && (value.Scope.Transport == "both" || value.Scope.Transport == "") {
				selected, found = value, true
				break
			}
		}
	}
	return found && selected.DesiredNodeID == want.Group.SelectedNodeID && selected.ObservedNodeID == want.Group.SelectedNodeID
}

func (b *gatewayRuntimeBridge) publishGroup(ctx context.Context, group outbounds.Group) (gateway.Snapshot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	connection, before, err := b.connection(ctx, group.GatewayID, gateway.CapabilityGroupPublish)
	if err != nil {
		return gateway.Snapshot{}, gateway.RejectBeforeMutation("group_preflight_failed", err.Error(), err)
	}
	request, err := b.groupPublication(ctx, group, connection, before)
	if err != nil {
		return gateway.Snapshot{}, gateway.RejectBeforeMutation("group_configuration_rejected", err.Error(), err)
	}
	_, correlated := gateway.MutationIdentityFromContext(ctx)
	if groupPublicationMatches(before, request) && !correlated {
		return before, nil
	}
	_, applyErr := connection.client.PublishGroup(ctx, request, before.Generation)
	// Once transport can have reached the agent, only exact readback establishes
	// success. An unchanged generation alone cannot prove rejection.
	after, readErr := connection.client.Readback(ctx)
	if readErr == nil && groupPublicationMatches(after, request) {
		return after, nil
	}
	if gateway.IsDefiniteRejection(applyErr) {
		return gateway.Snapshot{}, applyErr
	}
	return gateway.Snapshot{}, fmt.Errorf("%w: group publication requires authoritative recovery", gateway.ErrOutcomeUnknown)
}

func (b *gatewayRuntimeBridge) groupReadback(ctx context.Context, group outbounds.Group) (gateway.Snapshot, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	connection, before, err := b.connection(ctx, group.GatewayID, gateway.CapabilityGroupPublish)
	if err != nil {
		return gateway.Snapshot{}, err
	}
	request, err := b.groupPublication(ctx, group, connection, before)
	if err != nil || !groupPublicationMatches(before, request) {
		return gateway.Snapshot{}, gateway.ErrOutcomeUnknown
	}
	return before, nil
}
