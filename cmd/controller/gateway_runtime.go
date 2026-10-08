package main

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
)

// Runtime mutations require an operator opt-in and exact implementation match;
// stock dae and development simulations cannot be opted into these hooks.
type gatewayRuntimeConfig struct {
	EnableProviderPublish    bool                           `json:"enable_provider_publish,omitempty"`
	EnableSelection          bool                           `json:"enable_selection,omitempty"`
	ExpectedImplementation   string                         `json:"expected_implementation,omitempty"`
	SharedTransportSelection bool                           `json:"shared_transport_selection,omitempty"`
	Groups                   map[string]gatewayRuntimeGroup `json:"groups,omitempty"`
}
type gatewayRuntimeGroup struct {
	Name          string `json:"name"`
	InitialNodeID string `json:"initial_node_id,omitempty"`
}

func validateGatewayRuntimeConfig(config gatewayRuntimeConfig) error {
	if !config.EnableProviderPublish && !config.EnableSelection {
		return nil
	}
	if config.ExpectedImplementation == "" || strings.Contains(strings.ToLower(config.ExpectedImplementation), "fake") || config.ExpectedImplementation == "dae-stock" {
		return errors.New("runtime mutations require an explicit qualified implementation")
	}
	if !config.SharedTransportSelection {
		return errors.New("native gateway only supports explicitly shared TCP/UDP selection")
	}
	if len(config.Groups) == 0 {
		return errors.New("runtime mutations require predeclared outbound group bindings")
	}
	seen := map[string]bool{}
	for id, binding := range config.Groups {
		if strings.TrimSpace(id) == "" || strings.TrimSpace(binding.Name) == "" || seen[binding.Name] {
			return errors.New("runtime group bindings require unique native names")
		}
		seen[binding.Name] = true
	}
	return nil
}

type gatewayRuntimeBridge struct {
	server      *api.Server
	connections map[string]configuredGateway
	mu          sync.Mutex // one mutation stream across this initial single-gateway bridge
}

func configureGatewayRuntime(server *api.Server, connections map[string]configuredGateway) {
	bridge := &gatewayRuntimeBridge{server: server, connections: connections}
	providerEnabled, selectionEnabled := false, false
	for _, connection := range connections {
		providerEnabled = providerEnabled || connection.runtime.EnableProviderPublish
		selectionEnabled = selectionEnabled || connection.runtime.EnableSelection
	}
	if providerEnabled {
		server.Services.ProviderPublisher = bridge.publishProvider
		server.Services.ProviderReadback = bridge.providerReadback
		server.Services.ProviderTargetIDs = bridge.providerTargetIDs
		server.Services.GroupPublisher = bridge.publishGroup
		server.Services.GroupReadback = bridge.groupReadback
	}
	if selectionEnabled {
		server.Services.SelectionApplier = bridge.applySelection
		server.Services.SelectionPreflight = bridge.selectionPreflight
		server.Services.SelectionPersistence = true
		server.Services.SelectionScopeMode = func(group outbounds.Group) string {
			if connection, ok := connections[group.GatewayID]; ok && connection.runtime.EnableSelection && connection.runtime.SharedTransportSelection {
				return "shared"
			}
			return ""
		}
	}
}

func (b *gatewayRuntimeBridge) providerTargetIDs(ctx context.Context, provider domain.Provider) ([]string, error) {
	status := b.server.Services.Providers.Status(provider.ID)
	number := status.Staged
	if number == 0 {
		number = status.Active
	}
	revision, err := b.server.Services.Providers.Get(provider.ID, number)
	if err != nil {
		return nil, err
	}
	targets, err := b.providerTargets(ctx, provider.ID, revision)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(targets))
	for _, target := range targets {
		ids = append(ids, target.id)
	}
	return ids, nil
}

func (b *gatewayRuntimeBridge) connection(ctx context.Context, id string, operation gateway.CapabilityName) (configuredGateway, gateway.Snapshot, error) {
	c, ok := b.connections[id]
	if !ok {
		return configuredGateway{}, gateway.Snapshot{}, gateway.ErrUnsupported
	}
	if operation == gateway.CapabilityProviderPublish && !c.runtime.EnableProviderPublish {
		return c, gateway.Snapshot{}, gateway.ErrUnsupported
	}
	if operation == gateway.CapabilityGroupPublish && !c.runtime.EnableProviderPublish {
		return c, gateway.Snapshot{}, gateway.ErrUnsupported
	}
	if operation == gateway.CapabilitySelectionRuntime && !c.runtime.EnableSelection {
		return c, gateway.Snapshot{}, gateway.ErrUnsupported
	}
	registered, err := b.server.Store.GetGateway(ctx, id)
	if err != nil {
		return c, gateway.Snapshot{}, err
	}
	if strings.TrimRight(registered.Endpoint, "/") != c.endpoint {
		return c, gateway.Snapshot{}, errors.New("gateway endpoint differs from operator configuration")
	}
	caps, err := c.client.Capabilities(ctx)
	if err != nil {
		return c, gateway.Snapshot{}, err
	}
	if caps.Implementation != c.runtime.ExpectedImplementation || strings.Contains(strings.ToLower(caps.Implementation), "fake") {
		return c, gateway.Snapshot{}, gateway.ErrUnsupported
	}
	for _, required := range []gateway.CapabilityName{gateway.CapabilityInventoryRead, operation} {
		if !caps.Has(required) {
			return c, gateway.Snapshot{}, gateway.ErrUnsupported
		}
	}
	if operation == gateway.CapabilityProviderPublish && !caps.Has(gateway.CapabilityProviderStage) {
		return c, gateway.Snapshot{}, gateway.ErrUnsupported
	}
	if operation == gateway.CapabilitySelectionRuntime && !caps.Has(gateway.CapabilitySelectionPersist) {
		return c, gateway.Snapshot{}, gateway.ErrUnsupported
	}
	snapshot, err := c.client.Readback(ctx)
	return c, snapshot, err
}

func revisionIdentity(provider string, number int64) string {
	return provider + ":" + strconv.FormatInt(number, 10)
}

type runtimeProviderTarget struct {
	id         string
	connection configuredGateway
	before     gateway.Snapshot
	revision   gateway.ProviderRevision
}

func (b *gatewayRuntimeBridge) prospectiveInventory(ctx context.Context, replacement providers.Revision) ([]nodes.Node, error) {
	all, err := b.server.Store.ListProviders(ctx)
	if err != nil {
		return nil, err
	}
	inventory := append([]nodes.Node(nil), replacement.Nodes...)
	for _, provider := range all {
		if provider.ID == replacement.ProviderID {
			continue
		}
		active, err := b.server.Services.Providers.Active(provider.ID)
		if errors.Is(err, domain.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		inventory = append(inventory, active.Nodes...)
	}
	return inventory, nil
}

func (b *gatewayRuntimeBridge) providerTargets(ctx context.Context, providerID string, revision providers.Revision) ([]runtimeProviderTarget, error) {
	if revision.ProviderID != providerID || revision.Number <= 0 || revision.RequiresApproval() || len(revision.Nodes) == 0 {
		return nil, errors.New("provider revision requires approval or has invalid inventory")
	}
	native := gateway.ProviderRevision{ProviderID: providerID, Revision: revision.Number, ContentHash: revisionIdentity(providerID, revision.Number), Nodes: make([]gateway.Node, 0, len(revision.Nodes))}
	newNodes := map[string]bool{}
	owned := map[string]bool{}
	inventory, err := b.prospectiveInventory(ctx, revision)
	if err != nil {
		return nil, err
	}
	for _, old := range b.server.Services.Providers.List(providerID) {
		for _, node := range old.Nodes {
			owned[node.ID] = true
		}
	}
	for _, node := range revision.Nodes {
		if node.ProviderID != providerID || !node.Supported || node.ID == "" || nodes.ContentFingerprint(node.Definition) != node.ContentHash {
			return nil, errors.New("provider node is not bound to its private immutable revision")
		}
		stable := nodes.Clone(node)
		stable.Name = node.ID
		link, err := nodes.DaeLink(stable)
		if err != nil {
			return nil, errors.New("provider node cannot be rendered without changing native protocol semantics")
		}
		native.Nodes = append(native.Nodes, gateway.Node{ID: node.ID, ProviderID: providerID, Name: node.Name, Connection: link})
		newNodes[node.ID] = true
		owned[node.ID] = true
	}
	groupsByGateway := map[string][]outbounds.Group{}
	resolvedGroups := map[string][]string{}
	for _, group := range b.server.Services.Outbounds.List() {
		resolved, resolveErr := outbounds.ResolveCandidates(group, inventory)
		if resolveErr != nil {
			return nil, resolveErr
		}
		resolvedGroups[group.ID] = resolved
		affected := false
		for _, id := range group.NodeIDs {
			affected = affected || owned[id]
		}
		for _, id := range resolved {
			affected = affected || owned[id]
		}
		if affected {
			groupsByGateway[group.GatewayID] = append(groupsByGateway[group.GatewayID], group)
		}
	}
	if len(groupsByGateway) == 0 {
		return nil, errors.New("provider publication requires an explicitly bound outbound group")
	}
	ids := make([]string, 0, len(groupsByGateway))
	for id := range groupsByGateway {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	targets := make([]runtimeProviderTarget, 0, len(ids))
	for _, id := range ids {
		connection, before, err := b.connection(ctx, id, gateway.CapabilityProviderPublish)
		if err != nil {
			return nil, err
		}
		local := native
		local.Groups = nil
		for _, group := range groupsByGateway[id] {
			binding, ok := connection.runtime.Groups[group.ID]
			if !ok || group.Mode != outbounds.SelectionManual {
				return nil, errors.New("provider group lacks a qualified manual native binding")
			}
			candidates := []string{}
			for _, nodeID := range resolvedGroups[group.ID] {
				if !owned[nodeID] {
					return nil, errors.New("native outbound groups may reference only one provider")
				}
				if newNodes[nodeID] {
					candidates = append(candidates, nodeID)
				}
			}
			if len(candidates) == 0 {
				return nil, errors.New("provider update removes all group candidates")
			}
			selected := ""
			for _, selection := range b.server.Services.Outbounds.Selections(group.ID) {
				if selection.DesiredNodeID != "" {
					if selected != "" && selected != selection.DesiredNodeID {
						return nil, errors.New("native shared selection conflicts across transport scopes")
					}
					selected = selection.DesiredNodeID
				}
			}
			if selected == "" {
				if remote, ok := remoteSelection(before, id, group.ID); ok {
					selected = remote.DesiredNodeID
				}
			}
			if selected == "" {
				selected = binding.InitialNodeID
			}
			if !containsID(candidates, selected) {
				return nil, errors.New("provider publication requires an explicit surviving selected candidate")
			}
			revisionNumber := group.Revision
			if !sameIDs(group.NodeIDs, candidates) {
				revisionNumber++
			}
			local.Groups = append(local.Groups, gateway.PublicationGroup{ID: group.ID, Name: binding.Name, Revision: revisionNumber, CandidateIDs: candidates, SelectedNodeID: selected})
		}
		targets = append(targets, runtimeProviderTarget{id: id, connection: connection, before: before, revision: local})
	}
	return targets, nil
}

func (b *gatewayRuntimeBridge) publishProvider(ctx context.Context, provider domain.Provider, revision providers.Revision) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	stored, err := b.server.Services.Providers.Get(provider.ID, revision.Number)
	if err != nil {
		return err
	}
	if stored.Hash != revision.Hash || stored.State != providers.RevisionStaged {
		return domain.ErrConflict
	}
	targets, err := b.providerTargets(ctx, provider.ID, stored)
	if err != nil {
		return err
	}
	inventory, err := b.prospectiveInventory(ctx, stored)
	if err != nil {
		return err
	}
	fences := map[string]int64{}
	affected := map[string]bool{}
	for _, target := range targets {
		for _, group := range target.revision.Groups {
			affected[group.ID] = true
			current, err := b.server.Services.Outbounds.Get(group.ID)
			if err != nil {
				return err
			}
			fences[group.ID] = current.Revision
		}
	}
	impacts, err := b.server.Services.Outbounds.PreviewInventory(inventory)
	if err != nil {
		return err
	}
	for _, impact := range impacts {
		if affected[impact.GroupID] && (impact.RequiresBlock || impact.RemovalPrevented) {
			return errors.New("candidate publication requires isolated nonempty affected groups and surviving selections")
		}
	}
	for _, target := range targets {
		_, correlated := gateway.MutationIdentityFromContext(ctx)
		if verifyPublished(target.before, target.revision) == nil && !correlated {
			continue
		}
		stage, err := target.connection.client.StageProvider(ctx, target.revision, target.before.Generation)
		if err != nil {
			return err
		}
		_, publishErr := target.connection.client.PublishProvider(ctx, stage)
		observed, readErr := target.connection.client.Readback(ctx)
		if readErr != nil || verifyPublished(observed, target.revision) != nil {
			if publishErr != nil {
				return publishErr
			}
			return gateway.ErrOutcomeUnknown
		}
	}
	if _, err := b.server.Services.Outbounds.ReconcileGroups(inventory, fences); err != nil {
		return gateway.ErrOutcomeUnknown
	}
	for _, target := range targets {
		observed, err := target.connection.client.Readback(ctx)
		if err != nil || verifyPublished(observed, target.revision) != nil {
			return gateway.ErrOutcomeUnknown
		}
		for _, group := range target.revision.Groups {
			if _, err := b.server.Services.Outbounds.ObserveConfiguration(group.ID, group.Revision, group.CandidateIDs, observed.Generation); err != nil {
				return gateway.ErrOutcomeUnknown
			}
		}
	}
	return nil
}

func verifyPublished(snapshot gateway.Snapshot, want gateway.ProviderRevision) error {
	actual, ok := snapshot.Providers[want.ProviderID]
	if !ok || actual.Revision != want.Revision || actual.ContentHash != want.ContentHash {
		return gateway.ErrOutcomeUnknown
	}
	ids := map[string]bool{}
	for _, node := range actual.Nodes {
		ids[node.ID] = true
	}
	if len(ids) != len(want.Nodes) {
		return gateway.ErrOutcomeUnknown
	}
	for _, node := range want.Nodes {
		if !ids[node.ID] {
			return gateway.ErrOutcomeUnknown
		}
	}
	for _, group := range want.Groups {
		actual, ok := snapshot.Groups[group.ID]
		if !ok || actual.Name != group.Name || actual.Revision != group.Revision || !sameIDs(actual.NodeIDs, group.CandidateIDs) {
			return gateway.ErrOutcomeUnknown
		}
		matched := false
		for _, selection := range snapshot.Selections {
			if selection.Scope.GroupID == group.ID && selection.DesiredNodeID == group.SelectedNodeID && selection.ObservedNodeID == group.SelectedNodeID {
				matched = true
			}
		}
		if !matched {
			return gateway.ErrOutcomeUnknown
		}
	}
	return nil
}

func (b *gatewayRuntimeBridge) providerReadback(ctx context.Context, provider domain.Provider) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	status := b.server.Services.Providers.Status(provider.ID)
	number := status.Staged
	if number == 0 {
		number = status.Active
	}
	if number == 0 {
		return 0, gateway.ErrOutcomeUnknown
	}
	revision, err := b.server.Services.Providers.Get(provider.ID, number)
	if err != nil {
		return 0, err
	}
	targets, err := b.providerTargets(ctx, provider.ID, revision)
	if err != nil {
		return 0, err
	}
	for _, target := range targets {
		if err := verifyPublished(target.before, target.revision); err != nil {
			return 0, err
		}
	}
	return number, nil
}

func (b *gatewayRuntimeBridge) applySelection(ctx context.Context, group outbounds.Group, desired outbounds.Selection) (outbounds.Selection, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if group.GatewayID != desired.Scope.GatewayID || group.ID != desired.GroupID || group.Mode != outbounds.SelectionManual || !containsID(group.NodeIDs, desired.DesiredNodeID) {
		return outbounds.Selection{}, gateway.RejectBeforeMutation("invalid_selection", "selection is not a member of the configured group", outbounds.ErrNodeNotMember)
	}
	connection, before, err := b.connection(ctx, group.GatewayID, gateway.CapabilitySelectionRuntime)
	if err != nil {
		return outbounds.Selection{}, gateway.RejectBeforeMutation("selection_preflight_failed", err.Error(), err)
	}
	binding, ok := connection.runtime.Groups[group.ID]
	if !ok {
		return outbounds.Selection{}, gateway.RejectBeforeMutation("unsupported_group", "group has no native runtime binding", gateway.ErrUnsupported)
	}
	remoteGroup, ok := before.Groups[group.ID]
	if !ok || remoteGroup.Name != binding.Name || remoteGroup.Revision != group.Revision || !sameIDs(remoteGroup.NodeIDs, group.NodeIDs) {
		return outbounds.Selection{}, gateway.RejectBeforeMutation("group_configuration_not_applied", "apply the desired group configuration before selecting a node", domain.ErrConflict)
	}
	old, exists := remoteSelection(before, group.GatewayID, group.ID)
	expected := int64(0)
	if exists {
		expected = old.Revision
	}
	_, correlated := gateway.MutationIdentityFromContext(ctx)
	if correlated || !exists || old.DesiredNodeID != desired.DesiredNodeID || old.ObservedNodeID != desired.DesiredNodeID {
		_, applyErr := connection.client.PersistSelection(ctx, gateway.SelectionScope{GatewayID: group.GatewayID, GroupID: group.ID, Transport: "both"}, desired.DesiredNodeID, expected)
		after, readErr := connection.client.Readback(ctx)
		if readErr != nil {
			return outbounds.Selection{}, gateway.ErrOutcomeUnknown
		}
		observed, found := remoteSelection(after, group.GatewayID, group.ID)
		if !found || observed.DesiredNodeID != desired.DesiredNodeID || observed.ObservedNodeID != desired.DesiredNodeID {
			if applyErr != nil {
				return outbounds.Selection{}, applyErr
			}
			return outbounds.Selection{}, gateway.ErrOutcomeUnknown
		}
		before = after
	}
	if _, err := b.server.Services.Outbounds.MarkApplied(group.ID, desired.Scope, desired.DesiredNodeID, before.Generation); err != nil {
		return outbounds.Selection{}, err
	}
	return b.server.Services.Outbounds.Observe(group.ID, desired.Scope, desired.DesiredNodeID, before.Generation)
}

func remoteSelection(snapshot gateway.Snapshot, gatewayID, groupID string) (gateway.Selection, bool) {
	for _, selection := range snapshot.Selections {
		if selection.Scope.GroupID == groupID && (selection.Scope.GatewayID == gatewayID || selection.Scope.GatewayID == "") && (selection.Scope.Transport == "both" || selection.Scope.Transport == "") {
			return selection, true
		}
	}
	return gateway.Selection{}, false
}
func containsID(ids []string, id string) bool {
	for _, candidate := range ids {
		if candidate == id {
			return true
		}
	}
	return false
}
func sameIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left, right := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
