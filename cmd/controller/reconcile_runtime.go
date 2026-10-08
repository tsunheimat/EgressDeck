package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
)

// runtimeReadbackExecutor cannot submit an ordinary runtime mutation. It
// resolves only intent already durably accepted by the lifecycle API; the
// native resolver owns safe completion or cancellation of that exact intent.
type runtimeReadbackExecutor struct{ bridge *gatewayRuntimeBridge }

func (*runtimeReadbackExecutor) Validate(context.Context, deployment.Operation) error {
	return gateway.ErrUnsupported
}
func (*runtimeReadbackExecutor) Stage(context.Context, deployment.Operation, deployment.Fence) error {
	return gateway.ErrUnsupported
}
func (*runtimeReadbackExecutor) Apply(context.Context, deployment.Operation, deployment.Fence) (deployment.ApplyResult, error) {
	return deployment.ApplyResult{}, gateway.ErrUnsupported
}
func (*runtimeReadbackExecutor) Verify(context.Context, deployment.Operation, deployment.Fence) (deployment.VerifyResult, error) {
	return deployment.VerifyResult{}, gateway.ErrUnsupported
}
func (*runtimeReadbackExecutor) Rollback(context.Context, deployment.Operation, deployment.Fence) error {
	return gateway.ErrUnsupported
}

func (e *runtimeReadbackExecutor) Readback(ctx context.Context, op deployment.Operation, f deployment.Fence) (deployment.VerifyResult, error) {
	if f.Token == 0 || f.Token != op.FenceToken || f.Target != op.Target {
		return deployment.VerifyResult{}, deployment.ErrFenceLost
	}
	current, err := e.bridge.server.Services.Journal.FenceCurrent(ctx, f.Target, f.Token)
	if err != nil {
		return deployment.VerifyResult{}, err
	}
	if !current {
		return deployment.VerifyResult{}, deployment.ErrFenceLost
	}
	if op.Views.Desired == nil {
		return deployment.VerifyResult{}, errors.New("operation lacks immutable recovery intent")
	}
	if op.RequestHash != "" {
		resolved, terminal, err := e.resolveMutation(ctx, op)
		if err != nil || terminal {
			return resolved, err
		}
	}
	switch {
	case op.Target.Kind == "provider" && op.Action == "publish":
		return e.provider(ctx, op)
	case op.Target.Kind == "outbound_group" && op.Action == "selection":
		return e.selection(ctx, op)
	case op.Target.Kind == "outbound_group" && op.Action == "group_apply":
		return e.group(ctx, op)
	default:
		return deployment.VerifyResult{}, gateway.ErrUnsupported
	}
}

type providerRecoveryIntent struct {
	ProviderID             string   `json:"provider_id"`
	Revision               int64    `json:"revision"`
	ContentHash            string   `json:"content_hash"`
	ExpectedActiveRevision int64    `json:"expected_active_revision"`
	GatewayIDs             []string `json:"gateway_ids"`
}

func (e *runtimeReadbackExecutor) provider(ctx context.Context, op deployment.Operation) (deployment.VerifyResult, error) {
	var want providerRecoveryIntent
	if json.Unmarshal(op.Views.Desired.Data, &want) != nil || want.ProviderID != op.Target.ID || want.Revision <= 0 || want.ContentHash == "" || len(want.GatewayIDs) == 0 || op.Views.Desired.Revision != strconv.FormatInt(want.Revision, 10) {
		return deployment.VerifyResult{}, errors.New("provider operation has incomplete immutable recovery intent")
	}
	stored, err := e.bridge.server.Services.Providers.Get(want.ProviderID, want.Revision)
	if err != nil {
		return deployment.VerifyResult{}, err
	}
	if stored.Hash != want.ContentHash {
		return deployment.VerifyResult{}, errors.New("stored provider revision differs from operation intent")
	}
	targets, err := e.bridge.providerTargets(ctx, want.ProviderID, stored)
	if err != nil {
		return deployment.VerifyResult{}, err
	}
	actualIDs := make([]string, 0, len(targets))
	for _, target := range targets {
		actualIDs = append(actualIDs, target.id)
	}
	if !sameIDs(actualIDs, want.GatewayIDs) {
		return deployment.VerifyResult{}, errors.New("provider gateway bindings changed since requested publication")
	}
	for _, target := range targets {
		if err := verifyPublished(target.before, target.revision); err != nil {
			return deployment.VerifyResult{}, err
		}
	}
	groupStates := make([]api.GroupApplyReadback, 0)
	for _, target := range targets {
		for _, group := range target.revision.Groups {
			groupStates = append(groupStates, api.GroupApplyReadback{GroupID: group.ID, Revision: group.Revision, NodeIDs: group.CandidateIDs, Generation: target.before.Generation})
		}
	}
	encoded, _ := json.Marshal(struct {
		providerRecoveryIntent
		Groups []api.GroupApplyReadback `json:"groups,omitempty"`
	}{want, groupStates})
	return deployment.VerifyResult{VerifiedOK: true, Observed: &deployment.StateRecord{Revision: strconv.FormatInt(want.Revision, 10), Hash: want.ContentHash, Status: "configuration_observed", Data: encoded, At: time.Now().UTC()}}, nil
}

type selectionRecoveryIntent struct {
	NodeID            string           `json:"node_id"`
	GatewayID         string           `json:"gateway_id"`
	Transport         string           `json:"transport,omitempty"`
	TransportScopes   []string         `json:"transport_scopes"`
	ExpectedRevision  int64            `json:"expected_revision"`
	ExpectedRevisions map[string]int64 `json:"expected_revisions,omitempty"`
}

func (e *runtimeReadbackExecutor) selection(ctx context.Context, op deployment.Operation) (deployment.VerifyResult, error) {
	var want selectionRecoveryIntent
	if json.Unmarshal(op.Views.Desired.Data, &want) != nil || want.NodeID == "" || want.GatewayID == "" || len(want.TransportScopes) == 0 || want.ExpectedRevision < 0 {
		return deployment.VerifyResult{}, errors.New("selection operation has incomplete immutable recovery intent")
	}
	group, err := e.bridge.server.Services.Outbounds.Get(op.Target.ID)
	if err != nil {
		return deployment.VerifyResult{}, err
	}
	if group.GatewayID != want.GatewayID || !containsID(group.NodeIDs, want.NodeID) {
		return deployment.VerifyResult{}, errors.New("selection group changed since accepted intent")
	}
	connection, snapshot, err := e.bridge.connection(ctx, want.GatewayID, gateway.CapabilitySelectionRuntime)
	if err != nil {
		return deployment.VerifyResult{}, err
	}
	binding, ok := connection.runtime.Groups[group.ID]
	if !ok {
		return deployment.VerifyResult{}, gateway.ErrUnsupported
	}
	remoteGroup, ok := snapshot.Groups[group.ID]
	if !ok || remoteGroup.Name != binding.Name || !sameIDs(remoteGroup.NodeIDs, group.NodeIDs) {
		return deployment.VerifyResult{}, errors.New("remote selection group differs from owned group")
	}
	remote, found := remoteSelection(snapshot, want.GatewayID, group.ID)
	if !found || remote.DesiredNodeID != want.NodeID || remote.ObservedNodeID != want.NodeID {
		return deployment.VerifyResult{}, gateway.ErrOutcomeUnknown
	}
	selections := make([]outbounds.Selection, 0, len(want.TransportScopes))
	for _, transport := range want.TransportScopes {
		if transport != "tcp" && transport != "udp" && transport != "both" {
			return deployment.VerifyResult{}, errors.New("unsupported durable selection transport")
		}
		selected, err := e.bridge.server.Services.Outbounds.GetSelection(group.ID, outbounds.Scope{GatewayID: want.GatewayID, Transport: transport})
		if err != nil {
			return deployment.VerifyResult{}, err
		}
		expected := want.ExpectedRevision
		if want.ExpectedRevisions != nil {
			var present bool
			expected, present = want.ExpectedRevisions[transport]
			if !present || len(want.ExpectedRevisions) != len(want.TransportScopes) {
				return deployment.VerifyResult{}, errors.New("selection revision scopes differ from durable intent")
			}
		}
		if selected.DesiredNodeID != want.NodeID || selected.Revision != expected+1 {
			return deployment.VerifyResult{}, errors.New("local selection intent changed since accepted request")
		}
		selected.ObservedNodeID = want.NodeID
		selected.Generation = snapshot.Generation
		selections = append(selections, selected)
	}
	data, _ := json.Marshal(selections)
	return deployment.VerifyResult{VerifiedOK: true, Observed: &deployment.StateRecord{Generation: uint64(snapshot.Generation), Status: "configuration_observed", Data: data, At: time.Now().UTC()}}, nil
}

func (e *runtimeReadbackExecutor) group(ctx context.Context, op deployment.Operation) (deployment.VerifyResult, error) {
	var want api.GroupApplyIntent
	if json.Unmarshal(op.Views.Desired.Data, &want) != nil || want.Group.ID != op.Target.ID || want.Group.Revision <= 0 || want.Group.GatewayID == "" {
		return deployment.VerifyResult{}, errors.New("group operation has incomplete immutable recovery intent")
	}
	current, err := e.bridge.server.Services.Outbounds.Get(want.Group.ID)
	if err != nil || current.Revision != want.Group.Revision || current.GatewayID != want.Group.GatewayID || !sameIDs(current.NodeIDs, want.Group.NodeIDs) {
		return deployment.VerifyResult{}, errors.New("group changed since accepted configuration")
	}
	if e.bridge.server.Services.GroupReadback == nil {
		return deployment.VerifyResult{}, gateway.ErrUnsupported
	}
	snapshot, err := e.bridge.server.Services.GroupReadback(ctx, want.Group)
	if err != nil {
		return deployment.VerifyResult{}, err
	}
	remote, ok := snapshot.Groups[want.Group.ID]
	if !ok || remote.Revision != want.Group.Revision || !sameIDs(remote.NodeIDs, want.Group.NodeIDs) {
		return deployment.VerifyResult{}, gateway.ErrOutcomeUnknown
	}
	data, _ := json.Marshal(api.GroupApplyReadback{GroupID: want.Group.ID, Revision: remote.Revision, NodeIDs: remote.NodeIDs, Generation: snapshot.Generation})
	return deployment.VerifyResult{VerifiedOK: true, Observed: &deployment.StateRecord{Revision: strconv.FormatInt(remote.Revision, 10), Generation: uint64(snapshot.Generation), Status: "configuration_observed", Data: data, At: time.Now().UTC()}}, nil
}

// resolveMutation asks the authenticated target to resolve the exact durable
// request. Resolving an absent request installs a rejection tombstone before
// returning, so a delayed original request cannot execute after compensation.
// It never resends provider, group, or selection mutation payloads.
func (e *runtimeReadbackExecutor) resolveMutation(ctx context.Context, op deployment.Operation) (deployment.VerifyResult, bool, error) {
	identity := api.OperationMutationIdentity(op)
	if !identity.Valid() {
		return deployment.VerifyResult{}, false, errors.New("operation mutation identity is invalid")
	}
	var ids []string
	switch op.Action {
	case "publish":
		var want providerRecoveryIntent
		if op.Target.Kind != "provider" || json.Unmarshal(op.Views.Desired.Data, &want) != nil || want.ProviderID != op.Target.ID {
			return deployment.VerifyResult{}, false, errors.New("invalid provider recovery identity")
		}
		ids = want.GatewayIDs
	case "selection":
		var want selectionRecoveryIntent
		if op.Target.Kind != "outbound_group" || json.Unmarshal(op.Views.Desired.Data, &want) != nil {
			return deployment.VerifyResult{}, false, errors.New("invalid selection recovery identity")
		}
		ids = []string{want.GatewayID}
	case "group_apply":
		var want api.GroupApplyIntent
		if op.Target.Kind != "outbound_group" || json.Unmarshal(op.Views.Desired.Data, &want) != nil || want.Group.ID != op.Target.ID {
			return deployment.VerifyResult{}, false, errors.New("invalid group recovery identity")
		}
		ids = []string{want.Group.GatewayID}
	default:
		return deployment.VerifyResult{}, false, gateway.ErrUnsupported
	}
	if len(ids) == 0 {
		return deployment.VerifyResult{}, false, errors.New("operation lacks immutable gateway targets")
	}
	proof := api.OperationRejectionReadback{Receipts: map[string]gateway.MutationReceipt{}}
	committed, rejected := 0, 0
	for _, id := range ids {
		if id == "" {
			return deployment.VerifyResult{}, false, errors.New("operation has empty gateway target")
		}
		if _, duplicate := proof.Receipts[id]; duplicate {
			return deployment.VerifyResult{}, false, errors.New("operation has duplicate gateway target")
		}
		connection, ok := e.bridge.connections[id]
		if !ok {
			return deployment.VerifyResult{}, false, gateway.ErrUnsupported
		}
		registered, err := e.bridge.server.Store.GetGateway(ctx, id)
		if err != nil {
			return deployment.VerifyResult{}, false, err
		}
		if strings.TrimRight(registered.Endpoint, "/") != connection.endpoint {
			return deployment.VerifyResult{}, false, errors.New("gateway endpoint differs from immutable operator binding")
		}
		receipt, err := connection.client.ResolveMutation(ctx, identity)
		if err != nil {
			return deployment.VerifyResult{}, false, err
		}
		if err := receipt.ValidateFor(identity); err != nil {
			return deployment.VerifyResult{}, false, err
		}
		proof.Receipts[id] = receipt
		switch receipt.State {
		case gateway.MutationCommitted:
			committed++
		case gateway.MutationRejected:
			rejected++
		default:
			return deployment.VerifyResult{}, false, gateway.ErrOutcomeUnknown
		}
	}
	if rejected == len(ids) {
		data, _ := json.Marshal(proof)
		return deployment.VerifyResult{NotApplied: true, Observed: &deployment.StateRecord{Status: "rejected_before_commit", Data: data, At: time.Now().UTC()}}, true, nil
	}
	if committed != len(ids) {
		return deployment.VerifyResult{}, false, gateway.ErrOutcomeUnknown
	}
	return deployment.VerifyResult{}, false, nil
}
