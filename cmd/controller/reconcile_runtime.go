package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
)

// runtimeReadbackExecutor is deliberately incapable of remote mutation. It
// resolves only intent already durably accepted by the provider/selection API.
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
	switch {
	case op.Target.Kind == "provider" && op.Action == "publish":
		return e.provider(ctx, op)
	case op.Target.Kind == "outbound_group" && op.Action == "selection":
		return e.selection(ctx, op)
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
	encoded, _ := json.Marshal(want)
	return deployment.VerifyResult{VerifiedOK: true, Observed: &deployment.StateRecord{Revision: strconv.FormatInt(want.Revision, 10), Hash: want.ContentHash, Status: "configuration_observed", Data: encoded, At: time.Now().UTC()}}, nil
}

type selectionRecoveryIntent struct {
	NodeID           string   `json:"node_id"`
	GatewayID        string   `json:"gateway_id"`
	Transport        string   `json:"transport,omitempty"`
	TransportScopes  []string `json:"transport_scopes"`
	ExpectedRevision int64    `json:"expected_revision"`
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
		if selected.DesiredNodeID != want.NodeID || selected.Revision != want.ExpectedRevision+1 {
			return deployment.VerifyResult{}, errors.New("local selection intent changed since accepted request")
		}
		selected.ObservedNodeID = want.NodeID
		selected.Generation = snapshot.Generation
		selections = append(selections, selected)
	}
	data, _ := json.Marshal(selections)
	return deployment.VerifyResult{VerifiedOK: true, Observed: &deployment.StateRecord{Generation: uint64(snapshot.Generation), Status: "configuration_observed", Data: data, At: time.Now().UTC()}}, nil
}
