package api

import (
	"encoding/json"
	"errors"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
)

// OperationRejectionReadback is private operation evidence. Every target must
// reject the exact fenced identity before a multi-gateway operation can fail.
type OperationRejectionReadback struct {
	Receipts map[string]gateway.MutationReceipt `json:"receipts"`
}

func selectionExpectedRevision(desired selectionRequest, transport string) int64 {
	if desired.ExpectedRevisions != nil {
		return desired.ExpectedRevisions[transport]
	}
	return desired.ExpectedRevision
}

func (s *Services) completeRejectedOperation(op deployment.Operation, result deployment.VerifyResult) error {
	identity := OperationMutationIdentity(op)
	if !identity.Valid() || op.Views.Desired == nil || op.RequestHash != privateRequestHash(json.RawMessage(op.Views.Desired.Data)) {
		return errors.New("rejection does not identify an immutable operation")
	}
	var proof OperationRejectionReadback
	if json.Unmarshal(result.Observed.Data, &proof) != nil || len(proof.Receipts) == 0 {
		return errors.New("authoritative rejection receipts are required")
	}
	var gatewayIDs []string
	switch op.Action {
	case "publish":
		var desired struct {
			ProviderID     string   `json:"provider_id"`
			Revision       int64    `json:"revision"`
			ExpectedActive int64    `json:"expected_active_revision"`
			GatewayIDs     []string `json:"gateway_ids"`
		}
		if op.Target.Kind != "provider" || json.Unmarshal(op.Views.Desired.Data, &desired) != nil || desired.ProviderID != op.Target.ID || desired.Revision <= 0 || s.Providers.Status(desired.ProviderID).Active != desired.ExpectedActive {
			return errors.New("provider state differs from rejected intent")
		}
		gatewayIDs = desired.GatewayIDs
	case "selection":
		var desired selectionRequest
		if op.Target.Kind != "outbound_group" || json.Unmarshal(op.Views.Desired.Data, &desired) != nil || desired.GatewayID == "" || len(desired.TransportScopes) == 0 {
			return errors.New("invalid rejected selection intent")
		}
		gatewayIDs = []string{desired.GatewayID}
	case "group_apply":
		var desired GroupApplyIntent
		if op.Target.Kind != "outbound_group" || json.Unmarshal(op.Views.Desired.Data, &desired) != nil || desired.Group.ID != op.Target.ID || desired.Group.GatewayID == "" {
			return errors.New("invalid rejected group intent")
		}
		current, err := s.Outbounds.Get(op.Target.ID)
		if err != nil || current.Revision != desired.Group.Revision || current.GatewayID != desired.Group.GatewayID || !sameStringSet(current.NodeIDs, desired.Group.NodeIDs) {
			return errors.New("group changed after rejected intent")
		}
		gatewayIDs = []string{desired.Group.GatewayID}
	default:
		return errors.New("operation does not support rejection completion")
	}
	if len(gatewayIDs) == 0 || len(gatewayIDs) != len(proof.Receipts) {
		return errors.New("rejection does not cover every gateway")
	}
	seen := map[string]bool{}
	for _, id := range gatewayIDs {
		receipt, ok := proof.Receipts[id]
		if id == "" || seen[id] || !ok || receipt.State != gateway.MutationRejected || receipt.ValidateFor(identity) != nil {
			return errors.New("rejection receipt differs from operation identity")
		}
		seen[id] = true
	}
	if op.Action == "selection" {
		return s.restoreRejectedSelection(op)
	}
	return nil
}

func (s *Services) restoreRejectedSelection(op deployment.Operation) error {
	var desired selectionRequest
	var previous map[string]*outbounds.Selection
	if op.Views.Previous == nil || json.Unmarshal(op.Views.Desired.Data, &desired) != nil || json.Unmarshal(op.Views.Previous.Data, &previous) != nil || len(previous) != len(desired.TransportScopes) {
		return errors.New("rejected selection lacks durable prior state")
	}
	toRestore := make([]outbounds.Scope, 0, len(desired.TransportScopes))
	seen := map[string]bool{}
	for _, transport := range desired.TransportScopes {
		prior, present := previous[transport]
		expected := selectionExpectedRevision(desired, transport)
		if !present || seen[transport] || (transport != "tcp" && transport != "udp") || expected < 0 || (desired.ExpectedRevisions != nil && len(desired.ExpectedRevisions) != len(desired.TransportScopes)) {
			return errors.New("invalid durable selection scopes")
		}
		seen[transport] = true
		scope := outbounds.Scope{GatewayID: desired.GatewayID, Transport: transport}
		priorNode := ""
		if prior != nil {
			if prior.GroupID != op.Target.ID || prior.Scope != scope || prior.Revision != expected {
				return errors.New("durable prior selection differs from CAS")
			}
			priorNode = prior.DesiredNodeID
		} else if expected != 0 {
			return errors.New("durable prior selection is missing")
		}
		current, err := s.Outbounds.GetSelection(op.Target.ID, scope)
		if errors.Is(err, domain.ErrNotFound) && prior == nil {
			continue // The controller stopped before persisting desired intent.
		}
		if err != nil {
			return err
		}
		// Compensation can be durably saved before the operation journal's final
		// write. A restart must accept that exact compensation without another CAS.
		if (current.Revision == expected || current.Revision == expected+2) && current.DesiredNodeID == priorNode {
			continue
		}
		if current.Revision != expected+1 || current.DesiredNodeID != desired.NodeID {
			return errors.New("selection changed after rejected request")
		}
		toRestore = append(toRestore, scope)
	}
	before, err := s.Outbounds.ExportState()
	if err != nil {
		return err
	}
	for _, scope := range toRestore {
		if err := s.Outbounds.RestoreDesired(op.Target.ID, scope, previous[scope.Transport]); err != nil {
			_ = s.Outbounds.ImportState(before)
			return err
		}
	}
	return nil
}
