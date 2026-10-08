package api

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
)

// CompleteOperationReadback commits independently observed remote state before
// reconciliation marks an uncertain operation applied. It does not claim an
// enrolled-client traffic probe or retry a remote mutation.
func (s *Services) CompleteOperationReadback(ctx context.Context, operation deployment.Operation, result deployment.VerifyResult) error {
	if !result.VerifiedOK || result.Observed == nil || operation.Views.Desired == nil {
		return errors.New("confirmed operation readback is required")
	}
	if operation.FenceToken == 0 {
		return errors.New("operation has no recoverable fence")
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.mutationBlocked {
		return errors.New("management writes are paused")
	}
	current, err := s.Journal.FenceCurrent(ctx, operation.Target, operation.FenceToken)
	if err != nil || !current {
		return errors.New("operation fence is no longer current")
	}
	switch operation.Action {
	case "publish":
		if operation.Target.Kind != "provider" {
			return errors.New("provider operation target is invalid")
		}
		var desired struct {
			ProviderID     string   `json:"provider_id"`
			Revision       int64    `json:"revision"`
			ExpectedActive int64    `json:"expected_active_revision"`
			ContentHash    string   `json:"content_hash"`
			GatewayIDs     []string `json:"gateway_ids"`
		}
		var observed struct {
			ProviderID  string   `json:"provider_id"`
			Revision    int64    `json:"revision"`
			ContentHash string   `json:"content_hash"`
			GatewayIDs  []string `json:"gateway_ids"`
		}
		if json.Unmarshal(operation.Views.Desired.Data, &desired) != nil || json.Unmarshal(result.Observed.Data, &observed) != nil {
			return errors.New("invalid provider readback")
		}
		if desired.ProviderID != operation.Target.ID || observed.ProviderID != desired.ProviderID || observed.Revision != desired.Revision || observed.ContentHash != desired.ContentHash || !sameStringSet(desired.GatewayIDs, observed.GatewayIDs) {
			return errors.New("provider readback differs from journal intent")
		}
		revision, err := s.Providers.Get(desired.ProviderID, desired.Revision)
		if err != nil || revision.Hash != desired.ContentHash {
			return errors.New("staged provider identity does not match journal intent")
		}
		status := s.Providers.Status(desired.ProviderID)
		if status.Active != desired.Revision {
			if _, err := s.Providers.Publish(desired.ProviderID, desired.Revision, desired.ExpectedActive); err != nil {
				return err
			}
		}
	case "selection":
		if operation.Target.Kind != "outbound_group" {
			return errors.New("selection operation target is invalid")
		}
		var desired selectionRequest
		var observed []outbounds.Selection
		if json.Unmarshal(operation.Views.Desired.Data, &desired) != nil || json.Unmarshal(result.Observed.Data, &observed) != nil {
			return errors.New("invalid selection readback")
		}
		if len(desired.TransportScopes) == 0 || len(observed) != len(desired.TransportScopes) {
			return errors.New("incomplete selection readback")
		}
		byScope := map[string]outbounds.Selection{}
		for _, selection := range observed {
			if selection.GroupID != operation.Target.ID || selection.Scope.GatewayID != desired.GatewayID || selection.ObservedNodeID != desired.NodeID || selection.Generation < 0 {
				return errors.New("selection readback differs from journal intent")
			}
			if _, exists := byScope[selection.Scope.Transport]; exists {
				return errors.New("duplicate selection readback")
			}
			byScope[selection.Scope.Transport] = selection
		}
		for _, transport := range desired.TransportScopes {
			scope := outbounds.Scope{GatewayID: desired.GatewayID, Transport: transport}
			current, err := s.Outbounds.GetSelection(operation.Target.ID, scope)
			if err != nil || current.DesiredNodeID != desired.NodeID || current.Revision != desired.ExpectedRevision+1 {
				return errors.New("selection intent changed after operation")
			}
			if readback, ok := byScope[transport]; !ok {
				return errors.New("selection scope was not observed")
			} else if readback.Generation < current.AppliedGeneration || readback.Generation < current.ObservedGeneration {
				return errors.New("selection readback generation is stale")
			}
		}
		for _, transport := range desired.TransportScopes {
			observed := byScope[transport]
			if _, err := s.Outbounds.MarkApplied(operation.Target.ID, observed.Scope, desired.NodeID, observed.Generation); err != nil {
				return err
			}
			if _, err := s.Outbounds.Observe(operation.Target.ID, observed.Scope, desired.NodeID, observed.Generation); err != nil {
				return err
			}
		}
	default:
		return errors.New("operation does not support local readback completion")
	}
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.Persist(persistCtx); err != nil {
		s.mutationBlocked = true
		return err
	}
	return nil
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
