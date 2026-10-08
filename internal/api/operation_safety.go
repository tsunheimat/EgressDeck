package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

func privateRequestHash(value any) string {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
func publicOperation(value deployment.Operation) deployment.Operation {
	value = value.Clone()
	value.RequestHash = ""
	for _, view := range []*deployment.StateRecord{value.Views.Previous, value.Views.Desired, value.Views.Applied, value.Views.Observed, value.Views.Verified} {
		if view != nil {
			view.Hash = ""
			view.Data = nil
		}
	}
	return value
}

// OperationMutationIdentity binds remote recovery to the exact durable
// controller intent. It deliberately excludes mutable status and timestamps.
func OperationMutationIdentity(op deployment.Operation) gateway.MutationIdentity {
	if op.Views.Desired == nil || op.RequestHash != privateRequestHash(json.RawMessage(op.Views.Desired.Data)) {
		return gateway.MutationIdentity{}
	}
	return gateway.MutationIdentity{ID: op.ID, RequestHash: op.RequestHash, TargetKind: op.Target.Kind, TargetID: op.Target.ID, FenceToken: op.FenceToken}
}

func operationMutationContext(ctx context.Context, op deployment.Operation) context.Context {
	return gateway.WithMutationIdentity(ctx, OperationMutationIdentity(op))
}
func publicOperations(values []deployment.Operation) []deployment.Operation {
	out := make([]deployment.Operation, len(values))
	for i, value := range values {
		out[i] = publicOperation(value)
	}
	return out
}

func (s *Services) rejectUnknownTarget(ctx context.Context, target deployment.Target) error {
	operations, err := s.Journal.List(ctx)
	if err != nil {
		return errors.New("operation journal is unavailable")
	}
	for _, operation := range operations {
		if (operation.Status == deployment.StatusOutcomeUnknown || operation.Status == deployment.StatusApplying || operation.Status == deployment.StatusVerifying) && s.runtimeTargetsOverlap(operation.Target, target) {
			return errors.New("an earlier operation requires gateway readback before another mutation")
		}
	}
	return nil
}
