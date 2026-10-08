package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
)

func privateRequestHash(value any) string {
	data, _ := json.Marshal(value)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
func publicOperation(value deployment.Operation) deployment.Operation {
	value = value.Clone()
	value.RequestHash = ""
	for _, view := range []*deployment.StateRecord{value.Views.Desired, value.Views.Applied, value.Views.Observed, value.Views.Verified} {
		if view != nil {
			view.Hash = ""
			view.Data = nil
		}
	}
	return value
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
		if operation.Target == target && (operation.Status == deployment.StatusOutcomeUnknown || operation.Status == deployment.StatusApplying || operation.Status == deployment.StatusVerifying) {
			return errors.New("an earlier operation requires gateway readback before another mutation")
		}
	}
	return nil
}
