package api

import (
	"context"
	"errors"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
)

type lifecycleReadback struct {
	services *Services
	reader   deployment.ReadbackExecutor
}

// OperationReadback serializes recovery with typed lifecycle HTTP handlers.
// Their durable intents become visible before the remote send, so resolving
// without this same lock could cancel a request still executing normally.
func (s *Services) OperationReadback(reader deployment.ReadbackExecutor) deployment.ReadbackExecutor {
	return lifecycleReadback{services: s, reader: reader}
}

func (r lifecycleReadback) Readback(ctx context.Context, op deployment.Operation, f deployment.Fence) (deployment.VerifyResult, error) {
	r.services.mutationMu.Lock()
	defer r.services.mutationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return deployment.VerifyResult{}, err
	}
	if r.services.mutationBlocked {
		return deployment.VerifyResult{}, errors.New("management writes are paused")
	}
	latest, err := r.services.Journal.Get(ctx, op.ID)
	if err != nil {
		return deployment.VerifyResult{}, err
	}
	if latest.Status != op.Status || latest.FenceToken != op.FenceToken || latest.RequestHash != op.RequestHash || !latest.UpdatedAt.Equal(op.UpdatedAt) {
		return deployment.VerifyResult{}, deployment.ErrConflict
	}
	current, err := r.services.Journal.FenceCurrent(ctx, op.Target, op.FenceToken)
	if err != nil {
		return deployment.VerifyResult{}, err
	}
	if !current || f.Target != op.Target || f.Token != op.FenceToken {
		return deployment.VerifyResult{}, deployment.ErrFenceLost
	}
	result, err := r.reader.Readback(ctx, op, f)
	if err == nil && (result.VerifiedOK || result.NotApplied) {
		err = r.services.completeOperationReadback(ctx, op, result)
	}
	return result, err
}
