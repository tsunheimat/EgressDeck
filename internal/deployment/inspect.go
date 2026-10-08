package deployment

import (
	"context"
	"errors"
	"fmt"
)

// InspectOutcome is the read-only startup/periodic recovery path. It never
// calls Validate, Stage, Apply, Verify, or Rollback, and it never issues a new
// fence. Work not yet submitted to the remote target remains pending for an
// explicit operator action. Use the same Runner instance as API mutation calls
// so its target lock excludes an in-process apply during observation.
func (r *Runner) InspectOutcome(ctx context.Context, id string, reader ReadbackExecutor) (Operation, error) {
	if err := r.check(); err != nil {
		return Operation{}, err
	}
	if reader == nil {
		return Operation{}, fmt.Errorf("%w: readback executor is nil", ErrInvalidRequest)
	}
	op, err := r.Journal.Get(ctx, id)
	if err != nil {
		return Operation{}, err
	}
	if !needsReadback(op.Status) {
		return op, nil
	}
	if r.Locks == nil {
		return op, fmt.Errorf("%w: runner target locks are not initialized", ErrInvalidRequest)
	}
	unlock := r.Locks.lock(op.Target)
	defer unlock()
	op, err = r.Journal.Get(ctx, id)
	if err != nil {
		return Operation{}, err
	}
	if !needsReadback(op.Status) {
		return op, nil
	}
	f := Fence{Target: op.Target, Token: op.FenceToken}
	if err = r.ensureFence(ctx, op, f); err != nil {
		return op, err
	}
	result, readErr := reader.Readback(ctx, op, f)
	// Recheck after network I/O. A fencing change cannot be turned into a
	// successful observation even when the stale response matches old intent.
	if err = r.ensureFence(ctx, op, f); err != nil {
		return op, err
	}
	latest, getErr := r.Journal.Get(ctx, id)
	if getErr != nil {
		return op, getErr
	}
	if latest.Status != op.Status || latest.FenceToken != op.FenceToken || !latest.UpdatedAt.Equal(op.UpdatedAt) {
		return latest, ErrConflict
	}
	if result.Observed != nil {
		value := result.Observed.Clone()
		if value.At.IsZero() {
			value.At = r.now()
		}
		op.Views.Observed = &value
	}
	if readErr == nil && result.Observed == nil {
		readErr = fmt.Errorf("%w: readback requires an observed state", ErrInvalidRequest)
	}
	if readErr != nil {
		op.Status = StatusOutcomeUnknown
		op.Error = "remote outcome could not be confirmed by readback"
		if op.OriginalError == "" {
			op.OriginalError = op.Error
		}
		op.UpdatedAt = r.now()
		if saveErr := r.save(ctx, op); saveErr != nil {
			return op, errors.Join(readErr, saveErr)
		}
		return op, readErr
	}
	if result.VerifiedOK {
		applied := result.Observed.Clone()
		op.Views.Applied = &applied
		// Config readback is not an enrolled-client packet-path measurement.
		// A verifier must explicitly supply that separate evidence.
		if result.Verified != nil {
			verified := result.Verified.Clone()
			op.Views.Verified = &verified
		}
		op.Error = ""
		return r.finish(ctx, op, StatusApplied)
	}
	op.Error = "remote readback does not confirm all requested components"
	return r.finish(ctx, op, StatusPartiallyApplied)
}

func needsReadback(status Status) bool {
	return status == StatusApplying || status == StatusVerifying || status == StatusOutcomeUnknown
}
