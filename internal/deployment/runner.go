package deployment

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Runner drives one durable operation to a terminal state. It is safe to call
// Resume after a controller restart; in-flight operations are read from the
// journal and all remote calls are preceded by a current-fence check.
//
// Runner serializes one primary target at a time. CrossSystemExecutor adds
// coordinated gateway, guard, and firewall fences plus durable component
// receipts for enrollment and bypass operations without holding a database
// transaction across remote calls.
type Runner struct {
	Journal Journal
	Locks   *TargetLocker
	Now     func() time.Time
}

// Manager is a compatibility name for callers that treat the runner as the
// deployment manager/orchestrator.
type Manager = Runner

func NewManager(j Journal) *Runner          { return NewRunner(j) }
func NewOperationManager(j Journal) *Runner { return NewRunner(j) }

func NewRunner(j Journal) *Runner {
	return &Runner{Journal: j, Locks: NewTargetLocker(), Now: func() time.Time { return time.Now().UTC() }}
}

func (r *Runner) now() time.Time {
	if r.Now == nil {
		return time.Now().UTC()
	}
	return r.Now()
}
func (r *Runner) check() error {
	if r.Journal == nil {
		return fmt.Errorf("%w: journal is nil", ErrInvalidRequest)
	}
	return nil
}

func (r *Runner) Get(ctx context.Context, id string) (Operation, error) {
	if err := r.check(); err != nil {
		return Operation{}, err
	}
	return r.Journal.Get(ctx, id)
}

func (r *Runner) List(ctx context.Context) ([]Operation, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	return r.Journal.List(ctx)
}

// Submit creates and executes an operation. Reusing an idempotency key returns
// its existing operation without re-running it, including after a restart.
func (r *Runner) Submit(ctx context.Context, req Request, ex Executor) (Operation, error) {
	if err := r.check(); err != nil {
		return Operation{}, err
	}
	if err := validateRequest(req); err != nil {
		return Operation{}, err
	}
	if ex == nil {
		return Operation{}, fmt.Errorf("%w: executor is nil", ErrInvalidRequest)
	}
	if r.Locks == nil {
		r.Locks = NewTargetLocker()
	}
	unlock := r.Locks.lock(req.Target)
	defer unlock()
	hash := requestHash(req)
	if old, err := r.Journal.FindByIdempotency(ctx, req.Target, req.IdempotencyKey); err == nil {
		if old.RequestHash != "" && old.RequestHash != hash {
			return Operation{}, fmt.Errorf("%w: idempotency key is already bound to another request", ErrConflict)
		}
		return old, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Operation{}, err
	}
	ops, err := r.Journal.List(ctx)
	if err != nil {
		return Operation{}, err
	}
	for _, pending := range ops {
		if pending.Target == req.Target && !terminal(pending.Status) {
			return Operation{}, fmt.Errorf("%w: operation %s requires recovery/readback", ErrAlreadyRunning, pending.ID)
		}
	}
	fence, err := r.Journal.NextFence(ctx, req.Target)
	if err != nil {
		return Operation{}, err
	}
	op := Operation{ID: req.ID, IdempotencyKey: req.IdempotencyKey, RequestHash: hash, Target: req.Target, Action: req.Action, RequestedGeneration: req.RequestedGeneration, FenceToken: fence.Token, Status: StatusDraft, Rollback: RollbackNone, CreatedAt: r.now(), UpdatedAt: r.now()}
	if req.Desired != nil {
		desired := req.Desired.Clone()
		if desired.At.IsZero() {
			desired.At = r.now()
		}
		op.Views.Desired = &desired
	}
	op, err = r.Journal.Create(ctx, op)
	if err != nil {
		return Operation{}, err
	}
	return r.runLocked(ctx, op, fence, ex)
}

// Resume continues an existing operation. If the operation already reached a
// terminal state it is returned untouched. Resuming an old operation after a
// newer fence was issued records outcome_unknown and never performs a stale
// mutation.
func (r *Runner) Resume(ctx context.Context, id string, ex Executor) (Operation, error) {
	if err := r.check(); err != nil {
		return Operation{}, err
	}
	op, err := r.Journal.Get(ctx, id)
	if err != nil {
		return Operation{}, err
	}
	if terminal(op.Status) {
		return op, nil
	}
	if op.Status == StatusOutcomeUnknown {
		if ex == nil {
			return op, nil
		}
		if reader, ok := ex.(ReadbackExecutor); ok {
			return r.ReconcileOutcome(ctx, id, reader)
		}
		return op, nil
	}
	if ex == nil {
		return op, fmt.Errorf("%w: executor is nil", ErrInvalidRequest)
	}
	ok, err := r.Journal.FenceCurrent(ctx, op.Target, op.FenceToken)
	if err != nil {
		return op, err
	}
	if !ok {
		return r.finishUnknown(ctx, op, ErrFenceLost)
	}
	return r.run(ctx, op, Fence{Target: op.Target, Token: op.FenceToken}, ex)
}

// Recover resumes all durable non-terminal operations. Operations with no
// supplied executor are left untouched; callers should provide adapters only
// for targets they can reach. A returned map-like slice allows the caller to
// expose each operation's actual state to the UI.
func (r *Runner) Recover(ctx context.Context, executors map[string]Executor) ([]Operation, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	ops, err := r.Journal.List(ctx)
	if err != nil {
		return nil, err
	}
	results := make([]Operation, 0, len(ops))
	for _, op := range ops {
		if terminal(op.Status) {
			continue
		}
		ex := executors[op.Target.Key()]
		if ex == nil {
			results = append(results, op)
			continue
		}
		out, runErr := r.Resume(ctx, op.ID, ex)
		if runErr != nil {
			return results, runErr
		}
		results = append(results, out)
	}
	return results, nil
}

func terminal(s Status) bool {
	return s == StatusApplied || s == StatusPartiallyApplied || s == StatusFailed
}

func (r *Runner) run(ctx context.Context, op Operation, fence Fence, ex Executor) (Operation, error) {
	if r.Locks == nil {
		r.Locks = NewTargetLocker()
	}
	unlock := r.Locks.lock(op.Target)
	defer unlock()
	// Re-read after acquiring the target lock. A concurrent Resume may have
	// completed this operation while this caller was waiting; using its stale
	// copy could otherwise invoke Apply twice.
	if latest, err := r.Journal.Get(ctx, op.ID); err == nil {
		op = latest
		fence = Fence{Target: op.Target, Token: op.FenceToken}
		if terminal(op.Status) {
			return op, nil
		}
	}
	return r.runLocked(ctx, op, fence, ex)
}

func (r *Runner) runLocked(ctx context.Context, op Operation, fence Fence, ex Executor) (Operation, error) {
	var err error
	if op.Status == StatusDraft {
		err = ex.Validate(ctx, op)
		if err != nil {
			return r.fail(ctx, op, err, false)
		}
		if err = r.transition(ctx, &op, StatusValidated); err != nil {
			return op, err
		}
	}
	if op.Status == StatusValidated {
		if err = r.ensureFence(ctx, op, fence); err != nil {
			return r.finishUnknown(ctx, op, err)
		}
		err = ex.Stage(ctx, op, fence)
		if err != nil {
			return r.fail(ctx, op, err, isUnknown(err))
		}
		if err = r.transition(ctx, &op, StatusStaged); err != nil {
			return op, err
		}
	}
	if op.Status == StatusStaged {
		if err = r.ensureFence(ctx, op, fence); err != nil {
			return r.finishUnknown(ctx, op, err)
		}
		if err = r.transition(ctx, &op, StatusApplying); err != nil {
			return op, err
		}
		result, applyErr := ex.Apply(ctx, op, fence)
		if result.Applied != nil {
			applied := result.Applied.Clone()
			if applied.At.IsZero() {
				applied.At = r.now()
			}
			op.Views.Applied = &applied
			if err = r.save(ctx, op); err != nil {
				return op, err
			}
		}
		if applyErr != nil {
			return r.fail(ctx, op, applyErr, isUnknown(applyErr))
		}
	}
	if op.Status == StatusApplying || op.Status == StatusVerifying {
		if op.Status == StatusApplying {
			if err = r.ensureFence(ctx, op, fence); err != nil {
				return r.finishUnknown(ctx, op, err)
			}
			if err = r.transition(ctx, &op, StatusVerifying); err != nil {
				return op, err
			}
		}
		if err = r.ensureFence(ctx, op, fence); err != nil {
			return r.finishUnknown(ctx, op, err)
		}
		result, verifyErr := ex.Verify(ctx, op, fence)
		if result.Observed != nil {
			observed := result.Observed.Clone()
			if observed.At.IsZero() {
				observed.At = r.now()
			}
			op.Views.Observed = &observed
		}
		if result.Verified != nil {
			verified := result.Verified.Clone()
			if verified.At.IsZero() {
				verified.At = r.now()
			}
			op.Views.Verified = &verified
		}
		if err = r.save(ctx, op); err != nil {
			return op, err
		}
		if verifyErr != nil {
			return r.fail(ctx, op, verifyErr, isUnknown(verifyErr))
		}
		if !result.VerifiedOK {
			op.Error = result.Message
			if op.Error == "" {
				op.Error = "readback does not match desired state"
			}
			return r.finish(ctx, op, StatusPartiallyApplied)
		}
		return r.finish(ctx, op, StatusApplied)
	}
	return op, nil
}

func (r *Runner) ensureFence(ctx context.Context, op Operation, fence Fence) error {
	ok, err := r.Journal.FenceCurrent(ctx, fence.Target, fence.Token)
	if err != nil {
		return err
	}
	if !ok {
		return ErrFenceLost
	}
	return nil
}

func (r *Runner) transition(ctx context.Context, op *Operation, next Status) error {
	now := r.now()
	op.Status = next
	op.UpdatedAt = now
	op.Steps = append(op.Steps, Step{Name: string(next), Status: StepSucceeded, EndedAt: &now})
	return r.Journal.Save(ctx, *op)
}

func (r *Runner) save(ctx context.Context, op Operation) error {
	ctx, cancel := recoveryContext(ctx)
	defer cancel()
	op.UpdatedAt = r.now()
	return r.Journal.Save(ctx, op)
}

func (r *Runner) fail(ctx context.Context, op Operation, err error, unknown bool) (Operation, error) {
	ctx, cancel := recoveryContext(ctx)
	defer cancel()
	if err == nil {
		return op, nil
	}
	op.Error = err.Error()
	if op.OriginalError == "" {
		op.OriginalError = err.Error()
	}
	if unknown {
		op.Status = StatusOutcomeUnknown
	} else {
		var partial *PartialError
		if errors.As(err, &partial) {
			op.Status = StatusPartiallyApplied
		} else {
			op.Status = StatusFailed
		}
	}
	now := r.now()
	op.Steps = append(op.Steps, Step{Name: string(op.Status), Status: stepStatusFor(op.Status), EndedAt: &now})
	op.UpdatedAt = now
	op.CompletedAt = &now
	if saveErr := r.Journal.Save(ctx, op); saveErr != nil {
		return op, errors.Join(err, saveErr)
	}
	return op, err
}

func (r *Runner) finish(ctx context.Context, op Operation, status Status) (Operation, error) {
	op.Status = status
	now := r.now()
	op.Steps = append(op.Steps, Step{Name: string(status), Status: stepStatusFor(status), EndedAt: &now})
	op.UpdatedAt = now
	op.CompletedAt = &now
	if err := r.Journal.Save(ctx, op); err != nil {
		return op, err
	}
	return op, nil
}

func stepStatusFor(status Status) StepStatus {
	switch status {
	case StatusApplied:
		return StepSucceeded
	case StatusPartiallyApplied, StatusFailed:
		return StepFailed
	case StatusOutcomeUnknown:
		return StepUnknown
	default:
		return StepSucceeded
	}
}

func (r *Runner) finishUnknown(ctx context.Context, op Operation, err error) (Operation, error) {
	op.Error = err.Error()
	if op.OriginalError == "" {
		op.OriginalError = err.Error()
	}
	return r.finish(ctx, op, StatusOutcomeUnknown)
}

func isUnknown(err error) bool {
	var e *OutcomeUnknownError
	return errors.As(err, &e) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// ReconcileOutcome resolves a potentially successful remote call using
// readback only. It never invokes Apply and therefore is safe to call after a
// timeout or lost connection. The caller can subsequently submit a new
// operation after a verified/partial result is recorded.
func (r *Runner) ReconcileOutcome(ctx context.Context, id string, ex ReadbackExecutor) (Operation, error) {
	if err := r.check(); err != nil {
		return Operation{}, err
	}
	if ex == nil {
		return Operation{}, fmt.Errorf("%w: readback executor is nil", ErrInvalidRequest)
	}
	op, err := r.Journal.Get(ctx, id)
	if err != nil {
		return Operation{}, err
	}
	if op.Status != StatusOutcomeUnknown {
		return op, nil
	}
	if r.Locks == nil {
		r.Locks = NewTargetLocker()
	}
	unlock := r.Locks.lock(op.Target)
	defer unlock()
	if err := r.ensureFence(ctx, op, Fence{Target: op.Target, Token: op.FenceToken}); err != nil {
		return op, err
	}
	result, readErr := ex.Readback(ctx, op, Fence{Target: op.Target, Token: op.FenceToken})
	if result.Observed != nil {
		observed := result.Observed.Clone()
		if observed.At.IsZero() {
			observed.At = r.now()
		}
		op.Views.Observed = &observed
	}
	if result.Verified != nil {
		verified := result.Verified.Clone()
		if verified.At.IsZero() {
			verified.At = r.now()
		}
		op.Views.Verified = &verified
	}
	if readErr != nil {
		op.Error = readErr.Error()
		op.UpdatedAt = r.now()
		if err := r.Journal.Save(ctx, op); err != nil {
			return op, err
		}
		return op, readErr
	}
	if result.VerifiedOK {
		if op.Views.Verified != nil {
			applied := op.Views.Verified.Clone()
			op.Views.Applied = &applied
		}
		op.Error = ""
		return r.finish(ctx, op, StatusApplied)
	}
	if result.Message != "" {
		op.Error = result.Message
	} else {
		op.Error = "readback does not match desired state"
	}
	return r.finish(ctx, op, StatusPartiallyApplied)
}

// Rollback executes the adapter rollback while retaining the original
// deployment error. The operation's deployment status remains visible; callers
// can distinguish a failed deployment with successful rollback from one whose
// rollback also failed.
func (r *Runner) Rollback(ctx context.Context, id string, ex Executor) (Operation, error) {
	if err := r.check(); err != nil {
		return Operation{}, err
	}
	if ex == nil {
		return Operation{}, fmt.Errorf("%w: executor is nil", ErrInvalidRequest)
	}
	if r.Locks == nil {
		r.Locks = NewTargetLocker()
	}
	op, err := r.Journal.Get(ctx, id)
	if err != nil {
		return Operation{}, err
	}
	if op.Rollback == RollbackSucceeded {
		return op, nil
	}
	unlock := r.Locks.lock(op.Target)
	defer unlock()
	if latest, getErr := r.Journal.Get(ctx, op.ID); getErr == nil {
		op = latest
		if op.Rollback == RollbackSucceeded {
			return op, nil
		}
	}
	op.Rollback = RollbackPending
	op.UpdatedAt = r.now()
	if err := r.Journal.Save(ctx, op); err != nil {
		return op, err
	}
	if err := r.ensureFence(ctx, op, Fence{Target: op.Target, Token: op.FenceToken}); err != nil {
		op.Rollback = RollbackFailed
		op.Error = err.Error()
		_ = r.Journal.Save(ctx, op)
		return op, err
	}
	op.Rollback = RollbackRunning
	op.UpdatedAt = r.now()
	if err := r.Journal.Save(ctx, op); err != nil {
		return op, err
	}
	if err := ex.Rollback(ctx, op, Fence{Target: op.Target, Token: op.FenceToken}); err != nil {
		op.Rollback = RollbackFailed
		op.Error = err.Error()
		op.UpdatedAt = r.now()
		_ = r.Journal.Save(ctx, op)
		return op, err
	}
	op.Rollback = RollbackSucceeded
	op.UpdatedAt = r.now()
	if err := r.Journal.Save(ctx, op); err != nil {
		return op, err
	}
	return op, nil
}
