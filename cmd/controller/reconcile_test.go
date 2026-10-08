package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

type reconciliationCalls struct {
	mu    sync.Mutex
	names []string
}

func (c *reconciliationCalls) record(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.names = append(c.names, name)
}

func (c *reconciliationCalls) assert(t *testing.T, want ...string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.names) != len(want) {
		t.Fatalf("executor calls = %v, want %v", c.names, want)
	}
	for i := range want {
		if c.names[i] != want[i] {
			t.Fatalf("executor calls = %v, want %v", c.names, want)
		}
	}
}

// Keep the ordinary Verify method distinct: it may be a mutating adapter
// workflow and must never stand in for the explicit readback contract.
type reconciliationMutationExecutor struct{ calls *reconciliationCalls }

func (e reconciliationMutationExecutor) Validate(context.Context, deployment.Operation) error {
	e.calls.record("validate")
	return nil
}
func (e reconciliationMutationExecutor) Stage(context.Context, deployment.Operation, deployment.Fence) error {
	e.calls.record("stage")
	return nil
}
func (e reconciliationMutationExecutor) Apply(context.Context, deployment.Operation, deployment.Fence) (deployment.ApplyResult, error) {
	e.calls.record("apply")
	return deployment.ApplyResult{}, nil
}
func (e reconciliationMutationExecutor) Verify(context.Context, deployment.Operation, deployment.Fence) (deployment.VerifyResult, error) {
	e.calls.record("verify")
	return deployment.VerifyResult{}, nil
}
func (e reconciliationMutationExecutor) Rollback(context.Context, deployment.Operation, deployment.Fence) error {
	e.calls.record("rollback")
	return nil
}

type reconciliationReadbackExecutor struct {
	reconciliationMutationExecutor
	read func(context.Context, deployment.Operation, deployment.Fence) (deployment.VerifyResult, error)
}

func (e reconciliationReadbackExecutor) Readback(ctx context.Context, op deployment.Operation, fence deployment.Fence) (deployment.VerifyResult, error) {
	e.calls.record("readback")
	return e.read(ctx, op, fence)
}

func reconciliationSeed(t *testing.T, journal deployment.Journal, id string, status deployment.Status) deployment.Operation {
	t.Helper()
	ctx := context.Background()
	target := deployment.Target{Kind: "gateway", ID: id}
	fence, err := journal.NextFence(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, time.October, 8, 1, 2, 3, 0, time.UTC)
	desired := deployment.StateRecord{Generation: 7, Revision: "revision-seven", Hash: "desired-hash", Data: []byte(`{"revision":7}`), At: at}
	op, err := journal.Create(ctx, deployment.Operation{
		ID: id, IdempotencyKey: id, Action: "apply", Target: target,
		RequestedGeneration: 7, FenceToken: fence.Token, Status: status,
		Rollback: deployment.RollbackNone, CreatedAt: at,
		Views: deployment.StateViews{Desired: &desired},
	})
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func reconciliationMatch(op deployment.Operation) deployment.VerifyResult {
	observed, verified := op.Views.Desired.Clone(), op.Views.Desired.Clone()
	return deployment.VerifyResult{Observed: &observed, Verified: &verified, VerifiedOK: true}
}

func reconciliationGet(t *testing.T, journal deployment.Journal, id string) deployment.Operation {
	t.Helper()
	op, err := journal.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func reconciliationAssertApplied(t *testing.T, before, after deployment.Operation) {
	t.Helper()
	if after.Status != deployment.StatusApplied || after.Error != "" {
		t.Fatalf("readback status=%s error=%q", after.Status, after.Error)
	}
	if !reflect.DeepEqual(after.Views.Desired, before.Views.Desired) || after.RequestedGeneration != before.RequestedGeneration || after.FenceToken != before.FenceToken {
		t.Fatalf("readback changed durable intent or fence: before=%+v after=%+v", before, after)
	}
	if after.Views.Applied == nil || after.Views.Observed == nil || after.Views.Verified == nil {
		t.Fatalf("successful readback omitted independent views: %+v", after.Views)
	}
	for _, view := range []*deployment.StateRecord{after.Views.Applied, after.Views.Observed, after.Views.Verified} {
		var compact bytes.Buffer
		if err := json.Compact(&compact, view.Data); err != nil {
			t.Fatalf("invalid recovered view data: %v", err)
		}
		if view.Generation != 7 || view.Revision != "revision-seven" || compact.String() != `{"revision":7}` {
			t.Fatalf("wrong revision in recovered view: %+v", view)
		}
	}
}

func reconciliationLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func TestOperationReconcilerSweepsOnlyInterruptedRemoteOperations(t *testing.T) {
	for _, status := range []deployment.Status{
		deployment.StatusDraft, deployment.StatusValidated, deployment.StatusStaged,
		deployment.StatusApplying, deployment.StatusVerifying, deployment.StatusOutcomeUnknown,
		deployment.StatusApplied, deployment.StatusPartiallyApplied, deployment.StatusFailed,
	} {
		t.Run(string(status), func(t *testing.T) {
			journal := deployment.NewMemoryJournal()
			before := reconciliationSeed(t, journal, "operation", status)
			calls := &reconciliationCalls{}
			executor := reconciliationReadbackExecutor{
				reconciliationMutationExecutor: reconciliationMutationExecutor{calls},
				read: func(_ context.Context, op deployment.Operation, fence deployment.Fence) (deployment.VerifyResult, error) {
					if op.ID != before.ID || fence.Target != before.Target || fence.Token != before.FenceToken {
						t.Fatalf("readback received another operation or fence: op=%+v fence=%+v", op, fence)
					}
					return reconciliationMatch(op), nil
				},
			}
			reconciler := newOperationReconciler(journal, func(target deployment.Target) deployment.Executor {
				if target != before.Target {
					t.Fatalf("factory target=%+v want=%+v", target, before.Target)
				}
				return executor
			}, reconciliationLogger(), reconciliationOptions{Interval: time.Hour, Timeout: time.Second})
			if err := reconciler.Sweep(context.Background()); err != nil {
				t.Fatal(err)
			}
			after := reconciliationGet(t, journal, before.ID)
			switch status {
			case deployment.StatusApplying, deployment.StatusVerifying, deployment.StatusOutcomeUnknown:
				calls.assert(t, "readback")
				reconciliationAssertApplied(t, before, after)
			default:
				calls.assert(t)
				if !reflect.DeepEqual(before, after) {
					t.Fatalf("unapproved/terminal operation changed: before=%+v after=%+v", before, after)
				}
			}
			if current, err := journal.FenceCurrent(context.Background(), before.Target, before.FenceToken); err != nil || !current {
				t.Fatalf("sweep replaced existing fence: current=%v err=%v", current, err)
			}
		})
	}
}

func TestOperationReconcilerMissingReadbackLeavesJournalUntouched(t *testing.T) {
	for _, adapter := range []string{"unconfigured", "no-readback-interface"} {
		t.Run(adapter, func(t *testing.T) {
			journal := deployment.NewMemoryJournal()
			before := reconciliationSeed(t, journal, "operation", deployment.StatusOutcomeUnknown)
			calls := &reconciliationCalls{}
			reconciler := newOperationReconciler(journal, func(deployment.Target) deployment.Executor {
				if adapter == "unconfigured" {
					return nil
				}
				return reconciliationMutationExecutor{calls}
			}, reconciliationLogger(), reconciliationOptions{Timeout: time.Second})
			_ = reconciler.Sweep(context.Background())
			calls.assert(t)
			if after := reconciliationGet(t, journal, before.ID); !reflect.DeepEqual(before, after) {
				t.Fatalf("operation without a readback adapter changed: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestOperationReconcilerReadbackFailureRemainsRetryableAndOtherTargetsContinue(t *testing.T) {
	journal := deployment.NewMemoryJournal()
	failed := reconciliationSeed(t, journal, "a-unreachable", deployment.StatusApplying)
	healthy := reconciliationSeed(t, journal, "b-healthy", deployment.StatusVerifying)
	readErr := errors.New("gateway readback unavailable")
	failedCalls, healthyCalls := &reconciliationCalls{}, &reconciliationCalls{}
	retry := false
	factory := func(target deployment.Target) deployment.Executor {
		calls := healthyCalls
		if target == failed.Target {
			calls = failedCalls
		}
		return reconciliationReadbackExecutor{
			reconciliationMutationExecutor: reconciliationMutationExecutor{calls},
			read: func(_ context.Context, op deployment.Operation, _ deployment.Fence) (deployment.VerifyResult, error) {
				if target == failed.Target && !retry {
					return deployment.VerifyResult{}, readErr
				}
				return reconciliationMatch(op), nil
			},
		}
	}
	reconciler := newOperationReconciler(journal, factory, reconciliationLogger(), reconciliationOptions{Timeout: time.Second})
	if err := reconciler.Sweep(context.Background()); !errors.Is(err, readErr) {
		t.Fatalf("sweep error=%v want readback failure", err)
	}
	after := reconciliationGet(t, journal, failed.ID)
	if after.Status != deployment.StatusOutcomeUnknown || after.Error == "" || after.Views.Verified != nil || after.Views.Applied != nil {
		t.Fatalf("failed readback claimed completion or lost retry state: %+v", after)
	}
	if !reflect.DeepEqual(after.Views.Desired, failed.Views.Desired) {
		t.Fatal("failed readback changed desired intent")
	}
	reconciliationAssertApplied(t, healthy, reconciliationGet(t, journal, healthy.ID))
	retry = true
	if err := reconciler.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	reconciliationAssertApplied(t, failed, reconciliationGet(t, journal, failed.ID))
	failedCalls.assert(t, "readback", "readback")
	healthyCalls.assert(t, "readback")
}

func TestOperationReconcilerReadbackMismatchDoesNotClaimSuccess(t *testing.T) {
	journal := deployment.NewMemoryJournal()
	before := reconciliationSeed(t, journal, "operation", deployment.StatusOutcomeUnknown)
	calls := &reconciliationCalls{}
	reconciler := newOperationReconciler(journal, func(deployment.Target) deployment.Executor {
		return reconciliationReadbackExecutor{
			reconciliationMutationExecutor: reconciliationMutationExecutor{calls},
			read: func(context.Context, deployment.Operation, deployment.Fence) (deployment.VerifyResult, error) {
				return deployment.VerifyResult{Observed: &deployment.StateRecord{Generation: 6, Revision: "revision-six"}, Message: "remote revision differs"}, nil
			},
		}
	}, reconciliationLogger(), reconciliationOptions{Timeout: time.Second})
	_ = reconciler.Sweep(context.Background())
	after := reconciliationGet(t, journal, before.ID)
	if after.Status != deployment.StatusPartiallyApplied || after.Views.Verified != nil || after.Views.Applied != nil || after.Views.Observed == nil || after.Views.Observed.Generation != 6 {
		t.Fatalf("mismatched readback incorrectly recovered: %+v", after)
	}
	if !reflect.DeepEqual(after.Views.Desired, before.Views.Desired) {
		t.Fatal("mismatched readback changed desired intent")
	}
	calls.assert(t, "readback")
}

func TestOperationReconcilerObservedConfigurationDoesNotFabricateClientVerification(t *testing.T) {
	journal := deployment.NewMemoryJournal()
	before := reconciliationSeed(t, journal, "operation", deployment.StatusOutcomeUnknown)
	calls := &reconciliationCalls{}
	reconciler := newOperationReconciler(journal, func(deployment.Target) deployment.Executor {
		return reconciliationReadbackExecutor{
			reconciliationMutationExecutor: reconciliationMutationExecutor{calls},
			read: func(_ context.Context, op deployment.Operation, _ deployment.Fence) (deployment.VerifyResult, error) {
				observed := op.Views.Desired.Clone()
				return deployment.VerifyResult{Observed: &observed, VerifiedOK: true}, nil
			},
		}
	}, reconciliationLogger(), reconciliationOptions{Timeout: time.Second})
	if err := reconciler.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := reconciliationGet(t, journal, before.ID)
	if after.Status != deployment.StatusApplied || after.Views.Applied == nil || after.Views.Observed == nil || after.Views.Verified != nil {
		t.Fatalf("configuration-only readback fabricated client verification: %+v", after)
	}
	calls.assert(t, "readback")
}

func TestOperationReconcilerRejectsStaleFenceBeforeReadback(t *testing.T) {
	journal := deployment.NewMemoryJournal()
	before := reconciliationSeed(t, journal, "operation", deployment.StatusOutcomeUnknown)
	if _, err := journal.NextFence(context.Background(), before.Target); err != nil {
		t.Fatal(err)
	}
	calls := &reconciliationCalls{}
	reconciler := newOperationReconciler(journal, func(deployment.Target) deployment.Executor {
		return reconciliationReadbackExecutor{
			reconciliationMutationExecutor: reconciliationMutationExecutor{calls},
			read: func(_ context.Context, op deployment.Operation, _ deployment.Fence) (deployment.VerifyResult, error) {
				return reconciliationMatch(op), nil
			},
		}
	}, reconciliationLogger(), reconciliationOptions{Timeout: time.Second})
	if err := reconciler.Sweep(context.Background()); !errors.Is(err, deployment.ErrFenceLost) {
		t.Fatalf("stale fence error=%v", err)
	}
	calls.assert(t)
	after := reconciliationGet(t, journal, before.ID)
	if after.Status != deployment.StatusOutcomeUnknown || after.Views.Verified != nil || after.Views.Applied != nil {
		t.Fatalf("stale operation marked successful: %+v", after)
	}
}

func TestOperationReconcilerRejectsFenceChangedDuringReadback(t *testing.T) {
	journal := deployment.NewMemoryJournal()
	before := reconciliationSeed(t, journal, "operation", deployment.StatusOutcomeUnknown)
	calls := &reconciliationCalls{}
	reconciler := newOperationReconciler(journal, func(deployment.Target) deployment.Executor {
		return reconciliationReadbackExecutor{
			reconciliationMutationExecutor: reconciliationMutationExecutor{calls},
			read: func(ctx context.Context, op deployment.Operation, _ deployment.Fence) (deployment.VerifyResult, error) {
				if _, err := journal.NextFence(ctx, op.Target); err != nil {
					return deployment.VerifyResult{}, err
				}
				return reconciliationMatch(op), nil
			},
		}
	}, reconciliationLogger(), reconciliationOptions{Timeout: time.Second})
	if err := reconciler.Sweep(context.Background()); !errors.Is(err, deployment.ErrFenceLost) {
		t.Fatalf("fence lost during readback error=%v", err)
	}
	after := reconciliationGet(t, journal, before.ID)
	if after.Status == deployment.StatusApplied || after.Views.Verified != nil || after.Views.Applied != nil {
		t.Fatalf("stale readback persisted success: %+v", after)
	}
	calls.assert(t, "readback")
}

func TestOperationReconcilerReadbackTimeoutKeepsUnknownOutcome(t *testing.T) {
	journal := deployment.NewMemoryJournal()
	before := reconciliationSeed(t, journal, "operation", deployment.StatusVerifying)
	calls := &reconciliationCalls{}
	reconciler := newOperationReconciler(journal, func(deployment.Target) deployment.Executor {
		return reconciliationReadbackExecutor{
			reconciliationMutationExecutor: reconciliationMutationExecutor{calls},
			read: func(ctx context.Context, _ deployment.Operation, _ deployment.Fence) (deployment.VerifyResult, error) {
				<-ctx.Done()
				return deployment.VerifyResult{}, ctx.Err()
			},
		}
	}, reconciliationLogger(), reconciliationOptions{Timeout: 20 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := reconciler.Sweep(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error=%v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("sweep relied on caller timeout instead of configured readback timeout")
	}
	after := reconciliationGet(t, journal, before.ID)
	if after.Status != deployment.StatusOutcomeUnknown || after.Views.Verified != nil || after.Views.Applied != nil {
		t.Fatalf("timed out readback claimed success: %+v", after)
	}
	calls.assert(t, "readback")
}

func TestOperationReconcilerRunReadsPersistedOperationsImmediately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.json")
	journal, err := deployment.OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	before := reconciliationSeed(t, journal, "interrupted", deployment.StatusApplying)
	reopened, err := deployment.OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	// Compare the persisted representation: JSON journal formatting may add
	// whitespace inside the opaque desired-state JSON during the initial save.
	before = reconciliationGet(t, reopened, before.ID)
	calls := &reconciliationCalls{}
	reconciler := newOperationReconciler(reopened, func(deployment.Target) deployment.Executor {
		return reconciliationReadbackExecutor{
			reconciliationMutationExecutor: reconciliationMutationExecutor{calls},
			read: func(_ context.Context, op deployment.Operation, _ deployment.Fence) (deployment.VerifyResult, error) {
				return reconciliationMatch(op), nil
			},
		}
	}, reconciliationLogger(), reconciliationOptions{Interval: time.Hour, Timeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	reconciliationAwaitApplied(t, reopened, before.ID)
	cancel()
	reconciliationAwaitStopped(t, done)
	readback, err := deployment.OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	reconciliationAssertApplied(t, before, reconciliationGet(t, readback, before.ID))
	calls.assert(t, "readback")
}

func TestOperationReconcilerRunRetriesReadbackOnLaterTicks(t *testing.T) {
	journal := deployment.NewMemoryJournal()
	before := reconciliationSeed(t, journal, "operation", deployment.StatusOutcomeUnknown)
	calls := &reconciliationCalls{}
	attempt := 0
	reconciler := newOperationReconciler(journal, func(deployment.Target) deployment.Executor {
		return reconciliationReadbackExecutor{
			reconciliationMutationExecutor: reconciliationMutationExecutor{calls},
			read: func(_ context.Context, op deployment.Operation, _ deployment.Fence) (deployment.VerifyResult, error) {
				attempt++
				if attempt < 3 {
					return deployment.VerifyResult{}, errors.New("temporarily unreachable")
				}
				return reconciliationMatch(op), nil
			},
		}
	}, reconciliationLogger(), reconciliationOptions{Interval: 10 * time.Millisecond, Timeout: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	reconciliationAwaitApplied(t, journal, before.ID)
	cancel()
	reconciliationAwaitStopped(t, done)
	reconciliationAssertApplied(t, before, reconciliationGet(t, journal, before.ID))
	calls.assert(t, "readback", "readback", "readback")
}

func TestOperationReconcilerRunCancellationInterruptsReadback(t *testing.T) {
	journal := deployment.NewMemoryJournal()
	before := reconciliationSeed(t, journal, "operation", deployment.StatusOutcomeUnknown)
	calls := &reconciliationCalls{}
	started := make(chan struct{})
	reconciler := newOperationReconciler(journal, func(deployment.Target) deployment.Executor {
		return reconciliationReadbackExecutor{
			reconciliationMutationExecutor: reconciliationMutationExecutor{calls},
			read: func(ctx context.Context, _ deployment.Operation, _ deployment.Fence) (deployment.VerifyResult, error) {
				close(started)
				<-ctx.Done()
				return deployment.VerifyResult{}, ctx.Err()
			},
		}
	}, reconciliationLogger(), reconciliationOptions{Interval: time.Hour, Timeout: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- reconciler.Run(ctx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("startup reconciliation did not start")
	}
	cancel()
	reconciliationAwaitStopped(t, done)
	after := reconciliationGet(t, journal, before.ID)
	if after.Status != deployment.StatusOutcomeUnknown || after.Views.Verified != nil || after.Views.Applied != nil {
		t.Fatalf("canceled readback claimed success: %+v", after)
	}
	calls.assert(t, "readback")
}

type reconciliationBlockingApplyExecutor struct {
	reconciliationMutationExecutor
	started chan struct{}
	release <-chan struct{}
}

func (e reconciliationBlockingApplyExecutor) Apply(ctx context.Context, _ deployment.Operation, _ deployment.Fence) (deployment.ApplyResult, error) {
	e.calls.record("apply")
	close(e.started)
	select {
	case <-e.release:
		return deployment.ApplyResult{}, nil
	case <-ctx.Done():
		return deployment.ApplyResult{}, ctx.Err()
	}
}

func TestStartOperationReconciliationSharesAPIRunnerTargetLock(t *testing.T) {
	journal := deployment.NewMemoryJournal()
	server := api.NewServer(store.NewMemoryStore(), reconciliationLogger())
	server.Services.Journal = journal
	server.Services.Runner = deployment.NewRunner(journal)
	mutationCalls, readbackCalls := &reconciliationCalls{}, &reconciliationCalls{}
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseApply := func() { releaseOnce.Do(func() { close(release) }) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer releaseApply()
	mutationDone := make(chan error, 1)
	go func() {
		_, err := server.Services.Runner.Submit(ctx, deployment.Request{
			ID: "active", IdempotencyKey: "active", Action: "apply",
			Target: deployment.Target{Kind: "gateway", ID: "busy"},
		}, reconciliationBlockingApplyExecutor{reconciliationMutationExecutor{mutationCalls}, started, release})
		mutationDone <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("API runner did not enter Apply")
	}
	factoryCalled, readbackCalled := make(chan struct{}, 1), make(chan struct{}, 1)
	server.Services.ExecutorFactory = func(deployment.Target) deployment.Executor {
		factoryCalled <- struct{}{}
		return reconciliationReadbackExecutor{
			reconciliationMutationExecutor: reconciliationMutationExecutor{readbackCalls},
			read: func(context.Context, deployment.Operation, deployment.Fence) (deployment.VerifyResult, error) {
				readbackCalled <- struct{}{}
				return deployment.VerifyResult{}, nil
			},
		}
	}
	stop, err := startOperationReconciliation(ctx, server, reconciliationLogger(), reconciliationOptions{Interval: time.Hour, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { releaseApply(); stop() }()
	select {
	case <-factoryCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("production startup wrapper did not sweep active operation")
	}
	select {
	case <-readbackCalled:
		t.Fatal("startup readback overlapped API Apply on the same target")
	case <-time.After(25 * time.Millisecond):
	}
	releaseApply()
	select {
	case err := <-mutationDone:
		if err != nil {
			t.Fatalf("API Apply failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("API runner did not complete")
	}
	stop()
	// The waiting recovery must re-read the terminal record after acquiring
	// the shared lock, rather than inspect its stale applying snapshot.
	if after := reconciliationGet(t, journal, "active"); after.Status != deployment.StatusPartiallyApplied {
		t.Fatalf("recovery overwrote API runner completion: %+v", after)
	}
	mutationCalls.assert(t, "validate", "stage", "apply", "verify")
	readbackCalls.assert(t)
}

func reconciliationAwaitApplied(t *testing.T, journal deployment.Journal, id string) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if reconciliationGet(t, journal, id).Status == deployment.StatusApplied {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("operation did not complete readback: %+v", reconciliationGet(t, journal, id))
		}
	}
}

func reconciliationAwaitStopped(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("reconciler shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reconciler did not stop after cancellation")
	}
}
