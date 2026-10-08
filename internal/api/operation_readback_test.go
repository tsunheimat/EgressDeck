package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

type guardedReadbackFunc func(context.Context, deployment.Operation, deployment.Fence) (deployment.VerifyResult, error)

func (f guardedReadbackFunc) Readback(ctx context.Context, op deployment.Operation, fence deployment.Fence) (deployment.VerifyResult, error) {
	return f(ctx, op, fence)
}

type readbackCountingDocuments struct {
	store.DocumentStore
	saves int
}

func (d *readbackCountingDocuments) SaveDocument(ctx context.Context, key string, data json.RawMessage) error {
	d.saves++
	return d.DocumentStore.SaveDocument(ctx, key, data)
}

func TestOperationReadbackRechecksLiveOperationAfterLifecycleLock(t *testing.T) {
	for _, name := range []string{"already_applied", "canceled", "fence_changed", "writes_paused"} {
		t.Run(name, func(t *testing.T) {
			services, op, result := completionProviderFixture(t)
			op = rejectionSealOperation(t, services, op)
			before, err := services.Providers.ExportState()
			if err != nil {
				t.Fatal(err)
			}
			var remoteCalls atomic.Int32
			reader := services.OperationReadback(guardedReadbackFunc(func(context.Context, deployment.Operation, deployment.Fence) (deployment.VerifyResult, error) {
				remoteCalls.Add(1)
				return result, nil
			}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started, done := make(chan struct{}), make(chan error, 1)
			services.mutationMu.Lock()
			go func() {
				close(started)
				_, readErr := reader.Readback(ctx, op, deployment.Fence{Target: op.Target, Token: op.FenceToken})
				done <- readErr
			}()
			<-started
			var expected error
			switch name {
			case "already_applied":
				latest := op.Clone()
				latest.Status = deployment.StatusApplied
				latest.UpdatedAt = latest.UpdatedAt.Add(time.Second)
				err = services.Journal.Save(context.Background(), latest)
				expected = deployment.ErrConflict
			case "canceled":
				cancel()
				expected = context.Canceled
			case "fence_changed":
				_, err = services.Journal.NextFence(context.Background(), op.Target)
				expected = deployment.ErrFenceLost
			case "writes_paused":
				services.mutationBlocked = true
			}
			services.mutationMu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			select {
			case readErr := <-done:
				if readErr == nil || (expected != nil && !errors.Is(readErr, expected)) {
					t.Fatalf("readback ignored state changed under lifecycle lock: got %v want %v", readErr, expected)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("readback did not leave lifecycle lock after release")
			}
			if remoteCalls.Load() != 0 {
				t.Fatalf("recovery reached remote resolver despite invalidated intent: calls=%d", remoteCalls.Load())
			}
			after, err := services.Providers.ExportState()
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("blocked recovery changed provider lifecycle: %v", err)
			}
		})
	}
}

func TestOperationReadbackHoldsLifecycleGuardAcrossRemoteReadAndCompletion(t *testing.T) {
	ctx := context.Background()
	services, op, result := completionProviderFixture(t)
	op = rejectionSealOperation(t, services, op)
	documents := &readbackCountingDocuments{DocumentStore: store.NewMemoryStore()}
	if err := services.Load(ctx, documents, lifecycleTestVault(t, 19)); err != nil {
		t.Fatal(err)
	}
	if err := services.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	documents.saves = 0
	remoteCalls := 0
	reader := services.OperationReadback(guardedReadbackFunc(func(_ context.Context, got deployment.Operation, fence deployment.Fence) (deployment.VerifyResult, error) {
		remoteCalls++
		if services.mutationMu.TryLock() {
			services.mutationMu.Unlock()
			t.Fatal("remote resolver ran outside lifecycle mutation guard")
		}
		if got.ID != op.ID || fence.Target != op.Target || fence.Token != op.FenceToken {
			t.Fatal("guard changed correlated operation identity")
		}
		if services.Providers.Status("provider-1").Active != 0 {
			t.Fatal("controller completed operation before remote readback")
		}
		return result, nil
	}))
	runner := deployment.NewRunner(services.Journal)
	completed, err := runner.InspectOutcome(ctx, op.ID, reader)
	if err != nil || completed.Status != deployment.StatusApplied || completed.Views.Verified != nil {
		t.Fatalf("guarded readback did not complete configuration-only recovery: %+v %v", completed, err)
	}
	if remoteCalls != 1 || documents.saves != 1 || services.Providers.Status("provider-1").Active != 1 {
		t.Fatalf("guarded completion ran wrong number of times: remote=%d saves=%d active=%d", remoteCalls, documents.saves, services.Providers.Status("provider-1").Active)
	}
	if _, err := runner.InspectOutcome(ctx, op.ID, reader); err != nil || remoteCalls != 1 || documents.saves != 1 {
		t.Fatalf("terminal replay repeated guarded recovery: remote=%d saves=%d err=%v", remoteCalls, documents.saves, err)
	}
	restarted := NewServices()
	if err := restarted.Load(ctx, documents.DocumentStore, lifecycleTestVault(t, 19)); err != nil || restarted.Providers.Status("provider-1").Active != 1 {
		t.Fatalf("guarded completion was not durably stored: %v", err)
	}
}

func TestOperationMutationIdentityRejectsChangedDesiredBytes(t *testing.T) {
	services, op, _ := completionProviderFixture(t)
	op = rejectionSealOperation(t, services, op)
	if !OperationMutationIdentity(op).Valid() {
		t.Fatal("canonical immutable intent did not produce valid identity")
	}
	completionReplaceJSONField(t, op.Views.Desired, "revision", 99)
	if OperationMutationIdentity(op).Valid() {
		t.Fatal("changed desired bytes retained an authoritative identity with the old hash")
	}
}
