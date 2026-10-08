package reconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
)

type reconcileExecutor struct {
	readback int
	apply    int
	state    deployment.StateRecord
}

func (e *reconcileExecutor) Validate(context.Context, deployment.Operation) error { return nil }
func (e *reconcileExecutor) Stage(context.Context, deployment.Operation, deployment.Fence) error {
	return nil
}
func (e *reconcileExecutor) Apply(context.Context, deployment.Operation, deployment.Fence) (deployment.ApplyResult, error) {
	e.apply++
	return deployment.ApplyResult{Applied: &e.state}, nil
}
func (e *reconcileExecutor) Verify(context.Context, deployment.Operation, deployment.Fence) (deployment.VerifyResult, error) {
	return deployment.VerifyResult{Observed: &e.state, Verified: &e.state, VerifiedOK: true}, nil
}
func (e *reconcileExecutor) Readback(context.Context, deployment.Operation, deployment.Fence) (deployment.VerifyResult, error) {
	e.readback++
	return deployment.VerifyResult{Observed: &e.state, Verified: &e.state, VerifiedOK: true}, nil
}
func (e *reconcileExecutor) Rollback(context.Context, deployment.Operation, deployment.Fence) error {
	return nil
}

type observer struct {
	state deployment.StateRecord
	err   error
}

func (o observer) Observe(context.Context, deployment.Target) (deployment.StateRecord, error) {
	return o.state, o.err
}

type desiredReader struct{ state deployment.StateRecord }

func (d desiredReader) Desired(context.Context, deployment.Target) (deployment.StateRecord, error) {
	return d.state, nil
}

type failingDesired struct{}

func (failingDesired) Desired(context.Context, deployment.Target) (deployment.StateRecord, error) {
	return deployment.StateRecord{}, errors.New("desired store offline")
}

func TestReconcilePersistsObservedAndVerified(t *testing.T) {
	j := deployment.NewMemoryJournal()
	op := deployment.Operation{ID: "op1", IdempotencyKey: "k", Target: deployment.Target{Kind: "gateway", ID: "g1"}, Action: "apply", FenceToken: 1, Status: deployment.StatusOutcomeUnknown}
	if _, err := j.Create(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if _, err := j.NextFence(context.Background(), op.Target); err != nil {
		t.Fatal(err)
	}
	// Create's token is intentionally fixed above; make the journal fence current
	// for the recovery check.
	if err := j.Save(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	r := New(j)
	state := deployment.StateRecord{Generation: 1, Revision: "r1", Data: []byte(`{"ok":true}`)}
	r.Desired = desiredReader{state: state}
	result, err := r.Reconcile(context.Background(), op.Target, observer{state: state}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Views.Observed == nil || result.Views.Verified == nil {
		t.Fatalf("views: %#v", result.Views)
	}
	if result.Status != deployment.StatusApplied {
		t.Fatalf("status: %s", result.Status)
	}
	got, err := j.Get(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != deployment.StatusApplied || got.Views.Observed == nil || got.Views.Verified == nil {
		t.Fatalf("journal: %#v", got)
	}
}

func TestReconcileExternalDriftBlocks(t *testing.T) {
	j := deployment.NewMemoryJournal()
	target := deployment.Target{Kind: "gateway", ID: "g1"}
	if _, err := j.Create(context.Background(), deployment.Operation{ID: "op1", IdempotencyKey: "k", Target: target, Action: "apply", Status: deployment.StatusApplied, Views: deployment.StateViews{Applied: ptr(deployment.StateRecord{Revision: "r1", Data: []byte(`{"ok":true}`)})}}); err != nil {
		t.Fatal(err)
	}
	r := New(j)
	result, err := r.Reconcile(context.Background(), target, observer{state: deployment.StateRecord{Revision: "r2", Data: []byte(`{"ok":false}`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Blocked || len(result.Drifts) != 1 || result.Drifts[0].Kind != DriftExternalChange {
		t.Fatalf("result: %+v", result)
	}
}

func TestReconcileObserverFailureIsUnknown(t *testing.T) {
	r := New(deployment.NewMemoryJournal())
	target := deployment.Target{Kind: "gateway", ID: "g1"}
	result, err := r.Reconcile(context.Background(), target, observer{err: errors.New("offline")}, nil)
	if err == nil || !result.Blocked || result.Drifts[0].Kind != DriftUnknown {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestReconcileUsesReadbackForUnknownAndPersistsDesired(t *testing.T) {
	j := deployment.NewMemoryJournal()
	target := deployment.Target{Kind: "gateway", ID: "g1"}
	fence, err := j.NextFence(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Create(context.Background(), deployment.Operation{ID: "op1", IdempotencyKey: "k", Target: target, Action: "apply", FenceToken: fence.Token, Status: deployment.StatusOutcomeUnknown}); err != nil {
		t.Fatal(err)
	}
	state := deployment.StateRecord{Generation: 1, Revision: "r1", Data: []byte(`{"ok":true}`)}
	ex := &reconcileExecutor{state: state}
	r := New(j)
	r.Desired = desiredReader{state: state}
	result, err := r.Reconcile(context.Background(), target, observer{state: state}, ex)
	if err != nil {
		t.Fatal(err)
	}
	if ex.readback != 1 || ex.apply != 0 {
		t.Fatalf("executor calls readback=%d apply=%d", ex.readback, ex.apply)
	}
	if result.Status != deployment.StatusApplied {
		t.Fatalf("status=%s", result.Status)
	}
	got, err := j.Get(context.Background(), "op1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Views.Desired == nil || got.Views.Observed == nil || got.Views.Verified == nil || got.Status != deployment.StatusApplied {
		t.Fatalf("journal=%+v", got)
	}
}

func TestReconcileResumesStagedOperationThroughExecutor(t *testing.T) {
	j := deployment.NewMemoryJournal()
	target := deployment.Target{Kind: "gateway", ID: "g1"}
	fence, err := j.NextFence(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	desired := deployment.StateRecord{Generation: 2, Revision: "desired", Data: []byte(`{"ok":true}`)}
	if _, err := j.Create(context.Background(), deployment.Operation{ID: "op1", IdempotencyKey: "k", Target: target, Action: "apply", FenceToken: fence.Token, Status: deployment.StatusStaged, Views: deployment.StateViews{Desired: &desired}}); err != nil {
		t.Fatal(err)
	}
	ex := &reconcileExecutor{state: desired}
	r := New(j)
	result, err := r.Reconcile(context.Background(), target, observer{state: deployment.StateRecord{Generation: 1, Revision: "old"}}, ex)
	if err != nil {
		t.Fatal(err)
	}
	if ex.apply != 1 || result.Status != deployment.StatusApplied {
		t.Fatalf("apply=%d status=%s result=%+v", ex.apply, result.Status, result)
	}
}

func TestReconcileSavesObservedWhenDesiredReadFails(t *testing.T) {
	j := deployment.NewMemoryJournal()
	target := deployment.Target{Kind: "gateway", ID: "g1"}
	if _, err := j.Create(context.Background(), deployment.Operation{ID: "op1", IdempotencyKey: "k", Target: target, Action: "observe", Status: deployment.StatusApplied}); err != nil {
		t.Fatal(err)
	}
	r := New(j)
	r.Desired = failingDesired{}
	state := deployment.StateRecord{Revision: "observed"}
	if _, err := r.Reconcile(context.Background(), target, observer{state: state}, nil); err == nil {
		t.Fatal("expected desired error")
	}
	got, err := j.Get(context.Background(), "op1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Views.Observed == nil || got.Views.Observed.Revision != "observed" {
		t.Fatalf("observed view not persisted: %+v", got.Views)
	}
}

func ptr(v deployment.StateRecord) *deployment.StateRecord { return &v }
