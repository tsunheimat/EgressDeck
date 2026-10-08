package deployment

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

type testExecutor struct {
	mu                                                 sync.Mutex
	validate, stage, apply, verify, readback, rollback int
	applyErr                                           error
	verifyResult                                       VerifyResult
	started                                            chan struct{}
	continueApply                                      chan struct{}
}

func (e *testExecutor) Validate(context.Context, Operation) error {
	e.mu.Lock()
	e.validate++
	e.mu.Unlock()
	return nil
}
func (e *testExecutor) Stage(context.Context, Operation, Fence) error {
	e.mu.Lock()
	e.stage++
	e.mu.Unlock()
	return nil
}
func (e *testExecutor) Apply(_ context.Context, _ Operation, _ Fence) (ApplyResult, error) {
	e.mu.Lock()
	e.apply++
	started, wait := e.started, e.continueApply
	err := e.applyErr
	e.mu.Unlock()
	if started != nil {
		close(started)
		<-wait
	}
	return ApplyResult{Applied: &StateRecord{Generation: 1, Revision: "r1", Data: []byte(`{"ok":true}`)}}, err
}
func (e *testExecutor) Verify(context.Context, Operation, Fence) (VerifyResult, error) {
	e.mu.Lock()
	e.verify++
	out := e.verifyResult
	e.mu.Unlock()
	return out, nil
}
func (e *testExecutor) Readback(context.Context, Operation, Fence) (VerifyResult, error) {
	e.mu.Lock()
	e.readback++
	out := e.verifyResult
	e.mu.Unlock()
	return out, nil
}
func (e *testExecutor) Rollback(context.Context, Operation, Fence) error {
	e.mu.Lock()
	e.rollback++
	e.mu.Unlock()
	return nil
}

func matchingResult() VerifyResult {
	r := StateRecord{Generation: 1, Revision: "r1", Data: []byte(`{"ok":true}`)}
	return VerifyResult{Observed: &r, Verified: &r, VerifiedOK: true}
}

func TestRunnerLifecycleAndViews(t *testing.T) {
	j := NewMemoryJournal()
	r := NewRunner(j)
	ex := &testExecutor{verifyResult: matchingResult()}
	op, err := r.Submit(context.Background(), Request{IdempotencyKey: "one", Target: Target{Kind: "gateway", ID: "g1"}, Action: "apply", Desired: &StateRecord{Generation: 1, Revision: "r1", Data: []byte(`{"ok":true}`)}}, ex)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if op.Status != StatusApplied {
		t.Fatalf("status = %s", op.Status)
	}
	if op.Views.Desired == nil || op.Views.Applied == nil || op.Views.Observed == nil || op.Views.Verified == nil {
		t.Fatalf("missing state views: %#v", op.Views)
	}
	if ex.validate != 1 || ex.stage != 1 || ex.apply != 1 || ex.verify != 1 {
		t.Fatalf("unexpected calls: %#v", ex)
	}
	got, err := r.Submit(context.Background(), Request{IdempotencyKey: "one", Target: Target{Kind: "gateway", ID: "g1"}, Action: "apply", Desired: op.Views.Desired}, ex)
	if err != nil || got.ID != op.ID || ex.apply != 1 {
		t.Fatalf("idempotency reran: got=%+v err=%v calls=%d", got, err, ex.apply)
	}
}

func TestRunnerIdempotencyBindsRequest(t *testing.T) {
	j := NewMemoryJournal()
	r := NewRunner(j)
	ex := &testExecutor{verifyResult: matchingResult()}
	req := Request{IdempotencyKey: "one", Target: Target{Kind: "gateway", ID: "g1"}, Action: "apply", Desired: &StateRecord{Revision: "r1"}}
	if _, err := r.Submit(context.Background(), req, ex); err != nil {
		t.Fatal(err)
	}
	req.Action = "delete"
	if _, err := r.Submit(context.Background(), req, ex); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestRunnerUnknownReadbackDoesNotApplyAgain(t *testing.T) {
	j := NewMemoryJournal()
	r := NewRunner(j)
	ex := &testExecutor{applyErr: &OutcomeUnknownError{Err: errors.New("connection lost")}, verifyResult: matchingResult()}
	op, err := r.Submit(context.Background(), Request{IdempotencyKey: "one", Target: Target{Kind: "gateway", ID: "g1"}, Action: "apply"}, ex)
	if !errors.As(err, new(*OutcomeUnknownError)) || op.Status != StatusOutcomeUnknown {
		t.Fatalf("unknown result: op=%s err=%v", op.Status, err)
	}
	op, err = r.Resume(context.Background(), op.ID, ex)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if op.Status != StatusApplied || ex.apply != 1 || ex.readback != 1 {
		t.Fatalf("readback recovery failed: op=%s apply=%d readback=%d", op.Status, ex.apply, ex.readback)
	}
}

func TestRunnerSerializesTarget(t *testing.T) {
	j := NewMemoryJournal()
	r := NewRunner(j)
	first := &testExecutor{verifyResult: matchingResult(), started: make(chan struct{}), continueApply: make(chan struct{})}
	second := &testExecutor{verifyResult: matchingResult()}
	target := Target{Kind: "gateway", ID: "g1"}
	firstDone := make(chan Operation, 1)
	go func() {
		op, _ := r.Submit(context.Background(), Request{IdempotencyKey: "first", Target: target, Action: "apply"}, first)
		firstDone <- op
	}()
	select {
	case <-first.started:
	case <-time.After(time.Second):
		t.Fatal("first did not start")
	}
	secondDone := make(chan Operation, 1)
	go func() {
		op, _ := r.Submit(context.Background(), Request{IdempotencyKey: "second", Target: target, Action: "apply"}, second)
		secondDone <- op
	}()
	select {
	case <-secondDone:
		t.Fatal("second ran before first released")
	case <-time.After(25 * time.Millisecond):
	}
	close(first.continueApply)
	if got := (<-firstDone).Status; got != StatusApplied {
		t.Fatalf("first status %s", got)
	}
	if got := (<-secondDone).Status; got != StatusApplied {
		t.Fatalf("second status %s", got)
	}
}

func TestFileJournalSurvivesRestart(t *testing.T) {
	path := t.TempDir() + "/operations.json"
	j, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	fence, err := j.NextFence(context.Background(), Target{Kind: "gateway", ID: "g1"})
	if err != nil || fence.Token != 1 {
		t.Fatalf("fence=%+v err=%v", fence, err)
	}
	created, err := j.Create(context.Background(), Operation{ID: "op1", IdempotencyKey: "key", Target: Target{Kind: "gateway", ID: "g1"}, Action: "apply", FenceToken: fence.Token, Status: StatusDraft})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "op1" {
		t.Fatal(created.ID)
	}
	reopened, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Get(context.Background(), "op1")
	if err != nil || got.ID != "op1" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	current, err := reopened.FenceCurrent(context.Background(), Target{Kind: "gateway", ID: "g1"}, 1)
	if err != nil || !current {
		t.Fatalf("fence current=%v err=%v", current, err)
	}
}

func TestJournalRejectsStaleMutation(t *testing.T) {
	j := NewMemoryJournal()
	target := Target{Kind: "gateway", ID: "g1"}
	fence1, err := j.NextFence(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Create(context.Background(), Operation{ID: "op1", Target: target, Action: "apply", FenceToken: fence1.Token, Status: StatusDraft}); err != nil {
		t.Fatal(err)
	}
	if _, err := j.NextFence(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if err := j.Save(context.Background(), Operation{ID: "op1", Target: target, Action: "apply", FenceToken: fence1.Token, Status: StatusApplying}); !errors.Is(err, ErrFenceLost) {
		t.Fatalf("expected stale save rejection, got %v", err)
	}
	if err := j.Save(context.Background(), Operation{ID: "op1", Target: target, Action: "apply", FenceToken: fence1.Token, Status: StatusOutcomeUnknown}); err != nil {
		t.Fatalf("unknown result should remain journalable: %v", err)
	}
}

func TestFileJournalFailedWriteDoesNotPublishInMemory(t *testing.T) {
	dir := t.TempDir()
	parent := dir + "/blocked"
	if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	j := &FileJournal{MemoryJournal: NewMemoryJournal(), path: parent + "/journal.json"}
	target := Target{Kind: "gateway", ID: "g1"}
	if _, err := j.NextFence(context.Background(), target); err == nil {
		t.Fatal("expected persistence error")
	}
	if current, _ := j.FenceCurrent(context.Background(), target, 1); current {
		t.Fatal("failed fence was visible in memory")
	}
	if _, err := j.Create(context.Background(), Operation{ID: "unpersisted", Target: target, Action: "apply"}); err == nil {
		t.Fatal("expected persistence error")
	}
	if _, err := j.Get(context.Background(), "unpersisted"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed creation was visible: %v", err)
	}
}
