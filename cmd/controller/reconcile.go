package main

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
)

type reconciliationOptions struct {
	Interval time.Duration
	Timeout  time.Duration
}

type operationReconciler struct {
	journal  deployment.Journal
	runner   *deployment.Runner
	factory  func(deployment.Target) deployment.Executor
	logger   *log.Logger
	options  reconciliationOptions
	complete func(context.Context, deployment.Operation, deployment.VerifyResult) error
	guard    func(deployment.ReadbackExecutor) deployment.ReadbackExecutor
	mu       sync.Mutex
}

func newOperationReconciler(j deployment.Journal, factory func(deployment.Target) deployment.Executor, logger *log.Logger, options reconciliationOptions) *operationReconciler {
	if options.Interval <= 0 {
		options.Interval = 30 * time.Second
	}
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	return &operationReconciler{journal: j, runner: deployment.NewRunner(j), factory: factory, logger: logger, options: options}
}

// Sweep inspects durable uncertain operations independently; an unavailable
// gateway does not stop readback of another target. The controller never
// resubmits an ordinary mutation payload; native resolution may finish its
// exact durably identified transaction or cancel it authoritatively.
func (r *operationReconciler) Sweep(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.journal == nil {
		return errors.New("reconciliation journal is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ops, err := r.journal.List(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, op := range ops {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(failures, err)...)
		}
		if op.Status != deployment.StatusApplying && op.Status != deployment.StatusVerifying && op.Status != deployment.StatusOutcomeUnknown {
			continue
		}
		if r.factory == nil {
			continue
		}
		executor := r.factory(op.Target)
		if executor == nil {
			continue
		}
		reader, ok := executor.(deployment.ReadbackExecutor)
		if !ok {
			continue
		}
		if r.guard != nil && (op.Action == "publish" || op.Action == "selection" || op.Action == "group_apply") {
			reader = r.guard(reader)
		} else if r.complete != nil {
			reader = completionReadback{reader: reader, complete: r.complete}
		}
		readCtx, cancel := context.WithTimeout(ctx, r.options.Timeout)
		_, err := r.runner.InspectOutcome(readCtx, op.ID, reader)
		cancel()
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (r *operationReconciler) Run(ctx context.Context) error {
	r.report(r.Sweep(ctx))
	ticker := time.NewTicker(r.options.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			r.report(r.Sweep(ctx))
		}
	}
}

func (r *operationReconciler) report(err error) {
	if err != nil && r.logger != nil && !errors.Is(err, context.Canceled) {
		r.logger.Print("operation reconciliation incomplete; unresolved operations remain visible for readback")
	}
}

// startOperationReconciliation must run after durable service state and the
// configured executor factory are installed. Its Runner is shared with the
// API so a periodic observation never races that controller's mutation stream.
func startOperationReconciliation(ctx context.Context, server *api.Server, logger *log.Logger, options reconciliationOptions) (func(), error) {
	if server == nil || server.Services == nil || server.Services.Journal == nil || server.Services.Runner == nil {
		return nil, errors.New("operation reconciliation requires initialized durable services")
	}
	worker := newOperationReconciler(server.Services.Journal, server.Services.ExecutorFactory, logger, options)
	worker.runner = server.Services.Runner
	worker.complete = server.Services.CompleteOperationReadback
	worker.guard = server.Services.OperationReadback
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = worker.Run(runCtx) }()
	var once sync.Once
	return func() { once.Do(func() { cancel(); <-done }) }, nil
}

type completionReadback struct {
	reader   deployment.ReadbackExecutor
	complete func(context.Context, deployment.Operation, deployment.VerifyResult) error
}

func (r completionReadback) Readback(ctx context.Context, op deployment.Operation, f deployment.Fence) (deployment.VerifyResult, error) {
	result, err := r.reader.Readback(ctx, op, f)
	if err == nil && (result.VerifiedOK || result.NotApplied) && (op.Action == "publish" || op.Action == "selection" || op.Action == "group_apply") {
		if err = r.complete(ctx, op, result); err != nil {
			return result, err
		}
	}
	return result, err
}
