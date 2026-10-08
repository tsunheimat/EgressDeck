// Package reconcile compares controller intent with readback from a managed
// target. It only mutates the durable operation journal; remote mutations are
// delegated to deployment.Runner and are never guessed from an HTTP success.
package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
)

type DriftKind string

const (
	DriftNone            DriftKind = "none"
	DriftDesiredMismatch DriftKind = "desired_mismatch"
	DriftExternalChange  DriftKind = "external_change"
	DriftUnknown         DriftKind = "unknown"
)

type Drift struct {
	Target       deployment.Target `json:"target"`
	ExpectedHash string            `json:"expected_hash,omitempty"`
	ObservedHash string            `json:"observed_hash,omitempty"`
	Kind         DriftKind         `json:"kind"`
	Safe         bool              `json:"safe"`
	Message      string            `json:"message,omitempty"`
}

type Result struct {
	Target      deployment.Target     `json:"target"`
	OperationID string                `json:"operation_id,omitempty"`
	Status      deployment.Status     `json:"status,omitempty"`
	Views       deployment.StateViews `json:"views"`
	Drifts      []Drift               `json:"drifts,omitempty"`
	Blocked     bool                  `json:"blocked"`
	Changed     bool                  `json:"changed"`
	Error       string                `json:"error,omitempty"`
}

// Observer reads only the owned target scope. Implementations must return a
// normalized record and must not silently merge external objects into it.
type Observer interface {
	Observe(context.Context, deployment.Target) (deployment.StateRecord, error)
}

// DesiredReader is optional. When present it is the management authority for
// desired intent; when absent the latest operation's desired view is used.
type DesiredReader interface {
	Desired(context.Context, deployment.Target) (deployment.StateRecord, error)
}

// Reconciler is restart-safe. It uses the journal as the source of operation
// intent and delegates optional operation recovery to Runner.
type Reconciler struct {
	Journal deployment.Journal
	Runner  *deployment.Runner
	Desired DesiredReader
	Now     func() time.Time
}

func New(journal deployment.Journal) *Reconciler {
	return &Reconciler{Journal: journal, Runner: deployment.NewRunner(journal), Now: func() time.Time { return time.Now().UTC() }}
}

func (r *Reconciler) runner() *deployment.Runner {
	if r.Runner == nil {
		r.Runner = deployment.NewRunner(r.Journal)
	}
	return r.Runner
}

func NewReconciler(journal deployment.Journal) *Reconciler { return New(journal) }

// Adapter combines remote observation and deployment methods for callers that
// keep one gateway/OPNsense adapter object per target.
type Adapter interface {
	Observer
	deployment.Executor
}

func (r *Reconciler) Run(ctx context.Context, target deployment.Target, adapter Adapter) (Result, error) {
	if adapter == nil {
		return Result{}, fmt.Errorf("reconcile: adapter is nil")
	}
	return r.Reconcile(ctx, target, adapter, adapter)
}

func (r *Reconciler) now() time.Time {
	if r.Now == nil {
		return time.Now().UTC()
	}
	return r.Now()
}

// HashState returns a stable digest of the semantic state. Timestamp and the
// existing Hash field are excluded so repeated readback does not look like a
// change. An adapter may set StateRecord.Hash to a source-provided digest;
// reconciliation still computes this canonical digest for comparisons.
func HashState(s deployment.StateRecord) string {
	b, _ := json.Marshal(struct {
		Generation uint64          `json:"generation"`
		Revision   string          `json:"revision,omitempty"`
		Status     string          `json:"status,omitempty"`
		Data       json.RawMessage `json:"data,omitempty"`
	}{s.Generation, s.Revision, s.Status, s.Data})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (r *Reconciler) check() error {
	if r.Journal == nil {
		return fmt.Errorf("reconcile: journal is nil")
	}
	return nil
}

// Reconcile reads one target and updates its latest operation's Observed and
// Verified views. If an operation was interrupted, matching readback safely
// completes it; a mismatch is recorded as partial/drift and blocks further
// destructive writes until an operator or a new explicit operation resolves
// it. This method never overwrites an unexpected remote state.
func (r *Reconciler) Reconcile(ctx context.Context, target deployment.Target, observer Observer, executor deployment.Executor) (Result, error) {
	if err := r.check(); err != nil {
		return Result{}, err
	}
	if !target.Valid() {
		return Result{}, fmt.Errorf("reconcile: invalid target")
	}
	if observer == nil {
		return Result{}, fmt.Errorf("reconcile: observer is nil")
	}
	ops, err := r.Journal.List(ctx)
	if err != nil {
		return Result{}, err
	}
	var latest *deployment.Operation
	for i := range ops {
		if ops[i].Target != target {
			continue
		}
		candidate := ops[i]
		if latest == nil || candidate.UpdatedAt.After(latest.UpdatedAt) || (candidate.UpdatedAt.Equal(latest.UpdatedAt) && candidate.ID > latest.ID) {
			latest = &candidate
		}
	}
	result := Result{Target: target}
	if latest != nil {
		result.OperationID = latest.ID
		result.Status = latest.Status
		result.Views = latest.Views.Clone()
	}
	// Resolve and persist desired intent before reading the remote target. This
	// binds the later readback to the exact generation that was reconciled.
	var desired *deployment.StateRecord
	var desiredErr error
	if r.Desired != nil {
		value, err := r.Desired.Desired(ctx, target)
		if err != nil {
			desiredErr = err
		} else {
			if value.At.IsZero() {
				value.At = r.now()
			}
			desired = &value
			result.Views.Desired = desired
			if latest != nil {
				latest.Views.Desired = desired
				latest.UpdatedAt = r.now()
				if saveErr := r.Journal.Save(ctx, *latest); saveErr != nil {
					return result, saveErr
				}
			}
		}
	} else if result.Views.Desired != nil {
		desired = result.Views.Desired
	}
	observed, observeErr := observer.Observe(ctx, target)
	if observeErr != nil {
		result.Blocked = true
		result.Drifts = append(result.Drifts, Drift{Target: target, Kind: DriftUnknown, Safe: false, Message: observeErr.Error()})
		result.Error = observeErr.Error()
		return result, observeErr
	}
	if observed.At.IsZero() {
		observed.At = r.now()
	}
	result.Views.Observed = &observed
	observedHash := HashState(observed)
	if latest != nil {
		latest.Views.Observed = &observed
		latest.UpdatedAt = r.now()
		// Persist independently observed state before any desired-state lookup;
		// a management-store outage must not discard useful remote readback.
		if saveErr := r.Journal.Save(ctx, *latest); saveErr != nil {
			return result, saveErr
		}
	}
	if desiredErr != nil {
		result.Blocked = true
		result.Drifts = append(result.Drifts, Drift{Target: target, Kind: DriftUnknown, Safe: false, Message: desiredErr.Error()})
		result.Error = desiredErr.Error()
		return result, desiredErr
	}
	// Resolve an acknowledgement that may have been lost using readback only.
	// This happens after the observer has captured an independent observation;
	// it never retries Apply on an outcome_unknown operation.
	if latest != nil && latest.Status == deployment.StatusOutcomeUnknown && executor != nil {
		if reader, ok := executor.(deployment.ReadbackExecutor); ok {
			if recovered, recoverErr := r.runner().ReconcileOutcome(ctx, latest.ID, reader); recoverErr == nil {
				latest = &recovered
				result.Status = recovered.Status
				result.Views = recovered.Views.Clone()
			} else {
				result.Blocked = true
				result.Error = recoverErr.Error()
			}
		}
	}
	// For an interrupted non-terminal operation, resume only after the
	// independent readback above. Matching readback completes the operation in
	// the comparison below without replaying Apply; divergent readback resumes
	// its durable step journal through the supplied adapter.
	if latest != nil && latest.Status != deployment.StatusOutcomeUnknown && latest.Status != deployment.StatusApplied && latest.Status != deployment.StatusPartiallyApplied && latest.Status != deployment.StatusFailed && executor != nil {
		matchesDesired := desired != nil && observedHash == HashState(*desired)
		if !matchesDesired {
			if recovered, resumeErr := r.runner().Resume(ctx, latest.ID, executor); resumeErr != nil {
				result.Blocked = true
				result.Error = resumeErr.Error()
				latest = &recovered
				result.Status = recovered.Status
				result.Views = recovered.Views.Clone()
			} else {
				latest = &recovered
				result.Status = recovered.Status
				result.Views = recovered.Views.Clone()
			}
		}
	}
	if latest != nil && latest.Views.Observed != nil {
		observed = *latest.Views.Observed
		observedHash = HashState(observed)
		result.Views.Observed = &observed
	}
	if desired == nil && latest != nil && latest.Views.Applied != nil && observedHash != HashState(*latest.Views.Applied) {
		result.Blocked = true
		result.Drifts = append(result.Drifts, Drift{Target: target, ExpectedHash: HashState(*latest.Views.Applied), ObservedHash: observedHash, Kind: DriftExternalChange, Safe: false, Message: "observed state changed outside the controller"})
	}
	if desired != nil {
		desiredHash := HashState(*desired)
		switch {
		case observedHash == desiredHash:
			verified := observed.Clone()
			if latest != nil {
				latest.Views.Verified = &verified
			}
			result.Views.Verified = &verified
			if latest != nil && (latest.Status == deployment.StatusApplying || latest.Status == deployment.StatusVerifying || latest.Status == deployment.StatusOutcomeUnknown || latest.Status == deployment.StatusStaged) {
				latest.Views.Applied = &verified
				latest.Status = deployment.StatusApplied
				latest.Error = ""
				result.Status = deployment.StatusApplied
			}
		case latest != nil && latest.Views.Applied != nil && observedHash != HashState(*latest.Views.Applied):
			result.Blocked = true
			result.Drifts = append(result.Drifts, Drift{Target: target, ExpectedHash: HashState(*latest.Views.Applied), ObservedHash: observedHash, Kind: DriftExternalChange, Safe: false, Message: "observed state changed outside the controller"})
		default:
			result.Drifts = append(result.Drifts, Drift{Target: target, ExpectedHash: desiredHash, ObservedHash: observedHash, Kind: DriftDesiredMismatch, Safe: true, Message: "observed state does not match desired state"})
			if latest != nil && (latest.Status == deployment.StatusApplying || latest.Status == deployment.StatusVerifying) {
				latest.Status = deployment.StatusPartiallyApplied
				latest.Error = "readback does not match desired state"
				result.Status = latest.Status
			}
		}
	}
	if latest != nil {
		if err := r.Journal.Save(ctx, *latest); err != nil {
			return result, err
		}
		result.Views = latest.Views.Clone()
	}
	result.Changed = result.Views.Observed != nil && (result.Views.Applied == nil || HashState(*result.Views.Observed) != HashState(*result.Views.Applied))
	return result, nil
}

// ReconcileAll reads all supplied targets. One target's observer failure is
// represented in its Result while healthy targets continue, so a temporary
// gateway outage does not hide state from another gateway.
func (r *Reconciler) ReconcileAll(ctx context.Context, observers map[string]Observer, executors map[string]deployment.Executor) ([]Result, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(observers))
	for key := range observers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	results := make([]Result, 0, len(keys))
	var firstErr error
	for _, key := range keys {
		observer := observers[key]
		// The map key is intentionally parsed only for the common Kind:ID form;
		// callers should prefer Reconcile for IDs containing separators.
		target, parseErr := parseTargetKey(key)
		if parseErr != nil {
			if firstErr == nil {
				firstErr = parseErr
			}
			continue
		}
		result, err := r.Reconcile(ctx, target, observer, executors[key])
		results = append(results, result)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return results, firstErr
}

func parseTargetKey(key string) (deployment.Target, error) {
	// Target.Key uses length-prefixed components: <kind-len>:<kind><id-len>:<id>.
	var kindLen, idLen int
	var rest string
	if _, err := fmt.Sscanf(key, "%d:", &kindLen); err != nil || kindLen < 1 {
		return deployment.Target{}, errors.New("reconcile: malformed target key")
	}
	idx := 0
	for idx < len(key) && key[idx] != ':' {
		idx++
	}
	idx++
	if idx+kindLen > len(key) {
		return deployment.Target{}, errors.New("reconcile: malformed target key")
	}
	kind := key[idx : idx+kindLen]
	idx += kindLen
	colon := idx
	for colon < len(key) && key[colon] != ':' {
		colon++
	}
	if colon == len(key) {
		return deployment.Target{}, errors.New("reconcile: malformed target key")
	}
	if _, err := fmt.Sscanf(key[idx:colon], "%d", &idLen); err != nil || idLen < 1 || colon+1+idLen != len(key) {
		return deployment.Target{}, errors.New("reconcile: malformed target key")
	}
	rest = key[colon+1:]
	return deployment.Target{Kind: kind, ID: rest}, nil
}
