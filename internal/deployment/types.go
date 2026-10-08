// Package deployment contains the durable controller-side deployment state
// machine. It intentionally knows nothing about dae or OPNsense. Adapters
// implement Executor and return readback from the system they own.
package deployment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Status is the durable lifecycle of an operation. Status values are ordered
// by the state machine below; callers must not infer success from an accepted
// request or from an applying operation.
type Status string

const (
	StatusDraft            Status = "draft"
	StatusValidated        Status = "validated"
	StatusStaged           Status = "staged"
	StatusApplying         Status = "applying"
	StatusVerifying        Status = "verifying"
	StatusApplied          Status = "applied"
	StatusPartiallyApplied Status = "partially_applied"
	StatusFailed           Status = "failed"
	StatusOutcomeUnknown   Status = "outcome_unknown"
)

// Short aliases keep adapter code readable while the JSON/API names remain
// the explicit Status* constants above.
const (
	Draft            = StatusDraft
	Validated        = StatusValidated
	Staged           = StatusStaged
	Applying         = StatusApplying
	Verifying        = StatusVerifying
	Applied          = StatusApplied
	PartiallyApplied = StatusPartiallyApplied
	Failed           = StatusFailed
	OutcomeUnknown   = StatusOutcomeUnknown
)

// RollbackStatus is tracked independently because rolling back a failed
// operation is itself a durable operation and can fail independently.
type RollbackStatus string

const (
	RollbackNone      RollbackStatus = "none"
	RollbackPending   RollbackStatus = "pending"
	RollbackRunning   RollbackStatus = "running"
	RollbackSucceeded RollbackStatus = "succeeded"
	RollbackFailed    RollbackStatus = "failed"
)

// Target identifies the serialization and fencing scope. Kind should be a
// stable adapter name such as "gateway" or "opnsense" and ID must be the
// remote object's stable identity, never a display name.
type Target struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

func (t Target) Key() string {
	return strconv.Itoa(len(t.Kind)) + ":" + t.Kind + strconv.Itoa(len(t.ID)) + ":" + t.ID
}
func (t Target) Valid() bool { return strings.TrimSpace(t.Kind) != "" && strings.TrimSpace(t.ID) != "" }

// StateRecord stores an immutable state view. Data is deliberately opaque to
// this package; adapters can use JSON to carry normalized manifests or
// readback. Hash should be a digest of Data and Revision is the source
// revision that produced it.
type StateRecord struct {
	Generation uint64          `json:"generation"`
	Revision   string          `json:"revision,omitempty"`
	Hash       string          `json:"hash,omitempty"`
	Status     string          `json:"status,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`
	At         time.Time       `json:"at"`
}

func (s StateRecord) Clone() StateRecord {
	s.Data = append(json.RawMessage(nil), s.Data...)
	return s
}

// StateViews are kept separate intentionally. For example, a desired state
// can be accepted while applied is old, observed is unknown, and verified is
// absent. A successful controller call only updates these views when the
// corresponding adapter operation/readback actually succeeded.
type StateViews struct {
	Desired  *StateRecord `json:"desired,omitempty"`
	Applied  *StateRecord `json:"applied,omitempty"`
	Observed *StateRecord `json:"observed,omitempty"`
	Verified *StateRecord `json:"verified,omitempty"`
}

func (s StateViews) Clone() StateViews {
	clone := s
	if s.Desired != nil {
		v := s.Desired.Clone()
		clone.Desired = &v
	}
	if s.Applied != nil {
		v := s.Applied.Clone()
		clone.Applied = &v
	}
	if s.Observed != nil {
		v := s.Observed.Clone()
		clone.Observed = &v
	}
	if s.Verified != nil {
		v := s.Verified.Clone()
		clone.Verified = &v
	}
	return clone
}

type StepStatus string

const (
	StepPending   StepStatus = "pending"
	StepRunning   StepStatus = "running"
	StepSucceeded StepStatus = "succeeded"
	StepFailed    StepStatus = "failed"
	StepUnknown   StepStatus = "unknown"
)

type Step struct {
	Name      string     `json:"name"`
	Status    StepStatus `json:"status"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Error     string     `json:"error,omitempty"`
	Message   string     `json:"message,omitempty"`
}

func (s Step) Clone() Step { return s }

type Operation struct {
	ID                  string         `json:"id"`
	IdempotencyKey      string         `json:"idempotency_key,omitempty"`
	RequestHash         string         `json:"request_hash,omitempty"`
	Target              Target         `json:"target"`
	Action              string         `json:"action"`
	RequestedGeneration uint64         `json:"requested_generation"`
	FenceToken          uint64         `json:"fence_token"`
	Status              Status         `json:"status"`
	Rollback            RollbackStatus `json:"rollback"`
	Steps               []Step         `json:"steps,omitempty"`
	Views               StateViews     `json:"views"`
	Error               string         `json:"error,omitempty"`
	OriginalError       string         `json:"original_error,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
	CompletedAt         *time.Time     `json:"completed_at,omitempty"`
}

func (o Operation) Clone() Operation {
	o.Steps = append([]Step(nil), o.Steps...)
	o.Views = o.Views.Clone()
	return o
}

// Request creates a new operation. Desired may be nil for operations that
// only mutate runtime selection or perform an observation.
type Request struct {
	ID                  string       `json:"id,omitempty"`
	IdempotencyKey      string       `json:"idempotency_key,omitempty"`
	Target              Target       `json:"target"`
	Action              string       `json:"action"`
	RequestedGeneration uint64       `json:"requested_generation,omitempty"`
	Desired             *StateRecord `json:"desired,omitempty"`
}

func requestHash(r Request) string {
	var desired any
	if r.Desired != nil {
		desired = struct {
			Generation uint64          `json:"generation"`
			Revision   string          `json:"revision,omitempty"`
			Status     string          `json:"status,omitempty"`
			Data       json.RawMessage `json:"data,omitempty"`
		}{r.Desired.Generation, r.Desired.Revision, r.Desired.Status, r.Desired.Data}
	}
	b, _ := json.Marshal(struct {
		Target     Target `json:"target"`
		Action     string `json:"action"`
		Generation uint64 `json:"generation"`
		Desired    any    `json:"desired,omitempty"`
	}{r.Target, r.Action, r.RequestedGeneration, desired})
	h := sha256.Sum256(b)
	return fmt.Sprintf("%x", h[:])
}

type Fence struct {
	Target Target `json:"target"`
	Token  uint64 `json:"token"`
}

// ApplyResult describes what the adapter knows immediately after Apply. It is
// not verification: the executor must still read back the target in Verify.
type ApplyResult struct {
	Applied *StateRecord `json:"applied,omitempty"`
	Message string       `json:"message,omitempty"`
}

// VerifyResult contains independently read observed and verified views. A
// false Verified value is a valid readback result and leads to
// partially_applied, allowing the UI to display drift without claiming it was
// an adapter failure.
type VerifyResult struct {
	Observed   *StateRecord `json:"observed,omitempty"`
	Verified   *StateRecord `json:"verified,omitempty"`
	VerifiedOK bool         `json:"verified_ok"`
	Message    string       `json:"message,omitempty"`
}

// Journal is the durability boundary. Implementations must persist each
// mutation before returning. PostgreSQL implementations can map these calls
// to row updates and an advisory lock; MemoryJournal is provided for local
// development and contract tests.
type Journal interface {
	Create(context.Context, Operation) (Operation, error)
	Get(context.Context, string) (Operation, error)
	Save(context.Context, Operation) error
	FindByIdempotency(context.Context, Target, string) (Operation, error)
	List(context.Context) ([]Operation, error)
	NextFence(context.Context, Target) (Fence, error)
	FenceCurrent(context.Context, Target, uint64) (bool, error)
}

type OperationJournal = Journal

// Executor is implemented by one gateway/OPNsense adapter. The runner calls
// methods in this order and never holds a database transaction over them.
type Executor interface {
	Validate(context.Context, Operation) error
	Stage(context.Context, Operation, Fence) error
	Apply(context.Context, Operation, Fence) (ApplyResult, error)
	Verify(context.Context, Operation, Fence) (VerifyResult, error)
	Rollback(context.Context, Operation, Fence) error
}

// ReadbackExecutor is optional. It is used to resolve outcome_unknown after a
// lost acknowledgement without re-applying a potentially destructive change.
// The normal Executor.Verify method is intentionally not called in this path.
type ReadbackExecutor interface {
	Readback(context.Context, Operation, Fence) (VerifyResult, error)
}

var (
	ErrNotFound       = errors.New("deployment operation not found")
	ErrConflict       = errors.New("deployment operation conflict")
	ErrInvalidRequest = errors.New("invalid deployment request")
	ErrFenceLost      = errors.New("deployment fence lost")
	ErrAlreadyRunning = errors.New("deployment target is already running an operation")
	ErrOutcomeUnknown = errors.New("deployment outcome unknown")
	ErrPartial        = errors.New("deployment partially applied")
)

// OutcomeUnknownError signals that a remote call may have succeeded but its
// acknowledgement was lost. The runner records outcome_unknown and requires
// readback/reconciliation before another destructive operation.
type OutcomeUnknownError struct{ Err error }

func (e *OutcomeUnknownError) Error() string {
	if e == nil || e.Err == nil {
		return "deployment outcome unknown"
	}
	return "deployment outcome unknown: " + e.Err.Error()
}
func (e *OutcomeUnknownError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
func (e *OutcomeUnknownError) Is(target error) bool { return target == ErrOutcomeUnknown }

// PartialError indicates that the adapter applied only part of a manifest.
// The operation remains inspectable and can be reconciled or rolled back.
type PartialError struct{ Err error }

func (e *PartialError) Error() string {
	if e == nil || e.Err == nil {
		return "deployment partially applied"
	}
	return "deployment partially applied: " + e.Err.Error()
}
func (e *PartialError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
func (e *PartialError) Is(target error) bool { return target == ErrPartial }

// DriftError is returned by an adapter when an owned target changed outside
// the controller. Destructive writes stop until an operator reconciles it.
type DriftError struct{ Err error }

func (e *DriftError) Error() string {
	if e == nil || e.Err == nil {
		return "deployment target drifted"
	}
	return "deployment target drifted: " + e.Err.Error()
}
func (e *DriftError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func validateRequest(r Request) error {
	if !r.Target.Valid() || r.Action == "" {
		return fmt.Errorf("%w: target and action are required", ErrInvalidRequest)
	}
	if strings.TrimSpace(r.Target.Kind) != r.Target.Kind || strings.TrimSpace(r.Target.ID) != r.Target.ID || strings.TrimSpace(r.Action) != r.Action {
		return fmt.Errorf("%w: target and action may not contain surrounding whitespace", ErrInvalidRequest)
	}
	if r.IdempotencyKey == "" {
		return fmt.Errorf("%w: idempotency key is required", ErrInvalidRequest)
	}
	return nil
}

// TargetLocker serializes mutation streams in-process. A durable deployment
// backend should pair this with a database advisory lock; the lock is still
// useful to prevent duplicate work inside one controller process.
type TargetLocker struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func NewTargetLocker() *TargetLocker { return &TargetLocker{locks: make(map[string]*sync.Mutex)} }
func (l *TargetLocker) lock(target Target) func() {
	l.mu.Lock()
	if l.locks == nil {
		l.locks = make(map[string]*sync.Mutex)
	}
	m := l.locks[target.Key()]
	if m == nil {
		m = &sync.Mutex{}
		l.locks[target.Key()] = m
	}
	l.mu.Unlock()
	m.Lock()
	return m.Unlock
}

func sortedOperations(in []Operation) []Operation {
	out := append([]Operation(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}
