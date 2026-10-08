package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// nativePendingOperation is persisted before the first daemon request. It is
// intentionally request-local and contains private links only inside the
// encrypted native state journal.
type nativePendingOperation struct {
	ID      string          `json:"id"`
	Kind    string          `json:"kind"`
	Path    string          `json:"path"`
	Request json.RawMessage `json:"request"`
	Digest  string          `json:"digest"`
}
type nativeOperationStatus struct {
	OperationID   string `json:"operation_id"`
	RequestDigest string `json:"request_digest"`
	Kind          string `json:"kind"`
	State         string `json:"state"`
	Generation    uint64 `json:"generation"`
	ErrorCode     string `json:"error_code,omitempty"`
}
type nativeCorrelation struct {
	Identity   MutationIdentity `json:"identity"`
	DaemonID   string           `json:"daemon_id"`
	Digest     string           `json:"digest"`
	Kind       string           `json:"kind"`
	State      MutationState    `json:"state"`
	Generation uint64           `json:"generation,omitempty"`
	ErrorCode  string           `json:"error_code,omitempty"`
}

func operationDigest(kind string, request json.RawMessage) string {
	var obj any
	dec := json.NewDecoder(bytes.NewReader(request))
	dec.UseNumber()
	_ = dec.Decode(&obj)
	raw, _ := json.Marshal(struct {
		Kind    string `json:"kind"`
		Request any    `json:"request"`
	}{kind, obj})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func nativeOperationID(s *nativeState) (string, error) {
	if s.ClientID == "" {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return "", fmt.Errorf("%w: native client identity", ErrUnavailable)
		}
		s.ClientID = hex.EncodeToString(raw[:])
	}
	if s.Sequence == ^uint64(0) {
		return "", ErrBusy
	}
	s.Sequence++
	return s.ClientID + ":" + strconv.FormatUint(s.Sequence, 10), nil
}
func nativeWireWithOperation(input any, id string) (json.RawMessage, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err = dec.Decode(&obj); err != nil || obj == nil {
		return nil, errors.New("native mutation request must be object")
	}
	obj["operation_id"] = id
	return json.Marshal(obj)
}
func (e *NativeEngine) nativeBeginOperation(ctx context.Context, s *nativeState, kind, path string, input any) error {
	if s.Operation != nil {
		return nativeUnknown()
	}
	if err := e.checkNativeCorrelation(ctx, s); err != nil {
		return err
	}
	id, err := nativeOperationID(s)
	if err != nil {
		return err
	}
	// Check registration capacity before journaling pending intent. The daemon
	// never evicts client identities, so this refusal also excludes a delayed
	// request from that unregistered identity becoming accepted later.
	if _, statusErr := e.nativeStatus(ctx, id); statusErr != nil {
		var typed *Error
		if errors.As(statusErr, &typed) && typed.Code == "operation_limit" {
			return RejectBeforeMutation("busy", "native operation client registry is full", ErrBusy)
		}
		return statusErr
	}
	raw, err := nativeWireWithOperation(input, id)
	if err != nil || len(raw) > 1<<20 {
		return fmt.Errorf("%w: native operation encoding", ErrInvalidRevision)
	}
	s.Operation = &nativePendingOperation{ID: id, Kind: kind, Path: path, Request: raw, Digest: operationDigest(kind, rawWithoutOperationID(raw))}
	if ident, ok := MutationIdentityFromContext(ctx); ok {
		s.Correlations[ident.ID] = nativeCorrelation{Identity: ident, DaemonID: id, Digest: s.Operation.Digest, Kind: kind, State: MutationPending}
		s.MutationFences[mutationFenceKey(ident)] = ident.FenceToken
	}
	return nil
}
func mutationFenceKey(identity MutationIdentity) string {
	return identity.TargetKind + "\x00" + identity.TargetID
}
func (e *NativeEngine) checkNativeCorrelation(ctx context.Context, s *nativeState) error {
	ident, ok := MutationIdentityFromContext(ctx)
	if !ok {
		return nil
	}
	if err := ident.Validate(); err != nil {
		return RejectBeforeMutation("invalid_request", "invalid mutation identity", ErrInvalidRevision)
	}
	if s.Correlations == nil {
		s.Correlations = map[string]nativeCorrelation{}
	}
	if s.MutationFences == nil {
		s.MutationFences = map[string]uint64{}
	}
	if c, exists := s.Correlations[ident.ID]; exists {
		if c.Identity != ident {
			return conflict("mutation.identity", "mutation identity does not match durable receipt")
		}
		if c.State == MutationRejected {
			return RejectBeforeMutation("operation_rejected", "mutation identity was authoritatively rejected", ErrInvalidRevision)
		}
		return conflict("mutation.identity", "mutation identity already has a durable operation; read its result")
	}
	key := mutationFenceKey(ident)
	if ident.FenceToken <= s.MutationFences[key] {
		return conflict("mutation.identity", "mutation identity fence is stale; prior outcome requires readback")
	}
	if _, exists := s.MutationFences[key]; !exists && len(s.MutationFences) >= 4096 {
		return RejectBeforeMutation("busy", "mutation target retention is full", ErrBusy)
	}
	// Retain the latest receipt for every target. An unresolved lost-ack
	// receipt must remain queryable after unrelated operations; prune only a
	// terminal receipt whose target has since advanced to a newer fence.
	if len(s.Correlations) >= 4096 {
		for id, c := range s.Correlations {
			if c.State != MutationCommitted && c.State != MutationRejected {
				continue
			}
			if s.MutationFences[mutationFenceKey(c.Identity)] > c.Identity.FenceToken || (mutationFenceKey(c.Identity) == key && ident.FenceToken > c.Identity.FenceToken) {
				delete(s.Correlations, id)
				break
			}
		}
		if len(s.Correlations) >= 4096 {
			return RejectBeforeMutation("busy", "mutation receipt retention is full", ErrBusy)
		}
	}
	return nil
}
func rawWithoutOperationID(raw json.RawMessage) json.RawMessage {
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&obj) != nil {
		return raw
	}
	delete(obj, "operation_id")
	out, _ := json.Marshal(obj)
	return out
}
func (e *NativeEngine) nativeStatus(ctx context.Context, id string) (nativeOperationStatus, error) {
	var status nativeOperationStatus
	if err := e.do(ctx, http.MethodGet, "/v1/operations/"+id, nil, &status); err != nil {
		return status, err
	}
	return status, nil
}
func operationRejected(code string) error {
	if code == "generation_conflict" {
		return conflict("native.operation", "native operation was rejected by generation precondition")
	}
	return &Error{Code: "operation_rejected", Operation: "native.operation", Detail: "native mutation was rejected before commit", Cause: ErrInvalidRevision}
}
func (e *NativeEngine) completeNativeOperation(s *nativeState, state, code string, generation uint64) {
	if s.Operation == nil {
		return
	}
	opID := s.Operation.ID
	for id, c := range s.Correlations {
		if c.DaemonID == opID {
			c.State = MutationState(state)
			c.ErrorCode = code
			c.Generation = generation
			s.Correlations[id] = c
		}
	}
	s.Operation = nil
}

// reconcileNativeOperation first resolves the daemon receipt. An absent
// receipt is the only case that permits replaying the exact same request; an
// unchanged inventory generation is never treated as completion.
func (e *NativeEngine) reconcileNativeOperation(ctx context.Context, inv *nativeInventory) error {
	op := e.state.Operation
	if op == nil {
		return nil
	}
	st, err := e.nativeStatus(ctx, op.ID)
	if err != nil {
		var typed *Error
		if errors.As(err, &typed) && typed.Code == "operation_limit" {
			// Another authority may fill the registry between the preflight
			// and send. Its non-evicting capacity still proves this client
			// identity was never accepted and cannot be accepted late.
			next := e.cloneState()
			for id, stage := range next.Staged {
				if stage.Pending {
					stage.Pending = false
					next.Staged[id] = stage
				}
			}
			next.Pending = nil
			next.PendingGroup = nil
			e.completeNativeOperation(&next, "rejected", "operation_limit", 0)
			if persistErr := e.persist(context.WithoutCancel(ctx), next, "operation_rejected"); persistErr != nil {
				return persistErr
			}
			return RejectBeforeMutation("busy", "native operation client registry is full", ErrBusy)
		}
		return nativeUnknown()
	}
	if st.OperationID != op.ID {
		return nativeUnknown()
	}
	if st.State == "not_started" {
		var ack nativeMutationResponse
		// The status barrier plus exact-ID deduplication makes this safe even
		// if an earlier request arrives after the status response.
		_ = e.do(ctx, http.MethodPost, op.Path, json.RawMessage(op.Request), &ack)
		st, err = e.nativeStatus(ctx, op.ID)
		if err != nil {
			var typed *Error
			if errors.As(err, &typed) && typed.Code == "operation_limit" {
				return e.reconcileNativeOperation(ctx, inv)
			}
			return nativeUnknown()
		}
	}
	if st.OperationID != op.ID || st.RequestDigest != op.Digest || st.Kind != op.Kind {
		return nativeUnknown()
	}
	switch st.State {
	case "rejected":
		next := e.cloneState()
		for id, stage := range next.Staged {
			if stage.Pending {
				stage.Pending = false
				next.Staged[id] = stage
			}
		}
		next.Pending = nil
		next.PendingGroup = nil
		e.completeNativeOperation(&next, "rejected", st.ErrorCode, st.Generation)
		if err := e.persist(context.WithoutCancel(ctx), next, "operation_rejected"); err != nil {
			return err
		}
		return operationRejected(st.ErrorCode)
	case "committed":
		// A receipt may precede kernel admission acknowledgement. Healthy
		// inventory from the unfenced daemon is required before acceptance.
		fresh, readErr := e.inventory(ctx)
		if readErr != nil || fresh.Generation < st.Generation {
			return nativeUnknown()
		}
		*inv = fresh
		return nil
	default:
		return nativeUnknown()
	}
}

// MutationStatus exposes the correlated operation only after validating the
// caller's exact identity. It never infers completion from an unchanged gen.
func (e *NativeEngine) MutationStatus(ctx context.Context, identity MutationIdentity) (MutationReceipt, error) {
	if err := identity.Validate(); err != nil {
		return MutationReceipt{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mutationStatusLocked(ctx, identity)
}
func (e *NativeEngine) mutationStatusLocked(ctx context.Context, identity MutationIdentity) (MutationReceipt, error) {
	c, ok := e.state.Correlations[identity.ID]
	if !ok {
		return MutationReceipt{Identity: identity, State: MutationUnknown}, nil
	}
	if c.Identity != identity {
		return MutationReceipt{}, conflict("mutation.status", "mutation identity mismatch")
	}
	if c.State == MutationRejected {
		return MutationReceipt{Identity: identity, State: MutationRejected, ErrorCode: c.ErrorCode}, nil
	}

	// Locally completed receipts remain durable after the daemon advances to
	// the next sequence. Pending receipts must use authoritative native status.
	if c.State == MutationCommitted {
		inv, err := e.inventory(ctx)
		if err != nil || inv.Generation < c.Generation {
			return MutationReceipt{Identity: identity, State: MutationUnknown}, nativeUnknown()
		}
		return MutationReceipt{Identity: identity, State: MutationCommitted, Generation: int64(inv.Generation)}, nil
	}
	st, err := e.nativeStatus(ctx, c.DaemonID)
	if err != nil {
		return MutationReceipt{Identity: identity, State: MutationUnknown}, nativeUnknown()
	}
	if st.OperationID != c.DaemonID {
		return MutationReceipt{}, nativeUnknown()
	}
	r := MutationReceipt{Identity: identity, State: MutationPending}
	if st.State == "not_started" {
		return r, nil
	}
	if st.RequestDigest != c.Digest || st.Kind != c.Kind {
		return MutationReceipt{}, nativeUnknown()
	}
	switch st.State {
	case "rejected":
		r.State = MutationRejected
		r.ErrorCode = st.ErrorCode
	case "committed":
		inv, readErr := e.inventory(ctx)
		if readErr != nil || inv.Generation < st.Generation {
			return MutationReceipt{Identity: identity, State: MutationUnknown}, nativeUnknown()
		}
		r.State = MutationCommitted
		r.Generation = int64(inv.Generation)
	default:
		r.State = MutationUnknown
	}
	return r, nil
}
func (e *NativeEngine) ResolveMutation(ctx context.Context, identity MutationIdentity) (MutationReceipt, error) {
	if err := identity.Validate(); err != nil {
		return MutationReceipt{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.state.Correlations[identity.ID]; ok {
		if c.Identity != identity {
			return MutationReceipt{}, conflict("mutation.resolve", "mutation identity mismatch")
		}
		if c.State == MutationPending && e.state.Operation != nil && e.state.Operation.ID == c.DaemonID {
			inv, err := e.inventory(ctx)
			if err != nil {
				return MutationReceipt{Identity: identity, State: MutationUnknown}, nativeUnknown()
			}
			err = e.reconcile(ctx, &inv)
			if err != nil && e.state.Operation != nil {
				return MutationReceipt{Identity: identity, State: MutationUnknown}, err
			}
		}
		return e.mutationStatusLocked(ctx, identity)
	}
	// Absence becomes an authoritative rejection only after a durable
	// tombstone and target fence are written under the same mutation lock.
	next := e.cloneState()
	if next.Correlations == nil {
		next.Correlations = map[string]nativeCorrelation{}
	}
	if next.MutationFences == nil {
		next.MutationFences = map[string]uint64{}
	}
	key := mutationFenceKey(identity)
	if identity.FenceToken <= next.MutationFences[key] {
		return MutationReceipt{Identity: identity, State: MutationUnknown}, nil
	}
	if _, ok := next.MutationFences[key]; !ok && len(next.MutationFences) >= 4096 {
		return MutationReceipt{}, ErrBusy
	}
	if len(next.Correlations) >= 4096 {
		for id, c := range next.Correlations {
			if (c.State == MutationCommitted || c.State == MutationRejected) && (next.MutationFences[mutationFenceKey(c.Identity)] > c.Identity.FenceToken || (mutationFenceKey(c.Identity) == key && identity.FenceToken > c.Identity.FenceToken)) {
				delete(next.Correlations, id)
				break
			}
		}
	}
	if len(next.Correlations) >= 4096 {
		return MutationReceipt{}, ErrBusy
	}
	next.Correlations[identity.ID] = nativeCorrelation{Identity: identity, State: MutationRejected, ErrorCode: "never_accepted"}
	if identity.FenceToken > next.MutationFences[key] {
		next.MutationFences[key] = identity.FenceToken
	}
	if err := e.persist(context.WithoutCancel(ctx), next, "mutation_never_accepted"); err != nil {
		return MutationReceipt{}, err
	}
	return MutationReceipt{Identity: identity, State: MutationRejected, ErrorCode: "never_accepted"}, nil
}

var _ MutationStatusReader = (*NativeEngine)(nil)
var _ MutationResolver = (*NativeEngine)(nil)

func (e *NativeEngine) recordNativeNoop(ctx context.Context, s *nativeState, generation uint64) error {
	if err := e.checkNativeCorrelation(ctx, s); err != nil {
		return err
	}
	if identity, ok := MutationIdentityFromContext(ctx); ok {
		s.Correlations[identity.ID] = nativeCorrelation{Identity: identity, State: MutationCommitted, Generation: generation}
		s.MutationFences[mutationFenceKey(identity)] = identity.FenceToken
	}
	return nil
}
