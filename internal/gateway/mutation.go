package gateway

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// MutationIdentity is the durable correlation identity of one gateway
// mutation.  It is sent over the authenticated agent transport so the agent
// can distinguish a request that never arrived from one whose acknowledgement
// was lost.  Values deliberately use a conservative header-safe alphabet.
type MutationIdentity struct {
	ID          string `json:"id"`
	RequestHash string `json:"request_hash"`
	TargetKind  string `json:"target_kind"`
	TargetID    string `json:"target_id"`
	FenceToken  uint64 `json:"fence_token"`
}

func (i MutationIdentity) Validate() error {
	if !mutationToken(i.ID, 256) || i.ID == "." || i.ID == ".." {
		return errors.New("mutation identity id is required and must be a safe token")
	}
	if len(i.RequestHash) != 64 || strings.ToLower(i.RequestHash) != i.RequestHash {
		return errors.New("mutation identity request hash must be 64 lowercase hexadecimal characters")
	}
	if _, err := hex.DecodeString(i.RequestHash); err != nil {
		return errors.New("mutation identity request hash must be hexadecimal")
	}
	if !mutationToken(i.TargetKind, 64) {
		return errors.New("mutation identity target kind is required and must be a safe token")
	}
	if !mutationToken(i.TargetID, 256) {
		return errors.New("mutation identity target id is required and must be a safe token")
	}
	if i.FenceToken == 0 {
		return errors.New("mutation identity fence token must be non-zero")
	}
	return nil
}

func (i MutationIdentity) Valid() bool { return i.Validate() == nil }

func mutationToken(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

type mutationIdentityContextKey struct{}

// WithMutationIdentity associates a validated (or soon-to-be validated)
// identity with an outgoing controller request.  Validation is performed at
// the transport boundary so callers can build an identity incrementally.
func WithMutationIdentity(ctx context.Context, identity MutationIdentity) context.Context {
	return context.WithValue(ctx, mutationIdentityContextKey{}, identity)
}

func MutationIdentityFromContext(ctx context.Context) (MutationIdentity, bool) {
	if ctx == nil {
		return MutationIdentity{}, false
	}
	identity, ok := ctx.Value(mutationIdentityContextKey{}).(MutationIdentity)
	return identity, ok
}

// MutationState is the agent's authoritative result for a correlated request.
type MutationState string

const (
	MutationCommitted MutationState = "committed"
	MutationRejected  MutationState = "rejected"
	MutationPending   MutationState = "pending"
	MutationUnknown   MutationState = "unknown"
)

// MutationReceipt is intentionally small. Generation is supplied only when
// daemon readback is healthy; callers must never infer commitment from an
// unchanged generation alone.
type MutationReceipt struct {
	Identity   MutationIdentity `json:"identity"`
	State      MutationState    `json:"state"`
	Generation int64            `json:"generation,omitempty"`
	ErrorCode  string           `json:"error_code,omitempty"`
}

func (r MutationReceipt) ValidateFor(identity MutationIdentity) error {
	if err := identity.Validate(); err != nil {
		return fmt.Errorf("invalid requested mutation identity: %w", err)
	}
	if err := r.Identity.Validate(); err != nil {
		return fmt.Errorf("invalid mutation receipt identity: %w", err)
	}
	if r.Identity != identity {
		return errors.New("mutation receipt identity does not match the request")
	}
	if r.Generation < 0 || (r.ErrorCode != "" && !mutationToken(r.ErrorCode, 128)) {
		return errors.New("invalid mutation receipt generation or error code")
	}
	switch r.State {
	case MutationCommitted, MutationRejected, MutationPending, MutationUnknown:
		return nil
	default:
		return fmt.Errorf("invalid mutation receipt state %q", r.State)
	}
}

func ValidateMutationReceipt(identity MutationIdentity, receipt MutationReceipt) error {
	return receipt.ValidateFor(identity)
}

// MutationStatusReader reports durable agent state without changing it.
type MutationStatusReader interface {
	MutationStatus(context.Context, MutationIdentity) (MutationReceipt, error)
}

// MutationResolver explicitly resolves an uncertain request. Implementations
// may write a rejected tombstone when the daemon proves that the identity was
// never accepted; they must not clear a pending request speculatively.
type MutationResolver interface {
	ResolveMutation(context.Context, MutationIdentity) (MutationReceipt, error)
}
