package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
)

// MutationStatus performs a read-only authoritative lookup. It intentionally
// does not classify an absent record as committed or rejected.
func (c *Client) MutationStatus(ctx context.Context, identity MutationIdentity) (MutationReceipt, error) {
	if err := identity.Validate(); err != nil {
		return MutationReceipt{}, clientFailure("mutation.status", "invalid_request", "mutation identity is invalid", ErrValidation)
	}
	ctx = WithMutationIdentity(ctx, identity)
	var out MutationReceipt
	path := "/v1/mutations/" + url.PathEscape(identity.ID)
	if err := c.request(ctx, http.MethodGet, path, "mutation.status", nil, &out, http.StatusOK, false); err != nil {
		return MutationReceipt{}, err
	}
	if err := out.ValidateFor(identity); err != nil {
		return MutationReceipt{}, clientFailure("mutation.status", "invalid_response", "mutation status acknowledgement is invalid", ErrProtocol)
	}
	return out, nil
}

// ResolveMutation asks the agent to reconcile an uncertain request using its
// durable identity. The daemon may safely replay a known idempotent operation
// or persist a tombstone proving a missing request was never accepted.
func (c *Client) ResolveMutation(ctx context.Context, identity MutationIdentity) (MutationReceipt, error) {
	if err := identity.Validate(); err != nil {
		return MutationReceipt{}, clientFailure("mutation.resolve", "invalid_request", "mutation identity is invalid", ErrValidation)
	}
	ctx = WithMutationIdentity(ctx, identity)
	var out MutationReceipt
	path := "/v1/mutations/" + url.PathEscape(identity.ID) + "/resolve"
	if err := c.request(ctx, http.MethodPost, path, "mutation.resolve", nil, &out, http.StatusOK, true); err != nil {
		return MutationReceipt{}, err
	}
	if err := out.ValidateFor(identity); err != nil {
		return MutationReceipt{}, clientFailure("mutation.resolve", "outcome_unknown", "mutation resolution acknowledgement is invalid; read back before retrying", ErrOutcomeUnknown)
	}
	return out, nil
}

func matchesMutationRejection(data []byte, identity MutationIdentity) bool {
	var proof struct {
		Rejected bool             `json:"rejected_before_mutation"`
		Identity MutationIdentity `json:"mutation_identity"`
	}
	return json.Unmarshal(data, &proof) == nil && proof.Rejected && proof.Identity.Valid() && proof.Identity == identity
}

func setMutationIdentityHeaders(req *http.Request, identity MutationIdentity) {
	req.Header.Set("X-EgressDeck-Mutation-ID", identity.ID)
	req.Header.Set("X-EgressDeck-Mutation-Hash", identity.RequestHash)
	req.Header.Set("X-EgressDeck-Mutation-Target-Kind", identity.TargetKind)
	req.Header.Set("X-EgressDeck-Mutation-Target-ID", identity.TargetID)
	req.Header.Set("X-EgressDeck-Mutation-Fence", strconv.FormatUint(identity.FenceToken, 10))
}

var _ MutationStatusReader = (*Client)(nil)
var _ MutationResolver = (*Client)(nil)
