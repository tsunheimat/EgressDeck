package gateway

import (
	"context"
	"net/http"
)

// GroupPublishRequest is the authenticated gateway-agent wire request. The
// expected generation binds provider and group readback to a single snapshot.
type GroupPublishRequest struct {
	Publication        GroupPublication `json:"publication"`
	ExpectedGeneration int64            `json:"expected_generation"`
}

func (c *Client) PublishGroup(ctx context.Context, publication GroupPublication, expectedGeneration int64) (Snapshot, error) {
	p, err := publication.normalized()
	if err != nil {
		return Snapshot{}, err
	}
	var out struct {
		Status   string    `json:"status"`
		Snapshot *Snapshot `json:"snapshot"`
	}
	if err := c.request(ctx, http.MethodPost, "/v1/groups/publish", string(CapabilityGroupPublish), GroupPublishRequest{p, expectedGeneration}, &out, http.StatusOK, true); err != nil {
		return Snapshot{}, err
	}
	if out.Status != "published" || out.Snapshot == nil || out.Snapshot.Generation < expectedGeneration {
		return Snapshot{}, clientFailure(string(CapabilityGroupPublish), "outcome_unknown", "group publication acknowledgement is incomplete; readback required", ErrOutcomeUnknown)
	}
	g, ok := out.Snapshot.Groups[p.Group.ID]
	provider, providerOK := out.Snapshot.Providers[p.ProviderID]
	if !ok || !providerOK || provider.Revision != p.ProviderRevision || g.Revision != p.Group.Revision || g.Name != p.Group.Name || len(g.ProviderIDs) != 1 || g.ProviderIDs[0] != p.ProviderID || !sameGroupCandidates(g.NodeIDs, p.Group.CandidateIDs) {
		return Snapshot{}, clientFailure(string(CapabilityGroupPublish), "outcome_unknown", "group publication readback did not match requested membership and revisions", ErrOutcomeUnknown)
	}
	return *out.Snapshot, nil
}

func sameGroupCandidates(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, id := range a {
		if seen[id] {
			return false
		}
		seen[id] = true
	}
	for _, id := range b {
		if !seen[id] {
			return false
		}
		delete(seen, id)
	}
	return true
}

var _ GroupPublisher = (*Client)(nil)
