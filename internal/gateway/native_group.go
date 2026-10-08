package gateway

import (
	"context"
	"strconv"
	"time"
)

type nativePendingGroup struct {
	Publication    GroupPublication `json:"publication"`
	BaseGeneration uint64           `json:"base_generation"`
}

type nativeGroupRequest struct {
	ExpectedGeneration uint64                 `json:"expected_generation"`
	ProviderID         string                 `json:"provider_id"`
	RevisionID         string                 `json:"revision_id"`
	Group              nativePublicationGroup `json:"group"`
}

// PublishGroup changes only a managed group's membership. The existing active
// provider's immutable links remain authoritative; this path never stages a
// synthetic provider revision to manufacture a membership update.
func (e *NativeEngine) PublishGroup(ctx context.Context, publication GroupPublication, expectedGeneration int64) (Snapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Correlation is checked before request validation. A replayed operation ID
	// with a changed or malformed body must resolve against its durable receipt,
	// never be reclassified as a fresh pre-mutation rejection.
	check := e.cloneState()
	if err := e.checkNativeCorrelation(ctx, &check); err != nil {
		return Snapshot{}, err
	}
	p, err := publication.normalized()
	if err != nil {
		return Snapshot{}, RejectBeforeMutation("invalid_request", "invalid group publication", err)
	}
	inv, err := e.inventory(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if err := e.reconcile(ctx, &inv); err != nil {
		return Snapshot{}, err
	}
	if expectedGeneration < 0 || uint64(expectedGeneration) != inv.Generation {
		return Snapshot{}, RejectBeforeMutation("conflict", "expected generation does not match native inventory", ErrConflict)
	}
	active, exists := e.state.Active[p.ProviderID]
	if !exists || active.Revision != p.ProviderRevision || !nativeRequestObserved(inv, active) {
		return Snapshot{}, RejectBeforeMutation("conflict", "provider revision is not the active native revision", ErrConflict)
	}
	previous, exists := providerGroup(active.ProviderRevision(), p.Group.ID)
	if !exists || previous.Name != p.Group.Name {
		return Snapshot{}, RejectBeforeMutation("conflict", "group is not owned by the requested provider", ErrConflict)
	}
	if p.Group.Revision == previous.Revision && sameGroupCandidates(p.Group.CandidateIDs, previous.CandidateIDs) && nativeGroupPublicationObserved(inv, p) {
		next := e.cloneState()
		if err := e.recordNativeNoop(ctx, &next, inv.Generation); err != nil {
			return Snapshot{}, err
		}
		if _, ok := MutationIdentityFromContext(ctx); ok {
			if err := e.persist(ctx, next, "group_noop"); err != nil {
				return Snapshot{}, err
			}
		}
		return e.snapshot(inv), nil
	}
	if p.Group.Revision <= previous.Revision {
		return Snapshot{}, RejectBeforeMutation("conflict", "group revision must advance", ErrConflict)
	}
	nodes := map[string]bool{}
	for _, n := range active.Nodes {
		nodes[n.ID] = true
	}
	for _, id := range p.Group.CandidateIDs {
		if !nodes[id] {
			return Snapshot{}, RejectBeforeMutation("invalid_request", "group candidate is outside the active provider", ErrInvalidRevision)
		}
	}
	wire := nativeGroupRequest{ExpectedGeneration: inv.Generation, ProviderID: p.ProviderID, RevisionID: strconv.FormatInt(p.ProviderRevision, 10), Group: nativePublicationGroup{Name: p.Group.Name, CandidateIDs: p.Group.CandidateIDs, Selection: p.Group.SelectedNodeID, Revision: p.Group.Revision}}
	next := e.cloneState()
	next.PendingGroup = &nativePendingGroup{Publication: p.clone(), BaseGeneration: inv.Generation}
	if err := e.nativeBeginOperation(ctx, &next, "group_publish", "/v1/groups/publish", wire); err != nil {
		return Snapshot{}, err
	}
	if err := e.persist(ctx, next, "group_pending"); err != nil {
		return Snapshot{}, err
	}
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.options.Timeout)
	defer cancel()
	if err := e.reconcile(readCtx, &inv); err != nil {
		return Snapshot{}, err
	}
	if e.state.PendingGroup != nil || !nativeGroupPublicationObserved(inv, p) {
		return Snapshot{}, nativeUnknown()
	}
	return e.snapshot(inv), nil
}

func nativeGroupPublicationObserved(inv nativeInventory, p GroupPublication) bool {
	group, exists := nativeGroupByName(inv, p.Group.Name)
	return exists && group.Identity == p.ProviderID+"/"+strconv.FormatInt(p.ProviderRevision, 10) && group.GroupRevision == p.Group.Revision && group.Selection == p.Group.SelectedNodeID && sameGroupCandidates(group.CandidateIDs, p.Group.CandidateIDs)
}

// reconcileGroup is called only after the common native operation protocol
// has proved this durable operation committed. Exact inventory readback also
// binds the candidate set and group revision, rather than inferring a commit
// solely from the unchanged provider identity or global generation.
func (e *NativeEngine) reconcileGroup(_ context.Context, next *nativeState, inv nativeInventory) (bool, error) {
	pending := next.PendingGroup
	if pending == nil {
		return false, nil
	}
	p := pending.Publication
	if inv.Generation <= pending.BaseGeneration || !nativeGroupPublicationObserved(inv, p) {
		return false, nativeUnknown()
	}
	active, exists := next.Active[p.ProviderID]
	if !exists || active.Revision != p.ProviderRevision {
		return false, nativeUnknown()
	}
	found := false
	for i, g := range active.Groups {
		if g.ID == p.Group.ID && g.Name == p.Group.Name {
			active.Groups[i] = p.Group
			found = true
			break
		}
	}
	if !found {
		return false, nativeUnknown()
	}
	next.Active[p.ProviderID] = active
	selection := next.Selections[p.Group.ID]
	if selection.Scope.GroupID == "" {
		selection.Scope = SelectionScope{GroupID: p.Group.ID, Transport: "both"}
	}
	if selection.DesiredNodeID != p.Group.SelectedNodeID {
		selection.Revision++
	}
	selection.DesiredNodeID, selection.ObservedNodeID = p.Group.SelectedNodeID, p.Group.SelectedNodeID
	selection.UpdatedAt = time.Now().UTC()
	next.Selections[p.Group.ID] = selection
	next.PendingGroup = nil
	return true, nil
}

var _ GroupPublisher = (*NativeEngine)(nil)
