package providers

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
)

// RevisionState tracks the explicit stage/publish boundary.
type RevisionState string

const (
	RevisionStaged     RevisionState = "staged"
	RevisionActive     RevisionState = "active"
	RevisionSuperseded RevisionState = "superseded"
	RevisionFailed     RevisionState = "failed"
)

// RetainedRevisionLimit is an admission bound, not a garbage-collection rule.
// The registry cannot prove that a superseded revision is no longer referenced
// by a gateway session or pending rollback, so it never silently deletes one.
const RetainedRevisionLimit = 128

var ErrRevisionCapacity = errors.New("provider retained revision capacity reached")

type Revision struct {
	ProviderID  string        `json:"provider_id"`
	Number      int64         `json:"number"`
	Hash        string        `json:"-"`
	Nodes       []nodes.Node  `json:"nodes"`
	Report      ParseReport   `json:"parse_report"`
	Changes     ChangeReport  `json:"changes"`
	State       RevisionState `json:"state"`
	CreatedAt   time.Time     `json:"created_at"`
	PublishedAt *time.Time    `json:"published_at,omitempty"`
}

// RequiresApproval prevents automatic publication of an incomplete or
// identity-ambiguous inventory. Pinned-node removal additionally needs the
// caller's outbound-selection policy, which is outside this registry.
func (r Revision) RequiresApproval() bool {
	return len(r.Report.Unsupported) > 0 || len(r.Report.Errors) > 0 || r.Report.Skipped > 0 || len(r.Changes.Ambiguous) > 0
}

type NodeChange struct {
	NodeID string `json:"node_id"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// IdentityAmbiguity reports possible continuity without assigning an old node's
// ID to a new credential. IDs in this report are random public IDs.
type IdentityAmbiguity struct {
	PreviousNodeIDs []string `json:"previous_node_ids"`
	NewNodeIDs      []string `json:"new_node_ids"`
	Reason          string   `json:"reason"`
}

type ChangeReport struct {
	Added     []NodeChange        `json:"added,omitempty"`
	Removed   []NodeChange        `json:"removed,omitempty"`
	Changed   []NodeChange        `json:"changed,omitempty"`
	Renamed   []NodeChange        `json:"renamed,omitempty"`
	Ambiguous []IdentityAmbiguity `json:"ambiguous,omitempty"`
	Unchanged int                 `json:"unchanged"`
	Noop      bool                `json:"noop"`
}

type ProviderStatus struct {
	ProviderID    string     `json:"provider_id"`
	Active        int64      `json:"active_revision"`
	Staged        int64      `json:"staged_revision"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

type ProviderFetcher func(context.Context, domain.Provider) ([]byte, error)

// MetadataImpactEvaluator reports whether a display-only provider update
// changes effective outbound membership. Implementations must only read their
// own state and must not re-enter this registry. It runs under the provider
// mutation boundary; the caller serializes group configuration changes.
type MetadataImpactEvaluator func(providerID string, before, after []nodes.Node) (bool, error)

type refreshCall struct {
	provider domain.Provider
	format   Format
	done     chan struct{}
	revision Revision
	changes  ChangeReport
	err      error
}

type providerState struct {
	// mutation serializes fetch, stage, and publish while mu keeps reads and
	// duplicate-request joining responsive during network I/O.
	mutation  sync.Mutex
	mu        sync.Mutex
	revisions map[int64]Revision
	next      int64
	status    ProviderStatus
	refresh   *refreshCall
}

type Registry struct {
	boundary       sync.RWMutex
	mu             sync.RWMutex
	providers      map[string]*providerState
	limits         Limits
	fetch          ProviderFetcher
	metadataImpact MetadataImpactEvaluator
}

// SetMetadataImpactEvaluator connects provider metadata to outbound semantics.
// Replacing an evaluator waits for current registry operations to complete.
func (r *Registry) SetMetadataImpactEvaluator(evaluate MetadataImpactEvaluator) {
	r.boundary.Lock()
	defer r.boundary.Unlock()
	r.metadataImpact = evaluate
}

func NewRegistry(limits Limits, fetch ProviderFetcher) *Registry {
	return &Registry{providers: make(map[string]*providerState), limits: limits.withDefaults(), fetch: fetch}
}

func NewHTTPRegistry(limits Limits, options FetchOptions) *Registry {
	return NewRegistry(limits, func(ctx context.Context, provider domain.Provider) ([]byte, error) {
		result, err := FetchProvider(ctx, provider, limits, options)
		if err != nil {
			return nil, err
		}
		return result.Content, nil
	})
}

func (r *Registry) state(providerID string) *providerState {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := r.providers[providerID]; s != nil {
		return s
	}
	s := &providerState{revisions: make(map[int64]Revision), status: ProviderStatus{ProviderID: providerID}}
	r.providers[providerID] = s
	return s
}

func cloneNodes(in []nodes.Node) []nodes.Node {
	if in == nil {
		return nil
	}
	out := make([]nodes.Node, len(in))
	for i, n := range in {
		out[i] = nodes.Clone(n)
	}
	return out
}

func cloneChanges(in ChangeReport) ChangeReport {
	in.Added = append([]NodeChange(nil), in.Added...)
	in.Removed = append([]NodeChange(nil), in.Removed...)
	in.Changed = append([]NodeChange(nil), in.Changed...)
	in.Renamed = append([]NodeChange(nil), in.Renamed...)
	in.Ambiguous = append([]IdentityAmbiguity(nil), in.Ambiguous...)
	for i := range in.Ambiguous {
		in.Ambiguous[i].PreviousNodeIDs = append([]string(nil), in.Ambiguous[i].PreviousNodeIDs...)
		in.Ambiguous[i].NewNodeIDs = append([]string(nil), in.Ambiguous[i].NewNodeIDs...)
	}
	return in
}

func cloneTime(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneStatus(in ProviderStatus) ProviderStatus {
	in.LastAttemptAt = cloneTime(in.LastAttemptAt)
	in.LastSuccessAt = cloneTime(in.LastSuccessAt)
	return in
}

func cloneRevision(in Revision) Revision {
	in.Nodes = cloneNodes(in.Nodes)
	in.Report.Unsupported = append([]Unsupported(nil), in.Report.Unsupported...)
	in.Report.Warnings = append([]string(nil), in.Report.Warnings...)
	in.Report.Errors = append([]string(nil), in.Report.Errors...)
	in.Changes = cloneChanges(in.Changes)
	in.PublishedAt = cloneTime(in.PublishedAt)
	return in
}

// Stage validates content without changing the active runtime revision.
func (r *Registry) Stage(providerID string, content []byte, format Format) (Revision, ChangeReport, error) {
	r.boundary.RLock()
	defer r.boundary.RUnlock()
	if providerID == "" {
		return Revision{}, ChangeReport{}, errors.New("provider id is required")
	}
	s := r.state(providerID)
	s.mutation.Lock()
	defer s.mutation.Unlock()
	parsed, err := Parse(providerID, content, format, r.limits)
	if err != nil {
		return Revision{}, ChangeReport{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return stageParsed(s, parsed, r.metadataImpact)
}

// reconcileNodes retains random public node IDs only when the private logical
// identity matches. Credential rotation without trustworthy provider identity
// deliberately creates a new public ID and is reported by compareNodes.
func reconcileNodes(s *providerState, parsed []nodes.Node) []nodes.Node {
	latest := make(map[string]nodes.Node)
	revisions := make([]int64, 0, len(s.revisions))
	for number := range s.revisions {
		revisions = append(revisions, number)
	}
	sort.Slice(revisions, func(i, j int) bool { return revisions[i] < revisions[j] })
	for _, number := range revisions {
		for _, n := range s.revisions[number].Nodes {
			latest[n.Identity] = n
		}
	}
	out := cloneNodes(parsed)
	for i := range out {
		if old, ok := latest[out[i].Identity]; ok {
			out[i].ID, out[i].Revision = old.ID, old.Revision
			if old.ContentHash != out[i].ContentHash {
				out[i].Revision++
			}
		}
	}
	return out
}

func supersedeStaged(s *providerState) {
	if previous, ok := s.revisions[s.status.Staged]; ok && previous.State == RevisionStaged {
		previous.State = RevisionSuperseded
		s.revisions[previous.Number] = previous
	}
}

func stageParsed(s *providerState, parsed Parsed, evaluate MetadataImpactEvaluator) (Revision, ChangeReport, error) {
	if len(parsed.Nodes) == 0 {
		return Revision{}, ChangeReport{}, ErrNoNodes
	}
	for _, number := range []int64{s.status.Staged, s.status.Active} {
		existing, ok := s.revisions[number]
		if !ok || existing.Hash != parsed.ContentHash {
			continue
		}
		previous := make(map[string]nodes.Node, len(existing.Nodes))
		for _, n := range existing.Nodes {
			previous[n.Identity] = n
		}
		parsed.Nodes = cloneNodes(parsed.Nodes)
		for i := range parsed.Nodes {
			if old, ok := previous[parsed.Nodes[i].Identity]; ok {
				parsed.Nodes[i].ID, parsed.Nodes[i].Revision = old.ID, old.Revision
			}
		}
		if evaluate != nil {
			changed, err := evaluate(parsed.ProviderID, cloneNodes(existing.Nodes), cloneNodes(parsed.Nodes))
			if err != nil {
				return Revision{}, ChangeReport{}, err
			}
			if changed {
				// The connection inventory digest is unchanged, but name-based
				// membership changed. Give this semantic update a new immutable
				// revision and retain the active metadata until explicit apply.
				continue
			}
		}
		changes := compareNodes(existing.Nodes, parsed.Nodes)
		changes.Noop = true
		// Names and order are inventory metadata. Retain their latest values
		// without manufacturing a connection revision or runtime publication.
		existing.Nodes, existing.Report, existing.Changes = parsed.Nodes, parsed.Report, changes
		if existing.State == RevisionStaged {
			var activeNodes []nodes.Node
			if active, ok := s.revisions[s.status.Active]; ok {
				activeNodes = active.Nodes
			}
			existing.Changes = compareNodes(activeNodes, parsed.Nodes)
		}
		s.revisions[number] = existing
		if number == s.status.Active {
			supersedeStaged(s)
			s.status.Staged = 0
		}
		s.status.LastError = ""
		return cloneRevision(existing), cloneChanges(changes), nil
	}
	if len(s.revisions) >= RetainedRevisionLimit {
		return Revision{}, ChangeReport{}, ErrRevisionCapacity
	}
	parsed.Nodes = reconcileNodes(s, parsed.Nodes)
	var before []nodes.Node
	if active, ok := s.revisions[s.status.Active]; ok {
		before = active.Nodes
	}
	changes := compareNodes(before, parsed.Nodes)
	s.next++
	supersedeStaged(s)
	rev := Revision{ProviderID: parsed.ProviderID, Number: s.next, Hash: parsed.ContentHash, Nodes: parsed.Nodes, Report: parsed.Report, Changes: changes, State: RevisionStaged, CreatedAt: time.Now().UTC()}
	s.revisions[rev.Number] = rev
	s.status.ProviderID, s.status.Staged, s.status.LastError = parsed.ProviderID, rev.Number, ""
	return cloneRevision(rev), cloneChanges(changes), nil
}

func compareNodes(before, after []nodes.Node) ChangeReport {
	a, b := make(map[string]nodes.Node, len(before)), make(map[string]nodes.Node, len(after))
	for _, n := range before {
		a[n.Identity] = n
	}
	for _, n := range after {
		b[n.Identity] = n
	}
	var out ChangeReport
	// Group unmatched entries by endpoint only to flag uncertainty. An
	// endpoint match never establishes logical identity.
	removedEndpoints, addedEndpoints := map[string][]string{}, map[string][]string{}
	endpoint := func(n nodes.Node) string { return n.ProtocolName() + ":" + n.Address() }
	for identity, n := range b {
		old, ok := a[identity]
		if !ok {
			out.Added = append(out.Added, NodeChange{NodeID: n.ID, After: n.Name})
			key := endpoint(n)
			addedEndpoints[key] = append(addedEndpoints[key], n.ID)
		} else if old.ContentHash != n.ContentHash {
			out.Changed = append(out.Changed, NodeChange{NodeID: n.ID, Before: old.Name, After: n.Name})
		} else if old.Name != n.Name {
			out.Renamed = append(out.Renamed, NodeChange{NodeID: n.ID, Before: old.Name, After: n.Name})
		} else {
			out.Unchanged++
		}
	}
	for identity, n := range a {
		if _, ok := b[identity]; !ok {
			out.Removed = append(out.Removed, NodeChange{NodeID: n.ID, Before: n.Name})
			key := endpoint(n)
			removedEndpoints[key] = append(removedEndpoints[key], n.ID)
		}
	}
	for key, previous := range removedEndpoints {
		if added := addedEndpoints[key]; len(added) > 0 {
			sort.Strings(previous)
			sort.Strings(added)
			out.Ambiguous = append(out.Ambiguous, IdentityAmbiguity{PreviousNodeIDs: previous, NewNodeIDs: added, Reason: "connection data changed at the same endpoint without a trustworthy stable provider identifier"})
		}
	}
	for _, changes := range [][]NodeChange{out.Added, out.Removed, out.Changed, out.Renamed} {
		sort.Slice(changes, func(i, j int) bool { return changes[i].NodeID < changes[j].NodeID })
	}
	sort.Slice(out.Ambiguous, func(i, j int) bool { return out.Ambiguous[i].PreviousNodeIDs[0] < out.Ambiguous[j].PreviousNodeIDs[0] })
	return out
}

// Publish activates a staged revision with an exact active-generation CAS;
// expectedActive=0 means the caller expects no active revision. The caller's
// explicit Publish is manual approval; automatic callers must first enforce
// RequiresApproval and their pinned-node protection policy.
func (r *Registry) Publish(providerID string, revision int64, expectedActive int64) (Revision, error) {
	r.boundary.RLock()
	defer r.boundary.RUnlock()
	s := r.state(providerID)
	s.mutation.Lock()
	defer s.mutation.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.Active != expectedActive {
		return Revision{}, domain.ErrConflict
	}
	rev, ok := s.revisions[revision]
	if !ok {
		return Revision{}, domain.ErrNotFound
	}
	if rev.State == RevisionActive && s.status.Active == revision {
		return cloneRevision(rev), nil
	}
	if rev.State != RevisionStaged || s.status.Staged != revision {
		return Revision{}, fmt.Errorf("%w: revision %d is %s", domain.ErrConflict, revision, rev.State)
	}
	if old, ok := s.revisions[s.status.Active]; ok {
		old.State = RevisionSuperseded
		s.revisions[old.Number] = old
	}
	now := time.Now().UTC()
	rev.State, rev.PublishedAt = RevisionActive, &now
	s.revisions[rev.Number] = rev
	s.status.Active, s.status.Staged, s.status.LastError = rev.Number, 0, ""
	return cloneRevision(rev), nil
}

// Refresh coalesces concurrent identical fetches. Requests with different
// provider settings wait for the current fetch, then perform their own fetch.
// A waiting caller's cancellation does not cancel another caller's request.
func (r *Registry) Refresh(ctx context.Context, provider domain.Provider, format Format) (Revision, ChangeReport, error) {
	r.boundary.RLock()
	defer r.boundary.RUnlock()
	if provider.ID == "" {
		return Revision{}, ChangeReport{}, errors.New("provider id is required")
	}
	s := r.state(provider.ID)
	for {
		s.mu.Lock()
		if current := s.refresh; current != nil {
			identical := current.provider == provider && current.format == format
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return Revision{}, ChangeReport{}, ctx.Err()
			case <-current.done:
				if identical {
					return cloneRevision(current.revision), cloneChanges(current.changes), current.err
				}
				continue
			}
		}
		call := &refreshCall{provider: provider, format: format, done: make(chan struct{})}
		s.refresh = call
		s.mu.Unlock()

		s.mutation.Lock()
		revision, changes, err := r.refresh(ctx, s, provider, format)
		s.mu.Lock()
		call.revision, call.changes, call.err = revision, changes, err
		s.refresh = nil
		close(call.done)
		s.mu.Unlock()
		s.mutation.Unlock()
		return cloneRevision(revision), cloneChanges(changes), err
	}
}

func (r *Registry) refresh(ctx context.Context, s *providerState, provider domain.Provider, format Format) (Revision, ChangeReport, error) {
	now := time.Now().UTC()
	s.mu.Lock()
	s.status.LastAttemptAt = &now
	s.mu.Unlock()
	var parsed Parsed
	var err error
	if r.fetch == nil {
		err = ErrFetch
	} else {
		var content []byte
		content, err = r.fetch(ctx, provider)
		if err != nil {
			err = ErrFetch
		} else {
			parsed, err = Parse(provider.ID, content, format, r.limits)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		// Fetcher errors may contain source URLs, authentication headers, or
		// complete node links. The detailed cause never enters public status.
		if errors.Is(err, ErrFetch) {
			s.status.LastError = ErrFetch.Error()
		} else {
			s.status.LastError = "provider content could not be parsed"
		}
		return Revision{}, ChangeReport{}, err
	}
	revision, changes, err := stageParsed(s, parsed, r.metadataImpact)
	if err != nil {
		s.status.LastError = "provider content could not be parsed"
		return Revision{}, ChangeReport{}, err
	}
	success := time.Now().UTC()
	s.status.LastSuccessAt, s.status.LastError = &success, ""
	return revision, changes, nil
}

func (r *Registry) Get(providerID string, revision int64) (Revision, error) {
	r.boundary.RLock()
	defer r.boundary.RUnlock()
	s := r.state(providerID)
	s.mu.Lock()
	defer s.mu.Unlock()
	rev, ok := s.revisions[revision]
	if !ok {
		return Revision{}, domain.ErrNotFound
	}
	return cloneRevision(rev), nil
}

func (r *Registry) Active(providerID string) (Revision, error) {
	r.boundary.RLock()
	defer r.boundary.RUnlock()
	s := r.state(providerID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.status.Active == 0 {
		return Revision{}, domain.ErrNotFound
	}
	return cloneRevision(s.revisions[s.status.Active]), nil
}

func (r *Registry) List(providerID string) []Revision {
	r.boundary.RLock()
	defer r.boundary.RUnlock()
	s := r.state(providerID)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Revision, 0, len(s.revisions))
	for _, rev := range s.revisions {
		out = append(out, cloneRevision(rev))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out
}

func (r *Registry) Status(providerID string) ProviderStatus {
	r.boundary.RLock()
	defer r.boundary.RUnlock()
	s := r.state(providerID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneStatus(s.status)
}
