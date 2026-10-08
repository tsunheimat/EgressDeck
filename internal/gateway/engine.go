// Package gateway defines the controller-to-data-plane contract.
//
// The interface intentionally describes application semantics instead of dae's
// HTTP or command line surface.  A real adapter can implement the contract
// once its behavior has passed the same tests as the in-process engine below.
package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type CapabilityName string

const (
	CapabilityInventoryRead      CapabilityName = "inventory.read"
	CapabilityProviderStage      CapabilityName = "provider.stage"
	CapabilityProviderPublish    CapabilityName = "provider.publish_hot"
	CapabilitySelectionRuntime   CapabilityName = "selection.set_runtime"
	CapabilitySelectionPersist   CapabilityName = "selection.persist_restart"
	CapabilityPolicyValidate     CapabilityName = "policy.validate"
	CapabilityPolicyApply        CapabilityName = "policy.apply_generation"
	CapabilityProbeNode          CapabilityName = "probe.node"
	CapabilityProbeGroup         CapabilityName = "probe.group"
	CapabilityConnectionsObserve CapabilityName = "connections.observe"
	CapabilityConnectionsClose   CapabilityName = "connections.close_filtered"
	CapabilityProxyCounters      CapabilityName = "traffic.proxy_counters"
	CapabilityDirectCounters     CapabilityName = "traffic.direct_counters"
	CapabilityEventsResume       CapabilityName = "events.resume"
)

var AllCapabilities = []CapabilityName{
	CapabilityInventoryRead, CapabilityProviderStage, CapabilityProviderPublish, CapabilityGroupPublish,
	CapabilitySelectionRuntime, CapabilitySelectionPersist, CapabilityPolicyValidate,
	CapabilityPolicyApply, CapabilityProbeNode, CapabilityProbeGroup,
	CapabilityConnectionsObserve, CapabilityConnectionsClose, CapabilityProxyCounters,
	CapabilityDirectCounters, CapabilityEventsResume,
}

type Capability struct {
	Name           CapabilityName `json:"name"`
	Supported      bool           `json:"supported"`
	Implementation string         `json:"implementation,omitempty"`
	Restrictions   []string       `json:"restrictions,omitempty"`
}

type Capabilities struct {
	Implementation string       `json:"implementation"`
	Version        string       `json:"version"`
	Items          []Capability `json:"capabilities"`
}

func DefaultCapabilities(implementation, version string) Capabilities {
	items := make([]Capability, 0, len(AllCapabilities))
	for _, n := range AllCapabilities {
		items = append(items, Capability{Name: n, Supported: true, Implementation: implementation})
	}
	return Capabilities{Implementation: implementation, Version: version, Items: items}
}

func (c Capabilities) Has(name CapabilityName) bool {
	for _, item := range c.Items {
		if item.Name == name {
			return item.Supported
		}
	}
	return false
}

var (
	ErrUnsupported     = errors.New("gateway capability is unsupported")
	ErrConflict        = errors.New("gateway generation conflict")
	ErrStageNotFound   = errors.New("gateway staged revision not found")
	ErrInvalidRevision = errors.New("invalid provider revision")
	ErrEmptyRevision   = errors.New("provider revision has no nodes")
	ErrSelection       = errors.New("invalid runtime selection")
	ErrJournal         = errors.New("gateway journal write failed")
	ErrBusy            = errors.New("gateway retained state limit reached")
)

type Error struct {
	Code      string `json:"code"`
	Operation string `json:"operation,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Cause     error  `json:"-"`
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Code + ": " + e.Detail
	}
	return e.Code
}
func (e *Error) Unwrap() error { return e.Cause }

func unsupported(op string) error {
	return &Error{Code: "unsupported", Operation: op, Cause: ErrUnsupported}
}
func conflict(op, detail string) error {
	return &Error{Code: "conflict", Operation: op, Detail: detail, Cause: ErrConflict}
}

type Node struct {
	ID             string `json:"id"`
	ProviderID     string `json:"provider_id"`
	Name           string `json:"name"`
	Identity       string `json:"identity,omitempty"`
	DefinitionHash string `json:"definition_hash,omitempty"`
	Handle         uint64 `json:"handle"`
	// Connection is request-local native engine material. It is never included
	// in inventory, snapshots, journals, or public controller responses.
	Connection string `json:"-"`
}

type ProviderRevision struct {
	ProviderID  string `json:"provider_id"`
	Revision    int64  `json:"revision"`
	ContentHash string `json:"content_hash"`
	Nodes       []Node `json:"nodes"`
	// AllowEmpty is only for an explicitly approved empty provider.  Ordinary
	// empty/failed downloads must never evict a working inventory.
	AllowEmpty bool               `json:"allow_empty,omitempty"`
	Groups     []PublicationGroup `json:"groups,omitempty"`
}

type PublicationGroup struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Revision       int64    `json:"revision"`
	CandidateIDs   []string `json:"candidate_ids"`
	SelectedNodeID string   `json:"selected_node_id,omitempty"`
}

func (r ProviderRevision) normalized() (ProviderRevision, error) {
	if strings.TrimSpace(r.ProviderID) == "" {
		return ProviderRevision{}, fmt.Errorf("%w: provider_id is required", ErrInvalidRevision)
	}
	if r.Revision < 0 {
		return ProviderRevision{}, fmt.Errorf("%w: revision must be non-negative", ErrInvalidRevision)
	}
	out := r
	out.Nodes = append([]Node(nil), r.Nodes...)
	out.Groups = append([]PublicationGroup(nil), r.Groups...)
	for i := range out.Groups {
		out.Groups[i].CandidateIDs = append([]string(nil), out.Groups[i].CandidateIDs...)
	}
	seen := map[string]bool{}
	for i := range out.Nodes {
		n := &out.Nodes[i]
		if strings.TrimSpace(n.ID) == "" {
			return ProviderRevision{}, fmt.Errorf("%w: nodes[%d].id is required", ErrInvalidRevision, i)
		}
		if n.ProviderID == "" {
			n.ProviderID = out.ProviderID
		}
		if n.ProviderID != out.ProviderID {
			return ProviderRevision{}, fmt.Errorf("%w: node %s belongs to provider %s", ErrInvalidRevision, n.ID, n.ProviderID)
		}
		if seen[n.ID] {
			return ProviderRevision{}, fmt.Errorf("%w: duplicate node %s", ErrInvalidRevision, n.ID)
		}
		seen[n.ID] = true
	}
	if len(out.Nodes) == 0 && !out.AllowEmpty {
		return ProviderRevision{}, ErrEmptyRevision
	}
	if out.ContentHash == "" {
		b, _ := json.Marshal(out.Nodes)
		h := sha256.Sum256(b)
		out.ContentHash = hex.EncodeToString(h[:])
	}
	return out, nil
}

type OutboundGroup struct {
	Name          string   `json:"name,omitempty"`
	ID            string   `json:"id"`
	ProviderIDs   []string `json:"provider_ids,omitempty"`
	NodeIDs       []string `json:"node_ids"`
	SelectionMode string   `json:"selection_mode,omitempty"`
	Revision      int64    `json:"revision"`
}

type SelectionScope struct {
	GatewayID string `json:"gateway_id"`
	GroupID   string `json:"group_id"`
	Transport string `json:"transport,omitempty"`
}

func (s SelectionScope) key() string { return s.GatewayID + "\x00" + s.GroupID + "\x00" + s.Transport }

type Selection struct {
	Scope          SelectionScope `json:"scope"`
	DesiredNodeID  string         `json:"desired_node_id"`
	ObservedNodeID string         `json:"observed_node_id"`
	Revision       int64          `json:"revision"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type Connection struct {
	ID         string    `json:"id"`
	GroupID    string    `json:"group_id,omitempty"`
	ProviderID string    `json:"provider_id,omitempty"`
	NodeID     string    `json:"node_id,omitempty"`
	Transport  string    `json:"transport,omitempty"`
	State      string    `json:"state,omitempty"`
	OpenedAt   time.Time `json:"opened_at"`
}

type ConnectionFilter struct {
	GroupID, ProviderID, NodeID, Transport string
}

func (f ConnectionFilter) match(c Connection) bool {
	return (f.GroupID == "" || f.GroupID == c.GroupID) && (f.ProviderID == "" || f.ProviderID == c.ProviderID) && (f.NodeID == "" || f.NodeID == c.NodeID) && (f.Transport == "" || f.Transport == c.Transport)
}

type Policy struct {
	ID         string          `json:"id"`
	Generation int64           `json:"generation"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

type ProbeResult struct {
	Target   string        `json:"target"`
	OK       bool          `json:"ok"`
	Latency  time.Duration `json:"latency"`
	Error    string        `json:"error,omitempty"`
	Observed time.Time     `json:"observed_at"`
}

type Counters struct {
	ProxyBytes    uint64 `json:"proxy_bytes"`
	DirectBytes   uint64 `json:"direct_bytes"`
	ProxyPackets  uint64 `json:"proxy_packets"`
	DirectPackets uint64 `json:"direct_packets"`
}

type Event struct {
	ID         int64     `json:"id"`
	Type       string    `json:"type"`
	Generation int64     `json:"generation"`
	Target     string    `json:"target,omitempty"`
	At         time.Time `json:"at"`
	Detail     string    `json:"detail,omitempty"`
}

type Snapshot struct {
	Generation  int64                       `json:"generation"`
	Providers   map[string]ProviderRevision `json:"providers"`
	Groups      map[string]OutboundGroup    `json:"groups"`
	Selections  map[string]Selection        `json:"selections"`
	Connections []Connection                `json:"connections"`
	Counters    Counters                    `json:"counters"`
	Policy      Policy                      `json:"policy"`
	Events      []Event                     `json:"events,omitempty"`
}

// Engine is the complete gateway operation contract. Implementations must
// preserve old active state if staging or publishing fails.
type Engine interface {
	Capabilities(context.Context) (Capabilities, error)
	Inventory(context.Context) (Snapshot, error)
	StageProvider(context.Context, ProviderRevision, int64) (string, error)
	PublishProvider(context.Context, string) (Snapshot, error)
	SetRuntimeSelection(context.Context, SelectionScope, string, int64) (Selection, error)
	PersistSelection(context.Context, SelectionScope, string, int64) (Selection, error)
	ValidatePolicy(context.Context, Policy) error
	ApplyPolicyGeneration(context.Context, Policy, int64) (Snapshot, error)
	ProbeNode(context.Context, string) (ProbeResult, error)
	ProbeGroup(context.Context, string) (ProbeResult, error)
	ObserveConnections(context.Context) ([]Connection, error)
	CloseFiltered(context.Context, ConnectionFilter) (int, error)
	Counters(context.Context) (Counters, error)
	ResumeEvents(context.Context, int64) ([]Event, error)
}

// StageInfoProvider is optional metadata for API adapters that need to report
// the normalized immutable revision returned by StageProvider.
type StageInfoProvider interface {
	StageInfo(string) (ProviderRevision, int64, bool)
}

type JournalEntry struct {
	ID         string          `json:"id"`
	Operation  string          `json:"operation"`
	Target     string          `json:"target,omitempty"`
	Status     string          `json:"status"`
	Generation int64           `json:"generation,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	FinishedAt time.Time       `json:"finished_at,omitempty"`
	Error      string          `json:"error,omitempty"`
	State      json.RawMessage `json:"state,omitempty"`
}

type Journal interface {
	Append(context.Context, JournalEntry) error
	Entries(context.Context) ([]JournalEntry, error)
}

type MemoryJournal struct {
	mu      sync.Mutex
	entries []JournalEntry
}

func NewMemoryJournal() *MemoryJournal { return &MemoryJournal{} }
func (j *MemoryJournal) Append(_ context.Context, e JournalEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = append(j.entries, e)
	return nil
}
func (j *MemoryJournal) Entries(_ context.Context) ([]JournalEntry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]JournalEntry(nil), j.entries...), nil
}

// FileJournal uses newline-delimited JSON so a partially written final record
// can be ignored during recovery. The file is append-only and parent dirs are
// created on first use.
type FileJournal struct {
	mu   sync.Mutex
	Path string
}

func NewFileJournal(path string) *FileJournal { return &FileJournal{Path: path} }
func (j *FileJournal) Append(_ context.Context, e JournalEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if strings.TrimSpace(j.Path) == "" {
		return fmt.Errorf("journal path is required")
	}
	if err := os.MkdirAll(filepathDir(j.Path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(j.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
func (j *FileJournal) Entries(_ context.Context) ([]JournalEntry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	b, err := os.ReadFile(j.Path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []JournalEntry
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e JournalEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}
func filepathDir(path string) string {
	i := strings.LastIndexAny(path, "/\\")
	if i < 0 {
		return "."
	}
	if i == 0 {
		return path[:1]
	}
	return path[:i]
}

type FakeEngine struct {
	mu           sync.RWMutex
	capabilities Capabilities
	generation   int64
	providers    map[string]ProviderRevision
	groups       map[string]OutboundGroup
	selections   map[string]Selection
	staged       map[string]ProviderRevision
	stagedBase   map[string]int64
	handles      map[string]uint64
	nextHandle   uint64
	connections  map[string]Connection
	counters     Counters
	events       []Event
	journal      Journal
	policy       Policy
}

func NewFakeEngine(journals ...Journal) *FakeEngine {
	var j Journal
	if len(journals) > 0 {
		j = journals[0]
	}
	e := &FakeEngine{capabilities: DefaultCapabilities("egressdeck-fake-engine", "0.1.0"), providers: map[string]ProviderRevision{}, groups: map[string]OutboundGroup{}, selections: map[string]Selection{}, staged: map[string]ProviderRevision{}, stagedBase: map[string]int64{}, handles: map[string]uint64{}, nextHandle: 1, connections: map[string]Connection{}, journal: j}
	for i := range e.capabilities.Items {
		e.capabilities.Items[i].Restrictions = []string{"Simulation only. No dae runtime operation, network probe, or traffic verification is performed."}
	}
	if j != nil {
		e.restoreJournal()
	}
	return e
}

func cloneRevision(r ProviderRevision) ProviderRevision {
	r.Nodes = append([]Node(nil), r.Nodes...)
	r.Groups = append([]PublicationGroup(nil), r.Groups...)
	for i := range r.Groups {
		r.Groups[i].CandidateIDs = append([]string(nil), r.Groups[i].CandidateIDs...)
	}
	return r
}
func cloneSnapshot(s Snapshot) Snapshot {
	s.Providers = copyProviders(s.Providers)
	s.Groups = copyGroups(s.Groups)
	s.Selections = copySelections(s.Selections)
	s.Connections = append([]Connection(nil), s.Connections...)
	s.Events = append([]Event(nil), s.Events...)
	s.Policy.Payload = append([]byte(nil), s.Policy.Payload...)
	return s
}
func copyProviders(in map[string]ProviderRevision) map[string]ProviderRevision {
	out := map[string]ProviderRevision{}
	for k, v := range in {
		out[k] = cloneRevision(v)
	}
	return out
}
func copyGroups(in map[string]OutboundGroup) map[string]OutboundGroup {
	out := map[string]OutboundGroup{}
	for k, v := range in {
		v.NodeIDs = append([]string(nil), v.NodeIDs...)
		v.ProviderIDs = append([]string(nil), v.ProviderIDs...)
		out[k] = v
	}
	return out
}
func copySelections(in map[string]Selection) map[string]Selection {
	out := map[string]Selection{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (e *FakeEngine) Capabilities(context.Context) (Capabilities, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	c := e.capabilities
	c.Items = append([]Capability(nil), c.Items...)
	for i := range c.Items {
		c.Items[i].Restrictions = append([]string(nil), c.Items[i].Restrictions...)
	}
	return c, nil
}

// SetCapabilities supports contract tests and adapters whose capabilities are
// restricted by the qualified engine/version combination.
func (e *FakeEngine) SetCapabilities(c Capabilities) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c.Items = append([]Capability(nil), c.Items...)
	e.capabilities = c
}
func (e *FakeEngine) Health(context.Context) (Health, error) {
	return Health{Status: "simulation", Implementation: "egressdeck-fake-engine", ObservedAt: time.Now().UTC(), Details: []string{"Simulation only. No real daemon, packet path, or traffic verification."}}, nil
}
func (e *FakeEngine) supports(capability CapabilityName) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.capabilities.Has(capability)
}
func (e *FakeEngine) Inventory(context.Context) (Snapshot, error) {
	if !e.supports(CapabilityInventoryRead) {
		return Snapshot{}, unsupported("inventory.read")
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.snapshotLocked(), nil
}

// Readback is an explicit alias used by reconciliation code. It returns the
// complete desired/applied/observed snapshot and never reports optimistic
// success from a prior mutation.
func (e *FakeEngine) Readback(ctx context.Context) (Snapshot, error) { return e.Inventory(ctx) }

func (e *FakeEngine) JournalEntries(ctx context.Context) ([]JournalEntry, error) {
	if e.journal == nil {
		return nil, nil
	}
	return e.journal.Entries(ctx)
}
func (e *FakeEngine) snapshotLocked() Snapshot {
	return cloneSnapshot(Snapshot{Generation: e.generation, Providers: e.providers, Groups: e.groups, Selections: e.selections, Connections: valuesConnections(e.connections), Counters: e.counters, Policy: e.policy, Events: e.events})
}
func valuesConnections(in map[string]Connection) []Connection {
	out := make([]Connection, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (e *FakeEngine) appendJournal(ctx context.Context, op, target, status string, generation int64, started time.Time, cause error) {
	if e.journal == nil {
		return
	}
	entry := JournalEntry{ID: fmt.Sprintf("%d-%s", started.UnixNano(), op), Operation: op, Target: target, Status: status, Generation: generation, StartedAt: started, FinishedAt: time.Now().UTC()}
	if cause != nil {
		entry.Error = cause.Error()
	}
	_ = e.journal.Append(ctx, entry)
}

func (e *FakeEngine) appendStateJournal(ctx context.Context, op, target, status string, generation int64, started time.Time, cause error) error {
	if e.journal == nil {
		return nil
	}
	entry := JournalEntry{ID: fmt.Sprintf("%d-%s", started.UnixNano(), op), Operation: op, Target: target, Status: status, Generation: generation, StartedAt: started, FinishedAt: time.Now().UTC()}
	if cause != nil {
		entry.Error = cause.Error()
	}
	if state, err := json.Marshal(e.snapshotLocked()); err == nil {
		entry.State = state
	}
	if err := e.journal.Append(ctx, entry); err != nil {
		return fmt.Errorf("%w: %v", ErrJournal, err)
	}
	return nil
}

func (e *FakeEngine) restoreJournal() {
	entries, err := e.journal.Entries(context.Background())
	if err != nil {
		return
	}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if entry.Status != "published" || len(entry.State) == 0 {
			continue
		}
		var snap Snapshot
		if json.Unmarshal(entry.State, &snap) != nil {
			continue
		}
		e.generation = snap.Generation
		e.providers = copyProviders(snap.Providers)
		e.groups = copyGroups(snap.Groups)
		e.selections = copySelections(snap.Selections)
		e.connections = map[string]Connection{}
		for _, c := range snap.Connections {
			e.connections[c.ID] = c
		}
		e.counters = snap.Counters
		e.policy = snap.Policy
		e.events = append([]Event(nil), snap.Events...)
		for _, p := range e.providers {
			for _, n := range p.Nodes {
				e.handles[n.ID] = n.Handle
				if n.Handle >= e.nextHandle {
					e.nextHandle = n.Handle + 1
				}
			}
		}
		return
	}
}
func (e *FakeEngine) eventLocked(typ, target, detail string) {
	e.events = append(e.events, Event{ID: int64(len(e.events) + 1), Type: typ, Target: target, Generation: e.generation, At: time.Now().UTC(), Detail: detail})
}

func (e *FakeEngine) StageProvider(ctx context.Context, revision ProviderRevision, expectedGeneration int64) (string, error) {
	if !e.supports(CapabilityProviderStage) {
		return "", unsupported("provider.stage")
	}
	started := time.Now().UTC()
	normalized, err := revision.normalized()
	if err != nil {
		e.appendJournal(ctx, "provider.stage", revision.ProviderID, "failed", 0, started, err)
		return "", err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if expectedGeneration != e.generation {
		err = conflict("provider.stage", fmt.Sprintf("expected generation %d, current %d", expectedGeneration, e.generation))
		e.appendJournal(ctx, "provider.stage", normalized.ProviderID, "failed", e.generation, started, err)
		return "", err
	}
	id := fmt.Sprintf("%s:%d:%s", normalized.ProviderID, normalized.Revision, normalized.ContentHash)
	if _, exists := e.staged[id]; !exists && len(e.staged) >= 64 {
		return "", &Error{Code: "busy", Operation: "provider.stage", Detail: "staged revision limit reached; publish or replace existing revisions", Cause: ErrBusy}
	}
	for stagedID, staged := range e.staged {
		if staged.ProviderID == normalized.ProviderID && stagedID != id {
			delete(e.staged, stagedID)
			delete(e.stagedBase, stagedID)
		}
	}
	e.staged[id] = normalized
	e.stagedBase[id] = e.generation
	e.appendJournal(ctx, "provider.stage", normalized.ProviderID, "staged", e.generation, started, nil)
	return id, nil
}

func (e *FakeEngine) StageInfo(stageID string) (ProviderRevision, int64, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	revision, ok := e.staged[stageID]
	if !ok {
		return ProviderRevision{}, 0, false
	}
	return cloneRevision(revision), e.stagedBase[stageID], true
}

func (e *FakeEngine) PublishProvider(ctx context.Context, stageID string) (Snapshot, error) {
	if !e.supports(CapabilityProviderPublish) {
		return Snapshot{}, unsupported("provider.publish_hot")
	}
	started := time.Now().UTC()
	e.mu.Lock()
	defer e.mu.Unlock()
	rev, ok := e.staged[stageID]
	if !ok {
		err := fmt.Errorf("%w: %s", ErrStageNotFound, stageID)
		e.appendJournal(ctx, "provider.publish_hot", stageID, "failed", e.generation, started, err)
		return Snapshot{}, err
	}
	if base := e.stagedBase[stageID]; base != e.generation {
		err := conflict("provider.publish_hot", fmt.Sprintf("staged at generation %d, current %d", base, e.generation))
		e.appendJournal(ctx, "provider.publish_hot", stageID, "failed", e.generation, started, err)
		return Snapshot{}, err
	}
	old, exists := e.providers[rev.ProviderID]
	if exists && old.ContentHash == rev.ContentHash {
		delete(e.staged, stageID)
		delete(e.stagedBase, stageID)
		e.appendJournal(ctx, "provider.publish_hot", rev.ProviderID, "noop", e.generation, started, nil)
		return e.snapshotLocked(), nil
	}
	previousSelections := copySelections(e.selections)
	previousHandles := make(map[string]uint64, len(e.handles))
	for id, handle := range e.handles {
		previousHandles[id] = handle
	}
	previousNextHandle, previousGeneration, previousEvents := e.nextHandle, e.generation, len(e.events)
	previousStage := cloneRevision(rev)
	for i := range rev.Nodes {
		if h := e.handles[rev.Nodes[i].ID]; h != 0 {
			rev.Nodes[i].Handle = h
		} else {
			rev.Nodes[i].Handle = e.nextHandle
			e.handles[rev.Nodes[i].ID] = e.nextHandle
			e.nextHandle++
		}
	}
	// Keep all unrelated providers/groups/connections intact. Selections that
	// point at a removed node become explicitly missing and are read back.
	newIDs := map[string]bool{}
	for _, n := range rev.Nodes {
		newIDs[n.ID] = true
	}
	oldIDs := map[string]bool{}
	for _, n := range old.Nodes {
		oldIDs[n.ID] = true
	}
	for key, sel := range e.selections {
		if oldIDs[sel.DesiredNodeID] && !newIDs[sel.DesiredNodeID] && sel.DesiredNodeID != "" {
			if oldID := sel.ObservedNodeID; oldID != "" && oldID != sel.DesiredNodeID {
				continue
			}
			sel.ObservedNodeID = ""
			e.selections[key] = sel
		}
	}
	e.providers[rev.ProviderID] = cloneRevision(rev)
	// Handles no longer referenced by any published node or active connection
	// may be retired. Existing sessions preserve the handle until drained.
	retainedHandles := map[string]bool{}
	for _, provider := range e.providers {
		for _, node := range provider.Nodes {
			retainedHandles[node.ID] = true
		}
	}
	for _, connection := range e.connections {
		retainedHandles[connection.NodeID] = true
	}
	for nodeID := range e.handles {
		if !retainedHandles[nodeID] {
			delete(e.handles, nodeID)
		}
	}
	delete(e.staged, stageID)
	delete(e.stagedBase, stageID)
	e.generation++
	e.eventLocked("provider.published", rev.ProviderID, rev.ContentHash)
	if err := e.appendStateJournal(ctx, "provider.publish_hot", rev.ProviderID, "published", e.generation, started, nil); err != nil {
		if exists {
			e.providers[rev.ProviderID] = old
		} else {
			delete(e.providers, rev.ProviderID)
		}
		e.selections, e.handles, e.nextHandle, e.generation = previousSelections, previousHandles, previousNextHandle, previousGeneration
		e.events = e.events[:previousEvents]
		e.staged[stageID], e.stagedBase[stageID] = previousStage, previousGeneration
		return Snapshot{}, err
	}
	return e.snapshotLocked(), nil
}

func (e *FakeEngine) findNodeLocked(id string) (Node, bool) {
	for _, p := range e.providers {
		for _, n := range p.Nodes {
			if n.ID == id {
				return n, true
			}
		}
	}
	return Node{}, false
}
func (e *FakeEngine) SetRuntimeSelection(ctx context.Context, scope SelectionScope, nodeID string, expectedRevision int64) (Selection, error) {
	if !e.supports(CapabilitySelectionRuntime) {
		return Selection{}, unsupported("selection.set_runtime")
	}
	return e.setSelection(ctx, scope, nodeID, expectedRevision, false)
}
func (e *FakeEngine) PersistSelection(ctx context.Context, scope SelectionScope, nodeID string, expectedRevision int64) (Selection, error) {
	if !e.supports(CapabilitySelectionPersist) {
		return Selection{}, unsupported("selection.persist_restart")
	}
	return e.setSelection(ctx, scope, nodeID, expectedRevision, true)
}
func (e *FakeEngine) setSelection(ctx context.Context, scope SelectionScope, nodeID string, expectedRevision int64, persist bool) (Selection, error) {
	started := time.Now().UTC()
	if strings.TrimSpace(scope.GroupID) == "" || strings.TrimSpace(scope.GatewayID) == "" || strings.TrimSpace(nodeID) == "" {
		err := fmt.Errorf("%w: group, gateway and node are required", ErrSelection)
		e.appendJournal(ctx, "selection.set_runtime", scope.GroupID, "failed", 0, started, err)
		return Selection{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.findNodeLocked(nodeID); !ok {
		err := fmt.Errorf("%w: node %s not found", ErrSelection, nodeID)
		e.appendJournal(ctx, "selection.set_runtime", scope.GroupID, "failed", e.generation, started, err)
		return Selection{}, err
	}
	key := scope.key()
	old := e.selections[key]
	previousSelection, hadSelection, previousEvents := old, old.Revision > 0, len(e.events)
	if expectedRevision != old.Revision {
		err := conflict("selection.set_runtime", fmt.Sprintf("expected revision %d, current %d", expectedRevision, old.Revision))
		e.appendJournal(ctx, "selection.set_runtime", scope.GroupID, "failed", e.generation, started, err)
		return Selection{}, err
	}
	old.Scope = scope
	old.DesiredNodeID = nodeID
	old.ObservedNodeID = nodeID
	old.Revision++
	old.UpdatedAt = time.Now().UTC()
	e.selections[key] = old
	e.eventLocked("selection.changed", scope.GroupID, nodeID)
	op := "selection.set_runtime"
	if persist {
		op = "selection.persist_restart"
	}
	if persist {
		if err := e.appendStateJournal(ctx, op, scope.GroupID, "published", e.generation, started, nil); err != nil {
			if hadSelection {
				e.selections[key] = previousSelection
			} else {
				delete(e.selections, key)
			}
			e.events = e.events[:previousEvents]
			return Selection{}, err
		}
	} else {
		e.appendJournal(ctx, op, scope.GroupID, "published", e.generation, started, nil)
	}
	return old, nil
}

func (e *FakeEngine) ValidatePolicy(_ context.Context, p Policy) error {
	if !e.supports(CapabilityPolicyValidate) {
		return unsupported("policy.validate")
	}
	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("policy id is required")
	}
	if p.Generation < 0 {
		return fmt.Errorf("policy generation must be non-negative")
	}
	return nil
}
func (e *FakeEngine) ApplyPolicyGeneration(ctx context.Context, p Policy, expectedGeneration int64) (Snapshot, error) {
	if !e.supports(CapabilityPolicyApply) {
		return Snapshot{}, unsupported("policy.apply_generation")
	}
	started := time.Now().UTC()
	if err := e.ValidatePolicy(ctx, p); err != nil {
		return Snapshot{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if expectedGeneration != e.generation {
		err := conflict("policy.apply_generation", fmt.Sprintf("expected generation %d, current %d", expectedGeneration, e.generation))
		e.appendJournal(ctx, "policy.apply_generation", p.ID, "failed", e.generation, started, err)
		return Snapshot{}, err
	}
	previousPolicy, previousGeneration, previousEvents := e.policy, e.generation, len(e.events)
	e.policy = p
	e.generation++
	e.eventLocked("policy.applied", p.ID, "")
	if err := e.appendStateJournal(ctx, "policy.apply_generation", p.ID, "published", e.generation, started, nil); err != nil {
		e.policy, e.generation = previousPolicy, previousGeneration
		e.events = e.events[:previousEvents]
		return Snapshot{}, err
	}
	return e.snapshotLocked(), nil
}
func (e *FakeEngine) ProbeNode(ctx context.Context, nodeID string) (ProbeResult, error) {
	if !e.supports(CapabilityProbeNode) {
		return ProbeResult{}, unsupported("probe.node")
	}
	started := time.Now()
	e.mu.RLock()
	_, ok := e.findNodeLocked(nodeID)
	e.mu.RUnlock()
	if !ok {
		return ProbeResult{Target: nodeID, Observed: time.Now().UTC(), Error: "node not found"}, fmt.Errorf("%w: node %s", ErrSelection, nodeID)
	}
	return ProbeResult{Target: nodeID, OK: true, Latency: time.Since(started), Observed: time.Now().UTC()}, nil
}
func (e *FakeEngine) ProbeGroup(_ context.Context, groupID string) (ProbeResult, error) {
	if !e.supports(CapabilityProbeGroup) {
		return ProbeResult{}, unsupported("probe.group")
	}
	e.mu.RLock()
	g, ok := e.groups[groupID]
	e.mu.RUnlock()
	if !ok {
		return ProbeResult{Target: groupID, Observed: time.Now().UTC(), Error: "group not found"}, fmt.Errorf("%w: group %s", ErrSelection, groupID)
	}
	return ProbeResult{Target: groupID, OK: len(g.NodeIDs) > 0, Observed: time.Now().UTC()}, nil
}
func (e *FakeEngine) ObserveConnections(_ context.Context) ([]Connection, error) {
	if !e.supports(CapabilityConnectionsObserve) {
		return nil, unsupported("connections.observe")
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return valuesConnections(e.connections), nil
}
func (e *FakeEngine) CloseFiltered(_ context.Context, f ConnectionFilter) (int, error) {
	if !e.supports(CapabilityConnectionsClose) {
		return 0, unsupported("connections.close_filtered")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for id, c := range e.connections {
		if f.match(c) {
			delete(e.connections, id)
			n++
		}
	}
	return n, nil
}
func (e *FakeEngine) Counters(_ context.Context) (Counters, error) {
	if !e.supports(CapabilityProxyCounters) || !e.supports(CapabilityDirectCounters) {
		return Counters{}, unsupported("traffic.counters")
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.counters, nil
}
func (e *FakeEngine) ResumeEvents(_ context.Context, after int64) ([]Event, error) {
	if !e.supports(CapabilityEventsResume) {
		return nil, unsupported("events.resume")
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := []Event{}
	for _, v := range e.events {
		if v.ID > after {
			out = append(out, v)
		}
	}
	return out, nil
}

// AddGroup and AddConnection are test/adapter helpers. They do not pretend to
// be control-plane operations; production adapters populate these via the
// engine's native inventory.
func (e *FakeEngine) AddGroup(g OutboundGroup) {
	e.mu.Lock()
	defer e.mu.Unlock()
	g.NodeIDs = append([]string(nil), g.NodeIDs...)
	e.groups[g.ID] = g
}
func (e *FakeEngine) AddConnection(c Connection) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c.OpenedAt.IsZero() {
		c.OpenedAt = time.Now().UTC()
	}
	e.connections[c.ID] = c
}
func (e *FakeEngine) AddTraffic(proxy bool, bytes, packets uint64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if proxy {
		e.counters.ProxyBytes += bytes
		e.counters.ProxyPackets += packets
	} else {
		e.counters.DirectBytes += bytes
		e.counters.DirectPackets += packets
	}
}
