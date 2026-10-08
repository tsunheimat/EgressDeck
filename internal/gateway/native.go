package gateway

// NativeEngine speaks only the authenticated Unix API supplied by the patched
// dae runtime. It never starts, reloads, or substitutes a simulated daemon.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
)

type NativeOptions struct {
	SocketPath string
	Timeout    time.Duration
	Vault      *secrets.Vault
}

// NativeEngine keeps only encrypted private management requests in its journal.
// Native inventory remains authoritative after any agent or daemon restart.
type NativeEngine struct {
	mu      sync.Mutex
	options NativeOptions
	journal Journal
	state   nativeState
}

type nativeState struct {
	Version    int                             `json:"version"`
	Staged     map[string]nativeStage          `json:"staged"`
	Active     map[string]ProviderStageRequest `json:"active"`
	Selections map[string]Selection            `json:"selections"`
	Pending    *nativePendingSelection         `json:"pending_selection,omitempty"`
}
type nativeStage struct {
	Request ProviderStageRequest `json:"request"`
	Pending bool                 `json:"pending"`
}
type nativePendingSelection struct {
	Scope            SelectionScope `json:"scope"`
	Node             string         `json:"node"`
	BaseGeneration   uint64         `json:"base_generation"`
	ExpectedRevision int64          `json:"expected_revision"`
}
type nativeInventory struct {
	Generation uint64        `json:"generation"`
	Groups     []nativeGroup `json:"groups"`
}
type nativeGroup struct {
	Handle    uint8  `json:"handle"`
	Name      string `json:"name"`
	Identity  string `json:"identity"`
	Selection string `json:"selection"`
}
type nativePublicationGroup struct {
	Name         string   `json:"name"`
	CandidateIDs []string `json:"candidate_ids"`
	Selection    string   `json:"selection"`
}
type nativePublishRequest struct {
	ExpectedGeneration uint64                   `json:"expected_generation"`
	ProviderID         string                   `json:"provider_id"`
	RevisionID         string                   `json:"revision_id"`
	Nodes              []nativeNode             `json:"nodes"`
	Groups             []nativePublicationGroup `json:"groups"`
}
type nativeNode struct {
	ID   string `json:"id"`
	Link string `json:"link"`
}
type nativeMutationResponse struct {
	Snapshot       nativeInventory `json:"snapshot"`
	Adopted        []int           `json:"adopted"`
	CleanupPending bool            `json:"cleanup_pending"`
}

func NewNativeEngine(options NativeOptions, journal Journal) (*NativeEngine, error) {
	if !filepath.IsAbs(options.SocketPath) {
		return nil, errors.New("native mode requires an absolute daemon socket path")
	}
	if options.Vault == nil || journal == nil {
		return nil, errors.New("native mode requires a durable journal and encryption key")
	}
	if options.Timeout <= 0 {
		options.Timeout = 10 * time.Second
	}
	e := &NativeEngine{options: options, journal: journal, state: nativeState{Version: 1, Staged: map[string]nativeStage{}, Active: map[string]ProviderStageRequest{}, Selections: map[string]Selection{}}}
	entries, err := journal.Entries(context.Background())
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read native journal", ErrJournal)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Operation != "native.state" {
			continue
		}
		var envelope secrets.Envelope
		if json.Unmarshal(entries[i].State, &envelope) != nil || options.Vault.OpenJSON(e.stateBinding(), envelope, &e.state) != nil || e.state.Version != 1 || e.state.Staged == nil || e.state.Active == nil || e.state.Selections == nil {
			return nil, fmt.Errorf("%w: native journal cannot be authenticated", ErrJournal)
		}
		break
	}
	return e, nil
}

func (e *NativeEngine) stateBinding() string {
	return "egressdeck.native-journal:" + e.options.SocketPath
}
func (e *NativeEngine) persist(ctx context.Context, state nativeState, status string) error {
	envelope, err := e.options.Vault.SealJSON(e.stateBinding(), state)
	if err != nil {
		return fmt.Errorf("%w: native state encryption failed", ErrJournal)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("%w: native state encoding failed", ErrJournal)
	}
	now := time.Now().UTC()
	err = e.journal.Append(ctx, JournalEntry{ID: strconv.FormatInt(now.UnixNano(), 10), Operation: "native.state", Status: status, StartedAt: now, FinishedAt: now, State: encoded})
	if err != nil {
		return fmt.Errorf("%w: native state write failed", ErrJournal)
	}
	e.state = state
	return nil
}
func (e *NativeEngine) cloneState() nativeState {
	b, _ := json.Marshal(e.state)
	var out nativeState
	_ = json.Unmarshal(b, &out)
	return out
}

func nativeUnavailable(detail string) error {
	return &Error{Code: "unavailable", Detail: detail, Cause: ErrUnavailable}
}
func nativeUnknown() error {
	return &Error{Code: "outcome_unknown", Detail: "native mutation requires authoritative readback before another mutation", Cause: ErrUnavailable}
}

func verifyNativeSocket(path string) error {
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSocket == 0 {
		return nativeUnavailable("native socket is unavailable")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || st.Mode().Perm() != 0o600 {
		return nativeUnavailable("native socket ownership or permissions are unsafe")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0o700 {
		return nativeUnavailable("native socket parent permissions are unsafe")
	}
	if owner, ok := parent.Sys().(*syscall.Stat_t); !ok || owner.Uid != uint32(os.Geteuid()) {
		return nativeUnavailable("native socket parent ownership is unsafe")
	}
	return nil
}
func verifyNativePeer(conn net.Conn) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nativeUnavailable("native transport is not Unix")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nativeUnavailable("native peer identity is unavailable")
	}
	var credential *syscall.Ucred
	var readErr error
	err = raw.Control(func(fd uintptr) {
		credential, readErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || readErr != nil || credential == nil || credential.Uid != uint32(os.Geteuid()) {
		return nativeUnavailable("native peer identity does not match the agent")
	}
	return nil
}
func (e *NativeEngine) do(ctx context.Context, method, path string, input, output any) error {
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if err := verifyNativeSocket(e.options.SocketPath); err != nil {
			return nil, err
		}
		d := net.Dialer{Timeout: e.options.Timeout}
		conn, err := d.DialContext(ctx, "unix", e.options.SocketPath)
		if err != nil {
			return nil, nativeUnavailable("native socket connection failed")
		}
		if err := verifyNativePeer(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: e.options.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("native redirect rejected") }}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil || len(encoded) > 1<<20 {
			return fmt.Errorf("%w: native request exceeds the encoding limit", ErrInvalidRevision)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://native"+path, body)
	if err != nil {
		return nativeUnavailable("native request could not be created")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nativeUnavailable("native request did not complete")
	}
	defer resp.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(encoded) > 1<<20 {
		return nativeUnavailable("native response exceeds the decoding limit")
	}
	if resp.StatusCode != http.StatusOK {
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(encoded, &envelope)
		// Do not echo daemon diagnostics: parser errors can contain node links.
		switch envelope.Error.Code {
		case "generation_conflict":
			return conflict("native", "native generation changed")
		case "inventory_busy":
			return &Error{Code: "busy", Detail: "native retained inventory is full", Cause: ErrBusy}
		case "invalid_request":
			return &Error{Code: "invalid_request", Detail: "native daemon rejected the request", Cause: ErrInvalidRevision}
		case "outcome_unknown":
			return nativeUnknown()
		default:
			return nativeUnavailable("native daemon rejected the operation")
		}
	}
	if len(encoded) == 0 || json.Unmarshal(encoded, output) != nil {
		return nativeUnavailable("native response is malformed")
	}
	return nil
}
func (e *NativeEngine) inventory(ctx context.Context) (nativeInventory, error) {
	var inv nativeInventory
	if err := e.do(ctx, http.MethodGet, "/v1/inventory", nil, &inv); err != nil {
		return inv, err
	}
	if inv.Generation > uint64(^uint64(0)>>1) || inv.Groups == nil {
		return inv, nativeUnavailable("native inventory has invalid generation or groups")
	}
	names, handles := map[string]bool{}, map[uint8]bool{}
	for _, g := range inv.Groups {
		if g.Name == "" || names[g.Name] || handles[g.Handle] {
			return inv, nativeUnavailable("native inventory contains duplicate or unnamed groups")
		}
		names[g.Name] = true
		handles[g.Handle] = true
	}
	return inv, nil
}
func nativeIdentity(r ProviderStageRequest) string {
	return r.ProviderID + "/" + strconv.FormatInt(r.Revision, 10)
}
func nativeGroupByName(inv nativeInventory, name string) (nativeGroup, bool) {
	for _, g := range inv.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return nativeGroup{}, false
}
func nativeRequestObserved(inv nativeInventory, r ProviderStageRequest) bool {
	if len(r.Groups) == 0 {
		return false
	}
	for _, g := range r.Groups {
		observed, ok := nativeGroupByName(inv, g.Name)
		if !ok || observed.Identity != nativeIdentity(r) {
			return false
		}
	}
	return true
}
func (e *NativeEngine) reconcile(ctx context.Context, inv nativeInventory) error {
	next := e.cloneState()
	changed := false
	for id, stage := range next.Staged {
		if !stage.Pending {
			continue
		}
		if nativeRequestObserved(inv, stage.Request) && inv.Generation > uint64(stage.Request.ExpectedGeneration) {
			next.Active[stage.Request.ProviderID] = stage.Request
			for _, group := range stage.Request.Groups {
				selection, existed := next.Selections[group.ID]
				if selection.Scope.GroupID == "" {
					selection.Scope = SelectionScope{GroupID: group.ID, Transport: "both"}
				}
				if existed && selection.DesiredNodeID != group.SelectedNodeID {
					selection.Revision++
				}
				selection.DesiredNodeID = group.SelectedNodeID
				observed, _ := nativeGroupByName(inv, group.Name)
				selection.ObservedNodeID = observed.Selection
				selection.UpdatedAt = time.Now().UTC()
				next.Selections[group.ID] = selection
			}
			delete(next.Staged, id)
			changed = true
			continue
		}
		return nativeUnknown()
	}
	if p := next.Pending; p != nil {
		name, active, ok := nativeManagedGroup(next, p.Scope.GroupID)
		g, found := nativeGroupByName(inv, name)
		if ok && found && nativeRequestObserved(inv, active) && g.Selection == p.Node && inv.Generation > p.BaseGeneration {
			next.Selections[p.Scope.GroupID] = Selection{Scope: p.Scope, DesiredNodeID: p.Node, ObservedNodeID: p.Node, Revision: p.ExpectedRevision + 1, UpdatedAt: time.Now().UTC()}
			next.Pending = nil
			changed = true
		} else {
			return nativeUnknown()
		}
	}
	for _, active := range next.Active {
		if !nativeRequestObserved(inv, active) {
			continue
		}
		for _, group := range active.Groups {
			observed, _ := nativeGroupByName(inv, group.Name)
			selection, exists := next.Selections[group.ID]
			if exists && selection.ObservedNodeID != observed.Selection {
				selection.ObservedNodeID = observed.Selection
				selection.Revision++
				selection.UpdatedAt = time.Now().UTC()
				next.Selections[group.ID] = selection
				changed = true
			}
		}
	}
	if changed {
		return e.persist(ctx, next, "readback")
	}
	return nil
}
func nativeManagedGroup(s nativeState, id string) (string, ProviderStageRequest, bool) {
	for _, r := range s.Active {
		for _, g := range r.Groups {
			if g.ID == id {
				return g.Name, r, true
			}
		}
	}
	return "", ProviderStageRequest{}, false
}
func (e *NativeEngine) snapshot(inv nativeInventory) Snapshot {
	s := Snapshot{Generation: int64(inv.Generation), Providers: map[string]ProviderRevision{}, Groups: map[string]OutboundGroup{}, Selections: map[string]Selection{}}
	claimed := map[string]bool{}
	for provider, r := range e.state.Active {
		if !nativeRequestObserved(inv, r) {
			continue
		}
		revision := r.ProviderRevision()
		for i := range revision.Nodes {
			revision.Nodes[i].Connection = ""
			revision.Nodes[i].Identity = ""
			revision.Nodes[i].DefinitionHash = ""
		}
		s.Providers[provider] = revision
		for _, g := range r.Groups {
			observed, _ := nativeGroupByName(inv, g.Name)
			claimed[g.Name] = true
			s.Groups[g.ID] = OutboundGroup{ID: g.ID, Name: g.Name, ProviderIDs: []string{provider}, NodeIDs: append([]string(nil), g.CandidateIDs...), SelectionMode: "manual", Revision: g.Revision}
			selection := e.state.Selections[g.ID]
			if selection.Scope.GroupID == "" {
				selection.Scope = SelectionScope{GroupID: g.ID, Transport: "both"}
			}
			if selection.DesiredNodeID == "" {
				selection.DesiredNodeID = g.SelectedNodeID
			}
			selection.ObservedNodeID = observed.Selection
			s.Selections[selection.Scope.key()] = selection
		}
	}
	// Unknown daemon-owned groups have no asserted provider, candidates, or
	// controller selection revision. They remain visible by their native name.
	for _, g := range inv.Groups {
		if !claimed[g.Name] {
			s.Groups[g.Name] = OutboundGroup{ID: g.Name, Name: g.Name, SelectionMode: "manual"}
		}
	}
	return s
}
func (e *NativeEngine) Inventory(ctx context.Context) (Snapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	inv, err := e.inventory(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if err = e.reconcile(ctx, inv); err != nil {
		return Snapshot{}, err
	}
	return e.snapshot(inv), nil
}
func (e *NativeEngine) StageInfo(id string) (ProviderRevision, int64, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.state.Staged[id]
	if !ok {
		return ProviderRevision{}, 0, false
	}
	r := s.Request.ProviderRevision()
	for i := range r.Nodes {
		r.Nodes[i].Connection = ""
	}
	return r, s.Request.ExpectedGeneration, true
}
func (e *NativeEngine) StageProvider(ctx context.Context, revision ProviderRevision, expected int64) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if expected < 0 {
		return "", conflict("provider.stage", "expected generation must be nonnegative")
	}
	r, err := revision.normalized()
	if err != nil {
		return "", err
	}
	if strings.Contains(r.ProviderID, "/") || len(r.Groups) == 0 {
		return "", fmt.Errorf("%w: native mode requires publication groups and a provider ID without slashes", ErrInvalidRevision)
	}
	if len(r.Nodes) == 0 {
		return "", ErrEmptyRevision
	}
	nodes := map[string]bool{}
	for _, n := range r.Nodes {
		if strings.TrimSpace(n.Connection) == "" {
			return "", fmt.Errorf("%w: every native node requires a connection", ErrInvalidRevision)
		}
		nodes[n.ID] = true
	}
	groupIDs, groupNames := map[string]bool{}, map[string]bool{}
	for _, g := range r.Groups {
		if g.ID == "" || g.Name == "" || g.Revision < 0 || len(g.CandidateIDs) == 0 || groupIDs[g.ID] || groupNames[g.Name] {
			return "", fmt.Errorf("%w: unique native group metadata and candidates are required", ErrInvalidRevision)
		}
		groupIDs[g.ID], groupNames[g.Name] = true, true
		candidates := map[string]bool{}
		for _, id := range g.CandidateIDs {
			if !nodes[id] || candidates[id] {
				return "", fmt.Errorf("%w: native group references invalid candidates", ErrInvalidRevision)
			}
			candidates[id] = true
		}
		if !candidates[g.SelectedNodeID] {
			return "", fmt.Errorf("%w: native selection must reference a group candidate", ErrInvalidRevision)
		}
	}
	inv, err := e.inventory(ctx)
	if err != nil {
		return "", err
	}
	if err = e.reconcile(ctx, inv); err != nil {
		return "", err
	}
	if int64(inv.Generation) != expected {
		return "", conflict("provider.stage", "expected generation does not match native inventory")
	}
	for _, g := range r.Groups {
		if _, ok := nativeGroupByName(inv, g.Name); !ok {
			return "", fmt.Errorf("%w: native group name is not predeclared", ErrInvalidRevision)
		}
	}
	for provider, active := range e.state.Active {
		for _, existing := range active.Groups {
			if provider != r.ProviderID && (groupIDs[existing.ID] || groupNames[existing.Name]) {
				return "", fmt.Errorf("%w: native group is already managed by another provider", ErrInvalidRevision)
			}
		}
		if provider == r.ProviderID && r.Revision <= active.Revision {
			return "", conflict("provider.stage", "provider revision must advance")
		}
	}
	req := NewProviderStageRequest(r, expected)
	wire := nativePublishWire(req)
	if encoded, err := json.Marshal(wire); err != nil || len(encoded) > 1<<20 {
		return "", fmt.Errorf("%w: native publication exceeds 1 MiB", ErrInvalidRevision)
	}
	fingerprint := nativeStageHash(req)
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("%w: stage token generation failed", ErrUnavailable)
	}
	id := "native_" + hex.EncodeToString(token[:])
	next := e.cloneState()
	for stagedID, stage := range next.Staged {
		if stage.Request.ProviderID == r.ProviderID {
			if stage.Request.Revision > r.Revision {
				return "", conflict("provider.stage", "staged provider revision must not regress")
			}
			if stage.Request.Revision == r.Revision && nativeStageHash(stage.Request) != fingerprint {
				return "", conflict("provider.stage", "immutable revision was already staged with different content")
			}
			if stage.Request.Revision == r.Revision && stage.Request.ExpectedGeneration == expected {
				return stagedID, nil
			}
			delete(next.Staged, stagedID)
		}
	}
	if len(next.Staged) >= 64 {
		return "", &Error{Code: "busy", Cause: ErrBusy}
	}
	next.Staged[id] = nativeStage{Request: req}
	if err = e.persist(ctx, next, "staged"); err != nil {
		return "", err
	}
	return id, nil
}
func (e *NativeEngine) PublishProvider(ctx context.Context, id string) (Snapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	stage, ok := e.state.Staged[id]
	if !ok {
		return Snapshot{}, ErrStageNotFound
	}
	inv, err := e.inventory(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if err = e.reconcile(ctx, inv); err != nil {
		return Snapshot{}, err
	}
	if _, ok = e.state.Staged[id]; !ok {
		return e.snapshot(inv), nil
	}
	if int64(inv.Generation) != stage.Request.ExpectedGeneration {
		return Snapshot{}, conflict("provider.publish_hot", "staged generation does not match native inventory")
	}
	next := e.cloneState()
	stage.Pending = true
	next.Staged[id] = stage
	if err = e.persist(ctx, next, "publish_pending"); err != nil {
		return Snapshot{}, err
	}
	r := stage.Request
	request := nativePublishWire(r)
	var ack nativeMutationResponse
	mutationErr := e.do(ctx, http.MethodPost, "/v1/providers/publish", request, &ack)
	if definiteNativeRejection(mutationErr) {
		next := e.cloneState()
		stage.Pending = false
		next.Staged[id] = stage
		if err := e.persist(context.WithoutCancel(ctx), next, "publish_rejected"); err != nil {
			return Snapshot{}, err
		}
		return Snapshot{}, mutationErr
	}
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.options.Timeout)
	defer cancel()
	read, readErr := e.inventory(readCtx)
	if readErr != nil {
		return Snapshot{}, nativeUnknown()
	}
	if err = e.reconcile(readCtx, read); err != nil {
		return Snapshot{}, err
	}
	if active, ok := e.state.Active[r.ProviderID]; ok && nativeIdentity(active) == nativeIdentity(r) && nativeRequestObserved(read, r) {
		return e.snapshot(read), nil
	}
	if mutationErr != nil {
		return Snapshot{}, mutationErr
	}
	return Snapshot{}, nativeUnknown()
}
func (e *NativeEngine) SetRuntimeSelection(ctx context.Context, scope SelectionScope, node string, expected int64) (Selection, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if scope.Transport != "" && scope.Transport != "both" {
		return Selection{}, &Error{Code: "unsupported", Operation: "selection.set_runtime", Detail: "native group selection is shared by TCP and UDP; use transport both", Cause: ErrUnsupported}
	}
	if expected < 0 || scope.GroupID == "" || node == "" {
		return Selection{}, ErrSelection
	}
	inv, err := e.inventory(ctx)
	if err != nil {
		return Selection{}, err
	}
	if err = e.reconcile(ctx, inv); err != nil {
		return Selection{}, err
	}
	name, r, ok := nativeManagedGroup(e.state, scope.GroupID)
	if !ok || !nativeRequestObserved(inv, r) {
		return Selection{}, ErrSelection
	}
	group, ok := nativeGroupByName(inv, name)
	if !ok {
		return Selection{}, ErrSelection
	}
	valid := false
	for _, g := range r.Groups {
		if g.ID == scope.GroupID {
			for _, id := range g.CandidateIDs {
				if id == node {
					valid = true
				}
			}
		}
	}
	if !valid {
		return Selection{}, ErrSelection
	}
	current := e.state.Selections[scope.GroupID]
	if current.Revision != expected {
		return Selection{}, conflict("selection.set_runtime", "selection revision changed")
	}
	if group.Selection == node {
		selection := Selection{Scope: scope, DesiredNodeID: node, ObservedNodeID: node, Revision: expected + 1, UpdatedAt: time.Now().UTC()}
		next := e.cloneState()
		next.Selections[scope.GroupID] = selection
		if err := e.persist(ctx, next, "selection_unchanged"); err != nil {
			return Selection{}, err
		}
		return selection, nil
	}
	next := e.cloneState()
	next.Pending = &nativePendingSelection{Scope: scope, Node: node, BaseGeneration: inv.Generation, ExpectedRevision: expected}
	if err = e.persist(ctx, next, "selection_pending"); err != nil {
		return Selection{}, err
	}
	var ack nativeMutationResponse
	mutationErr := e.do(ctx, http.MethodPost, "/v1/selection", nativeSelectionRequest{ExpectedGeneration: inv.Generation, Handle: group.Handle, CandidateID: node}, &ack)
	if definiteNativeRejection(mutationErr) {
		next := e.cloneState()
		next.Pending = nil
		if err := e.persist(context.WithoutCancel(ctx), next, "selection_rejected"); err != nil {
			return Selection{}, err
		}
		return Selection{}, mutationErr
	}
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.options.Timeout)
	defer cancel()
	read, readErr := e.inventory(readCtx)
	if readErr != nil {
		return Selection{}, nativeUnknown()
	}
	if err = e.reconcile(readCtx, read); err != nil {
		return Selection{}, err
	}
	selection := e.state.Selections[scope.GroupID]
	if selection.Revision > expected && selection.ObservedNodeID == node {
		return selection, nil
	}
	if mutationErr != nil {
		return Selection{}, mutationErr
	}
	return Selection{}, nativeUnknown()
}

type nativeSelectionRequest struct {
	ExpectedGeneration uint64 `json:"expected_generation"`
	Handle             uint8  `json:"handle"`
	CandidateID        string `json:"candidate_id"`
}

func (e *NativeEngine) Capabilities(ctx context.Context) (Capabilities, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err := e.inventory(ctx)
	c := Capabilities{Implementation: "dae-native-unix", Version: "v1", Items: make([]Capability, 0, len(AllCapabilities))}
	for _, name := range AllCapabilities {
		supported := err == nil && (name == CapabilityInventoryRead || name == CapabilityProviderStage || name == CapabilityProviderPublish || name == CapabilitySelectionRuntime || name == CapabilitySelectionPersist)
		item := Capability{Name: name, Supported: supported, Implementation: c.Implementation}
		if name == CapabilityProviderStage || name == CapabilityProviderPublish {
			item.Restrictions = []string{"One provider per group; predeclared native group names; private native links required; encrypted agent journal required."}
		}
		if name == CapabilitySelectionRuntime {
			item.Restrictions = []string{"Manual selection shared by TCP and UDP; transport must be both or empty; independent transport selection is unsupported."}
		}
		if name == CapabilitySelectionPersist {
			item.Restrictions = []string{"Requires patched daemon encrypted native journal, retained external daemon and agent encryption keys, and unchanged predeclared native group layout."}
		}
		if name == CapabilityPolicyApply {
			item.Restrictions = []string{"Full policy reload is disabled in native mode."}
		}
		if err != nil {
			item.Restrictions = append(item.Restrictions, "Native inventory is currently unavailable.")
		}
		c.Items = append(c.Items, item)
	}
	return c, nil
}
func (e *NativeEngine) Health(ctx context.Context) (Health, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err := e.inventory(ctx)
	h := Health{Status: "degraded", Implementation: "dae-native-unix", ObservedAt: time.Now().UTC(), Details: []string{"Authenticated native inventory readback does not establish privileged packet-path or eBPF acceptance."}}
	if err != nil {
		h.Status = "unavailable"
		h.Details = append(h.Details, "Native inventory unavailable.")
	}
	return h, nil
}
func (e *NativeEngine) PersistSelection(ctx context.Context, scope SelectionScope, node string, expected int64) (Selection, error) {
	// The native mutation commits the daemon encrypted journal before adoption.
	return e.SetRuntimeSelection(ctx, scope, node, expected)
}
func (*NativeEngine) ApplyPolicyGeneration(context.Context, Policy, int64) (Snapshot, error) {
	return Snapshot{}, unsupported("policy.apply_generation")
}
func (*NativeEngine) ValidatePolicy(context.Context, Policy) error {
	return unsupported("policy.validate")
}
func (*NativeEngine) ProbeNode(context.Context, string) (ProbeResult, error) {
	return ProbeResult{}, unsupported("probe.node")
}
func (*NativeEngine) ProbeGroup(context.Context, string) (ProbeResult, error) {
	return ProbeResult{}, unsupported("probe.group")
}
func (*NativeEngine) ObserveConnections(context.Context) ([]Connection, error) {
	return nil, unsupported("connections.observe")
}
func (*NativeEngine) CloseFiltered(context.Context, ConnectionFilter) (int, error) {
	return 0, unsupported("connections.close_filtered")
}
func (*NativeEngine) Counters(context.Context) (Counters, error) {
	return Counters{}, unsupported("traffic.counters")
}
func (*NativeEngine) ResumeEvents(context.Context, int64) ([]Event, error) {
	return nil, unsupported("events.resume")
}

var _ Engine = (*NativeEngine)(nil)

// A transport failure leaves a request potentially running in the daemon.
// An unchanged readback must therefore never unlock a retry. Only explicit
// rejections from the native transaction boundary release the pending intent.
func definiteNativeRejection(err error) bool {
	var typed *Error
	if !errors.As(err, &typed) {
		return false
	}
	return typed.Code == "conflict" || typed.Code == "busy" || typed.Code == "invalid_request"
}

func nativePublishWire(r ProviderStageRequest) nativePublishRequest {
	request := nativePublishRequest{ExpectedGeneration: uint64(r.ExpectedGeneration), ProviderID: r.ProviderID, RevisionID: strconv.FormatInt(r.Revision, 10)}
	for _, n := range r.Nodes {
		request.Nodes = append(request.Nodes, nativeNode{ID: n.ID, Link: n.Connection})
	}
	for _, g := range r.Groups {
		request.Groups = append(request.Groups, nativePublicationGroup{Name: g.Name, CandidateIDs: g.CandidateIDs, Selection: g.SelectedNodeID})
	}
	return request
}

func nativeStageHash(r ProviderStageRequest) string {
	r.ExpectedGeneration = 0
	encoded, _ := json.Marshal(r)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
