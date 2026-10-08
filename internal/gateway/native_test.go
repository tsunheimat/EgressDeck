package gateway

import (
	"bytes"
	"context"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
)

type nativeFixture struct {
	mu                         sync.Mutex
	inventory                  nativeInventory
	socket                     string
	publishes, selections      int
	publishBody                nativePublishRequest
	lostPublish, lostSelection bool
	dropBeforePublish          bool
	rejectCode                 string
	afterMutationReadFailure   bool
	readFailure                bool
	operationLimit             bool
	operations                 map[string]nativeOperationStatus
	deliveries                 map[string]int
}

func newNativeFixture(t *testing.T) *nativeFixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "ednative-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f := &nativeFixture{socket: filepath.Join(dir, "dae.sock"), inventory: nativeInventory{Generation: 1, Groups: []nativeGroup{{Handle: 17, Name: "outbound", Identity: "baseline"}}}, operations: map[string]nativeOperationStatus{}, deliveries: map[string]int{}}
	listener, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(f.socket, 0600); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: f}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return f
}
func (f *nativeFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "GET" && r.URL.Path == "/v1/inventory" {
		if f.readFailure {
			w.WriteHeader(503)
			io.WriteString(w, `{"error":{"code":"inventory_closed"}}`)
			return
		}
		_ = json.NewEncoder(w).Encode(f.inventory)
		return
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/operations/") {
		id := strings.TrimPrefix(r.URL.Path, "/v1/operations/")
		status, exists := f.operations[id]
		if !exists && f.operationLimit {
			w.WriteHeader(429)
			io.WriteString(w, `{"error":{"code":"operation_limit"}}`)
			return
		}
		if !exists {
			status = nativeOperationStatus{OperationID: id, State: "not_started"}
		}
		_ = json.NewEncoder(w).Encode(status)
		return
	}
	kind := map[string]string{"/v1/providers/publish": "provider_publish", "/v1/selection": "selection_set", "/v1/groups/publish": "group_publish"}[r.URL.Path]
	if r.Method != http.MethodPost || kind == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&object) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id, _ := object["operation_id"].(string)
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.deliveries[id]++
	delete(object, "operation_id")
	// The daemon computes the request digest after decoding its native wire
	// types. Their optional group revision omits zero during canonical encoding.
	// Keep that contract independent of the agent's nativePublicationGroup tag.
	if groups, ok := object["groups"].([]any); ok {
		for _, value := range groups {
			if group, ok := value.(map[string]any); ok && group["revision"] == json.Number("0") {
				delete(group, "revision")
			}
		}
	}
	if group, ok := object["group"].(map[string]any); ok && group["revision"] == json.Number("0") {
		delete(group, "revision")
	}
	canonical, _ := json.Marshal(map[string]any{"kind": kind, "request": object})
	sum := sha256.Sum256(canonical)
	digest := hex.EncodeToString(sum[:])
	if previous, exists := f.operations[id]; exists {
		if previous.RequestDigest != digest || previous.Kind != kind {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":{"code":"operation_conflict"}}`)
			return
		}
		if previous.State == "rejected" {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": previous.ErrorCode}})
			return
		}
		_ = json.NewEncoder(w).Encode(nativeMutationResponse{Snapshot: f.inventory})
		return
	}
	if kind == "provider_publish" && f.dropBeforePublish {
		f.dropBeforePublish = false
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	status := nativeOperationStatus{OperationID: id, RequestDigest: digest, Kind: kind, Generation: f.inventory.Generation}
	reject := func(code string) {
		status.State, status.ErrorCode = "rejected", code
		f.operations[id] = status
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": "secret://redact-me"}})
	}
	if f.rejectCode != "" {
		reject(f.rejectCode)
		return
	}
	if kind == "provider_publish" {
		var req nativePublishRequest
		if json.Unmarshal(raw, &req) != nil {
			reject("invalid_request")
			return
		}
		f.publishBody = req
		if req.ExpectedGeneration != f.inventory.Generation {
			reject("generation_conflict")
			return
		}
		f.publishes++
		f.inventory.Generation++
		for i := range f.inventory.Groups {
			for _, g := range req.Groups {
				if g.Name == f.inventory.Groups[i].Name {
					f.inventory.Groups[i].Identity = req.ProviderID + "/" + req.RevisionID
					f.inventory.Groups[i].Selection = g.Selection
					f.inventory.Groups[i].GroupRevision = g.Revision
					f.inventory.Groups[i].CandidateIDs = append([]string(nil), g.CandidateIDs...)
				}
			}
		}
	}
	if kind == "selection_set" {
		var req nativeSelectionRequest
		if json.Unmarshal(raw, &req) != nil {
			reject("invalid_request")
			return
		}
		if req.ExpectedGeneration != f.inventory.Generation || req.Handle != 17 {
			reject("generation_conflict")
			return
		}
		f.selections++
		f.inventory.Generation++
		f.inventory.Groups[0].Selection = req.CandidateID
	}
	if kind == "group_publish" {
		var req nativeGroupRequest
		if json.Unmarshal(raw, &req) != nil {
			reject("invalid_request")
			return
		}
		if req.ExpectedGeneration != f.inventory.Generation {
			reject("generation_conflict")
			return
		}
		found := false
		for i := range f.inventory.Groups {
			g := &f.inventory.Groups[i]
			if g.Name == req.Group.Name && g.Identity == req.ProviderID+"/"+req.RevisionID {
				g.GroupRevision, g.Selection = req.Group.Revision, req.Group.Selection
				g.CandidateIDs = append([]string(nil), req.Group.CandidateIDs...)
				found = true
			}
		}
		if !found {
			reject("invalid_request")
			return
		}
		f.inventory.Generation++
	}
	status.State, status.Generation = "committed", f.inventory.Generation
	f.operations[id] = status
	if f.afterMutationReadFailure {
		f.readFailure = true
	}
	if (kind == "provider_publish" && f.lostPublish) || (kind == "selection_set" && f.lostSelection) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	_ = json.NewEncoder(w).Encode(nativeMutationResponse{Snapshot: f.inventory, Adopted: []int{17}})
}
func nativeTestEngine(t *testing.T, f *nativeFixture, j Journal) *NativeEngine {
	t.Helper()
	vault, err := secrets.New("test-key", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewNativeEngine(NativeOptions{SocketPath: f.socket, Vault: vault, Timeout: time.Second}, j)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}
func nativeTestRevision() ProviderRevision {
	return ProviderRevision{ProviderID: "provider", Revision: 3, ContentHash: "provider:3", Nodes: []Node{{ID: "one", Name: "First", Connection: "socks5://username:private-password@192.0.2.1:1080"}, {ID: "two", Name: "Second", Connection: "socks5://192.0.2.2:1080"}}, Groups: []PublicationGroup{{ID: "group-id", Name: "outbound", Revision: 5, CandidateIDs: []string{"one", "two"}, SelectedNodeID: "one"}}}
}
func nativePublish(t *testing.T, e *NativeEngine) Snapshot {
	t.Helper()
	id, err := e.StageProvider(context.Background(), nativeTestRevision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.PublishProvider(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestNativeUnixPublishReadbackEncryptedRestart(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	id, err := e.StageProvider(context.Background(), nativeTestRevision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	// Staging is durable and recovers private links only through authenticated encryption.
	e = nativeTestEngine(t, f, j)
	s, err := e.PublishProvider(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if s.Generation != 2 || s.Providers["provider"].Revision != 3 || s.Providers["provider"].ContentHash != "provider:3" || s.Groups["group-id"].Name != "outbound" || s.Groups["group-id"].Revision != 5 {
		t.Fatalf("incorrect readback: %#v", s)
	}
	if f.publishBody.Nodes[0].Link != nativeTestRevision().Nodes[0].Connection || f.publishBody.ExpectedGeneration != 1 {
		t.Fatal("private native request lost connection or CAS")
	}
	b, _ := json.Marshal(s)
	entries, _ := j.Entries(context.Background())
	journal, _ := json.Marshal(entries)
	if strings.Contains(string(b), "private-password") || strings.Contains(string(journal), "private-password") || strings.Contains(string(journal), "socks5://") {
		t.Fatal("secret exposed")
	}
	for _, n := range s.Providers["provider"].Nodes {
		if n.Connection != "" {
			t.Fatal("in-process snapshot leaked private links")
		}
	}
	e = nativeTestEngine(t, f, j)
	s, err = e.Inventory(context.Background())
	if err != nil || s.Providers["provider"].Revision != 3 {
		t.Fatalf("restart readback: %v %#v", err, s)
	}
	f.mu.Lock()
	f.inventory.Generation = 1
	f.inventory.Groups[0].Identity = "baseline"
	f.mu.Unlock()
	s, err = e.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Providers) != 0 {
		t.Fatal("daemon restart falsely restored old provider")
	}
}
func TestNativeLostAcknowledgementUsesRealReadback(t *testing.T) {
	f := newNativeFixture(t)
	f.lostPublish = true
	f.lostSelection = true
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	nativePublish(t, e)
	scope := SelectionScope{GatewayID: "gateway", GroupID: "group-id", Transport: "both"}
	result, err := e.SetRuntimeSelection(context.Background(), scope, "two", 0)
	if err != nil || result.Revision != 1 || result.ObservedNodeID != "two" {
		t.Fatalf("lost selection ack: %#v %v", result, err)
	}
	if f.publishes != 1 || f.selections != 1 {
		t.Fatal("mutation retried")
	}
	e = nativeTestEngine(t, f, j)
	s, err := e.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Selections[scope.key()].ObservedNodeID != "two" || s.Selections[scope.key()].Revision != 1 {
		t.Fatal("selection not recovered")
	}
	if _, err = e.SetRuntimeSelection(context.Background(), scope, "one", 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("CAS accepted: %v", err)
	}
}
func TestNativeUnknownOutcomeQuarantinesAndRecovers(t *testing.T) {
	f := newNativeFixture(t)
	f.afterMutationReadFailure = true
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	id, err := e.StageProvider(context.Background(), nativeTestRevision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.PublishProvider(context.Background(), id); err == nil {
		t.Fatal("missing readback acknowledged")
	}
	e = nativeTestEngine(t, f, j)
	if _, err = e.Inventory(context.Background()); err == nil {
		t.Fatal("unavailable readback returned stale success")
	}
	f.mu.Lock()
	f.readFailure = false
	f.mu.Unlock()
	s, err := e.Inventory(context.Background())
	if err != nil || s.Providers["provider"].Revision != 3 {
		t.Fatalf("readback recovery failed: %v", err)
	}
	if f.publishes != 1 {
		t.Fatal("recovery republished")
	}
}
func TestNativeExplicitConflictDoesNotPoisonInventory(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	id, err := e.StageProvider(context.Background(), nativeTestRevision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.rejectCode = "generation_conflict"
	f.mu.Unlock()
	if _, err = e.PublishProvider(context.Background(), id); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong error %v", err)
	}
	if _, err = e.Inventory(context.Background()); err != nil {
		t.Fatalf("known rejection poisoned inventory: %v", err)
	}
	entries, _ := j.Entries(context.Background())
	b, _ := json.Marshal(entries)
	if strings.Contains(string(b), "redact-me") {
		t.Fatal("native diagnostics exposed")
	}
}
func TestNativeRestrictionsAndValidation(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	cases := []struct {
		name  string
		alter func(*ProviderRevision)
	}{
		{"connection", func(r *ProviderRevision) { r.Nodes[0].Connection = "" }},
		{"unconfigured group", func(r *ProviderRevision) { r.Groups[0].Name = "missing" }},
		{"candidate", func(r *ProviderRevision) { r.Groups[0].CandidateIDs = []string{"absent"} }},
		{"selection", func(r *ProviderRevision) { r.Groups[0].SelectedNodeID = "absent" }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := nativeTestRevision()
			tt.alter(&r)
			if _, err := e.StageProvider(context.Background(), r, 1); err == nil {
				t.Fatal("invalid stage accepted")
			}
		})
	}
	c, err := e.Capabilities(context.Background())
	if err != nil || !c.Has(CapabilityProviderPublish) || c.Has(CapabilityPolicyApply) || !c.Has(CapabilitySelectionPersist) {
		t.Fatal("incorrect capabilities")
	}
	nativePublish(t, e)
	for _, transport := range []string{"tcp", "udp"} {
		if _, err := e.SetRuntimeSelection(context.Background(), SelectionScope{GroupID: "group-id", Transport: transport}, "two", 0); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("transport accepted: %s %v", transport, err)
		}
	}
	if f.selections != 0 {
		t.Fatal("rejected scopes reached daemon")
	}
	if err = os.Chmod(f.socket, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err = e.Inventory(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unsafe socket accepted: %v", err)
	}
	c, _ = e.Capabilities(context.Background())
	if c.Has(CapabilityProviderPublish) {
		t.Fatal("unavailable socket advertised supported runtime")
	}
}
func TestNativeJournalWrongKeyFailsClosed(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	if _, err := e.StageProvider(context.Background(), nativeTestRevision(), 1); err != nil {
		t.Fatal(err)
	}
	other, _ := secrets.New("test-key", bytes.Repeat([]byte{8}, 32))
	if _, err := NewNativeEngine(NativeOptions{SocketPath: f.socket, Vault: other}, j); !errors.Is(err, ErrJournal) {
		t.Fatalf("wrong key accepted: %v", err)
	}
}

func TestNativeOversizeStageDoesNotQuarantine(t *testing.T) {
	f := newNativeFixture(t)
	e := nativeTestEngine(t, f, NewMemoryJournal())
	r := nativeTestRevision()
	r.Nodes[0].Connection = strings.Repeat("x", 1<<20)
	if _, err := e.StageProvider(context.Background(), r, 1); !errors.Is(err, ErrInvalidRevision) {
		t.Fatalf("oversize staged: %v", err)
	}
	if _, err := e.Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	nativePublish(t, e)
}
func TestNativeRestageSameRevisionAfterUnrelatedGeneration(t *testing.T) {
	f := newNativeFixture(t)
	e := nativeTestEngine(t, f, NewMemoryJournal())
	first, err := e.StageProvider(context.Background(), nativeTestRevision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.inventory.Generation = 2
	f.mu.Unlock()
	second, err := e.StageProvider(context.Background(), nativeTestRevision(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("stale token retained")
	}
	if _, err = e.PublishProvider(context.Background(), first); !errors.Is(err, ErrStageNotFound) {
		t.Fatal("stale staged token was not invalidated")
	}
	if _, err = e.PublishProvider(context.Background(), second); err != nil {
		t.Fatal(err)
	}
}
func TestNativeSelectionRestartRejectsDifferentProviderIdentity(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	nativePublish(t, e)
	f.mu.Lock()
	f.afterMutationReadFailure = true
	f.mu.Unlock()
	scope := SelectionScope{GroupID: "group-id", Transport: "both"}
	if _, err := e.SetRuntimeSelection(context.Background(), scope, "two", 0); err == nil {
		t.Fatal("readback loss acknowledged")
	}
	f.mu.Lock()
	f.readFailure = false
	f.inventory.Groups[0].Identity = "someone-else/99"
	f.mu.Unlock()
	e = nativeTestEngine(t, f, j)
	if _, err := e.Inventory(context.Background()); err == nil {
		t.Fatal("wrong identity adopted as pending selection")
	}
	if f.selections != 1 {
		t.Fatal("selection retried")
	}
}
func TestNativeSelectionAlreadyChosenPreservesDaemonGeneration(t *testing.T) {
	f := newNativeFixture(t)
	e := nativeTestEngine(t, f, NewMemoryJournal())
	nativePublish(t, e)
	scope := SelectionScope{GroupID: "group-id", Transport: "both"}
	selected, err := e.SetRuntimeSelection(context.Background(), scope, "one", 0)
	if err != nil || selected.Revision != 1 || selected.ObservedNodeID != "one" {
		t.Fatalf("idempotent selection: %#v %v", selected, err)
	}
	if f.selections != 0 || f.inventory.Generation != 2 {
		t.Fatal("no-op selection changed daemon")
	}
}
func TestNativePublishReplacementAdvancesChangedSelection(t *testing.T) {
	f := newNativeFixture(t)
	e := nativeTestEngine(t, f, NewMemoryJournal())
	nativePublish(t, e)
	r := nativeTestRevision()
	r.Revision = 4
	r.ContentHash = "provider:4"
	r.Nodes = r.Nodes[1:]
	r.Groups[0].CandidateIDs = []string{"two"}
	r.Groups[0].SelectedNodeID = "two"
	r.Groups[0].Revision++
	id, err := e.StageProvider(context.Background(), r, 2)
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.PublishProvider(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	selection := s.Selections[SelectionScope{GroupID: "group-id", Transport: "both"}.key()]
	if selection.DesiredNodeID != "two" || selection.ObservedNodeID != "two" || selection.Revision != 1 {
		t.Fatalf("obsolete selection retained: %#v", selection)
	}
}

func TestNativeAuthoritativeAbsenceSafelyRetriesSameOperation(t *testing.T) {
	f := newNativeFixture(t)
	f.dropBeforePublish = true
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	id, err := e.StageProvider(context.Background(), nativeTestRevision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.PublishProvider(context.Background(), id); err == nil {
		t.Fatal("missing acknowledgement treated as success")
	}
	pendingID := e.state.Operation.ID
	e = nativeTestEngine(t, f, j)
	snapshot, err := e.Inventory(context.Background())
	if err != nil || snapshot.Providers["provider"].Revision != 3 {
		t.Fatalf("authoritative absence did not recover after restart: %#v %v", snapshot, err)
	}
	if f.publishes != 1 || f.deliveries[pendingID] != 2 || len(f.operations) != 1 {
		t.Fatalf("recovery must deliver the same ID twice and commit once: committed=%d deliveries=%v receipts=%v", f.publishes, f.deliveries, f.operations)
	}
}

func TestNativeCrashAfterPendingPersistBeforeSendRecovers(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	ctx := context.Background()
	id, err := e.StageProvider(ctx, nativeTestRevision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	next := e.cloneState()
	stage := next.Staged[id]
	stage.Pending = true
	next.Staged[id] = stage
	if err := e.nativeBeginOperation(ctx, &next, "provider_publish", "/v1/providers/publish", nativePublishWire(stage.Request)); err != nil {
		t.Fatal(err)
	}
	if err := e.persist(ctx, next, "publish_pending"); err != nil {
		t.Fatal(err)
	}
	pendingID := next.Operation.ID
	if f.publishes != 0 || len(f.deliveries) != 0 {
		t.Fatal("pre-send crash boundary already sent mutation")
	}
	e = nativeTestEngine(t, f, j)
	snapshot, err := e.Inventory(ctx)
	if err != nil || snapshot.Generation != 2 || snapshot.Providers["provider"].Revision != 3 {
		t.Fatalf("pre-send crash did not recover: %#v %v", snapshot, err)
	}
	if e.state.Operation != nil || f.publishes != 1 || f.deliveries[pendingID] != 1 {
		t.Fatalf("pre-send recovery did not terminate once: operation=%#v commits=%d deliveries=%v", e.state.Operation, f.publishes, f.deliveries)
	}
}

func TestNativeRejectedOperationAllowsFreshMutation(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	ctx := context.Background()
	id, err := e.StageProvider(ctx, nativeTestRevision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.rejectCode = "invalid_request"
	f.mu.Unlock()
	if _, err := e.PublishProvider(ctx, id); !errors.Is(err, ErrInvalidRevision) {
		t.Fatalf("validation rejection lost: %v", err)
	}
	if e.state.Operation != nil || e.state.Staged[id].Pending {
		t.Fatal("definite rejection left pending intent")
	}
	f.mu.Lock()
	f.rejectCode = ""
	f.mu.Unlock()
	e = nativeTestEngine(t, f, j)
	snapshot, err := e.PublishProvider(ctx, id)
	if err != nil || snapshot.Providers["provider"].Revision != 3 || f.publishes != 1 {
		t.Fatalf("rejected operation poisoned fresh mutation: %#v %v commits=%d", snapshot, err, f.publishes)
	}
	if len(f.operations) != 2 {
		t.Fatalf("fresh mutation reused a rejected operation ID: %#v", f.operations)
	}
}

func nativeControllerIdentity(id string, fence uint64) MutationIdentity {
	return MutationIdentity{ID: id, RequestHash: strings.Repeat("a", 64), TargetKind: "outbound", TargetID: "group-id", FenceToken: fence}
}

func TestNativeResolvedAbsenceFencesDelayedControllerMutation(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	nativePublish(t, e)
	identity := nativeControllerIdentity("lost-before-agent", 1)
	ctx := context.Background()
	status, err := e.MutationStatus(ctx, identity)
	if err != nil || status.State != MutationUnknown {
		t.Fatalf("absence was prematurely treated as rejection: %#v %v", status, err)
	}
	status, err = e.ResolveMutation(ctx, identity)
	if err != nil || status.State != MutationRejected || status.ErrorCode != "never_accepted" {
		t.Fatalf("absence did not become durable rejection: %#v %v", status, err)
	}
	e = nativeTestEngine(t, f, j)
	scope := SelectionScope{GroupID: "group-id", Transport: "both"}
	if _, err := e.SetRuntimeSelection(WithMutationIdentity(ctx, identity), scope, "two", 0); !IsDefiniteRejection(err) {
		t.Fatalf("late request bypassed durable tombstone: %v", err)
	}
	if f.selections != 0 || f.inventory.Groups[0].Selection != "one" {
		t.Fatal("late rejected mutation changed daemon")
	}
	newIdentity := nativeControllerIdentity("fresh-controller-request", 2)
	if _, err := e.SetRuntimeSelection(WithMutationIdentity(ctx, newIdentity), scope, "two", 0); err != nil {
		t.Fatalf("resolved request blocked a new fenced mutation: %v", err)
	}
}

func TestNativeMutationIdentityMismatchCannotResolveOrExecute(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	nativePublish(t, e)
	ctx := context.Background()
	identity := nativeControllerIdentity("identity-bound", 1)
	if _, err := e.ResolveMutation(ctx, identity); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*MutationIdentity){
		func(i *MutationIdentity) { i.RequestHash = strings.Repeat("b", 64) },
		func(i *MutationIdentity) { i.TargetKind = "provider" },
		func(i *MutationIdentity) { i.TargetID = "another" },
		func(i *MutationIdentity) { i.FenceToken++ },
	} {
		mismatch := identity
		alter(&mismatch)
		if _, err := e.MutationStatus(ctx, mismatch); !errors.Is(err, ErrConflict) {
			t.Fatalf("mismatched status identity accepted: %#v %v", mismatch, err)
		}
		if _, err := e.ResolveMutation(ctx, mismatch); !errors.Is(err, ErrConflict) {
			t.Fatalf("mismatched resolution identity accepted: %#v %v", mismatch, err)
		}
		if _, err := e.SetRuntimeSelection(WithMutationIdentity(ctx, mismatch), SelectionScope{GroupID: "group-id", Transport: "both"}, "two", 0); !errors.Is(err, ErrConflict) {
			t.Fatalf("mismatched execution identity accepted: %#v %v", mismatch, err)
		}
	}
	if f.selections != 0 {
		t.Fatal("mismatched identity reached daemon")
	}
}

func TestNativeAlreadySelectedLostControllerAcknowledgementHasCommittedReceipt(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	nativePublish(t, e)
	ctx := context.Background()
	identity := nativeControllerIdentity("noop-lost-response", 1)
	if _, err := e.SetRuntimeSelection(WithMutationIdentity(ctx, identity), SelectionScope{GroupID: "group-id", Transport: "both"}, "one", 0); err != nil {
		t.Fatal(err)
	}
	// Discard the response and restart the agent, as when the authenticated
	// controller connection disappears after the agent's journal commit.
	e = nativeTestEngine(t, f, j)
	status, err := e.MutationStatus(ctx, identity)
	if err != nil || status.State != MutationCommitted || status.Generation != 2 {
		t.Fatalf("no-op lost acknowledgement did not recover: %#v %v", status, err)
	}
	if f.selections != 0 || f.inventory.Generation != 2 {
		t.Fatal("no-op receipt required a native mutation")
	}
}

func TestNativeControllerFenceSurvivesReceiptPruningAndRestart(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	nativePublish(t, e)
	ctx := context.Background()
	// Seed terminal history through the same encrypted persistence boundary,
	// then perform a real resolver write at the bounded-retention threshold.
	next := e.cloneState()
	next.Correlations = map[string]nativeCorrelation{}
	next.MutationFences = map[string]uint64{}
	for fence := uint64(1); fence <= 4096; fence++ {
		identity := nativeControllerIdentity(fmt.Sprintf("resolved-%d", fence), fence)
		next.Correlations[identity.ID] = nativeCorrelation{Identity: identity, State: MutationRejected, ErrorCode: "never_accepted"}
		next.MutationFences[mutationFenceKey(identity)] = fence
	}
	if err := e.persist(ctx, next, "test_terminal_history"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ResolveMutation(ctx, nativeControllerIdentity("resolved-4097", 4097)); err != nil {
		t.Fatal(err)
	}
	if len(e.state.Correlations) > 4096 {
		t.Fatalf("receipt retention is unbounded: %d", len(e.state.Correlations))
	}
	var pruned MutationIdentity
	for fence := uint64(1); fence <= 4096; fence++ {
		candidate := nativeControllerIdentity(fmt.Sprintf("resolved-%d", fence), fence)
		if _, exists := e.state.Correlations[candidate.ID]; !exists {
			pruned = candidate
			break
		}
	}
	if pruned.ID == "" {
		t.Fatal("test did not exercise a pruned receipt")
	}
	e = nativeTestEngine(t, f, j)
	scope := SelectionScope{GroupID: "group-id", Transport: "both"}
	if _, err := e.SetRuntimeSelection(WithMutationIdentity(ctx, pruned), scope, "two", 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("pruned receipt bypassed durable target fence: %#v %v", pruned, err)
	}
	if f.selections != 0 {
		t.Fatal("old request reached daemon after receipt pruning")
	}
	if _, err := e.SetRuntimeSelection(WithMutationIdentity(ctx, nativeControllerIdentity("new-after-pruning", 4098)), scope, "two", 0); err != nil {
		t.Fatalf("retained fence blocked a newer operation: %v", err)
	}
}

func TestNativeOperationReceiptMismatchRetainsPendingIntent(t *testing.T) {
	f := newNativeFixture(t)
	f.afterMutationReadFailure = true
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	ctx := context.Background()
	id, err := e.StageProvider(ctx, nativeTestRevision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.PublishProvider(ctx, id); err == nil {
		t.Fatal("inventory outage acknowledged provider")
	}
	operationID := e.state.Operation.ID
	f.mu.Lock()
	correct := f.operations[operationID]
	f.readFailure = false
	f.mu.Unlock()
	for _, alter := range []func(*nativeOperationStatus){
		func(s *nativeOperationStatus) { s.OperationID = "another-operation" },
		func(s *nativeOperationStatus) { s.RequestDigest = strings.Repeat("f", 64) },
		func(s *nativeOperationStatus) { s.Kind = "selection_set" },
	} {
		mismatch := correct
		alter(&mismatch)
		f.mu.Lock()
		f.operations[operationID] = mismatch
		f.mu.Unlock()
		e = nativeTestEngine(t, f, j)
		if _, err := e.Inventory(ctx); err == nil || e.state.Operation == nil {
			t.Fatalf("mismatched native receipt released operation: %#v %v", mismatch, err)
		}
		if f.publishes != 1 {
			t.Fatal("mismatched receipt triggered replay")
		}
	}
	f.mu.Lock()
	f.operations[operationID] = correct
	f.mu.Unlock()
	snapshot, err := e.Inventory(ctx)
	if err != nil || snapshot.Providers["provider"].Revision != 3 || e.state.Operation != nil {
		t.Fatalf("matching receipt did not resolve pending intent: %#v %v", snapshot, err)
	}
}

func TestNativeZeroGroupRevisionUsesDaemonCanonicalDigest(t *testing.T) {
	f := newNativeFixture(t)
	f.lostPublish = true
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	ctx := context.Background()
	revision := nativeTestRevision()
	revision.Groups[0].Revision = 0
	id, err := e.StageProvider(ctx, revision, 1)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := e.PublishProvider(ctx, id)
	if err != nil || snapshot.Providers["provider"].Revision != 3 || snapshot.Groups["group-id"].Revision != 0 {
		t.Fatalf("zero group revision did not match daemon receipt: %#v %v", snapshot, err)
	}
	if e.state.Operation != nil || f.publishes != 1 {
		t.Fatal("zero revision publication remained pending or retried")
	}
	e = nativeTestEngine(t, f, j)
	if _, err := e.Inventory(ctx); err != nil || f.publishes != 1 {
		t.Fatalf("canonical zero revision did not survive restart: %v", err)
	}
}

func TestNativeFullDistinctTargetRetentionAllowsExistingTargetAdvance(t *testing.T) {
	for _, mode := range []string{"mutation", "resolution"} {
		t.Run(mode, func(t *testing.T) {
			f := newNativeFixture(t)
			j := NewMemoryJournal()
			e := nativeTestEngine(t, f, j)
			nativePublish(t, e)
			ctx := context.Background()
			next := e.cloneState()
			next.Correlations = map[string]nativeCorrelation{}
			next.MutationFences = map[string]uint64{}
			first := nativeControllerIdentity("latest-group", 1)
			for i := 0; i < 4096; i++ {
				identity := first
				if i > 0 {
					identity.ID = fmt.Sprintf("latest-target-%d", i)
					identity.TargetID = fmt.Sprintf("target-%d", i)
				}
				next.Correlations[identity.ID] = nativeCorrelation{Identity: identity, State: MutationRejected, ErrorCode: "never_accepted"}
				next.MutationFences[mutationFenceKey(identity)] = 1
			}
			if err := e.persist(ctx, next, "test_distinct_target_history"); err != nil {
				t.Fatal(err)
			}
			e = nativeTestEngine(t, f, j)
			scope := SelectionScope{GroupID: "group-id", Transport: "both"}
			newTarget := nativeControllerIdentity("new-target-operation", 1)
			newTarget.TargetID = "new-target"
			if _, err := e.ResolveMutation(ctx, newTarget); !errors.Is(err, ErrBusy) {
				t.Fatalf("new target bypassed full retention: %v", err)
			}
			if _, err := e.SetRuntimeSelection(WithMutationIdentity(ctx, newTarget), scope, "two", 0); !errors.Is(err, ErrBusy) {
				t.Fatalf("new target mutation bypassed full retention: %v", err)
			}
			advanced := nativeControllerIdentity("newer-group-operation", 2)
			if mode == "mutation" {
				if _, err := e.SetRuntimeSelection(WithMutationIdentity(ctx, advanced), scope, "two", 0); err != nil {
					t.Fatalf("full retention blocked existing target advance: %v", err)
				}
			} else {
				if _, err := e.ResolveMutation(ctx, advanced); err != nil {
					t.Fatalf("full retention blocked existing target resolution: %v", err)
				}
			}
			if len(e.state.Correlations) != 4096 || len(e.state.MutationFences) != 4096 {
				t.Fatalf("advance changed retention bounds: receipts=%d targets=%d", len(e.state.Correlations), len(e.state.MutationFences))
			}
			if _, retained := e.state.Correlations[first.ID]; retained {
				t.Fatal("superseded target receipt retained instead of making room for its successor")
			}
			for i := 1; i < 4096; i++ {
				if _, retained := e.state.Correlations[fmt.Sprintf("latest-target-%d", i)]; !retained {
					t.Fatalf("lost latest receipt for unrelated target %d", i)
				}
			}
			e = nativeTestEngine(t, f, j)
			if _, err := e.SetRuntimeSelection(WithMutationIdentity(ctx, first), scope, "one", 1); !errors.Is(err, ErrConflict) {
				t.Fatalf("late request bypassed advanced target fence after restart: %v", err)
			}
		})
	}
}

func TestNativeLostAcknowledgementReceiptSurvivesOtherTargetsAndRestart(t *testing.T) {
	f := newNativeFixture(t)
	f.lostSelection = true
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	nativePublish(t, e)
	ctx := context.Background()
	lost := nativeControllerIdentity("lost-controller-ack", 1)
	if _, err := e.SetRuntimeSelection(WithMutationIdentity(ctx, lost), SelectionScope{GroupID: "group-id", Transport: "both"}, "two", 0); err != nil {
		t.Fatal(err)
	}
	// Discard this successful controller response, then let unrelated target
	// requests complete before the original caller recovers its acknowledgement.
	for i := 0; i < 160; i++ {
		identity := nativeControllerIdentity(fmt.Sprintf("other-operation-%d", i), 1)
		identity.TargetID = fmt.Sprintf("other-target-%d", i)
		if _, err := e.ResolveMutation(ctx, identity); err != nil {
			t.Fatalf("resolve unrelated target %d: %v", i, err)
		}
	}
	e = nativeTestEngine(t, f, j)
	for i := 0; i < 160; i++ {
		identity := nativeControllerIdentity(fmt.Sprintf("other-operation-%d", i), 1)
		identity.TargetID = fmt.Sprintf("other-target-%d", i)
		status, err := e.MutationStatus(ctx, identity)
		if err != nil || status.State != MutationRejected {
			t.Fatalf("latest receipt disappeared for unrelated target %d: %#v %v", i, status, err)
		}
	}
	status, err := e.ResolveMutation(ctx, lost)
	if err != nil || status.State != MutationCommitted || status.Generation != 3 {
		t.Fatalf("lost acknowledgement did not resolve after unrelated targets: %#v %v", status, err)
	}
	if f.selections != 1 || f.inventory.Groups[0].Selection != "two" {
		t.Fatal("recovery replayed or changed the acknowledged mutation")
	}
}

func TestNativeMultipleIndependentGroupsShareProviderNodes(t *testing.T) {
	f := newNativeFixture(t)
	f.inventory.Groups = append(f.inventory.Groups, nativeGroup{Handle: 18, Name: "another", Identity: "baseline"})
	e := nativeTestEngine(t, f, NewMemoryJournal())
	r := nativeTestRevision()
	r.Groups = append(r.Groups, PublicationGroup{ID: "group-two", Name: "another", Revision: 1, CandidateIDs: []string{"one", "two"}, SelectedNodeID: "two"})
	id, err := e.StageProvider(context.Background(), r, 1)
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.PublishProvider(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Groups) != 2 || s.Selections[SelectionScope{GroupID: "group-two", Transport: "both"}.key()].ObservedNodeID != "two" || s.Selections[SelectionScope{GroupID: "group-id", Transport: "both"}.key()].ObservedNodeID != "one" {
		t.Fatal("independent native groups lost their selections")
	}
}
func TestNativeFileJournalBoundsAndRecoversLatestEncryptedState(t *testing.T) {
	f := newNativeFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "native.jsonl")
	j := NewNativeFileJournal(path)
	e := nativeTestEngine(t, f, j)
	nativePublish(t, e)
	scope := SelectionScope{GroupID: "group-id", Transport: "both"}
	for revision := int64(0); revision < 80; revision++ {
		if _, err := e.PersistSelection(context.Background(), scope, "one", revision); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := j.Entries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 64 {
		t.Fatalf("retention records %d", len(entries))
	}
	states := 0
	for _, entry := range entries {
		if len(entry.State) > 0 {
			states++
		}
	}
	if states != 1 {
		t.Fatalf("encrypted snapshots retained: %d", states)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 100<<10 || strings.Contains(string(b), "private-password") || strings.Contains(string(b), "socks5://") {
		t.Fatal("unbounded or unencrypted state")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("journal permissions")
	}
	e = nativeTestEngine(t, f, NewNativeFileJournal(path))
	s, err := e.Inventory(context.Background())
	if err != nil || s.Selections[scope.key()].Revision != 80 {
		t.Fatalf("latest state recovery: %v", err)
	}
	if err = os.WriteFile(path, []byte("broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	vault, _ := secrets.New("test-key", bytes.Repeat([]byte{7}, 32))
	if _, err = NewNativeEngine(NativeOptions{SocketPath: f.socket, Vault: vault}, NewNativeFileJournal(path)); !errors.Is(err, ErrJournal) {
		t.Fatal("corrupt journal accepted")
	}
}

func TestNativeExternalSelectionChangeAdvancesCAS(t *testing.T) {
	f := newNativeFixture(t)
	e := nativeTestEngine(t, f, NewMemoryJournal())
	nativePublish(t, e)
	f.mu.Lock()
	f.inventory.Generation++
	f.inventory.Groups[0].Selection = "two"
	f.mu.Unlock()
	scope := SelectionScope{GroupID: "group-id", Transport: "both"}
	if _, err := e.SetRuntimeSelection(context.Background(), scope, "one", 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision after native selection drift accepted: %v", err)
	}
	if f.selections != 0 {
		t.Fatal("stale request reached native daemon")
	}
	snapshot, err := e.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	selection := snapshot.Selections[scope.key()]
	if selection.Revision != 1 || selection.ObservedNodeID != "two" || selection.DesiredNodeID != "one" {
		t.Fatalf("drift absent in readback: %#v", selection)
	}
}

func TestNativeLegacyPendingJournalRequiresResolvedUpgrade(t *testing.T) {
	for _, kind := range []string{"provider", "selection"} {
		t.Run(kind, func(t *testing.T) {
			f := newNativeFixture(t)
			journal := NewMemoryJournal()
			e := nativeTestEngine(t, f, journal)
			state := e.cloneState()
			if kind == "provider" {
				state.Staged["legacy"] = nativeStage{Request: NewProviderStageRequest(nativeTestRevision(), 1), Pending: true}
			} else {
				state.Pending = &nativePendingSelection{Scope: SelectionScope{GroupID: "group-id", Transport: "both"}, Node: "two", BaseGeneration: 1}
			}
			if err := e.persist(context.Background(), state, "legacy_pending"); err != nil {
				t.Fatal(err)
			}
			_, err := NewNativeEngine(e.options, journal)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code != "upgrade_required" {
				t.Fatalf("legacy unresolved journal accepted: %v", err)
			}
			if f.publishes != 0 || f.selections != 0 {
				t.Fatal("legacy intent replayed")
			}
		})
	}
}

func TestNativeProviderAlreadyAppliedHasDurableCorrelatedNoop(t *testing.T) {
	f := newNativeFixture(t)
	journal := NewMemoryJournal()
	e := nativeTestEngine(t, f, journal)
	nativePublish(t, e)
	identity := MutationIdentity{ID: "provider-repeat", RequestHash: strings.Repeat("a", 64), TargetKind: "provider", TargetID: "provider", FenceToken: 1}
	ctx := WithMutationIdentity(context.Background(), identity)
	stage, err := e.StageProvider(ctx, nativeTestRevision(), 2)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := e.PublishProvider(ctx, stage)
	if err != nil || snapshot.Generation != 2 {
		t.Fatalf("provider no-op: %v %#v", err, snapshot)
	}
	if f.publishes != 1 {
		t.Fatal("provider no-op dispatched daemon mutation")
	}
	e = nativeTestEngine(t, f, journal)
	receipt, err := e.ResolveMutation(context.Background(), identity)
	if err != nil || receipt.State != MutationCommitted || receipt.Generation != 2 {
		t.Fatalf("no-op receipt lost: %#v %v", receipt, err)
	}
}

func TestNativeAuthorityCapacityRejectsWithoutPendingPoison(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	id, err := e.StageProvider(context.Background(), nativeTestRevision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	f.operationLimit = true
	if _, err = e.PublishProvider(context.Background(), id); !errors.Is(err, ErrBusy) {
		t.Fatalf("capacity did not reject: %v", err)
	}
	if e.state.Operation != nil || e.state.Staged[id].Pending || f.publishes != 0 {
		t.Fatal("capacity poisoned pending intent")
	}
	if _, err = e.Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestNativeAuthorityCapacityRaceTerminatesExistingPending(t *testing.T) {
	f := newNativeFixture(t)
	j := NewMemoryJournal()
	e := nativeTestEngine(t, f, j)
	id, err := e.StageProvider(context.Background(), nativeTestRevision(), 1)
	if err != nil {
		t.Fatal(err)
	}
	next := e.cloneState()
	stage := next.Staged[id]
	stage.Pending = true
	next.Staged[id] = stage
	if err = e.nativeBeginOperation(context.Background(), &next, "provider_publish", "/v1/providers/publish", nativePublishWire(stage.Request)); err != nil {
		t.Fatal(err)
	}
	if err = e.persist(context.Background(), next, "publish_pending"); err != nil {
		t.Fatal(err)
	}
	f.operationLimit = true
	e = nativeTestEngine(t, f, j)
	if _, err = e.Inventory(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("capacity race did not terminate: %v", err)
	}
	if e.state.Operation != nil || e.state.Staged[id].Pending || f.publishes != 0 {
		t.Fatal("capacity race retained pending intent")
	}
	if _, err = e.Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
}
