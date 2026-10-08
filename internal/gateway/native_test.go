package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	f := &nativeFixture{socket: filepath.Join(dir, "dae.sock"), inventory: nativeInventory{Generation: 1, Groups: []nativeGroup{{Handle: 17, Name: "outbound", Identity: "baseline"}}}}
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
	if f.rejectCode != "" {
		f.inventory.Generation++
		w.WriteHeader(409)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": f.rejectCode, "message": "secret://redact-me"}})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/providers/publish" {
		f.publishes++
		if f.dropBeforePublish {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		var req nativePublishRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			w.WriteHeader(400)
			return
		}
		f.publishBody = req
		if req.ExpectedGeneration != f.inventory.Generation {
			w.WriteHeader(409)
			io.WriteString(w, `{"error":{"code":"generation_conflict"}}`)
			return
		}
		f.inventory.Generation++
		for i := range f.inventory.Groups {
			for _, g := range req.Groups {
				if g.Name == f.inventory.Groups[i].Name {
					f.inventory.Groups[i].Identity = req.ProviderID + "/" + req.RevisionID
					f.inventory.Groups[i].Selection = g.Selection
				}
			}
		}
		if f.afterMutationReadFailure {
			f.readFailure = true
		}
		if f.lostPublish {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		_ = json.NewEncoder(w).Encode(nativeMutationResponse{Snapshot: f.inventory, Adopted: []int{17}})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/selection" {
		f.selections++
		var req nativeSelectionRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ExpectedGeneration != f.inventory.Generation || req.Handle != 17 {
			w.WriteHeader(409)
			io.WriteString(w, `{"error":{"code":"generation_conflict"}}`)
			return
		}
		f.inventory.Generation++
		f.inventory.Groups[0].Selection = req.CandidateID
		if f.afterMutationReadFailure {
			f.readFailure = true
		}
		if f.lostSelection {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		_ = json.NewEncoder(w).Encode(nativeMutationResponse{Snapshot: f.inventory})
		return
	}
	w.WriteHeader(404)
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

func TestNativeUnchangedGenerationDoesNotReleaseUnknownRequest(t *testing.T) {
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
	if _, err = e.Inventory(context.Background()); err == nil {
		t.Fatal("unchanged generation released unknown native request")
	}
	e = nativeTestEngine(t, f, j)
	if _, err = e.PublishProvider(context.Background(), id); err == nil {
		t.Fatal("unknown request replayed")
	}
	if f.publishes != 1 {
		t.Fatal("native mutation replayed after uncertain delivery")
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
