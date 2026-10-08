package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
)

// This fixture exercises encrypted adapter state and the exact durable native
// operation wire. The separate source fixture exercises dae's real data types.
type nativeGroupFixture struct {
	mu                  sync.Mutex
	socket              string
	inv                 nativeInventory
	statuses            map[string]nativeOperationStatus
	writes              int
	reject              bool
	dropAcknowledgement bool
	failReadback        bool
}

func newNativeGroupFixture(t *testing.T) (*nativeGroupFixture, *NativeEngine, *MemoryJournal) {
	t.Helper()
	dir, err := os.MkdirTemp("", "edgroup-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f := &nativeGroupFixture{socket: filepath.Join(dir, "dae.sock"), statuses: map[string]nativeOperationStatus{}, inv: nativeInventory{Generation: 2, Groups: []nativeGroup{{Handle: 2, Name: "managed", Identity: "provider/7", Selection: "a", GroupRevision: 3, CandidateIDs: []string{"a", "b"}}, {Handle: 3, Name: "untouched", Identity: "provider/7", Selection: "b", GroupRevision: 3, CandidateIDs: []string{"a", "b"}}}}}
	l, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.socket, 0600); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: f}
	go func() { _ = server.Serve(l) }()
	t.Cleanup(func() { _ = server.Close() })
	journal := NewMemoryJournal()
	e := nativeGroupEngine(t, f, journal)
	state := e.cloneState()
	state.Active["provider"] = NewProviderStageRequest(ProviderRevision{ProviderID: "provider", Revision: 7, ContentHash: "immutable", Nodes: []Node{{ID: "a", Connection: "socks5://secret@192.0.2.1:1080"}, {ID: "b", Connection: "socks5://192.0.2.2:1080"}}, Groups: []PublicationGroup{{ID: "g", Name: "managed", Revision: 3, CandidateIDs: []string{"a", "b"}, SelectedNodeID: "a"}, {ID: "other", Name: "untouched", Revision: 3, CandidateIDs: []string{"a", "b"}, SelectedNodeID: "b"}}}, 1)
	state.Selections["g"] = Selection{Scope: SelectionScope{GatewayID: "gw", GroupID: "g", Transport: "both"}, DesiredNodeID: "a", ObservedNodeID: "a", Revision: 8}
	if err := e.persist(context.Background(), state, "fixture"); err != nil {
		t.Fatal(err)
	}
	return f, e, journal
}

func nativeGroupEngine(t *testing.T, f *nativeGroupFixture, journal Journal) *NativeEngine {
	t.Helper()
	vault, err := secrets.New("group-key", bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewNativeEngine(NativeOptions{SocketPath: f.socket, Vault: vault, Timeout: time.Second}, journal)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (f *nativeGroupFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && r.URL.Path == "/v1/inventory" {
		if f.failReadback {
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(f.inv)
		return
	}
	if r.Method == http.MethodGet && len(r.URL.Path) > len("/v1/operations/") && r.URL.Path[:len("/v1/operations/")] == "/v1/operations/" {
		id := r.URL.Path[len("/v1/operations/"):]
		status, ok := f.statuses[id]
		if !ok {
			status = nativeOperationStatus{OperationID: id, State: "not_started"}
		}
		_ = json.NewEncoder(w).Encode(status)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/groups/publish" {
		w.WriteHeader(404)
		return
	}
	var raw json.RawMessage
	if json.NewDecoder(r.Body).Decode(&raw) != nil {
		w.WriteHeader(400)
		return
	}
	var req struct {
		nativeGroupRequest
		OperationID string `json:"operation_id"`
	}
	if json.Unmarshal(raw, &req) != nil {
		w.WriteHeader(400)
		return
	}
	f.writes++
	status := nativeOperationStatus{OperationID: req.OperationID, Kind: "group_publish", RequestDigest: operationDigest("group_publish", rawWithoutOperationID(raw)), Generation: f.inv.Generation}
	if f.reject || req.ExpectedGeneration != f.inv.Generation {
		status.State = "rejected"
		status.ErrorCode = "generation_conflict"
	} else {
		f.inv.Generation++
		status.Generation = f.inv.Generation
		status.State = "committed"
		f.inv.Groups[0].CandidateIDs = append([]string(nil), req.Group.CandidateIDs...)
		f.inv.Groups[0].Selection = req.Group.Selection
		f.inv.Groups[0].GroupRevision = req.Group.Revision
	}
	f.statuses[req.OperationID] = status
	if f.dropAcknowledgement {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
	_ = json.NewEncoder(w).Encode(nativeMutationResponse{Snapshot: f.inv, Adopted: []int{2}})
}

func nativeGroupPublication() GroupPublication {
	return GroupPublication{ProviderID: "provider", ProviderRevision: 7, Group: PublicationGroup{ID: "g", Name: "managed", Revision: 4, CandidateIDs: []string{"a"}, SelectedNodeID: "a"}}
}

func TestNativeGroupPublicationPreservesProviderAndSelectionAcrossRestart(t *testing.T) {
	f, e, j := newNativeGroupFixture(t)
	f.dropAcknowledgement = true
	before, _ := e.Inventory(context.Background())
	after, err := e.PublishGroup(context.Background(), nativeGroupPublication(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != 3 || after.Groups["g"].Revision != 4 || !reflect.DeepEqual(after.Groups["g"].NodeIDs, []string{"a"}) || after.Providers["provider"].Revision != 7 || !reflect.DeepEqual(after.Providers["provider"].Nodes, before.Providers["provider"].Nodes) || !reflect.DeepEqual(before.Groups["other"], after.Groups["other"]) {
		t.Fatalf("incorrect group readback: %#v", after)
	}
	if f.writes != 1 {
		t.Fatalf("duplicate publication: %d", f.writes)
	}
	e = nativeGroupEngine(t, f, j)
	after, err = e.Inventory(context.Background())
	if err != nil || after.Groups["g"].Revision != 4 || after.Providers["provider"].Revision != 7 {
		t.Fatalf("restart: %#v %v", after, err)
	}
	selection, err := e.SetRuntimeSelection(context.Background(), SelectionScope{GatewayID: "gw", GroupID: "g", Transport: "both"}, "a", 8)
	if err != nil || selection.ObservedNodeID != "a" {
		t.Fatalf("selection after independent group apply: %#v %v", selection, err)
	}
}

func TestNativeGroupPreflightRejectsBeforeDurableMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*GroupPublication, *int64)
	}{
		{"stale generation", func(_ *GroupPublication, g *int64) { *g = 1 }},
		{"stale provider", func(p *GroupPublication, _ *int64) { p.ProviderRevision = 6 }},
		{"stale group", func(p *GroupPublication, _ *int64) { p.Group.Revision = 2 }},
		{"reused group revision with different membership", func(p *GroupPublication, _ *int64) { p.Group.Revision = 3 }},
		{"unknown member", func(p *GroupPublication, _ *int64) {
			p.Group.CandidateIDs = []string{"foreign"}
			p.Group.SelectedNodeID = "foreign"
		}},
		{"removed selection", func(p *GroupPublication, _ *int64) { p.Group.SelectedNodeID = "b" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, e, j := newNativeGroupFixture(t)
			before, _ := j.Entries(context.Background())
			p, generation := nativeGroupPublication(), int64(2)
			test.change(&p, &generation)
			_, err := e.PublishGroup(context.Background(), p, generation)
			if err == nil {
				t.Fatal("invalid group publication accepted")
			}
			after, _ := j.Entries(context.Background())
			if !reflect.DeepEqual(before, after) || f.writes != 0 {
				t.Fatal("preflight rejection mutated journal or daemon")
			}
		})
	}
}

func TestNativeGroupAuthoritativeRejectionClearsPending(t *testing.T) {
	f, e, j := newNativeGroupFixture(t)
	f.reject = true
	if _, err := e.PublishGroup(context.Background(), nativeGroupPublication(), 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("rejection: %v", err)
	}
	e = nativeGroupEngine(t, f, j)
	if _, err := e.Inventory(context.Background()); err != nil {
		t.Fatalf("rejected group operation poisoned inventory: %v", err)
	}
	f.mu.Lock()
	f.reject = false
	f.mu.Unlock()
	if _, err := e.PublishGroup(context.Background(), nativeGroupPublication(), 2); err != nil {
		t.Fatalf("next group operation blocked: %v", err)
	}
}

func TestNativeGroupSameRevisionRecordsCorrelatedNoop(t *testing.T) {
	f, e, j := newNativeGroupFixture(t)
	identity := MutationIdentity{ID: "group-noop-1", RequestHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TargetKind: "group", TargetID: "g", FenceToken: 1}
	ctx := WithMutationIdentity(context.Background(), identity)
	if _, err := e.PublishGroup(ctx, GroupPublication{ProviderID: "provider", ProviderRevision: 7, Group: PublicationGroup{ID: "g", Name: "managed", Revision: 3, CandidateIDs: []string{"a", "b"}, SelectedNodeID: "a"}}, 2); err != nil {
		t.Fatalf("same-revision no-op: %v", err)
	}
	if f.writes != 0 {
		t.Fatalf("no-op contacted daemon: %d", f.writes)
	}
	receipt, err := e.MutationStatus(context.Background(), identity)
	if err != nil || receipt.State != MutationCommitted || receipt.Generation != 2 {
		t.Fatalf("no-op receipt: %#v %v", receipt, err)
	}
	restarted := nativeGroupEngine(t, f, j)
	receipt, err = restarted.MutationStatus(context.Background(), identity)
	if err != nil || receipt.State != MutationCommitted {
		t.Fatalf("restarted no-op receipt: %#v %v", receipt, err)
	}
}

func TestNativeGroupDuplicateCorrelationMalformedBodyDoesNotBecomeFreshRejection(t *testing.T) {
	f, e, _ := newNativeGroupFixture(t)
	identity := MutationIdentity{ID: "group-malformed-1", RequestHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", TargetKind: "group", TargetID: "g", FenceToken: 1}
	ctx := WithMutationIdentity(context.Background(), identity)
	publication := nativeGroupPublication()
	if _, err := e.PublishGroup(ctx, publication, 2); err != nil {
		t.Fatal(err)
	}
	publication.Group.CandidateIDs = nil
	if _, err := e.PublishGroup(ctx, publication, 2); err == nil || IsDefiniteRejection(err) {
		t.Fatalf("malformed duplicate was treated as a fresh rejection: %v", err)
	}
	if f.writes != 1 {
		t.Fatalf("duplicate mutated daemon: %d", f.writes)
	}
}
