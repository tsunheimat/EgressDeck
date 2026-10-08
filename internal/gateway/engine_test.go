package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type failingJournal struct{}

func (failingJournal) Append(context.Context, JournalEntry) error      { return errors.New("disk full") }
func (failingJournal) Entries(context.Context) ([]JournalEntry, error) { return nil, nil }

func revision(provider string, rev int64, nodes ...string) ProviderRevision {
	r := ProviderRevision{ProviderID: provider, Revision: rev}
	for _, id := range nodes {
		r.Nodes = append(r.Nodes, Node{ID: id, ProviderID: provider, Name: id})
	}
	return r
}

func publish(t *testing.T, e *FakeEngine, r ProviderRevision) Snapshot {
	t.Helper()
	ctx := context.Background()
	current, err := e.Inventory(ctx)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	id, err := e.StageProvider(ctx, r, current.Generation)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	s, err := e.PublishProvider(ctx, id)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	return s
}

func TestHotPublishKeepsUnrelatedStateAndStableHandles(t *testing.T) {
	e := NewFakeEngine()
	first := publish(t, e, revision("p1", 1, "a", "b"))
	publish(t, e, revision("p2", 1, "x"))
	e.AddGroup(OutboundGroup{ID: "g1", ProviderIDs: []string{"p1"}, NodeIDs: []string{"a", "b"}})
	e.AddGroup(OutboundGroup{ID: "g2", ProviderIDs: []string{"p2"}, NodeIDs: []string{"x"}})
	if _, err := e.PersistSelection(context.Background(), SelectionScope{GatewayID: "gw", GroupID: "g1"}, "a", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := e.PersistSelection(context.Background(), SelectionScope{GatewayID: "gw", GroupID: "g2"}, "x", 0); err != nil {
		t.Fatal(err)
	}
	before, _ := e.Inventory(context.Background())
	published := publish(t, e, revision("p1", 2, "a", "c"))
	if published.Generation != first.Generation+2 { // p2 was published between first and update
		t.Fatalf("generation = %d, want %d", published.Generation, first.Generation+2)
	}
	var handleA uint64
	for _, n := range published.Providers["p1"].Nodes {
		if n.ID == "a" {
			handleA = n.Handle
		}
	}
	var oldHandleA uint64
	for _, n := range before.Providers["p1"].Nodes {
		if n.ID == "a" {
			oldHandleA = n.Handle
		}
	}
	if handleA == 0 || handleA != oldHandleA {
		t.Fatalf("stable handle lost: old=%d new=%d", oldHandleA, handleA)
	}
	if published.Groups["g2"].NodeIDs[0] != "x" {
		t.Fatal("unrelated group changed")
	}
	if got := published.Selections[SelectionScope{GatewayID: "gw", GroupID: "g2"}.key()].ObservedNodeID; got != "x" {
		t.Fatalf("unrelated selection changed: %q", got)
	}
	if got := published.Selections[SelectionScope{GatewayID: "gw", GroupID: "g1"}.key()].ObservedNodeID; got != "a" {
		t.Fatalf("retained selection changed: %q", got)
	}
}

func TestFailedStageLeavesActiveRevision(t *testing.T) {
	e := NewFakeEngine()
	publish(t, e, revision("p", 1, "n"))
	if _, err := e.StageProvider(context.Background(), revision("p", 2), 0); !errors.Is(err, ErrEmptyRevision) {
		t.Fatalf("empty stage error = %v", err)
	}
	s, _ := e.Inventory(context.Background())
	if len(s.Providers["p"].Nodes) != 1 || s.Providers["p"].Nodes[0].ID != "n" {
		t.Fatal("failed stage evicted active revision")
	}
}

func TestUnsupportedPublicationReturnsTypedError(t *testing.T) {
	e := NewFakeEngine()
	c, _ := e.Capabilities(context.Background())
	for i := range c.Items {
		if c.Items[i].Name == CapabilityProviderPublish {
			c.Items[i].Supported = false
		}
	}
	e.SetCapabilities(c)
	id, err := e.StageProvider(context.Background(), revision("p", 1, "n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.PublishProvider(context.Background(), id); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported publication error = %v", err)
	}
	snapshot, _ := e.Inventory(context.Background())
	if snapshot.Generation != 0 {
		t.Fatal("unsupported operation mutated state")
	}
}

func TestGenerationConflictPreventsPublish(t *testing.T) {
	e := NewFakeEngine()
	id, err := e.StageProvider(context.Background(), revision("p", 1, "n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	publish(t, e, revision("other", 1, "x"))
	if _, err := e.PublishProvider(context.Background(), id); !errors.Is(err, ErrConflict) {
		t.Fatalf("publish error = %v", err)
	}
	if got, _ := e.Inventory(context.Background()); len(got.Providers["p"].Nodes) != 0 {
		t.Fatal("stale staged revision published")
	}
}

func TestSelectionRevisionAndMissingNodeReadback(t *testing.T) {
	e := NewFakeEngine()
	publish(t, e, revision("p", 1, "a", "b"))
	s, err := e.PersistSelection(context.Background(), SelectionScope{GatewayID: "gw", GroupID: "g"}, "b", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.SetRuntimeSelection(context.Background(), s.Scope, "a", s.Revision+1); !errors.Is(err, ErrConflict) {
		t.Fatalf("selection conflict = %v", err)
	}
	publish(t, e, revision("p", 2, "a"))
	got, _ := e.Inventory(context.Background())
	sel := got.Selections[s.Scope.key()]
	if sel.DesiredNodeID != "b" || sel.ObservedNodeID != "" {
		t.Fatalf("missing selection readback = %+v", sel)
	}
}

func TestFileJournalIgnoresTruncatedTail(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "journal", "ops.jsonl")
	j := NewFileJournal(path)
	if err := j.Append(context.Background(), JournalEntry{ID: "1", Operation: "test", Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(mustRead(t, path), []byte("{broken\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := j.Entries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "1" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestFileJournalRecoversLastPublishedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j := NewFileJournal(path)
	e := NewFakeEngine(j)
	publish(t, e, revision("p", 1, "n"))
	recovered := NewFakeEngine(NewFileJournal(path))
	s, err := recovered.Readback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Generation != 1 || len(s.Providers["p"].Nodes) != 1 || s.Providers["p"].Nodes[0].ID != "n" {
		t.Fatalf("recovered snapshot = %+v", s)
	}
}

func TestFileJournalRecoversPersistedSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j := NewFileJournal(path)
	e := NewFakeEngine(j)
	publish(t, e, revision("p", 1, "n"))
	if _, err := e.PersistSelection(context.Background(), SelectionScope{GatewayID: "gw", GroupID: "g"}, "n", 0); err != nil {
		t.Fatal(err)
	}
	recovered := NewFakeEngine(NewFileJournal(path))
	s, err := recovered.Readback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	key := (SelectionScope{GatewayID: "gw", GroupID: "g"}).key()
	if got := s.Selections[key].DesiredNodeID; got != "n" {
		t.Fatalf("desired node after restart = %q", got)
	}
	events, err := recovered.ResumeEvents(context.Background(), 0)
	if err != nil || len(events) == 0 {
		t.Fatalf("events after restart = %+v, err=%v", events, err)
	}
}

func TestJournalFailureRollsBackPublish(t *testing.T) {
	e := NewFakeEngine(failingJournal{})
	if _, err := func() (Snapshot, error) {
		id, stageErr := e.StageProvider(context.Background(), revision("p", 1, "n"), 0)
		if stageErr != nil {
			return Snapshot{}, stageErr
		}
		return e.PublishProvider(context.Background(), id)
	}(); !errors.Is(err, ErrJournal) {
		t.Fatalf("publish error = %v", err)
	}
	s, _ := e.Inventory(context.Background())
	if len(s.Providers) != 0 || s.Generation != 0 {
		t.Fatalf("failed journal changed active state: %+v", s)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
