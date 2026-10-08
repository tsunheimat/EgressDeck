package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

func TestDocumentStoreLifecycleAndRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadDocument(ctx, "lifecycle-v1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing document: %v", err)
	}
	payload := json.RawMessage(`{"version":1,"generation":17}`)
	if err := s.SaveDocument(ctx, "lifecycle-v1", payload); err != nil {
		t.Fatal(err)
	}
	payload[0] = '['
	data, err := s.LoadDocument(ctx, "lifecycle-v1")
	if err != nil || string(data) != `{"version":1,"generation":17}` {
		t.Fatalf("saved data aliases caller memory: %s %v", data, err)
	}
	data[0] = '['
	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err = reopened.LoadDocument(ctx, "lifecycle-v1")
	var compact bytes.Buffer
	if err != nil || json.Compact(&compact, data) != nil || compact.String() != `{"version":1,"generation":17}` {
		t.Fatalf("document did not survive restart: %s %v", data, err)
	}
	if err := reopened.SaveDocument(ctx, "lifecycle-v1", json.RawMessage(`invalid`)); err == nil {
		t.Fatal("accepted invalid JSON")
	}
	if err := reopened.SaveDocument(ctx, "", json.RawMessage(`{}`)); err == nil {
		t.Fatal("accepted empty key")
	}
	data, err = reopened.LoadDocument(ctx, "lifecycle-v1")
	compact.Reset()
	if err != nil || json.Compact(&compact, data) != nil || compact.String() != `{"version":1,"generation":17}` {
		t.Fatalf("invalid write changed document: %s %v", data, err)
	}
}

type immutableDocumentFixture interface {
	DocumentStore
	ImmutableDocumentStore
}

func exerciseImmutableDocumentRace(t *testing.T, s immutableDocumentFixture) string {
	t.Helper()
	ctx := context.Background()
	const key = "immutable-plan"
	payloads := []json.RawMessage{json.RawMessage(`{"created_at":"first"}`), json.RawMessage(`{"created_at":"second"}`)}
	type createResult struct {
		index int
		err   error
	}
	start := make(chan struct{})
	results := make(chan createResult, len(payloads))
	for i := range payloads {
		go func(index int) {
			<-start
			results <- createResult{index, s.CreateDocument(ctx, key, payloads[index])}
		}(i)
	}
	close(start)
	winner, conflicts := -1, 0
	for range payloads {
		result := <-results
		if result.err == nil {
			if winner != -1 {
				t.Fatal("both concurrent document creates succeeded")
			}
			winner = result.index
		} else if errors.Is(result.err, domain.ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("create document: %v", result.err)
		}
	}
	if winner < 0 || conflicts != 1 {
		t.Fatalf("create race winner=%d conflicts=%d", winner, conflicts)
	}
	want := string(payloads[winner])
	for i := range payloads {
		payloads[i][0] = '['
	}
	read := func() json.RawMessage {
		t.Helper()
		data, err := s.LoadDocument(ctx, key)
		var compact bytes.Buffer
		if err != nil || json.Compact(&compact, data) != nil || compact.String() != want {
			t.Fatalf("first document changed: %s, %v; want %s", data, err, want)
		}
		return data
	}
	data := read()
	data[0] = '['
	read()
	if err := s.CreateDocument(ctx, key, json.RawMessage(`{"created_at":"replacement"}`)); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("overwrite accepted: %v", err)
	}
	read()
	return want
}

func TestImmutableDocumentCreateIsAtomic(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		exerciseImmutableDocumentRace(t, NewMemoryStore())
	})
	t.Run("file", func(t *testing.T) {
		s, err := NewFileStore(filepath.Join(t.TempDir(), "store.json"))
		if err != nil {
			t.Fatal(err)
		}
		want := exerciseImmutableDocumentRace(t, s)
		s = reopenFileStore(t, s)
		if err := s.CreateDocument(context.Background(), "immutable-plan", json.RawMessage(`{"created_at":"after-restart"}`)); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("overwrite after restart accepted: %v", err)
		}
		data, err := s.LoadDocument(context.Background(), "immutable-plan")
		var compact bytes.Buffer
		if err != nil || json.Compact(&compact, data) != nil || compact.String() != want {
			t.Fatalf("first document changed after restart: %s, %v; want %s", data, err, want)
		}
	})
}
