package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

type providerMutationStore interface {
	Store
	DocumentStore
	ProviderMutator
	ProviderSourceMutator
}

func providerMutationStores() map[string]func(*testing.T) providerMutationStore {
	return map[string]func(*testing.T) providerMutationStore{
		"memory": func(*testing.T) providerMutationStore { return NewMemoryStore() },
		"file": func(t *testing.T) providerMutationStore {
			s, err := NewFileStore(filepath.Join(t.TempDir(), "store.json"))
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	}
}

func providerMutationFixture(t *testing.T, s providerMutationStore, active int64) domain.Provider {
	t.Helper()
	p, err := s.CreateProvider(context.Background(), domain.Provider{Name: "original", Source: "https://example.invalid/original", ActiveRevision: active})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDocument(context.Background(), "old-source", json.RawMessage(`{"ciphertext":"old"}`)); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertProviderDocument(t *testing.T, s DocumentStore, key, want string) {
	t.Helper()
	got, err := s.LoadDocument(context.Background(), key)
	var gotValue, wantValue any
	if err != nil || json.Unmarshal(got, &gotValue) != nil || json.Unmarshal([]byte(want), &wantValue) != nil || !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("document %q = %s, %v; want %s", key, got, err, want)
	}
}

func TestProviderMutationRequiresExactPositiveCAS(t *testing.T) {
	ctx := context.Background()
	for name, factory := range providerMutationStores() {
		t.Run(name, func(t *testing.T) {
			s := factory(t)
			original := providerMutationFixture(t, s, 0)
			var durableBefore []byte
			if fs, ok := s.(*FileStore); ok {
				var err error
				durableBefore, err = os.ReadFile(fs.Path())
				if err != nil {
					t.Fatal(err)
				}
			}
			changed := original
			changed.Name, changed.Source = "changed", "https://example.invalid/changed"
			for _, expected := range []int64{-1, 0, original.Revision + 1} {
				if _, err := s.UpdateProviderSource(ctx, changed, expected, "new-source", json.RawMessage(`{"ciphertext":"new"}`), "old-source"); !errors.Is(err, domain.ErrConflict) {
					t.Fatalf("update expected %d: %v", expected, err)
				}
				if err := s.DeleteProviderSource(ctx, original.ID, expected, "old-source"); !errors.Is(err, domain.ErrConflict) {
					t.Fatalf("delete expected %d: %v", expected, err)
				}
			}
			if got, err := s.GetProvider(ctx, original.ID); err != nil || !reflect.DeepEqual(got, original) {
				t.Fatalf("failed CAS changed provider: %+v, %v", got, err)
			}
			assertProviderDocument(t, s, "old-source", `{"ciphertext":"old"}`)
			if _, err := s.LoadDocument(ctx, "new-source"); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("failed CAS created a new source document: %v", err)
			}
			missing := changed
			missing.ID = domain.NewID()
			if _, err := s.UpdateProvider(ctx, missing, 1); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("missing update: %v", err)
			}
			if err := s.DeleteProvider(ctx, missing.ID, 1); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("missing delete: %v", err)
			}
			if fs, ok := s.(*FileStore); ok {
				durableAfter, err := os.ReadFile(fs.Path())
				if err != nil || !bytes.Equal(durableBefore, durableAfter) {
					t.Fatalf("rejected CAS changed durable bytes: %v", err)
				}
			}
		})
	}
}

func TestProviderMutationPreservesActiveRevisionAndRefusesDelete(t *testing.T) {
	ctx := context.Background()
	for name, factory := range providerMutationStores() {
		t.Run(name, func(t *testing.T) {
			s := factory(t)
			p := providerMutationFixture(t, s, 7)
			changed := p
			changed.Name, changed.ActiveRevision = "renamed", 99
			updated, err := s.UpdateProvider(ctx, changed, p.Revision)
			if err != nil || updated.Revision != p.Revision+1 || updated.ActiveRevision != 7 || !updated.CreatedAt.Equal(p.CreatedAt) {
				t.Fatalf("configuration update changed lifecycle identity: %+v, %v", updated, err)
			}
			if err := s.DeleteProviderSource(ctx, p.ID, updated.Revision, "old-source"); !errors.Is(err, ErrProviderReferenced) {
				t.Fatalf("deleted active provider: %v", err)
			}
			assertProviderDocument(t, s, "old-source", `{"ciphertext":"old"}`)
			if got, err := s.GetProvider(ctx, p.ID); err != nil || !reflect.DeepEqual(got, updated) {
				t.Fatalf("active deletion changed provider: %+v, %v", got, err)
			}
		})
	}
}

func TestProviderSourceMutationRotationRestartAndDelete(t *testing.T) {
	ctx := context.Background()
	for name, factory := range providerMutationStores() {
		t.Run(name, func(t *testing.T) {
			s := factory(t)
			p := providerMutationFixture(t, s, 0)
			p.Source = "https://example.invalid/rotated"
			data := json.RawMessage(`{"ciphertext":"new"}`)
			updated, err := s.UpdateProviderSource(ctx, p, p.Revision, "new-source", data, "old-source")
			if err != nil || updated.Revision != p.Revision+1 {
				t.Fatalf("rotate: %+v, %v", updated, err)
			}
			data[2] = 'X'
			if fs, ok := s.(*FileStore); ok {
				s = reopenFileStore(t, fs)
			}
			assertProviderDocument(t, s, "new-source", `{"ciphertext":"new"}`)
			assertProviderDocument(t, s, "old-source", providerSourceTombstone)
			if got, err := s.GetProvider(ctx, p.ID); err != nil || !reflect.DeepEqual(got, updated) {
				t.Fatalf("rotation readback: %+v, %v", got, err)
			}
			// Replacing in place must not retire the document that was just saved.
			updated, err = s.UpdateProviderSource(ctx, updated, updated.Revision, "new-source", json.RawMessage(`{"ciphertext":"replacement"}`), "new-source")
			if err != nil {
				t.Fatal(err)
			}
			assertProviderDocument(t, s, "new-source", `{"ciphertext":"replacement"}`)
			// A metadata-only update accepts an empty document pair.
			updated, err = s.UpdateProviderSource(ctx, updated, updated.Revision, "", nil, "")
			if err != nil {
				t.Fatal(err)
			}
			assertProviderDocument(t, s, "new-source", `{"ciphertext":"replacement"}`)
			if err := s.DeleteProviderSource(ctx, p.ID, updated.Revision, "new-source"); err != nil {
				t.Fatal(err)
			}
			if fs, ok := s.(*FileStore); ok {
				s = reopenFileStore(t, fs)
			}
			if _, err := s.GetProvider(ctx, p.ID); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("deleted provider survived: %v", err)
			}
			assertProviderDocument(t, s, "new-source", providerSourceTombstone)
		})
	}
}

func TestProviderSourceMutationConcurrentCASDoesNotPersistLosingCiphertext(t *testing.T) {
	ctx := context.Background()
	for name, factory := range providerMutationStores() {
		t.Run(name, func(t *testing.T) {
			s := factory(t)
			p := providerMutationFixture(t, s, 0)
			type result struct {
				key string
				err error
			}
			results := make(chan result, 2)
			var wg sync.WaitGroup
			for _, key := range []string{"one", "two"} {
				wg.Add(1)
				go func(key string) {
					defer wg.Done()
					changed := p
					changed.Name = key
					_, err := s.UpdateProviderSource(ctx, changed, p.Revision, key, json.RawMessage(`{"ciphertext":"candidate"}`), "old-source")
					results <- result{key, err}
				}(key)
			}
			wg.Wait()
			close(results)
			wins, conflicts := 0, 0
			for result := range results {
				if result.err == nil {
					wins++
					assertProviderDocument(t, s, result.key, `{"ciphertext":"candidate"}`)
				} else if errors.Is(result.err, domain.ErrConflict) {
					conflicts++
					if _, err := s.LoadDocument(ctx, result.key); !errors.Is(err, domain.ErrNotFound) {
						t.Fatalf("losing update persisted ciphertext: %v", err)
					}
				} else {
					t.Fatal(result.err)
				}
			}
			if wins != 1 || conflicts != 1 {
				t.Fatalf("concurrent CAS wins=%d conflicts=%d", wins, conflicts)
			}
		})
	}
}

func TestProviderSourceMutationValidationLeavesStateUnchanged(t *testing.T) {
	ctx := context.Background()
	for name, factory := range providerMutationStores() {
		t.Run(name, func(t *testing.T) {
			s := factory(t)
			original := providerMutationFixture(t, s, 0)
			for _, document := range []struct {
				key  string
				data json.RawMessage
			}{{"", json.RawMessage(`{}`)}, {"new-source", nil}, {"new-source", json.RawMessage(`invalid`)}} {
				if _, err := s.UpdateProviderSource(ctx, original, original.Revision, document.key, document.data, "old-source"); err == nil {
					t.Fatal("accepted incomplete/invalid document")
				}
			}
			changed := original
			changed.Name = ""
			if _, err := s.UpdateProviderSource(ctx, changed, original.Revision, "new-source", json.RawMessage(`{}`), "old-source"); err == nil {
				t.Fatal("accepted invalid provider")
			}
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if _, err := s.UpdateProviderSource(canceled, original, original.Revision, "new-source", json.RawMessage(`{}`), "old-source"); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled update: %v", err)
			}
			if err := s.DeleteProviderSource(canceled, original.ID, original.Revision, "old-source"); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled delete: %v", err)
			}
			assertProviderDocument(t, s, "old-source", `{"ciphertext":"old"}`)
			if _, err := s.LoadDocument(ctx, "new-source"); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("invalid mutation persisted ciphertext: %v", err)
			}
			if got, err := s.GetProvider(ctx, original.ID); err != nil || !reflect.DeepEqual(got, original) {
				t.Fatalf("canceled mutation changed provider: %+v, %v", got, err)
			}
		})
	}
}

func TestFileProviderMutationPersistenceFailureRollsBackInventoryAndSources(t *testing.T) {
	ctx := context.Background()
	mutations := map[string]func(*FileStore, domain.Provider) error{
		"update": func(s *FileStore, p domain.Provider) error {
			p.Name = "changed"
			_, err := s.UpdateProvider(ctx, p, p.Revision)
			return err
		},
		"update source": func(s *FileStore, p domain.Provider) error {
			p.Source = "https://example.invalid/changed"
			_, err := s.UpdateProviderSource(ctx, p, p.Revision, "new-source", json.RawMessage(`{"ciphertext":"new"}`), "old-source")
			return err
		},
		"delete": func(s *FileStore, p domain.Provider) error { return s.DeleteProvider(ctx, p.ID, p.Revision) },
		"delete source": func(s *FileStore, p domain.Provider) error {
			return s.DeleteProviderSource(ctx, p.ID, p.Revision, "old-source")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s := providerMutationStores()["file"](t).(*FileStore)
			p := providerMutationFixture(t, s, 0)
			before := s.mem.cloneState()
			bytesBefore, err := os.ReadFile(s.Path())
			if err != nil {
				t.Fatal(err)
			}
			restore := blockFileStorePersistence(t, s)
			if err := mutate(s, p); err == nil {
				t.Fatal("acknowledged a mutation whose persistence failed")
			}
			if got := s.mem.cloneState(); !reflect.DeepEqual(got, before) {
				t.Fatal("failed persistence changed inventory or encrypted source in memory")
			}
			restore()
			bytesAfter, err := os.ReadFile(s.Path())
			if err != nil || !bytes.Equal(bytesBefore, bytesAfter) {
				t.Fatalf("failed persistence changed durable bytes: %v", err)
			}
			s = reopenFileStore(t, s)
			// FileStore formats RawMessage documents while writing; compare the
			// canonical JSON state so formatting is not mistaken for a mutation.
			gotJSON, err := json.Marshal(s.mem.cloneState())
			if err != nil {
				t.Fatal(err)
			}
			beforeJSON, err := json.Marshal(before)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotJSON, beforeJSON) {
				t.Fatal("failed persistence changed state after restart")
			}
		})
	}
}
