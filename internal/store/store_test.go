package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

func TestMemoryStoreAddressOwnershipAndCAS(t *testing.T) {
	s := NewMemoryStore()
	first, err := s.CreateDevice(context.Background(), domain.Device{Name: "one", Addresses: []domain.DeviceAddress{{Address: "192.0.2.4"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDevice(context.Background(), domain.Device{Name: "two", Addresses: []domain.DeviceAddress{{Address: "192.0.2.4"}}}); !errors.Is(err, domain.ErrAddressConflict) {
		t.Fatalf("err=%v", err)
	}
	first.Name = "changed"
	if _, err := s.UpdateDevice(context.Background(), first, first.Revision+1); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("err=%v", err)
	}
	updated, err := s.UpdateDevice(context.Background(), first, first.Revision)
	if err != nil || updated.Revision != first.Revision+1 {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	read, err := s.GetDevice(context.Background(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	read.Addresses[0].Address = "198.51.100.9"
	readAgain, err := s.GetDevice(context.Background(), first.ID)
	if err != nil || readAgain.Addresses[0].Address != "192.0.2.4" {
		t.Fatalf("store leaked mutable state: %+v", readAgain)
	}
}

func TestFileStorePersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "store.json")
	first, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := first.CreateDevice(context.Background(), domain.Device{
		ID:   "6e9d1e3a-2f89-4b5e-a6b7-9cd0e1f2a3b4",
		Name: "persistent client",
		Addresses: []domain.DeviceAddress{{
			Address: "192.0.2.41",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.GetDevice(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != created.Name || got.Revision != created.Revision || len(got.Addresses) != 1 || got.Addresses[0].Address != "192.0.2.41" {
		t.Fatalf("restored device = %+v, want %+v", got, created)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode = %o, want 600", info.Mode().Perm())
	}
}

func TestFileStoreRejectsCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(path); err == nil {
		t.Fatal("NewFileStore accepted corrupt JSON")
	}
}

func TestOpenConfiguredStoreUsesDurableFileWhenDSNUnset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	got, closeStore, err := OpenConfiguredStore(context.Background(), path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.(*FileStore); !ok {
		t.Fatalf("store type = %T, want *FileStore", got)
	}
	if err := closeStore(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenConfiguredStoreDoesNotSilentlyFallbackFromDSN(t *testing.T) {
	_, _, err := OpenConfiguredStore(context.Background(), filepath.Join(t.TempDir(), "store.json"), "missing-driver", "postgres://example.invalid/controller")
	if !errors.Is(err, ErrPostgresDriverUnavailable) {
		t.Fatalf("error = %v, want ErrPostgresDriverUnavailable", err)
	}
}

func TestMemoryStoreListIsDeterministic(t *testing.T) {
	s := NewMemoryStore()
	if _, err := s.CreateDevice(context.Background(), domain.Device{ID: "b", Name: "b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDevice(context.Background(), domain.Device{ID: "a", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	items, err := s.ListDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].ID != "a" || items[1].ID != "b" {
		t.Fatalf("items=%+v", items)
	}
}
