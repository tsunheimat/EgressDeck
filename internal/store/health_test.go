package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStoreHealthIsReadOnlyAndDetectsLostStorage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckHealth(context.Background()); err != nil {
		t.Fatalf("valid state unhealthy: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("health check mutated file: %v", err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckHealth(context.Background()); err == nil {
		t.Fatal("corrupt state reported healthy")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckHealth(context.Background()); err == nil {
		t.Fatal("missing state reported healthy")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("health check recreated missing file: %v", err)
	}
}
