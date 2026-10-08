package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
)

// TestNativeSourcePublicationAndRestart connects to the actual patched dae
// startHotControl HTTP server and ControlPlane, launched by the source fixture
// runner. It deliberately makes no claim about privileged kernel attachment.
func TestNativeSourcePublicationAndRestart(t *testing.T) {
	dir := os.Getenv("EGRESSDECK_NATIVE_HARNESS_DIR")
	if dir == "" {
		t.Skip("run engine/dae/fixtures/run_native_source.py with a patched dae source tree")
	}
	ctx := context.Background()
	vault, err := secrets.New("native-source-fixture", bytes.Repeat([]byte{0x4b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(dir, "agent.jsonl")
	newEngine := func() *NativeEngine {
		t.Helper()
		e, err := NewNativeEngine(NativeOptions{SocketPath: filepath.Join(dir, "control.sock"), Vault: vault, Timeout: 3 * time.Second}, NewNativeFileJournal(journalPath))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := newEngine()
	initial, err := e.Inventory(ctx)
	if err != nil || initial.Generation != 1 || len(initial.Groups) != 2 {
		t.Fatalf("baseline inventory: generation=%d groups=%d err=%v", initial.Generation, len(initial.Groups), err)
	}
	revision := ProviderRevision{
		ProviderID: "source-provider", Revision: 7, ContentHash: "source-provider:7",
		Nodes: []Node{
			{ID: "candidate-a", Name: "same display name", Connection: "socks5://source-user:source-private-password@127.0.0.1:19281"},
			{ID: "candidate-b", Name: "same display name", Connection: "socks5://source-user:source-private-password@127.0.0.1:19282"},
		},
		Groups: []PublicationGroup{
			{ID: "group-a", Name: "egress-a", Revision: 2, CandidateIDs: []string{"candidate-a", "candidate-b"}, SelectedNodeID: "candidate-a"},
			{ID: "group-b", Name: "egress-b", Revision: 3, CandidateIDs: []string{"candidate-a", "candidate-b"}, SelectedNodeID: "candidate-b"},
		},
	}
	stage, err := e.StageProvider(ctx, revision, initial.Generation)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the native adapter from its on-disk encrypted stage before sending.
	e = newEngine()
	published, err := e.PublishProvider(ctx, stage)
	if err != nil {
		t.Fatal(err)
	}
	assertSnapshot := func(snapshot Snapshot, generation int64, selectedA, selectedB string) {
		t.Helper()
		if snapshot.Generation != generation || snapshot.Providers[revision.ProviderID].Revision != revision.Revision || len(snapshot.Groups) != 2 {
			t.Fatalf("publication readback lost identity: generation=%d groups=%d", snapshot.Generation, len(snapshot.Groups))
		}
		for _, item := range []struct{ id, name, selected string }{{"group-a", "egress-a", selectedA}, {"group-b", "egress-b", selectedB}} {
			group := snapshot.Groups[item.id]
			if group.Name != item.name || len(group.NodeIDs) != 2 {
				t.Fatalf("group %s lost native candidates", item.id)
			}
			found := false
			for _, selection := range snapshot.Selections {
				if selection.Scope.GroupID == item.id {
					found = true
					if selection.DesiredNodeID != item.selected || selection.ObservedNodeID != item.selected {
						t.Fatalf("group %s selection mismatch", item.id)
					}
				}
			}
			if !found {
				t.Fatalf("group %s selection missing", item.id)
			}
		}
		encoded, _ := json.Marshal(snapshot)
		if bytes.Contains(encoded, []byte("source-private-password")) || bytes.Contains(encoded, []byte("socks5://")) {
			t.Fatal("public native snapshot exposed credentials")
		}
	}
	assertSnapshot(published, 2, "candidate-a", "candidate-b")
	scope := SelectionScope{GatewayID: "source-gateway", GroupID: "group-a", Transport: "both"}
	selection, err := e.PersistSelection(ctx, scope, "candidate-b", 0)
	if err != nil || selection.Revision != 1 || selection.ObservedNodeID != "candidate-b" {
		t.Fatalf("native persisted selection: revision=%d err=%v", selection.Revision, err)
	}
	if _, err := e.SetRuntimeSelection(ctx, scope, "candidate-a", 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale agent selection revision was accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "restart.request"), []byte("restart\n"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "restarted")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("runner did not restart the real source server")
		}
		time.Sleep(25 * time.Millisecond)
	}
	e = newEngine()
	restored, err := e.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertSnapshot(restored, 3, "candidate-b", "candidate-b")
	if restored.Selections[scope.key()].Revision != 1 {
		t.Fatal("agent restart lost durable selection revision")
	}
	selection, err = e.PersistSelection(ctx, scope, "candidate-a", 1)
	if err != nil || selection.Revision != 2 || selection.ObservedNodeID != "candidate-a" {
		t.Fatalf("selection after source restart: revision=%d err=%v", selection.Revision, err)
	}
	final, err := e.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertSnapshot(final, 4, "candidate-a", "candidate-b")
	for _, path := range []string{journalPath, filepath.Join(dir, "state", "inventory.json")} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("native journal permissions are not private")
		}
		if strings.Contains(string(data), "source-private-password") || strings.Contains(string(data), "socks5://") {
			t.Fatal("private link appeared in a native journal")
		}
	}
	t.Log("actual NativeEngine -> Unix HTTP -> startHotControl -> ControlPlane: two groups published; stable IDs and isolated manual selection restored after source process and agent journal restart; journals encrypted")
}
