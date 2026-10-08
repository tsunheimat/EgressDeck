package deployment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
)

func journalVault(t *testing.T, id string, key byte) *secrets.Vault {
	t.Helper()
	v, err := secrets.New(id, bytes.Repeat([]byte{key}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func seedEncryptedJournal(t *testing.T, path string, vault *secrets.Vault) (*FileJournal, Operation) {
	t.Helper()
	j, err := OpenEncryptedFileJournal(path, vault)
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Kind: "gateway", ID: "gateway-one"}
	fence, err := j.NextFence(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	op, err := j.Create(context.Background(), Operation{
		ID: "native-operation", Target: target, Action: "policy-apply", IdempotencyKey: "apply-once", RequestHash: "immutable-request-hash", FenceToken: fence.Token,
		Views: StateViews{Desired: &StateRecord{Generation: 7, Revision: "revision-seven", Data: json.RawMessage(`{"native_config":"node { edge: 'trojan://private-node-password@edge.example:443' }","authorization":"Bearer private-bearer-token"}`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return j, op
}

func readJournalFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEncryptedJournalPreservesNativeConfigAndSemanticsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "operations.json")
	vault := journalVault(t, "application-key", 0x72)
	j, before := seedEncryptedJournal(t, path, vault)
	before.Status = StatusStaged
	if err := j.Save(ctx, before); err != nil {
		t.Fatal(err)
	}
	raw := readJournalFile(t, path)
	for _, forbidden := range []string{"private-node-password", "private-bearer-token", "native_config", "trojan://", "immutable-request-hash", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x72}, secrets.KeySize))} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("persisted journal contains sensitive state")
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode is %o", info.Mode().Perm())
	}
	j, err = OpenEncryptedFileJournal(path, vault)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, readJournalFile(t, path)) {
		t.Fatal("opening rewrote journal")
	}
	after, err := j.Get(ctx, before.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != before.Status || after.FenceToken != before.FenceToken || !bytes.Equal(after.Views.Desired.Data, before.Views.Desired.Data) {
		t.Fatal("restart changed operation state or native credentials")
	}
	indexed, err := j.FindByIdempotency(ctx, before.Target, before.IdempotencyKey)
	if err != nil || indexed.ID != before.ID {
		t.Fatalf("idempotency not restored: %v", err)
	}
	duplicate := before.Clone()
	duplicate.ID = "unused-id"
	got, err := j.Create(ctx, duplicate)
	if err != nil || got.ID != before.ID {
		t.Fatalf("idempotency retry changed identity: %v", err)
	}
	duplicate.RequestHash = "different-request"
	if _, err := j.Create(ctx, duplicate); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting retry: %v", err)
	}
	fence, err := j.NextFence(ctx, before.Target)
	if err != nil || fence.Token != before.FenceToken+1 {
		t.Fatalf("fence not restored: %v", err)
	}
	if current, err := j.FenceCurrent(ctx, before.Target, before.FenceToken); err != nil || current {
		t.Fatalf("old fence is current: %v", err)
	}
	after.Status = StatusApplying
	if err := j.Save(ctx, after); !errors.Is(err, ErrFenceLost) {
		t.Fatalf("stale save was accepted: %v", err)
	}
}

func TestEncryptedJournalRejectsUnconfiguredKeysAndPlaintextWithoutChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.json")
	for _, vault := range []*secrets.Vault{nil, new(secrets.Vault)} {
		if _, err := OpenEncryptedFileJournal(path, vault); !errors.Is(err, secrets.ErrKeyUnavailable) {
			t.Fatalf("missing key: %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("missing-key open created a file")
		}
	}
	legacy, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Create(context.Background(), Operation{ID: "old-operation", Target: Target{Kind: "gateway", ID: "one"}, Action: "apply"}); err != nil {
		t.Fatal(err)
	}
	before := readJournalFile(t, path)
	if _, err := OpenEncryptedFileJournal(path, journalVault(t, "active", 1)); !errors.Is(err, ErrPlaintextJournal) {
		t.Fatalf("legacy format silently accepted: %v", err)
	}
	if !bytes.Equal(before, readJournalFile(t, path)) {
		t.Fatal("legacy journal was rewritten")
	}
	got, err := legacy.Get(context.Background(), "old-operation")
	if err != nil || got.ID != "old-operation" {
		t.Fatalf("legacy state lost: %v", err)
	}
}

func TestEncryptedJournalRejectsTamperAndFormatDowngrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.json")
	vault := journalVault(t, "active", 1)
	_, _ = seedEncryptedJournal(t, path, vault)
	raw := readJournalFile(t, path)
	if _, err := OpenFileJournal(path); !errors.Is(err, ErrEncryptedJournal) {
		t.Fatalf("plaintext opener accepted encrypted file: %v", err)
	}
	if _, err := OpenEncryptedFileJournal(path, journalVault(t, "active", 2)); !errors.Is(err, secrets.ErrAuthentication) {
		t.Fatalf("wrong key accepted: %v", err)
	}
	if !bytes.Equal(raw, readJournalFile(t, path)) {
		t.Fatal("failed open rewrote original")
	}
	tests := []struct {
		name   string
		mutate func(*encryptedFileJournalDocument)
		want   error
	}{
		{"ciphertext", func(d *encryptedFileJournalDocument) { d.Envelope.Ciphertext[0] ^= 1 }, secrets.ErrAuthentication},
		{"nonce", func(d *encryptedFileJournalDocument) { d.Envelope.Nonce[0] ^= 1 }, secrets.ErrAuthentication},
		{"envelope version", func(d *encryptedFileJournalDocument) { d.Envelope.Version++ }, secrets.ErrInvalidEnvelope},
		{"unavailable key", func(d *encryptedFileJournalDocument) { d.Envelope.KeyID = "missing" }, secrets.ErrUnknownKey},
		{"document version", func(d *encryptedFileJournalDocument) { d.Version++ }, ErrInvalidJournal},
		{"document format", func(d *encryptedFileJournalDocument) { d.Format = "other-purpose" }, ErrInvalidJournal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var document encryptedFileJournalDocument
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			tt.mutate(&document)
			changed, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenEncryptedFileJournal(path, vault); !errors.Is(err, tt.want) {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(changed, readJournalFile(t, path)) {
				t.Fatal("failed decode rewrote journal")
			}
		})
	}
	for _, malformed := range []string{`{}`, `null`, `{"operations":{},"by_key":{},"fences":{}}`, `{"format":"egressdeck/deployment-journal","version":1,"envelope":null}`, `{"format":"egressdeck/deployment-journal","version":1,"envelope":{},"unexpected":"private-password"}`} {
		if err := os.WriteFile(path, []byte(malformed), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenEncryptedFileJournal(path, vault); err == nil {
			t.Fatal("malformed journal accepted")
		} else if strings.Contains(err.Error(), "private-password") {
			t.Fatal("decode error leaked secret")
		}
		if string(readJournalFile(t, path)) != malformed {
			t.Fatal("malformed file changed")
		}
	}
}

func TestEncryptedJournalAuthenticationPurposeAndRestoreRelocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.json")
	vault := journalVault(t, "active", 1)
	j, op := seedEncryptedJournal(t, path, vault)
	copyPath := filepath.Join(t.TempDir(), "restored.json")
	if err := os.WriteFile(copyPath, readJournalFile(t, path), 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenEncryptedFileJournal(copyPath, vault)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restored.Get(context.Background(), op.ID); err != nil || got.ID != op.ID {
		t.Fatalf("relocated restore failed: %v", err)
	}
	envelope, err := vault.SealJSON("another/purpose", j.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := json.Marshal(encryptedFileJournalDocument{Format: encryptedJournalFormat, Version: 1, Envelope: envelope})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, wrong, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEncryptedFileJournal(copyPath, vault); !errors.Is(err, secrets.ErrAuthentication) {
		t.Fatalf("wrong purpose accepted: %v", err)
	}
}

func TestEncryptedJournalAtomicFilesystemFailurePreservesDiskAndMemory(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "operations.json")
	vault := journalVault(t, "active", 1)
	j, op := seedEncryptedJournal(t, path, vault)
	before := readJournalFile(t, path)
	// Renaming the fully written temporary file onto a directory must fail.
	// The previous journal remains at its original path throughout the test.
	blocked := filepath.Join(dir, "blocked-destination")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	j.path = blocked
	changed := op.Clone()
	changed.Status = StatusApplying
	changed.Views.Desired.Data = json.RawMessage(`{"native_config":"changed-private-password"}`)
	if err := j.Save(ctx, changed); err == nil {
		t.Fatal("save unexpectedly succeeded")
	}
	got, err := j.Get(ctx, op.ID)
	if err != nil || got.Status != op.Status || !bytes.Equal(got.Views.Desired.Data, op.Views.Desired.Data) {
		t.Fatalf("failed save changed memory: %v", err)
	}
	if _, err := j.Create(ctx, Operation{ID: "failed-create", Target: op.Target, Action: "apply", IdempotencyKey: "failed-key"}); err == nil {
		t.Fatal("create unexpectedly succeeded")
	}
	if _, err := j.Get(ctx, "failed-create"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed create remained in memory: %v", err)
	}
	if _, err := j.FindByIdempotency(ctx, op.Target, "failed-key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed idempotency key remained: %v", err)
	}
	if _, err := j.NextFence(ctx, op.Target); err == nil {
		t.Fatal("fence unexpectedly succeeded")
	}
	if current, err := j.FenceCurrent(ctx, op.Target, op.FenceToken); err != nil || !current {
		t.Fatalf("failed fence changed memory: %v", err)
	}
	if !bytes.Equal(before, readJournalFile(t, path)) {
		t.Fatal("failed writes changed persisted journal")
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".deployment-journal-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("temporary journal files leaked: %v", err)
	}
	restored, err := OpenEncryptedFileJournal(path, vault)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := restored.FenceCurrent(ctx, op.Target, op.FenceToken); err != nil || !current {
		t.Fatalf("disk fence changed: %v", err)
	}
}

func TestEncryptedJournalEncryptionAndSizeFailurePreservePriorState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.json")
	vault := journalVault(t, "active", 1)
	j, op := seedEncryptedJournal(t, path, vault)
	before := readJournalFile(t, path)
	changed := op.Clone()
	changed.Status = StatusApplying
	j.codec = encryptedFileJournalCodec{}
	if err := j.Save(context.Background(), changed); !errors.Is(err, secrets.ErrKeyUnavailable) {
		t.Fatalf("encryption failure: %v", err)
	}
	j.codec = encryptedFileJournalCodec{vault: vault}
	changed.Views.Desired.Data = json.RawMessage(`{"native_config":"` + strings.Repeat("x", secrets.MaxPlaintextSize) + `"}`)
	if err := j.Save(context.Background(), changed); !errors.Is(err, secrets.ErrTooLarge) {
		t.Fatalf("oversize failure: %v", err)
	}
	if !bytes.Equal(before, readJournalFile(t, path)) {
		t.Fatal("failed encryption replaced prior file")
	}
	got, err := j.Get(context.Background(), op.ID)
	if err != nil || got.Status != op.Status || !bytes.Equal(got.Views.Desired.Data, op.Views.Desired.Data) {
		t.Fatalf("failed encryption changed memory: %v", err)
	}
}

func TestEncryptedJournalHistoricalKeyRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.json")
	_, op := seedEncryptedJournal(t, path, journalVault(t, "old", 1))
	vault, err := secrets.NewKeyring("new", map[string][]byte{"old": bytes.Repeat([]byte{1}, secrets.KeySize), "new": bytes.Repeat([]byte{2}, secrets.KeySize)})
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenEncryptedFileJournal(path, vault)
	if err != nil {
		t.Fatal(err)
	}
	op.Status = StatusStaged
	if err := j.Save(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	var document encryptedFileJournalDocument
	if err := json.Unmarshal(readJournalFile(t, path), &document); err != nil {
		t.Fatal(err)
	}
	if document.Envelope.KeyID != "new" {
		t.Fatal("mutation did not use active key")
	}
	if _, err := OpenEncryptedFileJournal(path, journalVault(t, "new", 2)); err != nil {
		t.Fatalf("rotated journal still needs retired key: %v", err)
	}
}

func TestJournalOfflineMigrationPreservesOriginalAndRefusesOverwrite(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	source := filepath.Join(dir, "legacy.json")
	destination := filepath.Join(dir, "encrypted.json")
	legacy, err := OpenFileJournal(source)
	if err != nil {
		t.Fatal(err)
	}
	target := Target{Kind: "gateway", ID: "migration-gateway"}
	fence, err := legacy.NextFence(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	op, err := legacy.Create(ctx, Operation{ID: "migration-operation", Target: target, IdempotencyKey: "migrate-key", RequestHash: "original-request", FenceToken: fence.Token, Views: StateViews{Desired: &StateRecord{Data: json.RawMessage(`{"native_config":"private-migration-password"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	original := readJournalFile(t, source)
	vault := journalVault(t, "active", 1)
	if err := MigratePlainFileJournal(source, destination, vault); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, readJournalFile(t, source)) {
		t.Fatal("migration changed original journal")
	}
	encrypted := readJournalFile(t, destination)
	if bytes.Contains(encrypted, []byte("private-migration-password")) {
		t.Fatal("migration output contains plaintext")
	}
	restored, err := OpenEncryptedFileJournal(destination, vault)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restored.FindByIdempotency(ctx, target, "migrate-key")
	if err != nil || got.ID != op.ID || !bytes.Equal(got.Views.Desired.Data, op.Views.Desired.Data) {
		t.Fatalf("migration lost operation state: %v", err)
	}
	if current, err := restored.FenceCurrent(ctx, target, fence.Token); err != nil || !current {
		t.Fatalf("migration lost fence: %v", err)
	}
	if err := MigratePlainFileJournal(source, destination, vault); !errors.Is(err, ErrMigrationDestinationExists) {
		t.Fatalf("migration overwrote destination: %v", err)
	}
	if !bytes.Equal(encrypted, readJournalFile(t, destination)) || !bytes.Equal(original, readJournalFile(t, source)) {
		t.Fatal("rejected migration changed files")
	}
	if err := MigratePlainFileJournal(source, source, vault); !errors.Is(err, ErrMigrationDestinationExists) {
		t.Fatalf("migration overwrote source: %v", err)
	}
	if err := MigratePlainFileJournal(destination, filepath.Join(dir, "double.json"), vault); !errors.Is(err, ErrEncryptedJournal) {
		t.Fatalf("accepted encrypted source: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "double.json")); !os.IsNotExist(err) {
		t.Fatal("invalid migration created destination")
	}
}

func TestJournalOfflineMigrationFailureLeavesOriginalAndDestinationUntouched(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "legacy.json")
	original := []byte(`{"operations":{},"by_key":{},"fences":{}}`)
	if err := os.WriteFile(source, original, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "encrypted.json")
	if err := MigratePlainFileJournal(source, destination, nil); !errors.Is(err, secrets.ErrKeyUnavailable) {
		t.Fatalf("nil key: %v", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("missing-key migration created output")
	}
	// A destination beneath an ordinary file fails before publication.
	blocked := filepath.Join(dir, "parent-file")
	if err := os.WriteFile(blocked, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MigratePlainFileJournal(source, filepath.Join(blocked, "journal.json"), journalVault(t, "active", 1)); err == nil {
		t.Fatal("filesystem failure ignored")
	}
	if !bytes.Equal(original, readJournalFile(t, source)) || string(readJournalFile(t, blocked)) != "keep" {
		t.Fatal("failed migration changed existing files")
	}
	// An existing symlink must never be followed or overwritten.
	if err := os.Symlink(source, destination); err != nil {
		t.Fatal(err)
	}
	if err := MigratePlainFileJournal(source, destination, journalVault(t, "active", 1)); !errors.Is(err, ErrMigrationDestinationExists) {
		t.Fatalf("symlink destination accepted: %v", err)
	}
	if !bytes.Equal(original, readJournalFile(t, source)) {
		t.Fatal("symlink migration damaged source")
	}
}
