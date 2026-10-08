package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
)

func migrationEnv(keyID string) func(string) string {
	return func(name string) string {
		switch name {
		case "APP_ENCRYPTION_KEY":
			return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, secrets.KeySize))
		case "APP_ENCRYPTION_KEY_ID":
			return keyID
		default:
			return ""
		}
	}
}

func writePlainJournal(t *testing.T, path string) deployment.Operation {
	t.Helper()
	journal, err := deployment.OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	target := deployment.Target{Kind: "gateway", ID: "gateway-migration"}
	fence, err := journal.NextFence(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	op, err := journal.Create(context.Background(), deployment.Operation{
		ID: "operation-migration", Target: target, Action: "apply", FenceToken: fence.Token,
		IdempotencyKey: "migration-request", RequestHash: "request-hash",
		Status: deployment.StatusOutcomeUnknown,
		Views: deployment.StateViews{Desired: &deployment.StateRecord{
			Generation: 4, Data: json.RawMessage(`{"token":"sensitive-journal-credential"}`),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRunMigratesJournalWithoutChangingSource(t *testing.T) {
	for _, configuredID := range []string{"", "rotation-2026"} {
		t.Run("key-id-"+configuredID, func(t *testing.T) {
			dir := t.TempDir()
			from, to := filepath.Join(dir, "source.json"), filepath.Join(dir, "encrypted.json")
			want := writePlainJournal(t, from)
			source := readBytes(t, from)
			var stdout, stderr bytes.Buffer
			getenv := migrationEnv(configuredID)
			if code := run([]string{"-from", from, "-to", to}, getenv, &stdout, &stderr); code != 0 {
				t.Fatalf("exit=%d stderr=%q", code, stderr.String())
			}
			if stderr.Len() != 0 || !strings.Contains(stdout.String(), "completed") {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if !bytes.Equal(source, readBytes(t, from)) {
				t.Fatal("migration changed the source")
			}
			encrypted := readBytes(t, to)
			if bytes.Contains(encrypted, []byte("sensitive-journal-credential")) || bytes.Contains(encrypted, []byte(want.ID)) {
				t.Fatal("encrypted journal contains plaintext state")
			}
			if strings.Contains(stdout.String()+stderr.String(), getenv("APP_ENCRYPTION_KEY")) || strings.Contains(stdout.String()+stderr.String(), "sensitive-journal-credential") {
				t.Fatal("command output leaked credentials")
			}
			var document struct {
				Envelope secrets.Envelope `json:"envelope"`
			}
			if err := json.Unmarshal(encrypted, &document); err != nil {
				t.Fatal(err)
			}
			keyID := configuredID
			if keyID == "" {
				keyID = "primary"
			}
			if document.Envelope.KeyID != keyID {
				t.Fatalf("key ID=%q want=%q", document.Envelope.KeyID, keyID)
			}
			key, err := secrets.ParseKey(getenv("APP_ENCRYPTION_KEY"))
			if err != nil {
				t.Fatal(err)
			}
			vault, err := secrets.New(keyID, key)
			clear(key)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := deployment.OpenEncryptedFileJournal(to, vault)
			if err != nil {
				t.Fatal(err)
			}
			got, err := journal.FindByIdempotency(context.Background(), want.Target, want.IdempotencyKey)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("recovered operation differs from source; err=%v", err)
			}
			current, err := journal.FenceCurrent(context.Background(), want.Target, want.FenceToken)
			if err != nil || !current {
				t.Fatalf("fence current=%v err=%v", current, err)
			}
		})
	}
}

func TestRunPreservesFilesOnMigrationFailure(t *testing.T) {
	for _, failure := range []string{"existing-destination", "same-path", "invalid-source"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			from, to := filepath.Join(dir, "source.json"), filepath.Join(dir, "destination.json")
			writePlainJournal(t, from)
			var destination []byte
			switch failure {
			case "existing-destination":
				destination = []byte("preserve-existing-destination")
				if err := os.WriteFile(to, destination, 0o600); err != nil {
					t.Fatal(err)
				}
			case "same-path":
				to = from
			case "invalid-source":
				if err := os.WriteFile(from, []byte("sensitive-invalid-source"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			source := readBytes(t, from)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"-from", from, "-to", to}, migrationEnv(""), &stdout, &stderr); code != 1 {
				t.Fatalf("exit=%d", code)
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), "journal migration failed") || strings.Contains(stderr.String(), "sensitive") {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if !bytes.Equal(source, readBytes(t, from)) {
				t.Fatal("failed migration changed the source")
			}
			if destination != nil && !bytes.Equal(destination, readBytes(t, to)) {
				t.Fatal("failed migration changed the destination")
			}
			if failure == "invalid-source" {
				if _, err := os.Stat(to); !os.IsNotExist(err) {
					t.Fatalf("failed migration created a destination; err=%v", err)
				}
			}
		})
	}
}

func TestRunRejectsInvalidEncryptionConfiguration(t *testing.T) {
	for _, invalid := range []string{"missing-key", "malformed-key", "short-key", "invalid-key-id"} {
		t.Run(invalid, func(t *testing.T) {
			dir := t.TempDir()
			from, to := filepath.Join(dir, "source.json"), filepath.Join(dir, "destination.json")
			writePlainJournal(t, from)
			source := readBytes(t, from)
			getenv := func(name string) string {
				if name == "APP_ENCRYPTION_KEY" {
					switch invalid {
					case "missing-key":
						return ""
					case "malformed-key":
						return "sensitive-invalid-key"
					case "short-key":
						return base64.StdEncoding.EncodeToString([]byte("short"))
					}
				}
				if name == "APP_ENCRYPTION_KEY_ID" && invalid == "invalid-key-id" {
					return "sensitive-invalid key id"
				}
				return migrationEnv("")(name)
			}
			var stdout, stderr bytes.Buffer
			if code := run([]string{"-from", from, "-to", to}, getenv, &stdout, &stderr); code != 1 {
				t.Fatalf("exit=%d", code)
			}
			if stdout.Len() != 0 || stderr.Len() == 0 || strings.Contains(stderr.String(), "sensitive") {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if !bytes.Equal(source, readBytes(t, from)) {
				t.Fatal("invalid configuration changed the source")
			}
			if _, err := os.Stat(to); !os.IsNotExist(err) {
				t.Fatalf("invalid configuration created a destination; err=%v", err)
			}
		})
	}
}

func TestRunArgumentsAndHelp(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"missing-flags", nil, 2},
		{"missing-from", []string{"-to", "destination"}, 2},
		{"missing-to", []string{"-from", "source"}, 2},
		{"missing-value", []string{"-from"}, 2},
		{"unknown-flag", []string{"-sensitive-argument"}, 2},
		{"extra-positional", []string{"-from", "source", "-to", "destination", "sensitive-argument"}, 2},
		{"help", []string{"-help"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			getenv := func(string) string {
				t.Fatal("argument validation must precede environment access")
				return ""
			}
			if code := run(tc.args, getenv, &stdout, &stderr); code != tc.code {
				t.Fatalf("exit=%d want=%d", code, tc.code)
			}
			if tc.code == 0 {
				if stderr.Len() != 0 || !strings.Contains(stdout.String(), "APP_ENCRYPTION_KEY") {
					t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
			} else if stdout.Len() != 0 || stderr.Len() == 0 || strings.Contains(stderr.String(), "sensitive-argument") {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}
