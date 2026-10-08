package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This test creates its own database and never truncates the supplied server.
// Encryption remains a caller responsibility; these checks prove that opaque
// ciphertext and inventory move together across failed writes and reconnects.
func TestPostgresProviderMutatorsIntegration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run provider mutations against a disposable PostgreSQL server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test PostgreSQL connection configuration")
	}
	admin := stdlib.OpenDB(*config)
	defer admin.Close()
	name := "egressdeck_provider_test_" + strings.ReplaceAll(domain.NewID(), "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create isolated provider test database: %v", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if _, err := admin.ExecContext(cleanup, `DROP DATABASE `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`); err != nil {
			t.Errorf("remove isolated provider test database: %v", err)
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	schema, err := os.ReadFile(filepath.Join("..", "..", "migrations", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(schema)); err != nil {
		t.Fatalf("apply canonical schema: %v", err)
	}
	s, err := NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.New("provider-integration", bytes.Repeat([]byte{0x41}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	newSource := func(t *testing.T, plaintext string) (string, json.RawMessage) {
		t.Helper()
		ref, err := secrets.NewSecretRef()
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := vault.Seal(string(ref), []byte(plaintext))
		if err != nil {
			t.Fatal(err)
		}
		document, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return string(ref), document
	}
	create := func(t *testing.T, source string) domain.Provider {
		t.Helper()
		p, err := s.CreateProvider(ctx, domain.Provider{Name: t.Name(), Source: source})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	assertProvider := func(t *testing.T, st *PostgresStore, want domain.Provider) {
		t.Helper()
		got, err := st.GetProvider(ctx, want.ID)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("provider changed unexpectedly: got=%+v want=%+v err=%v", got, want, err)
		}
	}
	assertDocument := func(t *testing.T, st *PostgresStore, key string, want json.RawMessage) {
		t.Helper()
		got, err := st.LoadDocument(ctx, key)
		if want == nil {
			if !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("unexpected source document at %s: err=%v", key, err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		var gotJSON, wantJSON any
		if json.Unmarshal(got, &gotJSON) != nil || json.Unmarshal(want, &wantJSON) != nil || !reflect.DeepEqual(gotJSON, wantJSON) {
			t.Fatalf("source document at %s changed unexpectedly", key)
		}
	}

	t.Run("exact positive inventory CAS", func(t *testing.T) {
		p := create(t, "https://subscription.example.invalid/initial")
		candidate := p
		candidate.Name = "updated metadata"
		candidate.ActiveRevision = 999 // Metadata updates cannot forge activation.
		for _, expected := range []int64{-1, 0, p.Revision + 1} {
			if _, err := s.UpdateProvider(ctx, candidate, expected); !errors.Is(err, domain.ErrConflict) {
				t.Fatalf("update with revision %d: %v", expected, err)
			}
			if err := s.DeleteProvider(ctx, p.ID, expected); !errors.Is(err, domain.ErrConflict) {
				t.Fatalf("delete with revision %d: %v", expected, err)
			}
			assertProvider(t, s, p)
		}
		updated, err := s.UpdateProvider(ctx, candidate, p.Revision)
		if err != nil || updated.Revision != p.Revision+1 || updated.ActiveRevision != 0 || updated.Name != candidate.Name || !updated.CreatedAt.Equal(p.CreatedAt) {
			t.Fatalf("metadata update: got=%+v err=%v", updated, err)
		}
		if err := s.DeleteProvider(ctx, p.ID, p.Revision); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("stale delete: %v", err)
		}
		assertProvider(t, s, updated)
		if err := s.DeleteProvider(ctx, p.ID, updated.Revision); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetProvider(ctx, p.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("deleted provider remains readable: %v", err)
		}
	})

	t.Run("encrypted source CAS rotation reconnect and delete", func(t *testing.T) {
		oldKey, oldDoc := newSource(t, "https://subscription.example.invalid/private?token=old-credential")
		newKey, newDoc := newSource(t, "https://subscription.example.invalid/private?token=new-credential")
		p := create(t, oldKey)
		if err := s.SaveDocument(ctx, oldKey, oldDoc); err != nil {
			t.Fatal(err)
		}
		candidate := p
		candidate.Name, candidate.Source = "rotated subscription", newKey
		for _, expected := range []int64{-1, 0, p.Revision + 1} {
			if _, err := s.UpdateProviderSource(ctx, candidate, expected, newKey, newDoc, oldKey); !errors.Is(err, domain.ErrConflict) {
				t.Fatalf("source update with revision %d: %v", expected, err)
			}
			if err := s.DeleteProviderSource(ctx, p.ID, expected, oldKey); !errors.Is(err, domain.ErrConflict) {
				t.Fatalf("source delete with revision %d: %v", expected, err)
			}
			assertProvider(t, s, p)
			assertDocument(t, s, oldKey, oldDoc)
			assertDocument(t, s, newKey, nil)
		}
		updated, err := s.UpdateProviderSource(ctx, candidate, p.Revision, newKey, newDoc, oldKey)
		if err != nil || updated.Revision != p.Revision+1 || updated.Source != newKey {
			t.Fatalf("source rotation: got=%+v err=%v", updated, err)
		}
		assertProvider(t, s, updated)
		assertDocument(t, s, oldKey, json.RawMessage(`{"version":1,"deleted":true}`))
		assertDocument(t, s, newKey, newDoc)
		// Open a fresh driver pool, so readback cannot use process-local state.
		reopenedDB := stdlib.OpenDB(*config)
		defer reopenedDB.Close()
		reopened, err := NewPostgresStore(reopenedDB)
		if err != nil {
			t.Fatal(err)
		}
		assertProvider(t, reopened, updated)
		assertDocument(t, reopened, oldKey, json.RawMessage(`{"version":1,"deleted":true}`))
		assertDocument(t, reopened, newKey, newDoc)
		persisted, err := reopened.LoadDocument(ctx, newKey)
		if err != nil {
			t.Fatal(err)
		}
		var envelope secrets.Envelope
		if err := json.Unmarshal(persisted, &envelope); err != nil {
			t.Fatal(err)
		}
		plaintext, err := vault.Open(newKey, envelope)
		if err != nil || string(plaintext) != "https://subscription.example.invalid/private?token=new-credential" {
			t.Fatalf("rotated source cannot be decrypted after reconnect: %v", err)
		}
		clear(plaintext)
		// Reusing a key, or having no retired key, must not retire the live value.
		for _, retired := range []string{newKey, ""} {
			updated.Name += " revised"
			updated, err = reopened.UpdateProviderSource(ctx, updated, updated.Revision, newKey, newDoc, retired)
			if err != nil {
				t.Fatal(err)
			}
			assertDocument(t, reopened, newKey, newDoc)
		}
		if err := reopened.DeleteProviderSource(ctx, p.ID, updated.Revision-1, newKey); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("stale source delete after reconnect: %v", err)
		}
		assertProvider(t, reopened, updated)
		assertDocument(t, reopened, newKey, newDoc)
		if err := reopened.DeleteProviderSource(ctx, p.ID, updated.Revision, newKey); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetProvider(ctx, p.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("deleted provider visible to original connection: %v", err)
		}
		assertDocument(t, s, newKey, json.RawMessage(`{"version":1,"deleted":true}`))
	})

	t.Run("retirement failure rolls back inventory and documents", func(t *testing.T) {
		oldKey, oldDoc := newSource(t, "https://subscription.example.invalid/old")
		newKey, newDoc := newSource(t, "https://subscription.example.invalid/new")
		p := create(t, oldKey)
		if err := s.SaveDocument(ctx, oldKey, oldDoc); err != nil {
			t.Fatal(err)
		}
		// Fail inside PostgreSQL, after the operation has begun, rather than
		// merely rejecting invalid input before any transaction can mutate.
		if _, err := db.ExecContext(ctx, `CREATE FUNCTION reject_provider_tombstone() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.document = '{"version":1,"deleted":true}'::jsonb THEN RAISE EXCEPTION 'injected retirement failure'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER reject_provider_tombstone BEFORE INSERT OR UPDATE ON controller_documents
FOR EACH ROW EXECUTE FUNCTION reject_provider_tombstone()`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := db.ExecContext(ctx, `DROP TRIGGER reject_provider_tombstone ON controller_documents; DROP FUNCTION reject_provider_tombstone()`); err != nil {
				t.Error(err)
			}
		}()
		candidate := p
		candidate.Name, candidate.Source = "must roll back", newKey
		if _, err := s.UpdateProviderSource(ctx, candidate, p.Revision, newKey, newDoc, oldKey); err == nil {
			t.Fatal("source update ignored injected retirement failure")
		}
		assertProvider(t, s, p)
		assertDocument(t, s, oldKey, oldDoc)
		assertDocument(t, s, newKey, nil)
		if err := s.DeleteProviderSource(ctx, p.ID, p.Revision, oldKey); err == nil {
			t.Fatal("source delete ignored injected retirement failure")
		}
		assertProvider(t, s, p)
		assertDocument(t, s, oldKey, oldDoc)
	})

	t.Run("referenced providers cannot cascade delete history", func(t *testing.T) {
		for _, reference := range []string{"active revision", "inactive revision", "node"} {
			t.Run(reference, func(t *testing.T) {
				key, document := newSource(t, "https://subscription.example.invalid/history")
				p := create(t, key)
				if err := s.SaveDocument(ctx, key, document); err != nil {
					t.Fatal(err)
				}
				var referencedTable string
				if reference == "node" {
					referencedTable = "nodes"
					if _, err := db.ExecContext(ctx, `INSERT INTO nodes(provider_id,identity,display_name) VALUES($1,'preserve-identity','preserve node')`, p.ID); err != nil {
						t.Fatal(err)
					}
				} else {
					referencedTable = "provider_revisions"
					revisionID := domain.NewID()
					if _, err := db.ExecContext(ctx, `INSERT INTO provider_revisions(id,provider_id,revision_number,content_hash) VALUES($1,$2,7,'preserve-history')`, revisionID, p.ID); err != nil {
						t.Fatal(err)
					}
					if reference == "active revision" {
						if _, err := db.ExecContext(ctx, `UPDATE providers SET active_revision_id=$2 WHERE id=$1`, p.ID, revisionID); err != nil {
							t.Fatal(err)
						}
						p.ActiveRevision = 7
						candidate := p
						candidate.ActiveRevision = 0
						updated, err := s.UpdateProvider(ctx, candidate, p.Revision)
						if err != nil || updated.ActiveRevision != 7 {
							t.Fatalf("metadata update lost stored active revision: got=%+v err=%v", updated, err)
						}
						p = updated
					}
				}
				for _, remove := range []func() error{
					func() error { return s.DeleteProvider(ctx, p.ID, p.Revision) },
					func() error { return s.DeleteProviderSource(ctx, p.ID, p.Revision, key) },
				} {
					if err := remove(); !errors.Is(err, ErrProviderReferenced) {
						t.Fatalf("provider deletion into %s returned %v; want ErrProviderReferenced", referencedTable, err)
					}
					assertProvider(t, s, p)
					assertDocument(t, s, key, document)
					assertProviderReferenceCount(t, ctx, db, referencedTable, p.ID, 1)
				}
			})
		}
	})
}

func assertProviderReferenceCount(t *testing.T, ctx context.Context, db *sql.DB, table, providerID string, want int) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()+` WHERE provider_id=$1`, providerID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("%s history count=%d want=%d", table, count, want)
	}
}
