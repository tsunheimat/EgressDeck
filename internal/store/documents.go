package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

// DocumentStore persists versioned service snapshots alongside inventory.
// Callers own document schemas and serialize updates within the single active
// controller. SaveDocument atomically replaces one document; it is not a
// transaction across independently saved documents or inventory rows.
type DocumentStore interface {
	LoadDocument(context.Context, string) (json.RawMessage, error)
	SaveDocument(context.Context, string, json.RawMessage) error
}

// ImmutableDocumentStore creates a document only when the key is absent.
// Content-addressed plans use this boundary to retain the first writer's
// snapshot when multiple controllers produce the same plan concurrently.
type ImmutableDocumentStore interface {
	CreateDocument(context.Context, string, json.RawMessage) error
}

var (
	_ DocumentStore          = (*MemoryStore)(nil)
	_ DocumentStore          = (*FileStore)(nil)
	_ DocumentStore          = (*PostgresStore)(nil)
	_ ImmutableDocumentStore = (*MemoryStore)(nil)
	_ ImmutableDocumentStore = (*FileStore)(nil)
	_ ImmutableDocumentStore = (*PostgresStore)(nil)
)

func validateDocument(key string, data json.RawMessage) error {
	if strings.TrimSpace(key) == "" || len(key) > 200 {
		return errors.New("document key must contain 1 to 200 characters")
	}
	if len(data) > 16<<20 || !json.Valid(data) {
		return errors.New("document must contain valid JSON no larger than 16 MiB")
	}
	return nil
}

func (s *MemoryStore) LoadDocument(ctx context.Context, key string) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.documents[key]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return append(json.RawMessage(nil), data...), nil
}

func (s *MemoryStore) SaveDocument(ctx context.Context, key string, data json.RawMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateDocument(key, data); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.documents[key] = append(json.RawMessage(nil), data...)
	return nil
}

func (s *MemoryStore) CreateDocument(ctx context.Context, key string, data json.RawMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateDocument(key, data); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.documents[key]; exists {
		return domain.ErrConflict
	}
	s.documents[key] = append(json.RawMessage(nil), data...)
	return nil
}

func (s *FileStore) LoadDocument(ctx context.Context, key string) (json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.LoadDocument(ctx, key)
}

func (s *FileStore) SaveDocument(ctx context.Context, key string, data json.RawMessage) error {
	return s.mutate(func(mem *MemoryStore) error { return mem.SaveDocument(ctx, key, data) })
}

func (s *FileStore) CreateDocument(ctx context.Context, key string, data json.RawMessage) error {
	return s.mutate(func(mem *MemoryStore) error { return mem.CreateDocument(ctx, key, data) })
}

func (s *PostgresStore) LoadDocument(ctx context.Context, key string) (json.RawMessage, error) {
	var data []byte
	if err := s.db.QueryRowContext(ctx, `SELECT document FROM controller_documents WHERE key=$1`, key).Scan(&data); err != nil {
		return nil, mapNotFound(err)
	}
	return json.RawMessage(data), nil
}

func (s *PostgresStore) SaveDocument(ctx context.Context, key string, data json.RawMessage) error {
	if err := validateDocument(key, data); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO controller_documents (key,document) VALUES ($1,$2::jsonb)
ON CONFLICT (key) DO UPDATE SET document=EXCLUDED.document,updated_at=now()`, key, string(data))
	return err
}

func (s *PostgresStore) CreateDocument(ctx context.Context, key string, data json.RawMessage) error {
	if err := validateDocument(key, data); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO controller_documents (key,document) VALUES ($1,$2::jsonb)
ON CONFLICT (key) DO NOTHING`, key, string(data))
	if err != nil {
		return err
	}
	created, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if created == 0 {
		return domain.ErrConflict
	}
	return nil
}
