package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *PostgresStore) UpdateProvider(ctx context.Context, p domain.Provider, expected int64) (domain.Provider, error) {
	return s.UpdateProviderSource(ctx, p, expected, "", nil, "")
}

func (s *PostgresStore) DeleteProvider(ctx context.Context, id string, expected int64) error {
	return s.DeleteProviderSource(ctx, id, expected, "")
}

func (s *PostgresStore) UpdateProviderSource(ctx context.Context, p domain.Provider, expected int64, key string, data json.RawMessage, retiredKey string) (domain.Provider, error) {
	if err := validateProviderSourceMutation(expected, key, data, retiredKey); err != nil {
		return domain.Provider{}, err
	}
	if err := p.Validate(); err != nil {
		return domain.Provider{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Provider{}, err
	}
	defer tx.Rollback()
	old, err := providerForUpdate(ctx, tx, p.ID)
	if err != nil {
		return domain.Provider{}, err
	}
	if old.Revision != expected {
		return domain.Provider{}, domain.ErrConflict
	}
	if err := tx.QueryRowContext(ctx, `UPDATE providers SET name=$2,source=$3,format=$4,fetch_route=$5,revision=revision+1,updated_at=now()
WHERE id=$1 RETURNING revision,created_at,updated_at`, p.ID, p.Name, p.Source, p.Format, p.FetchRoute).Scan(&p.Revision, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return domain.Provider{}, mapNotFound(err)
	}
	p.ActiveRevision = old.ActiveRevision
	if err := mutateProviderSourceDocuments(ctx, tx, key, data, retiredKey); err != nil {
		return domain.Provider{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.Provider{}, err
	}
	return p, nil
}

func (s *PostgresStore) DeleteProviderSource(ctx context.Context, id string, expected int64, retiredKey string) error {
	if err := validateProviderSourceMutation(expected, "", nil, retiredKey); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := providerForUpdate(ctx, tx, id)
	if err != nil {
		return err
	}
	if p.Revision != expected {
		return domain.ErrConflict
	}
	if p.ActiveRevision > 0 {
		return fmt.Errorf("%w: provider has an active revision", ErrProviderReferenced)
	}
	// These tables have historical ON DELETE CASCADE relations. Explicitly
	// retain their inventory/history instead of silently removing them. The
	// parent row lock also fences concurrent foreign-key inserts.
	var referenced bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM provider_revisions WHERE provider_id=$1)
OR EXISTS(SELECT 1 FROM nodes WHERE provider_id=$1)`, id).Scan(&referenced); err != nil {
		return err
	}
	if referenced {
		return fmt.Errorf("%w: provider has persisted revision or node history", ErrProviderReferenced)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM providers WHERE id=$1`, id); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return ErrProviderReferenced
		}
		return err
	}
	if err := mutateProviderSourceDocuments(ctx, tx, "", nil, retiredKey); err != nil {
		return err
	}
	return tx.Commit()
}

func providerForUpdate(ctx context.Context, tx *sql.Tx, id string) (domain.Provider, error) {
	var p domain.Provider
	err := tx.QueryRowContext(ctx, `SELECT p.id,p.revision,COALESCE(pr.revision_number,0)
FROM providers p LEFT JOIN provider_revisions pr ON pr.id=p.active_revision_id
WHERE p.id=$1 FOR UPDATE OF p`, id).Scan(&p.ID, &p.Revision, &p.ActiveRevision)
	if err != nil {
		return domain.Provider{}, mapNotFound(err)
	}
	return p, nil
}

func mutateProviderSourceDocuments(ctx context.Context, tx *sql.Tx, key string, data json.RawMessage, retiredKey string) error {
	save := func(key string, raw json.RawMessage) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO controller_documents (key,document) VALUES ($1,$2::jsonb)
ON CONFLICT (key) DO UPDATE SET document=EXCLUDED.document,updated_at=now()`, key, string(raw))
		return err
	}
	if key != "" {
		if err := save(key, data); err != nil {
			return err
		}
	}
	if retiredKey != "" && retiredKey != key {
		return save(retiredKey, json.RawMessage(providerSourceTombstone))
	}
	return nil
}
