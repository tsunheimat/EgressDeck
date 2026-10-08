package store

import "context"

// HealthChecker reports whether persisted controller state is readable. It is
// optional for Store consumers, and performs no writes or schema migrations.
type HealthChecker interface {
	CheckHealth(context.Context) error
}

var (
	_ HealthChecker = (*MemoryStore)(nil)
	_ HealthChecker = (*FileStore)(nil)
	_ HealthChecker = (*PostgresStore)(nil)
)

func (s *MemoryStore) CheckHealth(ctx context.Context) error { return ctx.Err() }

func (s *FileStore) CheckHealth(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, err := readFileStoreState(s.path)
	if err != nil {
		return err
	}
	// Validate into a temporary store. Readiness never replaces the live
	// in-memory state or repairs a missing/corrupt file.
	if err := NewMemoryStore().replaceState(state); err != nil {
		return err
	}
	return ctx.Err()
}

func (s *PostgresStore) CheckHealth(ctx context.Context) error {
	// Referencing critical canonical columns verifies both connectivity and
	// schema/read permissions without scanning application data. Ping alone
	// succeeds against an empty database that cannot serve any API request.
	rows, err := s.db.QueryContext(ctx, `SELECT d.id,d.revision,d.exceptions,a.address,g.gateway_id,g.policy_id,
p.active_revision_id,r.revision_number,w.observed_generation,c.document,pl.default_action
FROM devices d,device_addresses a,device_groups g,providers p,provider_revisions r,
gateways w,controller_documents c,policies pl WHERE FALSE`)
	if err != nil {
		return err
	}
	return rows.Close()
}
