package store

// The PostgreSQL adapter uses the pinned pgx database/sql driver and the
// canonical migrations/schema.sql schema.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var ErrPostgresDriverUnavailable = errors.New("postgresql driver is unavailable")

// PostgresStore is the durable multi-process backend. Run migrations/schema.sql
// before serving requests.
type PostgresStore struct{ db *sql.DB }

var _ Store = (*PostgresStore)(nil)

func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, errors.New("database handle is required")
	}
	return &PostgresStore{db: db}, nil
}

// OpenPostgresStore opens driverName/dsn and verifies the canonical schema is
// readable. The caller
// owns the returned store and should close it during graceful shutdown.
func OpenPostgresStore(ctx context.Context, driverName, dsn string) (*PostgresStore, error) {
	if strings.TrimSpace(driverName) == "" {
		driverName = "pgx"
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unknown driver") {
			return nil, fmt.Errorf("%w: %s", ErrPostgresDriverUnavailable, err)
		}
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	s := &PostgresStore{db: db}
	if err := s.CheckHealth(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("check postgres storage: %w", err)
	}
	return s, nil
}

func (s *PostgresStore) Close() error { return s.db.Close() }

func (s *PostgresStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *PostgresStore) CreateDevice(ctx context.Context, d domain.Device) (domain.Device, error) {
	d = cloneDevice(d)
	if err := d.Validate(); err != nil {
		return domain.Device{}, err
	}
	if d.ID == "" {
		d.ID = domain.NewID()
	}
	exceptions, err := encodeDeviceExceptions(d.Exceptions)
	if err != nil {
		return domain.Device{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Device{}, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `INSERT INTO devices (id,name,primary_group_id,exceptions,enrollment_state,revision,created_at,updated_at)
VALUES ($1,$2,NULLIF($3,'')::uuid,$4::jsonb,$5,1,now(),now())
RETURNING revision,created_at,updated_at`, d.ID, d.Name, d.PrimaryGroupID, exceptions, string(d.EnrollmentState)).Scan(&d.Revision, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return domain.Device{}, err
	}
	for _, a := range d.Addresses {
		if err := insertAddress(ctx, tx, d.ID, a); err != nil {
			return domain.Device{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return domain.Device{}, err
	}
	return d, nil
}

func (s *PostgresStore) GetDevice(ctx context.Context, id string) (domain.Device, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return domain.Device{}, err
	}
	defer tx.Rollback()
	d, err := getDevice(ctx, tx, id)
	if err != nil {
		return domain.Device{}, err
	}
	return d, tx.Commit()
}

func (s *PostgresStore) ListDevices(ctx context.Context) ([]domain.Device, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT id,name,COALESCE(primary_group_id::text,''),exceptions,enrollment_state,revision,created_at,updated_at FROM devices ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.Device, 0)
	for rows.Next() {
		var d domain.Device
		var enrollment string
		var exceptions []byte
		if err := rows.Scan(&d.ID, &d.Name, &d.PrimaryGroupID, &exceptions, &enrollment, &d.Revision, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		d.EnrollmentState = domain.EnrollmentState(enrollment)
		if err := decodeDeviceExceptions(&d, exceptions); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// Consume the result set before the next query on the same transaction.
	// This reads device metadata and address ownership from one MVCC snapshot
	// and also works when the connection pool has a single slot.
	for i := range out {
		if out[i].Addresses, err = s.listAddresses(ctx, tx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, tx.Commit()
}

func (s *PostgresStore) UpdateDevice(ctx context.Context, d domain.Device, expected int64) (domain.Device, error) {
	d = cloneDevice(d)
	if err := d.Validate(); err != nil {
		return domain.Device{}, err
	}
	exceptions, err := encodeDeviceExceptions(d.Exceptions)
	if err != nil {
		return domain.Device{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Device{}, err
	}
	defer tx.Rollback()
	old, err := getDeviceForUpdate(ctx, tx, d.ID)
	if err != nil {
		return domain.Device{}, err
	}
	if expected > 0 && old.Revision != expected {
		return domain.Device{}, domain.ErrConflict
	}
	if err := ensureAddressesAvailable(ctx, tx, d.ID, d.Addresses); err != nil {
		return domain.Device{}, err
	}
	if err := tx.QueryRowContext(ctx, `UPDATE devices SET name=$2,primary_group_id=NULLIF($3,'')::uuid,exceptions=$4::jsonb,enrollment_state=$5,revision=revision+1,updated_at=now()
WHERE id=$1 RETURNING revision,created_at,updated_at`, d.ID, d.Name, d.PrimaryGroupID, exceptions, string(d.EnrollmentState)).Scan(&d.Revision, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return domain.Device{}, mapNotFound(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM device_addresses WHERE device_id=$1`, d.ID); err != nil {
		return domain.Device{}, err
	}
	for _, a := range d.Addresses {
		if err := insertAddress(ctx, tx, d.ID, a); err != nil {
			return domain.Device{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return domain.Device{}, err
	}
	return d, nil
}

func (s *PostgresStore) DeleteDevice(ctx context.Context, id string, expected int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM devices WHERE id=$1 FOR UPDATE`, id).Scan(&revision); err != nil {
		return mapNotFound(err)
	}
	if expected > 0 && revision != expected {
		return domain.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) CreateDeviceGroup(ctx context.Context, g domain.DeviceGroup) (domain.DeviceGroup, error) {
	if err := g.Validate(); err != nil {
		return domain.DeviceGroup{}, err
	}
	if g.ID == "" {
		g.ID = domain.NewID()
	}
	if err := s.db.QueryRowContext(ctx, `INSERT INTO device_groups (id,name,gateway_id,policy_id,enabled,revision,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,1,now(),now()) RETURNING revision,created_at,updated_at`, g.ID, g.Name, g.GatewayID, g.PolicyID, g.Enabled).Scan(&g.Revision, &g.CreatedAt, &g.UpdatedAt); err != nil {
		return domain.DeviceGroup{}, err
	}
	return g, nil
}

func (s *PostgresStore) GetDeviceGroup(ctx context.Context, id string) (domain.DeviceGroup, error) {
	var g domain.DeviceGroup
	err := s.db.QueryRowContext(ctx, `SELECT id,name,gateway_id,policy_id,enabled,revision,created_at,updated_at FROM device_groups WHERE id=$1`, id).Scan(&g.ID, &g.Name, &g.GatewayID, &g.PolicyID, &g.Enabled, &g.Revision, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return domain.DeviceGroup{}, mapNotFound(err)
	}
	return g, nil
}

func (s *PostgresStore) ListDeviceGroups(ctx context.Context) ([]domain.DeviceGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,gateway_id,policy_id,enabled,revision,created_at,updated_at FROM device_groups ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.DeviceGroup, 0)
	for rows.Next() {
		var g domain.DeviceGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.GatewayID, &g.PolicyID, &g.Enabled, &g.Revision, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateDeviceGroup(ctx context.Context, g domain.DeviceGroup, expected int64) (domain.DeviceGroup, error) {
	if err := g.Validate(); err != nil {
		return domain.DeviceGroup{}, err
	}
	err := s.db.QueryRowContext(ctx, `UPDATE device_groups SET name=$2,gateway_id=$3,policy_id=$4,enabled=$5,revision=revision+1,updated_at=now()
WHERE id=$1 AND ($6=0 OR revision=$6) RETURNING revision,created_at,updated_at`, g.ID, g.Name, g.GatewayID, g.PolicyID, g.Enabled, expected).Scan(&g.Revision, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		if _, getErr := s.GetDeviceGroup(ctx, g.ID); getErr == nil {
			return domain.DeviceGroup{}, domain.ErrConflict
		} else if !errors.Is(getErr, domain.ErrNotFound) {
			return domain.DeviceGroup{}, getErr
		}
		return domain.DeviceGroup{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.DeviceGroup{}, err
	}
	return g, nil
}

func (s *PostgresStore) CreateProvider(ctx context.Context, p domain.Provider) (domain.Provider, error) {
	if err := p.Validate(); err != nil {
		return domain.Provider{}, err
	}
	if p.ID == "" {
		p.ID = domain.NewID()
	}
	if err := s.db.QueryRowContext(ctx, `INSERT INTO providers (id,name,source,format,fetch_route,revision,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,1,now(),now()) RETURNING revision,created_at,updated_at`, p.ID, p.Name, p.Source, p.Format, p.FetchRoute).Scan(&p.Revision, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return domain.Provider{}, err
	}
	p.ActiveRevision = 0
	return p, nil
}

func (s *PostgresStore) GetProvider(ctx context.Context, id string) (domain.Provider, error) {
	var p domain.Provider
	err := s.db.QueryRowContext(ctx, `SELECT p.id,p.name,p.source,p.format,p.fetch_route,COALESCE(pr.revision_number,0),p.revision,p.created_at,p.updated_at FROM providers p LEFT JOIN provider_revisions pr ON pr.id=p.active_revision_id WHERE p.id=$1`, id).Scan(&p.ID, &p.Name, &p.Source, &p.Format, &p.FetchRoute, &p.ActiveRevision, &p.Revision, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return domain.Provider{}, mapNotFound(err)
	}
	return p, nil
}

func (s *PostgresStore) ListProviders(ctx context.Context) ([]domain.Provider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id,p.name,p.source,p.format,p.fetch_route,COALESCE(pr.revision_number,0),p.revision,p.created_at,p.updated_at FROM providers p LEFT JOIN provider_revisions pr ON pr.id=p.active_revision_id ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.Provider, 0)
	for rows.Next() {
		var p domain.Provider
		if err := rows.Scan(&p.ID, &p.Name, &p.Source, &p.Format, &p.FetchRoute, &p.ActiveRevision, &p.Revision, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CreateGateway(ctx context.Context, g domain.Gateway) (domain.Gateway, error) {
	if err := g.Validate(); err != nil {
		return domain.Gateway{}, err
	}
	if g.ID == "" {
		g.ID = domain.NewID()
	}
	if err := s.db.QueryRowContext(ctx, `INSERT INTO gateways (id,name,endpoint,adapter,observed_generation,revision,created_at,updated_at)
VALUES ($1,$2,$3,$4,0,1,now(),now()) RETURNING revision,created_at,updated_at`, g.ID, g.Name, g.Endpoint, g.Adapter).Scan(&g.Revision, &g.CreatedAt, &g.UpdatedAt); err != nil {
		return domain.Gateway{}, err
	}
	return g, nil
}

func (s *PostgresStore) GetGateway(ctx context.Context, id string) (domain.Gateway, error) {
	var g domain.Gateway
	err := s.db.QueryRowContext(ctx, `SELECT id,name,endpoint,adapter,observed_generation,revision,created_at,updated_at FROM gateways WHERE id=$1`, id).Scan(&g.ID, &g.Name, &g.Endpoint, &g.Adapter, &g.ObservedGeneration, &g.Revision, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return domain.Gateway{}, mapNotFound(err)
	}
	return g, nil
}

func (s *PostgresStore) ListGateways(ctx context.Context) ([]domain.Gateway, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,endpoint,adapter,observed_generation,revision,created_at,updated_at FROM gateways ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.Gateway, 0)
	for rows.Next() {
		var g domain.Gateway
		if err := rows.Scan(&g.ID, &g.Name, &g.Endpoint, &g.Adapter, &g.ObservedGeneration, &g.Revision, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *PostgresStore) listAddresses(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, id string) ([]domain.DeviceAddress, error) {
	rows, err := q.QueryContext(ctx, `SELECT host(address),family,COALESCE(provenance,''),verified_at FROM device_addresses WHERE device_id=$1 ORDER BY address`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.DeviceAddress, 0)
	for rows.Next() {
		var a domain.DeviceAddress
		var family, provenance string
		var verified *time.Time
		if err := rows.Scan(&a.Address, &family, &provenance, &verified); err != nil {
			return nil, err
		}
		a.Family, a.Provenance, a.VerifiedAt = domain.AddressFamily(family), provenance, verified
		out = append(out, a)
	}
	return out, rows.Err()
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func getDevice(ctx context.Context, q queryer, id string) (domain.Device, error) {
	var d domain.Device
	var enrollment string
	var exceptions []byte
	err := q.QueryRowContext(ctx, `SELECT id,name,COALESCE(primary_group_id::text,''),exceptions,enrollment_state,revision,created_at,updated_at FROM devices WHERE id=$1`, id).Scan(&d.ID, &d.Name, &d.PrimaryGroupID, &exceptions, &enrollment, &d.Revision, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return domain.Device{}, mapNotFound(err)
	}
	d.EnrollmentState = domain.EnrollmentState(enrollment)
	if err := decodeDeviceExceptions(&d, exceptions); err != nil {
		return domain.Device{}, err
	}
	rows, err := q.QueryContext(ctx, `SELECT host(address),family,COALESCE(provenance,''),verified_at FROM device_addresses WHERE device_id=$1 ORDER BY address`, id)
	if err != nil {
		return domain.Device{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var a domain.DeviceAddress
		var family, provenance string
		var verified *time.Time
		if err := rows.Scan(&a.Address, &family, &provenance, &verified); err != nil {
			return domain.Device{}, err
		}
		a.Family, a.Provenance, a.VerifiedAt = domain.AddressFamily(family), provenance, verified
		d.Addresses = append(d.Addresses, a)
	}
	return d, rows.Err()
}

func getDeviceForUpdate(ctx context.Context, q queryer, id string) (domain.Device, error) {
	var d domain.Device
	var enrollment string
	var exceptions []byte
	err := q.QueryRowContext(ctx, `SELECT id,name,COALESCE(primary_group_id::text,''),exceptions,enrollment_state,revision,created_at,updated_at FROM devices WHERE id=$1 FOR UPDATE`, id).Scan(&d.ID, &d.Name, &d.PrimaryGroupID, &exceptions, &enrollment, &d.Revision, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return domain.Device{}, mapNotFound(err)
	}
	d.EnrollmentState = domain.EnrollmentState(enrollment)
	if err := decodeDeviceExceptions(&d, exceptions); err != nil {
		return domain.Device{}, err
	}
	rows, err := q.QueryContext(ctx, `SELECT host(address),family,COALESCE(provenance,''),verified_at FROM device_addresses WHERE device_id=$1 ORDER BY address`, id)
	if err != nil {
		return domain.Device{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var a domain.DeviceAddress
		var family, provenance string
		var verified *time.Time
		if err := rows.Scan(&a.Address, &family, &provenance, &verified); err != nil {
			return domain.Device{}, err
		}
		a.Family, a.Provenance, a.VerifiedAt = domain.AddressFamily(family), provenance, verified
		d.Addresses = append(d.Addresses, a)
	}
	return d, rows.Err()
}

func encodeDeviceExceptions(exceptions []json.RawMessage) ([]byte, error) {
	if exceptions == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(exceptions)
}

func decodeDeviceExceptions(d *domain.Device, raw []byte) error {
	if err := json.Unmarshal(raw, &d.Exceptions); err != nil {
		return fmt.Errorf("decode exceptions for device %s: %w", d.ID, err)
	}
	if err := d.Validate(); err != nil {
		return fmt.Errorf("invalid persisted device %s: %w", d.ID, err)
	}
	return nil
}

func insertAddress(ctx context.Context, tx *sql.Tx, deviceID string, a domain.DeviceAddress) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO device_addresses (device_id,address,family,provenance,verified_at) VALUES ($1,$2::inet,$3,$4,$5)`, deviceID, a.Address, string(a.Family), a.Provenance, a.VerifiedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "device_addresses_address_key" {
			return fmt.Errorf("%w: %s", domain.ErrAddressConflict, a.Address)
		}
	}
	return err
}

func ensureAddressesAvailable(ctx context.Context, tx *sql.Tx, deviceID string, addresses []domain.DeviceAddress) error {
	for _, a := range addresses {
		var owner string
		err := tx.QueryRowContext(ctx, `SELECT device_id::text FROM device_addresses WHERE address=$1::inet`, a.Address).Scan(&owner)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if owner != deviceID {
			return fmt.Errorf("%w: %s", domain.ErrAddressConflict, a.Address)
		}
	}
	return nil
}

func mapNotFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
