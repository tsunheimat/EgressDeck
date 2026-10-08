package store

import (
	"context"
	"errors"
	"fmt"
)

// OpenConfiguredStore selects the explicitly configured durable backend. An
// empty DSN selects the JSON file backend; a non-empty DSN selects PostgreSQL
// using the included pgx driver by default. There is intentionally no
// implicit in-memory fallback for a controller process.
func OpenConfiguredStore(ctx context.Context, storagePath, driverName, dsn string) (Store, func() error, error) {
	if dsn != "" {
		postgres, err := OpenPostgresStore(ctx, driverName, dsn)
		if err != nil {
			return nil, nil, err
		}
		return postgres, postgres.Close, nil
	}
	if storagePath == "" {
		return nil, nil, errors.New("storage path is required when postgres DSN is not configured")
	}
	file, err := NewFileStore(storagePath)
	if err != nil {
		return nil, nil, fmt.Errorf("open file store: %w", err)
	}
	return file, file.Close, nil
}
