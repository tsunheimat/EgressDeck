package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

// ProviderMutator is the optional inventory mutation boundary. Every mutation
// requires the exact positive inventory revision. Updating configuration must
// not change the separately managed active content revision.
type ProviderMutator interface {
	UpdateProvider(context.Context, domain.Provider, int64) (domain.Provider, error)
	DeleteProvider(context.Context, string, int64) error
}

// ProviderSourceMutator atomically changes provider inventory and its encrypted
// source document. Empty new key/data leave documents unchanged, except for an
// explicitly retired key. Retirement replaces ciphertext with a tombstone; a
// key that is also the new document key is never retired.
type ProviderSourceMutator interface {
	UpdateProviderSource(context.Context, domain.Provider, int64, string, json.RawMessage, string) (domain.Provider, error)
	DeleteProviderSource(context.Context, string, int64, string) error
}

const providerSourceTombstone = `{"version":1,"deleted":true}`

// ErrProviderReferenced means deleting inventory would remove active content
// or persisted provider history. It is distinct from a stale inventory CAS.
var ErrProviderReferenced = errors.New("provider is referenced")

var (
	_ ProviderMutator       = (*MemoryStore)(nil)
	_ ProviderMutator       = (*FileStore)(nil)
	_ ProviderMutator       = (*PostgresStore)(nil)
	_ ProviderSourceMutator = (*MemoryStore)(nil)
	_ ProviderSourceMutator = (*FileStore)(nil)
	_ ProviderSourceMutator = (*PostgresStore)(nil)
)

func validateProviderSourceMutation(expected int64, key string, data json.RawMessage, retiredKey string) error {
	if expected <= 0 {
		return fmt.Errorf("%w: expected provider revision must be positive", domain.ErrConflict)
	}
	if key == "" && len(data) != 0 {
		return errors.New("provider source document data requires a key")
	}
	if key != "" {
		if err := validateDocument(key, data); err != nil {
			return err
		}
	}
	if retiredKey != "" && retiredKey != key {
		if err := validateDocument(retiredKey, json.RawMessage(providerSourceTombstone)); err != nil {
			return err
		}
	}
	return nil
}
