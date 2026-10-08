package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

func (s *MemoryStore) UpdateProvider(ctx context.Context, p domain.Provider, expected int64) (domain.Provider, error) {
	return s.UpdateProviderSource(ctx, p, expected, "", nil, "")
}

func (s *MemoryStore) DeleteProvider(ctx context.Context, id string, expected int64) error {
	return s.DeleteProviderSource(ctx, id, expected, "")
}

func (s *MemoryStore) UpdateProviderSource(ctx context.Context, p domain.Provider, expected int64, key string, data json.RawMessage, retiredKey string) (domain.Provider, error) {
	if err := validateProviderSourceMutation(expected, key, data, retiredKey); err != nil {
		return domain.Provider{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return domain.Provider{}, err
	}
	old, ok := s.providers[p.ID]
	if !ok {
		return domain.Provider{}, domain.ErrNotFound
	}
	if old.Revision != expected {
		return domain.Provider{}, domain.ErrConflict
	}
	if err := p.Validate(); err != nil {
		return domain.Provider{}, err
	}
	p.CreatedAt, p.UpdatedAt, p.Revision = old.CreatedAt, time.Now().UTC(), old.Revision+1
	p.ActiveRevision = old.ActiveRevision
	s.providers[p.ID] = p
	if key != "" {
		s.documents[key] = append(json.RawMessage(nil), data...)
	}
	if retiredKey != "" && retiredKey != key {
		s.documents[retiredKey] = json.RawMessage(providerSourceTombstone)
	}
	return p, nil
}

func (s *MemoryStore) DeleteProviderSource(ctx context.Context, id string, expected int64, retiredKey string) error {
	if err := validateProviderSourceMutation(expected, "", nil, retiredKey); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	p, ok := s.providers[id]
	if !ok {
		return domain.ErrNotFound
	}
	if p.Revision != expected {
		return domain.ErrConflict
	}
	if p.ActiveRevision > 0 {
		return fmt.Errorf("%w: provider has an active revision", ErrProviderReferenced)
	}
	delete(s.providers, id)
	if retiredKey != "" {
		s.documents[retiredKey] = json.RawMessage(providerSourceTombstone)
	}
	return nil
}

func (s *FileStore) UpdateProvider(ctx context.Context, p domain.Provider, expected int64) (domain.Provider, error) {
	return s.UpdateProviderSource(ctx, p, expected, "", nil, "")
}

func (s *FileStore) DeleteProvider(ctx context.Context, id string, expected int64) error {
	return s.DeleteProviderSource(ctx, id, expected, "")
}

func (s *FileStore) UpdateProviderSource(ctx context.Context, p domain.Provider, expected int64, key string, data json.RawMessage, retiredKey string) (domain.Provider, error) {
	var updated domain.Provider
	err := s.mutate(func(mem *MemoryStore) error {
		var err error
		updated, err = mem.UpdateProviderSource(ctx, p, expected, key, data, retiredKey)
		return err
	})
	if err != nil {
		return domain.Provider{}, err
	}
	return updated, nil
}

func (s *FileStore) DeleteProviderSource(ctx context.Context, id string, expected int64, retiredKey string) error {
	return s.mutate(func(mem *MemoryStore) error {
		return mem.DeleteProviderSource(ctx, id, expected, retiredKey)
	})
}
