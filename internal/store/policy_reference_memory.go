package store

import (
	"context"
	"fmt"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

func clonePolicy(p domain.Policy) domain.Policy {
	p.Entries = append([]domain.Rule(nil), p.Entries...)
	for i := range p.Entries {
		p.Entries[i].DomainSuffix = append([]string(nil), p.Entries[i].DomainSuffix...)
		p.Entries[i].DestinationIP = append([]string(nil), p.Entries[i].DestinationIP...)
		p.Entries[i].Ports = append([]string(nil), p.Entries[i].Ports...)
		p.Entries[i].Transport = append([]string(nil), p.Entries[i].Transport...)
	}
	return p
}

func (s *MemoryStore) SavePolicyReference(ctx context.Context, p domain.Policy) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.ID == "" || p.Name == "" || p.Revision < 1 {
		return fmt.Errorf("policy reference requires id, name and positive revision")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[p.ID] = clonePolicy(p)
	return nil
}

func (s *MemoryStore) DeletePolicyReference(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, id)
	return nil
}

func (s *FileStore) SavePolicyReference(ctx context.Context, p domain.Policy) error {
	return s.mutate(func(mem *MemoryStore) error { return mem.SavePolicyReference(ctx, p) })
}

func (s *FileStore) DeletePolicyReference(ctx context.Context, id string) error {
	return s.mutate(func(mem *MemoryStore) error { return mem.DeletePolicyReference(ctx, id) })
}
