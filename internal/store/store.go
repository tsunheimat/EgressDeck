// Package store provides the persistence boundary used by the controller.
// MemoryStore is deterministic and useful for contract tests; FileStore is a
// durable single-process backend; PostgresStore is the multi-process backend.
// The API is shaped so these choices can be substituted without changing
// handlers.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

type Store interface {
	CreateDevice(context.Context, domain.Device) (domain.Device, error)
	GetDevice(context.Context, string) (domain.Device, error)
	ListDevices(context.Context) ([]domain.Device, error)
	UpdateDevice(context.Context, domain.Device, int64) (domain.Device, error)
	DeleteDevice(context.Context, string, int64) error
	CreateDeviceGroup(context.Context, domain.DeviceGroup) (domain.DeviceGroup, error)
	GetDeviceGroup(context.Context, string) (domain.DeviceGroup, error)
	ListDeviceGroups(context.Context) ([]domain.DeviceGroup, error)
	UpdateDeviceGroup(context.Context, domain.DeviceGroup, int64) (domain.DeviceGroup, error)
	CreateProvider(context.Context, domain.Provider) (domain.Provider, error)
	GetProvider(context.Context, string) (domain.Provider, error)
	ListProviders(context.Context) ([]domain.Provider, error)
	CreateGateway(context.Context, domain.Gateway) (domain.Gateway, error)
	GetGateway(context.Context, string) (domain.Gateway, error)
	ListGateways(context.Context) ([]domain.Gateway, error)
}

type MemoryStore struct {
	mu        sync.RWMutex
	devices   map[string]domain.Device
	groups    map[string]domain.DeviceGroup
	providers map[string]domain.Provider
	gateways  map[string]domain.Gateway
	policies  map[string]domain.Policy
	addresses map[string]string
	documents map[string]json.RawMessage
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{devices: map[string]domain.Device{}, groups: map[string]domain.DeviceGroup{}, providers: map[string]domain.Provider{}, gateways: map[string]domain.Gateway{}, policies: map[string]domain.Policy{}, addresses: map[string]string{}, documents: map[string]json.RawMessage{}}
}

func cloneAddresses(in []domain.DeviceAddress) []domain.DeviceAddress {
	if in == nil {
		return nil
	}
	out := make([]domain.DeviceAddress, len(in))
	copy(out, in)
	for i := range out {
		if in[i].VerifiedAt != nil {
			verified := *in[i].VerifiedAt
			out[i].VerifiedAt = &verified
		}
	}
	return out
}
func cloneDevice(in domain.Device) domain.Device {
	in.Addresses = cloneAddresses(in.Addresses)
	if in.Exceptions != nil {
		exceptions := make([]json.RawMessage, len(in.Exceptions))
		for i, raw := range in.Exceptions {
			exceptions[i] = append(json.RawMessage(nil), raw...)
		}
		in.Exceptions = exceptions
	}
	return in
}

func (s *MemoryStore) CreateDevice(_ context.Context, d domain.Device) (domain.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d = cloneDevice(d)
	if err := d.Validate(); err != nil {
		return domain.Device{}, err
	}
	if d.ID == "" {
		d.ID = domain.NewID()
	}
	if _, ok := s.devices[d.ID]; ok {
		return domain.Device{}, fmt.Errorf("device %s already exists", d.ID)
	}
	if d.EnrollmentState == "" {
		d.EnrollmentState = domain.EnrollmentUnenrolled
	}
	for _, a := range d.Addresses {
		if owner := s.addresses[a.Address]; owner != "" && owner != d.ID {
			return domain.Device{}, fmt.Errorf("%w: %s", domain.ErrAddressConflict, a.Address)
		}
	}
	now := time.Now().UTC()
	d.Revision, d.CreatedAt, d.UpdatedAt = 1, now, now
	s.devices[d.ID] = cloneDevice(d)
	for _, a := range d.Addresses {
		s.addresses[a.Address] = d.ID
	}
	return cloneDevice(d), nil
}

func (s *MemoryStore) GetDevice(_ context.Context, id string) (domain.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[id]
	if !ok {
		return domain.Device{}, domain.ErrNotFound
	}
	return cloneDevice(d), nil
}

func (s *MemoryStore) ListDevices(_ context.Context) ([]domain.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, cloneDevice(d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemoryStore) UpdateDevice(_ context.Context, d domain.Device, expected int64) (domain.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d = cloneDevice(d)
	old, ok := s.devices[d.ID]
	if !ok {
		return domain.Device{}, domain.ErrNotFound
	}
	if expected > 0 && old.Revision != expected {
		return domain.Device{}, domain.ErrConflict
	}
	if err := d.Validate(); err != nil {
		return domain.Device{}, err
	}
	for _, a := range d.Addresses {
		if owner := s.addresses[a.Address]; owner != "" && owner != d.ID {
			return domain.Device{}, fmt.Errorf("%w: %s", domain.ErrAddressConflict, a.Address)
		}
	}
	for _, a := range old.Addresses {
		delete(s.addresses, a.Address)
	}
	for _, a := range d.Addresses {
		s.addresses[a.Address] = d.ID
	}
	d.CreatedAt, d.UpdatedAt, d.Revision = old.CreatedAt, time.Now().UTC(), old.Revision+1
	s.devices[d.ID] = cloneDevice(d)
	return cloneDevice(d), nil
}

func (s *MemoryStore) DeleteDevice(_ context.Context, id string, expected int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return domain.ErrNotFound
	}
	if expected > 0 && d.Revision != expected {
		return domain.ErrConflict
	}
	for _, a := range d.Addresses {
		delete(s.addresses, a.Address)
	}
	delete(s.devices, id)
	return nil
}

func (s *MemoryStore) CreateDeviceGroup(_ context.Context, g domain.DeviceGroup) (domain.DeviceGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := g.Validate(); err != nil {
		return domain.DeviceGroup{}, err
	}
	if g.ID == "" {
		g.ID = domain.NewID()
	}
	if _, ok := s.groups[g.ID]; ok {
		return domain.DeviceGroup{}, fmt.Errorf("device group %s already exists", g.ID)
	}
	now := time.Now().UTC()
	g.Revision, g.CreatedAt, g.UpdatedAt = 1, now, now
	s.groups[g.ID] = g
	return g, nil
}
func (s *MemoryStore) GetDeviceGroup(_ context.Context, id string) (domain.DeviceGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[id]
	if !ok {
		return domain.DeviceGroup{}, domain.ErrNotFound
	}
	return g, nil
}
func (s *MemoryStore) ListDeviceGroups(_ context.Context) ([]domain.DeviceGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.DeviceGroup, 0, len(s.groups))
	for _, g := range s.groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (s *MemoryStore) UpdateDeviceGroup(_ context.Context, g domain.DeviceGroup, expected int64) (domain.DeviceGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.groups[g.ID]
	if !ok {
		return domain.DeviceGroup{}, domain.ErrNotFound
	}
	if expected > 0 && old.Revision != expected {
		return domain.DeviceGroup{}, domain.ErrConflict
	}
	if err := g.Validate(); err != nil {
		return domain.DeviceGroup{}, err
	}
	g.CreatedAt, g.UpdatedAt, g.Revision = old.CreatedAt, time.Now().UTC(), old.Revision+1
	s.groups[g.ID] = g
	return g, nil
}

func (s *MemoryStore) CreateProvider(_ context.Context, p domain.Provider) (domain.Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := p.Validate(); err != nil {
		return domain.Provider{}, err
	}
	if p.ID == "" {
		p.ID = domain.NewID()
	}
	if _, ok := s.providers[p.ID]; ok {
		return domain.Provider{}, fmt.Errorf("provider %s already exists", p.ID)
	}
	now := time.Now().UTC()
	p.Revision, p.CreatedAt, p.UpdatedAt = 1, now, now
	s.providers[p.ID] = p
	return p, nil
}
func (s *MemoryStore) GetProvider(_ context.Context, id string) (domain.Provider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.providers[id]
	if !ok {
		return domain.Provider{}, domain.ErrNotFound
	}
	return p, nil
}
func (s *MemoryStore) ListProviders(_ context.Context) ([]domain.Provider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Provider, 0, len(s.providers))
	for _, p := range s.providers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemoryStore) CreateGateway(_ context.Context, g domain.Gateway) (domain.Gateway, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := g.Validate(); err != nil {
		return domain.Gateway{}, err
	}
	if g.ID == "" {
		g.ID = domain.NewID()
	}
	if _, ok := s.gateways[g.ID]; ok {
		return domain.Gateway{}, fmt.Errorf("gateway %s already exists", g.ID)
	}
	now := time.Now().UTC()
	g.Revision, g.CreatedAt, g.UpdatedAt = 1, now, now
	s.gateways[g.ID] = g
	return g, nil
}
func (s *MemoryStore) GetGateway(_ context.Context, id string) (domain.Gateway, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.gateways[id]
	if !ok {
		return domain.Gateway{}, domain.ErrNotFound
	}
	return g, nil
}
func (s *MemoryStore) ListGateways(_ context.Context) ([]domain.Gateway, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Gateway, 0, len(s.gateways))
	for _, g := range s.gateways {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
