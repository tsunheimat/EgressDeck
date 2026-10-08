package store

// FileStore is a small durable store for single-controller installations and
// development environments. It uses an atomic JSON replacement on every
// mutation, so a process restart never loses an acknowledged write. It is
// deliberately behind the same Store interface as MemoryStore and
// PostgresStore; callers do not need to know which persistence backend is in
// use.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

const (
	fileStoreVersion = 1
	fileStoreMaxSize = 32 << 20
)

type fileStoreState struct {
	Version   int                           `json:"version"`
	Devices   map[string]domain.Device      `json:"devices"`
	Policies  map[string]domain.Policy      `json:"policies,omitempty"`
	Groups    map[string]domain.DeviceGroup `json:"device_groups"`
	Providers map[string]domain.Provider    `json:"providers"`
	Gateways  map[string]domain.Gateway     `json:"gateways"`
	Documents map[string]json.RawMessage    `json:"documents,omitempty"`
}

// FileStore persists the controller model in path. The file and containing
// directory are created with owner-only permissions. A FileStore instance is
// safe for concurrent use by handlers in one process; deployments that run
// multiple controller processes should use PostgresStore instead.
type FileStore struct {
	mu   sync.RWMutex
	path string
	mem  *MemoryStore
}

var _ Store = (*FileStore)(nil)

// NewFileStore opens path, restoring its state if it already exists. An empty
// path is rejected so a misconfigured controller cannot silently lose data in
// a process-local fallback.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, errors.New("storage path is required")
	}
	path = filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create storage directory: %w", err)
	}

	s := &FileStore{path: path, mem: NewMemoryStore()}
	state, err := readFileStoreState(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		// Create the initial file before returning. This catches permissions and
		// read-only volume mistakes during startup rather than on first write.
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err := s.mem.replaceState(state); err != nil {
		return nil, fmt.Errorf("restore storage state: %w", err)
	}
	return s, nil
}

// Path reports the backing file path. It is useful for diagnostics and tests.
func (s *FileStore) Path() string { return s.path }

// Close is provided so callers can use a common lifecycle for SQL and file
// stores. There are no open descriptors to release between mutations.
func (s *FileStore) Close() error { return nil }

func (s *FileStore) mutate(save func(*MemoryStore) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.mem.cloneState()
	if err := save(s.mem); err != nil {
		return err
	}
	if err := s.persistLocked(); err != nil {
		// Keep the in-memory view consistent with the acknowledged durable
		// view. The caller receives an error and can safely retry.
		_ = s.mem.replaceState(before)
		return fmt.Errorf("persist storage state: %w", err)
	}
	return nil
}

func (s *FileStore) CreateDevice(ctx context.Context, d domain.Device) (domain.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.mem.cloneState()
	out, err := s.mem.CreateDevice(ctx, d)
	if err != nil {
		return domain.Device{}, err
	}
	if err := s.persistLocked(); err != nil {
		_ = s.mem.replaceState(before)
		return domain.Device{}, fmt.Errorf("persist storage state: %w", err)
	}
	return out, nil
}

func (s *FileStore) GetDevice(ctx context.Context, id string) (domain.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.GetDevice(ctx, id)
}
func (s *FileStore) ListDevices(ctx context.Context) ([]domain.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.ListDevices(ctx)
}
func (s *FileStore) UpdateDevice(ctx context.Context, d domain.Device, expected int64) (domain.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.mem.cloneState()
	out, err := s.mem.UpdateDevice(ctx, d, expected)
	if err != nil {
		return domain.Device{}, err
	}
	if err := s.persistLocked(); err != nil {
		_ = s.mem.replaceState(before)
		return domain.Device{}, fmt.Errorf("persist storage state: %w", err)
	}
	return out, nil
}
func (s *FileStore) DeleteDevice(ctx context.Context, id string, expected int64) error {
	return s.mutate(func(mem *MemoryStore) error { return mem.DeleteDevice(ctx, id, expected) })
}

func (s *FileStore) CreateDeviceGroup(ctx context.Context, g domain.DeviceGroup) (domain.DeviceGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.mem.cloneState()
	out, err := s.mem.CreateDeviceGroup(ctx, g)
	if err != nil {
		return domain.DeviceGroup{}, err
	}
	if err := s.persistLocked(); err != nil {
		_ = s.mem.replaceState(before)
		return domain.DeviceGroup{}, fmt.Errorf("persist storage state: %w", err)
	}
	return out, nil
}
func (s *FileStore) GetDeviceGroup(ctx context.Context, id string) (domain.DeviceGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.GetDeviceGroup(ctx, id)
}
func (s *FileStore) ListDeviceGroups(ctx context.Context) ([]domain.DeviceGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.ListDeviceGroups(ctx)
}
func (s *FileStore) UpdateDeviceGroup(ctx context.Context, g domain.DeviceGroup, expected int64) (domain.DeviceGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.mem.cloneState()
	out, err := s.mem.UpdateDeviceGroup(ctx, g, expected)
	if err != nil {
		return domain.DeviceGroup{}, err
	}
	if err := s.persistLocked(); err != nil {
		_ = s.mem.replaceState(before)
		return domain.DeviceGroup{}, fmt.Errorf("persist storage state: %w", err)
	}
	return out, nil
}

func (s *FileStore) CreateProvider(ctx context.Context, p domain.Provider) (domain.Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.mem.cloneState()
	out, err := s.mem.CreateProvider(ctx, p)
	if err != nil {
		return domain.Provider{}, err
	}
	if err := s.persistLocked(); err != nil {
		_ = s.mem.replaceState(before)
		return domain.Provider{}, fmt.Errorf("persist storage state: %w", err)
	}
	return out, nil
}
func (s *FileStore) GetProvider(ctx context.Context, id string) (domain.Provider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.GetProvider(ctx, id)
}
func (s *FileStore) ListProviders(ctx context.Context) ([]domain.Provider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.ListProviders(ctx)
}

func (s *FileStore) CreateGateway(ctx context.Context, g domain.Gateway) (domain.Gateway, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.mem.cloneState()
	out, err := s.mem.CreateGateway(ctx, g)
	if err != nil {
		return domain.Gateway{}, err
	}
	if err := s.persistLocked(); err != nil {
		_ = s.mem.replaceState(before)
		return domain.Gateway{}, fmt.Errorf("persist storage state: %w", err)
	}
	return out, nil
}
func (s *FileStore) GetGateway(ctx context.Context, id string) (domain.Gateway, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.GetGateway(ctx, id)
}
func (s *FileStore) ListGateways(ctx context.Context) ([]domain.Gateway, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mem.ListGateways(ctx)
}

func readFileStoreState(path string) (fileStoreState, error) {
	f, err := os.Open(path)
	if err != nil {
		return fileStoreState{}, err
	}
	defer f.Close()
	var state *fileStoreState
	// Read one byte beyond the limit so an otherwise valid JSON prefix cannot
	// hide an oversized file or trailing data at the limit boundary.
	limited := &io.LimitedReader{R: f, N: fileStoreMaxSize + 1}
	dec := json.NewDecoder(limited)
	if err := dec.Decode(&state); err != nil {
		return fileStoreState{}, fmt.Errorf("decode storage file %q: %w", path, err)
	}
	if state == nil {
		return fileStoreState{}, fmt.Errorf("decode storage file %q: expected state object", path)
	}
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fileStoreState{}, fmt.Errorf("decode storage file %q: multiple JSON values", path)
		}
		return fileStoreState{}, fmt.Errorf("decode storage file %q: trailing data: %w", path, err)
	}
	if limited.N == 0 {
		return fileStoreState{}, fmt.Errorf("storage file %q exceeds %d bytes", path, fileStoreMaxSize)
	}
	if state.Version != 0 && state.Version != fileStoreVersion {
		return fileStoreState{}, fmt.Errorf("unsupported storage file version %d", state.Version)
	}
	if state.Devices == nil {
		state.Devices = map[string]domain.Device{}
	}
	if state.Groups == nil {
		state.Groups = map[string]domain.DeviceGroup{}
	}
	if state.Providers == nil {
		state.Providers = map[string]domain.Provider{}
	}
	if state.Gateways == nil {
		state.Gateways = map[string]domain.Gateway{}
	}
	state.Version = fileStoreVersion
	return *state, nil
}

func (s *FileStore) persistLocked() error {
	state := s.mem.cloneState()
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode storage state: %w", err)
	}
	payload = append(payload, '\n')
	if len(payload) > fileStoreMaxSize {
		return fmt.Errorf("storage state exceeds %d bytes", fileStoreMaxSize)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".egressdeck-store-*")
	if err != nil {
		return fmt.Errorf("create storage temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set storage file permissions: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write storage file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync storage file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close storage file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace storage file: %w", err)
	}
	// Syncing the directory makes the rename durable across a host restart on
	// filesystems that honor directory fsync. Some filesystems reject it; the
	// data file itself has already been synced and the rename remains valid.
	if dir, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
