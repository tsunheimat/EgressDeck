package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

func fileStoreFixture(t *testing.T) (*FileStore, domain.Device, domain.DeviceGroup, domain.Provider, domain.Gateway) {
	t.Helper()
	s, err := NewFileStore(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d, err := s.CreateDevice(ctx, domain.Device{ID: "device-1", Name: "client", Addresses: []domain.DeviceAddress{{Address: "192.0.2.10"}}, Exceptions: []json.RawMessage{json.RawMessage(`{"id":"exception-1","action":{"type":"block"}}`)}})
	if err != nil {
		t.Fatal(err)
	}
	g, err := s.CreateDeviceGroup(ctx, domain.DeviceGroup{ID: "group-1", Name: "clients", GatewayID: "gateway-1", PolicyID: "policy-1", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.CreateProvider(ctx, domain.Provider{ID: "provider-1", Name: "subscription", Source: "https://example.invalid/subscription"})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := s.CreateGateway(ctx, domain.Gateway{ID: "gateway-1", Name: "gateway", Endpoint: "https://gateway.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	return s, d, g, p, gw
}

func reopenFileStore(t *testing.T, s *FileStore) *FileStore {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	return reopened
}

func TestFileStoreEntityLifecycleSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	s, device, group, provider, gateway := fileStoreFixture(t)
	s = reopenFileStore(t, s)
	if got, err := s.GetDevice(ctx, device.ID); err != nil || !reflect.DeepEqual(got, device) {
		t.Fatalf("restored device = %+v, %v; want %+v", got, err, device)
	}
	if got, err := s.GetDeviceGroup(ctx, group.ID); err != nil || got != group {
		t.Fatalf("restored group = %+v, %v; want %+v", got, err, group)
	}
	if got, err := s.GetProvider(ctx, provider.ID); err != nil || got != provider {
		t.Fatalf("restored provider = %+v, %v; want %+v", got, err, provider)
	}
	if got, err := s.GetGateway(ctx, gateway.ID); err != nil || got != gateway {
		t.Fatalf("restored gateway = %+v, %v; want %+v", got, err, gateway)
	}
	if got, err := s.ListDevices(ctx); err != nil || !reflect.DeepEqual(got, []domain.Device{device}) {
		t.Fatalf("restored devices = %+v, %v", got, err)
	}
	if got, err := s.ListDeviceGroups(ctx); err != nil || !reflect.DeepEqual(got, []domain.DeviceGroup{group}) {
		t.Fatalf("restored groups = %+v, %v", got, err)
	}
	if got, err := s.ListProviders(ctx); err != nil || !reflect.DeepEqual(got, []domain.Provider{provider}) {
		t.Fatalf("restored providers = %+v, %v", got, err)
	}
	if got, err := s.ListGateways(ctx); err != nil || !reflect.DeepEqual(got, []domain.Gateway{gateway}) {
		t.Fatalf("restored gateways = %+v, %v", got, err)
	}
	if _, err := s.CreateDevice(ctx, domain.Device{Name: "duplicate address", Addresses: device.Addresses}); !errors.Is(err, domain.ErrAddressConflict) {
		t.Fatalf("restored address ownership: %v", err)
	}

	device.Name = "updated client"
	device.Addresses = []domain.DeviceAddress{{Address: "192.0.2.11"}}
	device.Exceptions = []json.RawMessage{json.RawMessage(`{"id":"exception-2","action":{"type":"direct"}}`)}
	if _, err := s.UpdateDevice(ctx, device, device.Revision+1); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale device update: %v", err)
	}
	updatedDevice, err := s.UpdateDevice(ctx, device, device.Revision)
	if err != nil || updatedDevice.Revision != device.Revision+1 {
		t.Fatalf("device update = %+v, %v", updatedDevice, err)
	}
	group.Name = "updated group"
	if _, err := s.UpdateDeviceGroup(ctx, group, group.Revision+1); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale group update: %v", err)
	}
	updatedGroup, err := s.UpdateDeviceGroup(ctx, group, group.Revision)
	if err != nil || updatedGroup.Revision != group.Revision+1 {
		t.Fatalf("group update = %+v, %v", updatedGroup, err)
	}
	s = reopenFileStore(t, s)
	if got, err := s.GetDevice(ctx, device.ID); err != nil || !reflect.DeepEqual(got, updatedDevice) {
		t.Fatalf("restored updated device = %+v, %v", got, err)
	}
	if got, err := s.GetDeviceGroup(ctx, group.ID); err != nil || got != updatedGroup {
		t.Fatalf("restored updated group = %+v, %v", got, err)
	}
	if _, err := s.CreateDevice(ctx, domain.Device{Name: "old address new owner", Addresses: []domain.DeviceAddress{{Address: "192.0.2.10"}}}); err != nil {
		t.Fatalf("released address remained reserved after restart: %v", err)
	}
	if _, err := s.CreateDevice(ctx, domain.Device{Name: "new address conflict", Addresses: updatedDevice.Addresses}); !errors.Is(err, domain.ErrAddressConflict) {
		t.Fatalf("new address lost ownership after restart: %v", err)
	}
	if err := s.DeleteDevice(ctx, device.ID, device.Revision); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if err := s.DeleteDevice(ctx, device.ID, updatedDevice.Revision); err != nil {
		t.Fatal(err)
	}
	s = reopenFileStore(t, s)
	if _, err := s.GetDevice(ctx, device.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted device returned after restart: %v", err)
	}
	if _, err := s.CreateDevice(ctx, domain.Device{Name: "deleted address new owner", Addresses: updatedDevice.Addresses}); err != nil {
		t.Fatalf("deleted device address remained reserved after restart: %v", err)
	}
}

// Replacing the destination with a directory makes the final rename fail even
// when the test runs as root. Preserve the original bytes for restart checks.
func blockFileStorePersistence(t *testing.T, s *FileStore) func() {
	t.Helper()
	backup := s.Path() + ".saved"
	if err := os.Rename(s.Path(), backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.Path(), 0o700); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.Remove(s.Path()); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(backup, s.Path()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFileStoreFailedPersistenceRollsBackEveryMutation(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		mutate func(*FileStore, domain.Device, domain.DeviceGroup) error
	}{
		{"create device", func(s *FileStore, _ domain.Device, _ domain.DeviceGroup) error {
			_, err := s.CreateDevice(ctx, domain.Device{Name: "new client", Addresses: []domain.DeviceAddress{{Address: "192.0.2.20"}}})
			return err
		}},
		{"update device", func(s *FileStore, d domain.Device, _ domain.DeviceGroup) error {
			d.Name, d.Addresses = "changed", []domain.DeviceAddress{{Address: "192.0.2.20"}}
			d.Exceptions[0] = json.RawMessage(`{"id":"replacement","action":{"type":"direct"}}`)
			_, err := s.UpdateDevice(ctx, d, d.Revision)
			return err
		}},
		{"delete device", func(s *FileStore, d domain.Device, _ domain.DeviceGroup) error {
			return s.DeleteDevice(ctx, d.ID, d.Revision)
		}},
		{"create group", func(s *FileStore, _ domain.Device, _ domain.DeviceGroup) error {
			_, err := s.CreateDeviceGroup(ctx, domain.DeviceGroup{Name: "new group", GatewayID: "gateway-1", PolicyID: "policy-1"})
			return err
		}},
		{"update group", func(s *FileStore, _ domain.Device, g domain.DeviceGroup) error {
			g.Name = "changed"
			_, err := s.UpdateDeviceGroup(ctx, g, g.Revision)
			return err
		}},
		{"create provider", func(s *FileStore, _ domain.Device, _ domain.DeviceGroup) error {
			_, err := s.CreateProvider(ctx, domain.Provider{Name: "new provider", Source: "https://example.invalid/new"})
			return err
		}},
		{"create gateway", func(s *FileStore, _ domain.Device, _ domain.DeviceGroup) error {
			_, err := s.CreateGateway(ctx, domain.Gateway{Name: "new gateway", Endpoint: "https://new-gateway.invalid"})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, device, group, _, _ := fileStoreFixture(t)
			before := s.mem.cloneState()
			bytesBefore, err := os.ReadFile(s.Path())
			if err != nil {
				t.Fatal(err)
			}
			restore := blockFileStorePersistence(t, s)
			if err := tt.mutate(s, device, group); err == nil || !strings.Contains(err.Error(), "persist storage state") {
				t.Fatalf("mutation without successful persistence returned %v", err)
			}
			if got := s.mem.cloneState(); !reflect.DeepEqual(got, before) {
				t.Fatalf("failed mutation changed memory: got %+v, want %+v", got, before)
			}
			restore()
			bytesAfter, err := os.ReadFile(s.Path())
			if err != nil || !bytes.Equal(bytesAfter, bytesBefore) {
				t.Fatalf("failed mutation changed durable bytes: %v", err)
			}
			s = reopenFileStore(t, s)
			if got := s.mem.cloneState(); !reflect.DeepEqual(got, before) {
				t.Fatalf("failed mutation changed restarted state: got %+v, want %+v", got, before)
			}
			if _, err := s.CreateDevice(ctx, domain.Device{Name: "conflicting address", Addresses: device.Addresses}); !errors.Is(err, domain.ErrAddressConflict) {
				t.Fatalf("rollback lost original address ownership: %v", err)
			}
			if _, err := s.CreateDevice(ctx, domain.Device{Name: "free address", Addresses: []domain.DeviceAddress{{Address: "192.0.2.20"}}}); err != nil {
				t.Fatalf("rollback retained new address ownership: %v", err)
			}
		})
	}
}

func TestFileStoreReadsWaitForFailedWriteRollback(t *testing.T) {
	ctx := context.Background()
	s, d, g, p, gw := fileStoreFixture(t)
	deviceBefore, groupBefore := d, g
	restore := blockFileStorePersistence(t, s)
	defer restore()
	entered, release := make(chan struct{}), make(chan struct{})
	writeResult := make(chan error, 1)
	go func() {
		writeResult <- s.mutate(func(mem *MemoryStore) error {
			d.Name, g.Name = "uncommitted client", "uncommitted group"
			if _, err := mem.UpdateDevice(ctx, d, d.Revision); err != nil {
				return err
			}
			if _, err := mem.UpdateDeviceGroup(ctx, g, g.Revision); err != nil {
				return err
			}
			if _, err := mem.CreateProvider(ctx, domain.Provider{Name: "uncommitted provider", Source: "https://example.invalid/new"}); err != nil {
				return err
			}
			if _, err := mem.CreateGateway(ctx, domain.Gateway{Name: "uncommitted gateway", Endpoint: "https://new-gateway.invalid"}); err != nil {
				return err
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-writeResult:
		t.Fatalf("write exited before persistence boundary: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("write never reached persistence boundary")
	}
	readers := []struct {
		name string
		read func() (any, error)
		want any
	}{
		{"get device", func() (any, error) { return s.GetDevice(ctx, d.ID) }, deviceBefore},
		{"list devices", func() (any, error) { return s.ListDevices(ctx) }, []domain.Device{deviceBefore}},
		{"get group", func() (any, error) { return s.GetDeviceGroup(ctx, g.ID) }, groupBefore},
		{"list groups", func() (any, error) { return s.ListDeviceGroups(ctx) }, []domain.DeviceGroup{groupBefore}},
		{"get provider", func() (any, error) { return s.GetProvider(ctx, p.ID) }, p},
		{"list providers", func() (any, error) { return s.ListProviders(ctx) }, []domain.Provider{p}},
		{"get gateway", func() (any, error) { return s.GetGateway(ctx, gw.ID) }, gw},
		{"list gateways", func() (any, error) { return s.ListGateways(ctx) }, []domain.Gateway{gw}},
	}
	type readResult struct {
		name string
		got  any
		err  error
	}
	started := make(chan struct{}, len(readers))
	results := make(chan readResult, len(readers))
	for _, reader := range readers {
		go func() {
			started <- struct{}{}
			got, err := reader.read()
			results <- readResult{reader.name, got, err}
		}()
	}
	for range readers {
		<-started
	}
	select {
	case result := <-results:
		close(release)
		<-writeResult
		t.Fatalf("%s returned during uncommitted write: %+v, %v", result.name, result.got, result.err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-writeResult; err == nil {
		t.Fatal("expected persistence failure")
	}
	for range readers {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("%s after rollback: %v", result.name, result.err)
			}
			for _, reader := range readers {
				if reader.name == result.name && !reflect.DeepEqual(result.got, reader.want) {
					t.Fatalf("%s after rollback: got %+v, want %+v", result.name, result.got, reader.want)
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatal("reader remained blocked after rollback")
		}
	}
}

func TestFileStoreRejectsTrailingAndInvalidState(t *testing.T) {
	tests := map[string]string{
		"empty":                "",
		"truncated":            `{"version":1`,
		"trailing object":      `{"version":1} {}`,
		"trailing null":        `{"version":1} null`,
		"trailing garbage":     `{"version":1} garbage`,
		"null":                 `null`,
		"array":                `[]`,
		"unsupported version":  `{"version":2}`,
		"device id mismatch":   `{"version":1,"devices":{"one":{"id":"two","name":"client"}}}`,
		"group id mismatch":    `{"version":1,"device_groups":{"one":{"id":"two","name":"group","gateway_id":"gateway","policy_id":"policy"}}}`,
		"provider id mismatch": `{"version":1,"providers":{"one":{"id":"two","name":"provider","source":"https://example.invalid"}}}`,
		"gateway id mismatch":  `{"version":1,"gateways":{"one":{"id":"two","name":"gateway","endpoint":"https://gateway.invalid"}}}`,
		"duplicate address":    `{"version":1,"devices":{"one":{"id":"one","name":"one","addresses":[{"address":"192.0.2.1"}]},"two":{"id":"two","name":"two","addresses":[{"address":"192.0.2.1"}]}}}`,
		"invalid exception":    `{"version":1,"devices":{"one":{"id":"one","name":"one","revision":1,"exceptions":[null]}}}`,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewFileStore(path); err == nil {
				t.Fatal("accepted corrupt state")
			}
		})
	}
	for _, payload := range []string{`{"version":1}`, "{\"version\":1}\n\t  "} {
		path := filepath.Join(t.TempDir(), "store.json")
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileStore(path); err != nil {
			t.Fatalf("rejected valid state with optional whitespace: %v", err)
		}
	}
}

func TestFileStoreSizeLimitAppliesToReadAndWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	oversized := append([]byte(`{"version":1}`), bytes.Repeat([]byte(" "), fileStoreMaxSize)...)
	if err := os.WriteFile(path, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileStore(path); err == nil {
		t.Fatal("accepted oversized file with valid JSON prefix")
	}
	s, _, _, _, _ := fileStoreFixture(t)
	before, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateProvider(context.Background(), domain.Provider{Name: "oversized", Format: "local", Source: strings.Repeat("x", fileStoreMaxSize)})
	if err == nil {
		t.Fatal("persisted state larger than the readable size limit")
	}
	after, err := os.ReadFile(s.Path())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("oversized write changed durable state: %v", err)
	}
	if !json.Valid(after) {
		t.Fatal("storage file was corrupted by oversized write")
	}
	if got, err := s.ListProviders(context.Background()); err != nil || len(got) != 1 {
		t.Fatalf("oversized write was not rolled back: %+v, %v", got, err)
	}
}
