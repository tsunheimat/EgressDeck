package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// TestPostgresIntegration uses an explicitly supplied disposable PostgreSQL
// server. TEST_DATABASE_URL (or DATABASE_URL) must permit CREATE DATABASE. The
// test creates and removes its own database; it never truncates caller data.
func TestPostgresIntegration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run PostgreSQL integration against a disposable server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test PostgreSQL connection configuration")
	}
	admin := stdlib.OpenDB(*config)
	defer admin.Close()
	name := "egressdeck_test_" + strings.ReplaceAll(domain.NewID(), "-", "")
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create isolated test database: %v", err)
	}
	defer func() {
		if _, err := admin.ExecContext(context.Background(), `DROP DATABASE `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`); err != nil {
			t.Errorf("remove isolated test database: %v", err)
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	schema, err := os.ReadFile(filepath.Join("..", "..", "migrations", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := db.ExecContext(ctx, string(schema)); err != nil {
			t.Fatalf("apply canonical schema pass %d: %v", i+1, err)
		}
	}
	// Emulate an existing installation before device exceptions were added.
	// Reapplying the canonical schema must add the column and preserve rows.
	if _, err := db.ExecContext(ctx, `ALTER TABLE devices DROP COLUMN exceptions`); err != nil {
		t.Fatal(err)
	}
	legacyID := domain.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO devices (id,name) VALUES ($1,'pre-upgrade client')`, legacyID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := db.ExecContext(ctx, string(schema)); err != nil {
			t.Fatalf("upgrade device exceptions pass %d: %v", i+1, err)
		}
	}
	s, err := NewPostgresStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CheckHealth(ctx); err != nil {
		t.Fatalf("canonical schema health: %v", err)
	}
	exerciseImmutableDocumentRace(t, s)
	if legacy, err := s.GetDevice(ctx, legacyID); err != nil || legacy.Name != "pre-upgrade client" || len(legacy.Exceptions) != 0 {
		t.Fatalf("legacy device after schema upgrade: %+v, %v", legacy, err)
	}
	if err := s.DeleteDevice(ctx, legacyID, 1); err != nil {
		t.Fatal(err)
	}
	gateway, err := s.CreateGateway(ctx, domain.Gateway{Name: "integration gateway", Endpoint: "https://gateway.example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetGateway(ctx, gateway.ID); err != nil || got.Name != gateway.Name || got.Adapter != "dae" {
		t.Fatalf("gateway readback: got=%+v err=%v", got, err)
	}
	if got, err := s.ListGateways(ctx); err != nil || len(got) != 1 {
		t.Fatalf("gateway list: got=%+v err=%v", got, err)
	}
	policyID := domain.NewID()
	if err := s.SavePolicyReference(ctx, domain.Policy{ID: policyID, Name: "integration policy", DefaultAction: domain.ActionDirect, UnknownDomainAction: domain.ActionDirect, ProxyFailureAction: domain.ActionBlock, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	group, err := s.CreateDeviceGroup(ctx, domain.DeviceGroup{Name: "integration group", GatewayID: gateway.ID, PolicyID: policyID, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetDeviceGroup(ctx, group.ID); err != nil || got.PolicyID != policyID {
		t.Fatalf("group readback: got=%+v err=%v", got, err)
	}
	if got, err := s.ListDeviceGroups(ctx); err != nil || len(got) != 1 {
		t.Fatalf("group list: got=%+v err=%v", got, err)
	}
	group.Name = "updated group"
	updatedGroup, err := s.UpdateDeviceGroup(ctx, group, group.Revision)
	if err != nil || updatedGroup.Revision != group.Revision+1 {
		t.Fatalf("group update: got=%+v err=%v", updatedGroup, err)
	}
	if _, err := s.UpdateDeviceGroup(ctx, group, group.Revision); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale group CAS: %v", err)
	}

	verified := time.Now().UTC().Truncate(time.Microsecond)
	exceptions := []json.RawMessage{json.RawMessage(`{"id":"exception-1","action":{"type":"block"},"match":{"domain_exact":["example.test"]}}`)}
	device, err := s.CreateDevice(ctx, domain.Device{Name: "integration client", PrimaryGroupID: group.ID, Addresses: []domain.DeviceAddress{
		{Address: "192.0.2.42", VerifiedAt: &verified, Provenance: "static"},
		{Address: "2001:db8::42", Provenance: "static"},
	}, Exceptions: exceptions})
	if err != nil {
		t.Fatal(err)
	}
	gotDevice, err := s.GetDevice(ctx, device.ID)
	if err != nil || len(gotDevice.Addresses) != 2 || gotDevice.Addresses[0].Address != "192.0.2.42" || gotDevice.Addresses[1].Address != "2001:db8::42" || gotDevice.Addresses[0].VerifiedAt == nil || !gotDevice.Addresses[0].VerifiedAt.Equal(verified) {
		t.Fatalf("device address readback: got=%+v err=%v", gotDevice, err)
	}
	assertDeviceExceptions(t, gotDevice.Exceptions, exceptions)
	// A single connection must support ListDevices without blocking on a
	// nested address query while holding the outer result set's connection.
	db.SetMaxOpenConns(1)
	if got, err := s.ListDevices(ctx); err != nil || len(got) != 1 || len(got[0].Addresses) != 2 {
		t.Fatalf("device list: got=%+v err=%v", got, err)
	} else {
		assertDeviceExceptions(t, got[0].Exceptions, exceptions)
	}
	db.SetMaxOpenConns(5)
	if _, err := s.CreateDevice(ctx, domain.Device{Name: "duplicate address", Addresses: []domain.DeviceAddress{{Address: "2001:0db8:0000:0000::42"}}}); !errors.Is(err, domain.ErrAddressConflict) {
		t.Fatalf("canonical address ownership: %v", err)
	}
	if got, err := s.ListDevices(ctx); err != nil || len(got) != 1 {
		t.Fatalf("duplicate address transaction was not rolled back: got=%+v err=%v", got, err)
	}
	device.Name = "updated client"
	device.Exceptions = []json.RawMessage{json.RawMessage(`{"id":"exception-2","action":{"type":"direct"}}`)}
	updated, err := s.UpdateDevice(ctx, device, device.Revision)
	if err != nil || updated.Revision != device.Revision+1 {
		t.Fatalf("device update: got=%+v err=%v", updated, err)
	}
	if _, err := s.UpdateDevice(ctx, device, device.Revision); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale device CAS: %v", err)
	}
	if got, err := s.GetDevice(ctx, device.ID); err != nil {
		t.Fatal(err)
	} else {
		assertDeviceExceptions(t, got.Exceptions, device.Exceptions)
	}
	if err := s.DeleteDevice(ctx, device.ID, device.Revision); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale device delete CAS: %v", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.UpdateDevice(ctx, updated, updated.Revision)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, domain.ErrConflict) {
			conflicts++
		} else {
			t.Errorf("concurrent update: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent CAS successes=%d conflicts=%d", successes, conflicts)
	}

	provider, err := s.CreateProvider(ctx, domain.Provider{Name: "integration provider", Source: "https://subscription.example.invalid/nodes"})
	if err != nil {
		t.Fatal(err)
	}
	providerRevision := domain.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO provider_revisions(id,provider_id,revision_number,content_hash) VALUES($1,$2,7,'sha256-test')`, providerRevision, provider.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE providers SET active_revision_id=$2 WHERE id=$1`, provider.ID, providerRevision); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetProvider(ctx, provider.ID); err != nil || got.ActiveRevision != 7 {
		t.Fatalf("provider revision join: got=%+v err=%v", got, err)
	}
	if got, err := s.ListProviders(ctx); err != nil || len(got) != 1 || got[0].ActiveRevision != 7 {
		t.Fatalf("provider list: got=%+v err=%v", got, err)
	}
	if _, err := s.LoadDocument(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing document: %v", err)
	}
	if err := s.SaveDocument(ctx, "api-lifecycle-v1", json.RawMessage(`{"version":1,"generation":42}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDocument(ctx, "api-lifecycle-v1", json.RawMessage(`{"version":1,"generation":43}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckHealth(ctx); err == nil {
		t.Fatal("closed PostgreSQL store reported healthy")
	}
	// Reopening the actual driver/database connection simulates a controller
	// process restart; all inventory and opaque service state must survive.
	reopenedDB := stdlib.OpenDB(*config)
	defer reopenedDB.Close()
	reopened, err := NewPostgresStore(reopenedDB)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.CheckHealth(ctx); err != nil {
		t.Fatalf("reopened PostgreSQL store health: %v", err)
	}
	if got, err := reopened.GetDevice(ctx, device.ID); err != nil || got.Revision != updated.Revision+1 || got.PrimaryGroupID != group.ID {
		t.Fatalf("device after reconnect: got=%+v err=%v", got, err)
	} else {
		assertDeviceExceptions(t, got.Exceptions, device.Exceptions)
	}
	if data, err := reopened.LoadDocument(ctx, "api-lifecycle-v1"); err != nil {
		t.Fatal(err)
	} else {
		var decoded struct {
			Generation int `json:"generation"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil || decoded.Generation != 43 {
			t.Fatalf("document after reconnect: %s err=%v", data, err)
		}
	}
	if err := reopened.DeleteDevice(ctx, device.ID, updated.Revision+1); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetDevice(ctx, device.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted device still readable: %v", err)
	}
	if _, err := reopened.CreateDevice(ctx, domain.Device{Name: "replacement client", Addresses: device.Addresses}); err != nil {
		t.Fatalf("deleted device still owns addresses: %v", err)
	}
	if _, err := reopenedDB.ExecContext(ctx, `DROP TABLE controller_documents`); err != nil {
		t.Fatal(err)
	}
	if err := reopened.CheckHealth(ctx); err == nil {
		t.Fatal("PostgreSQL store with missing canonical table reported healthy")
	}
}
