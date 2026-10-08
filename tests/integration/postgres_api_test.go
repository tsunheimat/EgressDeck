package integration_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/policy"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This test deliberately crosses the real HTTP, database/sql, PostgreSQL schema,
// encrypted document, and restart boundaries. TEST_DATABASE_URL must name a
// disposable PostgreSQL server whose user may CREATE DATABASE. Every invocation
// creates and drops its own database; the database in the supplied URL is never
// migrated or populated by this test.
func TestPostgresAPILifecycle(t *testing.T) {
	config := isolatedDatabase(t)
	vault, err := secrets.New("integration-key", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	app := openApplication(t, config, vault, nil)

	const source = "https://subscription.example.test/list?token=subscription-private-token"
	const nodePassword = "node-private-password"
	const content = "trojan://" + nodePassword + "@edge.example.test:443#Primary"
	privateValues := []string{source, "subscription-private-token", nodePassword, content}
	var provider domain.Provider
	app.request(t, http.MethodPost, "/api/v1/providers", domain.Provider{Name: "Subscription", Source: source, Format: "links"}, 0, http.StatusCreated, &provider)
	assertUUID(t, provider.ID)
	if provider.Source != "[redacted]" {
		t.Fatal("provider create did not redact its source")
	}
	var staged struct {
		Revision providers.Revision `json:"revision"`
		Status   string             `json:"status"`
	}
	stageBody := app.request(t, http.MethodPost, "/api/v1/providers/"+provider.ID+"/stage", map[string]string{"content": content, "format": "links"}, 0, http.StatusAccepted, &staged)
	assertNoSecrets(t, "stage response", stageBody, privateValues)
	if staged.Status != "staged" || staged.Revision.Number != 1 || len(staged.Revision.Nodes) != 1 {
		t.Fatalf("unexpected initial stage: status=%q number=%d nodes=%d", staged.Status, staged.Revision.Number, len(staged.Revision.Nodes))
	}
	nodeID := staged.Revision.Nodes[0].ID
	if nodeID == "" || staged.Revision.Nodes[0].ProviderID != provider.ID {
		t.Fatal("staged node has no stable provider identity")
	}
	var gateway domain.Gateway
	app.request(t, http.MethodPost, "/api/v1/gateways", domain.Gateway{Name: "Test gateway", Endpoint: "https://gateway.example.test", Adapter: "dae"}, 0, http.StatusCreated, &gateway)
	assertUUID(t, gateway.ID)
	var outbound outbounds.Group
	app.request(t, http.MethodPost, "/api/v1/outbound-groups", outbounds.Group{Name: "Primary outbound", GatewayID: gateway.ID, NodeIDs: []string{nodeID}}, 0, http.StatusCreated, &outbound)
	assertUUID(t, outbound.ID)
	var selection struct {
		Items []outbounds.Selection `json:"items"`
	}
	app.request(t, http.MethodPost, "/api/v1/outbound-groups/"+outbound.ID+"/selection", map[string]string{"node_id": nodeID, "transport": "tcp"}, 0, http.StatusAccepted, &selection, map[string]string{"If-Match": `"0"`})
	if len(selection.Items) != 1 || selection.Items[0].DesiredNodeID != nodeID {
		t.Fatalf("outbound selection was not retained: %+v", selection.Items)
	}
	var rules policy.RuleSet
	app.request(t, http.MethodPost, "/api/v1/rule-sets", policy.RuleSet{Name: "Local traffic", Rules: []policy.Rule{{ID: domain.NewID(), Enabled: true, Match: policy.Match{DomainSuffix: []string{"internal.example.test"}}, Action: policy.Direct()}}}, 0, http.StatusCreated, &rules)
	assertUUID(t, rules.ID)
	var routing policy.Policy
	app.request(t, http.MethodPost, "/api/v1/policies", policy.Policy{Name: "Protected egress", RuleSetIDs: []string{rules.ID}, DefaultAction: policy.Outbound(outbound.ID), UnknownDomainAction: policy.Block(), ProxyFailureAction: policy.Block()}, 0, http.StatusCreated, &routing)
	assertUUID(t, routing.ID)
	var group domain.DeviceGroup
	app.request(t, http.MethodPost, "/api/v1/device-groups", domain.DeviceGroup{Name: "Managed devices", GatewayID: gateway.ID, PolicyID: routing.ID, Enabled: true}, 0, http.StatusCreated, &group)
	assertUUID(t, group.ID)
	var device domain.Device
	app.request(t, http.MethodPost, "/api/v1/devices", domain.Device{Name: "Workstation", PrimaryGroupID: group.ID, Addresses: []domain.DeviceAddress{{Address: "192.0.2.10", Provenance: "manual"}, {Address: "2001:db8::10", Provenance: "manual"}}}, 0, http.StatusCreated, &device)
	assertUUID(t, device.ID)
	if device.EnrollmentState != domain.EnrollmentUnenrolled {
		t.Fatalf("inventory creation claimed enrollment: %q", device.EnrollmentState)
	}

	// Save a successful new revision, then send a stale write to every CAS
	// resource. Compare all durable resource state as well as HTTP readback
	// after each rejected write. Only its rejection audit event may be added.
	cases := []struct {
		name string
		path string
		body any
	}{
		{"outbound", "/api/v1/outbound-groups/" + outbound.ID, outbounds.Group{Name: "Updated outbound", GatewayID: gateway.ID, NodeIDs: []string{nodeID}}},
		{"rule set", "/api/v1/rule-sets/" + rules.ID, policy.RuleSet{Name: "Updated local traffic", Rules: rules.Rules}},
		{"policy", "/api/v1/policies/" + routing.ID, policy.Policy{Name: "Updated protected egress", RuleSetIDs: []string{rules.ID}, DefaultAction: policy.Outbound(outbound.ID), UnknownDomainAction: policy.Block(), ProxyFailureAction: policy.Block()}},
		{"device group", "/api/v1/device-groups/" + group.ID, domain.DeviceGroup{Name: "Updated devices", GatewayID: gateway.ID, PolicyID: routing.ID, Enabled: true}},
		{"device", "/api/v1/devices/" + device.ID, domain.Device{Name: "Updated workstation", PrimaryGroupID: group.ID, Addresses: device.Addresses}},
	}
	for _, tc := range cases {
		var revision struct {
			Revision int64 `json:"revision"`
		}
		app.request(t, http.MethodPut, tc.path, tc.body, 1, http.StatusOK, &revision)
		if revision.Revision != 2 {
			t.Fatalf("%s revision = %d, want 2", tc.name, revision.Revision)
		}
		before := databaseSnapshot(t, app.db)
		readback := app.request(t, http.MethodGet, tc.path, nil, 0, http.StatusOK, nil)
		var rejected struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		app.request(t, http.MethodPut, tc.path, tc.body, 1, http.StatusPreconditionFailed, &rejected)
		if rejected.Error.Code != "revision_conflict" {
			t.Fatalf("%s stale write: error code %q", tc.name, rejected.Error.Code)
		}
		assertRejectedCASPreserved(t, tc.name, tc.path, before, databaseSnapshot(t, app.db), vault)
		if after := app.request(t, http.MethodGet, tc.path, nil, 0, http.StatusOK, nil); !bytes.Equal(readback, after) {
			t.Fatalf("%s rejected CAS changed HTTP readback", tc.name)
		}
	}

	// The complete SQL-visible row set includes provider inventory and all
	// documents, not merely the lifecycle envelope selected by the application.
	for table, data := range databaseSnapshot(t, app.db) {
		assertNoSecrets(t, table, data, privateValues)
	}
	var storedSource string
	if err := app.db.QueryRow("SELECT source FROM providers WHERE id=$1", provider.ID).Scan(&storedSource); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^secret_[0-9a-f]{32}$`).MatchString(storedSource) {
		t.Fatal("provider inventory does not store an opaque secret reference")
	}
	var encryptedDocuments int
	if err := app.db.QueryRow("SELECT count(*) FROM controller_documents WHERE document ? 'envelope'").Scan(&encryptedDocuments); err != nil || encryptedDocuments < 2 {
		t.Fatalf("source and lifecycle envelopes missing: count=%d err=%v", encryptedDocuments, err)
	}

	paths := []string{"/api/v1/providers/" + provider.ID, "/api/v1/providers/" + provider.ID + "/revisions", "/api/v1/nodes", "/api/v1/gateways/" + gateway.ID, "/api/v1/outbound-groups/" + outbound.ID + "/selection", "/api/v1/audit-events", "/api/v1/devices", "/api/v1/device-groups"}
	for _, tc := range cases {
		paths = append(paths, tc.path)
	}
	beforeRestart := make(map[string][]byte, len(paths))
	for _, path := range paths {
		beforeRestart[path] = app.request(t, http.MethodGet, path, nil, 0, http.StatusOK, nil)
		assertNoSecrets(t, path, beforeRestart[path], privateValues)
	}
	privateRevision, err := app.services.Providers.Get(provider.ID, 1)
	if err != nil || privateRevision.Nodes[0].Definition.Password != nodePassword {
		t.Fatalf("private staged node credentials not available before restart: %v", err)
	}
	app.close()

	// A new connection pool, store, Services, registry, mux, and HTTP listener
	// ensure nothing survives through process-local maps from the first server.
	var recoveredSource string
	app = openApplication(t, config, vault, func(_ context.Context, value domain.Provider) ([]byte, error) {
		recoveredSource = value.Source
		return []byte(content), nil
	})
	for _, path := range paths {
		if after := app.request(t, http.MethodGet, path, nil, 0, http.StatusOK, nil); !bytes.Equal(beforeRestart[path], after) {
			t.Fatalf("HTTP content or identity changed after PostgreSQL reopen: %s", path)
		}
	}
	restoredRevision, err := app.services.Providers.Get(provider.ID, 1)
	if err != nil || !reflect.DeepEqual(privateRevision, restoredRevision) {
		t.Fatalf("private provider revision or credentials changed after restart: %v", err)
	}
	wrongVault, err := secrets.New("integration-key", bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := api.NewServices().Load(context.Background(), app.inventory, wrongVault); err == nil {
		t.Fatal("encrypted PostgreSQL lifecycle loaded with a wrong encryption key")
	}
	app.request(t, http.MethodPost, "/api/v1/providers/"+provider.ID+"/refresh", nil, 0, http.StatusAccepted, nil)
	if recoveredSource != source {
		t.Fatal("provider refresh did not decrypt the original source after restart")
	}
	for _, tc := range cases {
		before := databaseSnapshot(t, app.db)
		app.request(t, http.MethodPut, tc.path, tc.body, 1, http.StatusPreconditionFailed, nil)
		assertRejectedCASPreserved(t, tc.name+" after restart", tc.path, before, databaseSnapshot(t, app.db), vault)
	}
	for table, data := range databaseSnapshot(t, app.db) {
		assertNoSecrets(t, table, data, privateValues)
	}
	t.Log("real PostgreSQL HTTP lifecycle passed: automatic UUIDs, provider source encryption, inline staging, outbound/rule-set/policy/group/device creation, five CAS boundaries, SQL row secret scan, close/reopen identity and content restore, and provider source decryption")
}

type application struct {
	db        *sql.DB
	inventory *store.PostgresStore
	services  *api.Services
	server    *httptest.Server
}

func openApplication(t *testing.T, config *pgx.ConnConfig, vault *secrets.Vault, fetch providers.ProviderFetcher) *application {
	t.Helper()
	db := stdlib.OpenDB(*config.Copy())
	db.SetMaxOpenConns(1)
	inventory, err := store.NewPostgresStore(db)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	services := api.NewServices()
	services.ProviderStageEnabled = true
	services.SelectionApplier = func(_ context.Context, _ outbounds.Group, selection outbounds.Selection) (outbounds.Selection, error) {
		selection.AppliedNodeID = selection.DesiredNodeID
		selection.ObservedNodeID = selection.DesiredNodeID
		selection.AppliedGeneration = selection.Generation
		selection.ObservedGeneration = selection.Generation
		return selection, nil
	}
	if fetch != nil {
		services.Providers = providers.NewRegistry(providers.DefaultLimits(), fetch)
	}
	if err := services.Load(context.Background(), inventory, vault); err != nil {
		db.Close()
		t.Fatalf("load encrypted services: %v", err)
	}
	server := api.NewServer(inventory, nil)
	server.Services = services
	app := &application{db: db, inventory: inventory, services: services, server: httptest.NewServer(server.Handler())}
	app.server.Client().Timeout = 10 * time.Second
	t.Cleanup(app.close)
	return app
}

func (a *application) close() {
	a.server.Close()
	_ = a.inventory.Close()
}

func (a *application) request(t *testing.T, method, path string, body any, revision int64, want int, result any, headers ...map[string]string) []byte {
	t.Helper()
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, a.server.URL+path, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if revision > 0 {
		req.Header.Set("If-Match", fmt.Sprintf(`"%d"`, revision))
	}
	for _, values := range headers {
		for key, value := range values {
			req.Header.Set(key, value)
		}
	}
	response, err := a.server.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("%s %s returned %d, want %d: %s", method, path, response.StatusCode, want, data)
	}
	if result != nil {
		if err := json.Unmarshal(data, result); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return data
}

func isolatedDatabase(t *testing.T) *pgx.ConnConfig {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is unset; PostgreSQL HTTP integration requires a disposable PostgreSQL server")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse TEST_DATABASE_URL failed")
	}
	admin := stdlib.OpenDB(*config)
	t.Cleanup(func() { _ = admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatalf("connect PostgreSQL: %v", err)
	}
	name := "egressdeck_api_" + strings.ReplaceAll(domain.NewID(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatalf("create isolated PostgreSQL database (TEST_DATABASE_URL user needs CREATEDB): %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(ctx, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated PostgreSQL database %s: %v", name, err)
		}
	})
	config = config.Copy()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate canonical schema")
	}
	schema, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "migrations", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	for pass := 1; pass <= 2; pass++ {
		if _, err := db.ExecContext(ctx, string(schema)); err != nil {
			t.Fatalf("apply canonical schema pass %d: %v", pass, err)
		}
	}
	var version string
	if err := db.QueryRowContext(ctx, "SHOW server_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL %s; isolated database %s; canonical schema applied twice", version, name)
	return config
}

func databaseSnapshot(t *testing.T, db *sql.DB) map[string][]byte {
	t.Helper()
	rows, err := db.Query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	result := make(map[string][]byte, len(tables))
	for _, table := range tables {
		var data []byte
		query := "SELECT COALESCE(jsonb_agg(row ORDER BY row::text), '[]'::jsonb)::text FROM (SELECT to_jsonb(t) AS row FROM " + pgx.Identifier{"public", table}.Sanitize() + " t) s"
		if err := db.QueryRow(query).Scan(&data); err != nil {
			t.Fatalf("read table %s: %v", table, err)
		}
		result[table] = data
	}
	return result
}

func assertNoSecrets(t *testing.T, location string, data []byte, values []string) {
	t.Helper()
	for _, value := range values {
		if bytes.Contains(data, []byte(value)) {
			t.Fatalf("private source or node credential leaked in %s", location)
		}
	}
}

func assertRejectedCASPreserved(t *testing.T, resource, path string, before, after map[string][]byte, vault *secrets.Vault) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("%s rejected CAS changed the durable table set", resource)
	}
	for table, data := range before {
		if table != "controller_documents" && !bytes.Equal(data, after[table]) {
			t.Fatalf("%s rejected CAS changed table %s", resource, table)
		}
	}
	decode := func(data []byte) map[string]map[string]json.RawMessage {
		var rows []map[string]json.RawMessage
		if err := json.Unmarshal(data, &rows); err != nil {
			t.Fatal(err)
		}
		result := make(map[string]map[string]json.RawMessage, len(rows))
		for _, row := range rows {
			var key string
			if err := json.Unmarshal(row["key"], &key); err != nil {
				t.Fatal(err)
			}
			result[key] = row
		}
		return result
	}
	oldDocuments, newDocuments := decode(before["controller_documents"]), decode(after["controller_documents"])
	if len(oldDocuments) != len(newDocuments) {
		t.Fatalf("%s rejected CAS changed the document set", resource)
	}
	for key, row := range oldDocuments {
		if key != "lifecycle/v1" && !reflect.DeepEqual(row, newDocuments[key]) {
			t.Fatalf("%s rejected CAS changed document %s", resource, key)
		}
	}
	openLifecycle := func(row map[string]json.RawMessage) map[string]json.RawMessage {
		var document struct {
			Version  int              `json:"version"`
			Envelope secrets.Envelope `json:"envelope"`
		}
		if err := json.Unmarshal(row["document"], &document); err != nil || document.Version != 1 {
			t.Fatalf("invalid lifecycle document: %v", err)
		}
		var value map[string]json.RawMessage
		if err := vault.OpenJSON("lifecycle/v1", document.Envelope, &value); err != nil {
			t.Fatalf("authenticate stored lifecycle document: %v", err)
		}
		return value
	}
	oldState, newState := openLifecycle(oldDocuments["lifecycle/v1"]), openLifecycle(newDocuments["lifecycle/v1"])
	var oldAudit, newAudit []api.AuditEvent
	if err := json.Unmarshal(oldState["audit"], &oldAudit); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(newState["audit"], &newAudit); err != nil {
		t.Fatal(err)
	}
	if len(newAudit) != len(oldAudit)+1 || !reflect.DeepEqual(oldAudit, newAudit[:len(oldAudit)]) {
		t.Fatalf("%s rejected CAS did not preserve audit history plus one rejection event", resource)
	}
	event := newAudit[len(newAudit)-1]
	wantAction := "PUT " + path[:strings.LastIndex(path, "/")] + "/{id}"
	if event.ObjectType != "management_request" || event.ObjectID != "" || event.Actor != "development" || event.Outcome != "412" || event.Action != wantAction || event.ID == "" || event.CreatedAt.IsZero() {
		t.Fatalf("%s rejected CAS appended an unexpected audit event: %+v", resource, event)
	}
	delete(oldState, "audit")
	delete(newState, "audit")
	if !reflect.DeepEqual(oldState, newState) {
		t.Fatalf("%s rejected CAS changed encrypted lifecycle resource state", resource)
	}
}

func assertUUID(t *testing.T, id string) {
	t.Helper()
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(id) {
		t.Fatalf("API did not generate a UUID v4: %q", id)
	}
}
