package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/policy"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func plannerFixture(t *testing.T, storage store.Store) *Server {
	t.Helper()
	s := NewServer(storage, nil)
	ctx := context.Background()
	for _, g := range []domain.Gateway{{ID: "gateway-1", Name: "Actual gateway", Endpoint: "https://gateway.invalid", Adapter: "dae"}, {ID: "other-gateway", Name: "Other", Endpoint: "https://other.invalid"}} {
		if _, err := storage.CreateGateway(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	for _, g := range []domain.DeviceGroup{{ID: "group-1", Name: "Actual group", GatewayID: "gateway-1", PolicyID: "policy-1", Enabled: true}, {ID: "other-group", Name: "Other", GatewayID: "other-gateway", PolicyID: "missing-other-policy", Enabled: true}} {
		if _, err := storage.CreateDeviceGroup(ctx, g); err != nil {
			t.Fatal(err)
		}
	}
	exception, _ := json.Marshal(policy.Rule{ID: "device-exception", Enabled: true, Match: policy.Match{DomainSuffix: []string{"example.test"}}, Action: policy.Direct()})
	if _, err := storage.CreateDevice(ctx, domain.Device{ID: "device-1", Name: "Actual device", PrimaryGroupID: "group-1", Addresses: []domain.DeviceAddress{{Address: "192.0.2.11"}}, Exceptions: []json.RawMessage{exception}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.CreateDevice(ctx, domain.Device{ID: "device-2", Name: "Peer", PrimaryGroupID: "group-1", Addresses: []domain.DeviceAddress{{Address: "192.0.2.12"}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.CreateDevice(ctx, domain.Device{ID: "other-device", Name: "Other", PrimaryGroupID: "other-group", Addresses: []domain.DeviceAddress{{Address: "198.51.100.10"}}}); err != nil {
		t.Fatal(err)
	}
	s.Services.policies["policy-1"] = policy.Policy{ID: "policy-1", Name: "Actual policy", Revision: 7, MandatoryRules: []policy.Rule{{ID: "mandatory", Enabled: true, Match: policy.Match{DomainSuffix: []string{"blocked.example.test"}}, Action: policy.Block()}}, RuleSetIDs: []string{"set-1"}, DefaultAction: policy.Block()}
	s.Services.ruleSets["set-1"] = policy.RuleSet{ID: "set-1", Name: "Actual rule set", Revision: 4, Rules: []policy.Rule{{ID: "exit-rule", Enabled: true, Match: policy.Match{DomainSuffix: []string{"example.test"}}, Action: policy.Outbound("exit-1")}}}
	if _, err := s.Services.Outbounds.Create(outbounds.Group{ID: "exit-1", Name: "Actual exit", GatewayID: "gateway-1", NodeIDs: []string{"node-1"}}); err != nil {
		t.Fatal(err)
	}
	return s
}

func requestPlan(t *testing.T, s *Server) InventoryPlan {
	t.Helper()
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/deployments/plan", strings.NewReader(`{"gateway_id":"gateway-1"}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("plan status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var plan InventoryPlan
	if err := json.Unmarshal(recorder.Body.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if recorder.Header().Get("ETag") != `"`+plan.Checksum+`"` {
		t.Fatal("plan checksum not exposed as ETag")
	}
	return plan
}

func TestInventoryPlanBindsActualInventoryAndExceptionPrecedence(t *testing.T) {
	s := plannerFixture(t, store.NewMemoryStore())
	plan := requestPlan(t, s)
	if !plan.Valid || plan.Deployable || plan.Compilation == nil || plan.NativeArtifact == nil || len(plan.Input.Devices) != 2 || len(plan.Input.DeviceGroups) != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.Checksum != inventoryPlanChecksum(plan) {
		t.Fatal("snapshot checksum mismatch")
	}
	bound := map[string]int64{}
	for _, resource := range plan.ResourceRevisions {
		bound[resource.Kind+":"+resource.ID] = resource.Revision
		if len(resource.SHA256) != 64 {
			t.Fatal("missing resource hash")
		}
	}
	for key, revision := range map[string]int64{"gateway:gateway-1": 1, "device:device-1": 1, "device:device-2": 1, "device_group:group-1": 1, "policy:policy-1": 7, "rule_set:set-1": 4, "outbound_group:exit-1": 1} {
		if bound[key] != revision {
			t.Fatalf("binding %s=%d want %d", key, bound[key], revision)
		}
	}
	for _, test := range []struct {
		source, domain string
		want           policy.ActionKind
		phase          string
	}{{"192.0.2.11", "blocked.example.test", policy.ActionBlock, "mandatory"}, {"192.0.2.11", "www.example.test", policy.ActionDirect, "exception"}, {"192.0.2.12", "www.example.test", policy.ActionOutboundGroup, "group"}} {
		explanation := policy.Explain(plan.Compilation.Manifest, policy.Packet{SourceIP: test.source, DestinationIP: "203.0.113.1", DestinationPort: 443, Transport: policy.TransportTCP, Domain: test.domain})
		if explanation.Action.Kind != test.want || explanation.Source.Phase != test.phase {
			t.Fatalf("explanation=%+v", explanation)
		}
	}
	if len(plan.Compilation.Manifest.Enrollments) != 1 || len(plan.Compilation.Manifest.Enrollments[0].Addresses) != 2 {
		t.Fatal("plan did not contain full stored gateway membership")
	}
	if plan.Previous.Status != "unavailable" || plan.Target.ObservationStatus != "unavailable" {
		t.Fatal("unobserved state was promoted")
	}
}

func TestInventoryPlanPersistsImmutableSnapshotAndDetectsChangedRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	storage, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s := plannerFixture(t, storage)
	first, repeated := requestPlan(t, s), requestPlan(t, s)
	if first.Checksum != repeated.Checksum || !first.CreatedAt.Equal(repeated.CreatedAt) {
		t.Fatal("identical plan was not reused")
	}
	device, _ := storage.GetDevice(context.Background(), "device-1")
	device.Addresses[0].Address = "192.0.2.99"
	if _, err := storage.UpdateDevice(context.Background(), device, device.Revision); err != nil {
		t.Fatal(err)
	}
	second := requestPlan(t, s)
	if first.Checksum == second.Checksum {
		t.Fatal("changed inventory reused old checksum")
	}
	reopened, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	NewServer(reopened, nil).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/deployments/plans/"+first.Checksum, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("restart retrieval=%d %s", rec.Code, rec.Body.String())
	}
	var persisted InventoryPlan
	if err := json.Unmarshal(rec.Body.Bytes(), &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Checksum != first.Checksum || persisted.Input.Devices[0].Addresses[0].Address != "192.0.2.11" {
		t.Fatal("old immutable snapshot changed")
	}
}

func TestInventoryPlanRejectsCorruptedStoredChecksum(t *testing.T) {
	storage := store.NewMemoryStore()
	s := plannerFixture(t, storage)
	plan := requestPlan(t, s)
	key := "plans/v1/" + plan.Checksum
	plan.Checksum = strings.Repeat("0", 64)
	raw, _ := json.Marshal(plan)
	if err := storage.SaveDocument(context.Background(), key, raw); err != nil {
		t.Fatal(err)
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/api/v1/deployments/plans/"+strings.TrimPrefix(key, "plans/v1/"), nil),
		httptest.NewRequest(http.MethodPost, "/api/v1/deployments/plan", strings.NewReader(`{"gateway_id":"gateway-1"}`)),
	} {
		recorder := httptest.NewRecorder()
		s.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "plan_corrupt") {
			t.Fatalf("corrupt plan response=%d %s", recorder.Code, recorder.Body.String())
		}
	}
}

type racingPlanStore struct {
	*store.MemoryStore
	first json.RawMessage
}

func (s *racingPlanStore) CreateDocument(ctx context.Context, key string, data json.RawMessage) error {
	var concurrent InventoryPlan
	if err := json.Unmarshal(data, &concurrent); err != nil {
		return err
	}
	concurrent.CreatedAt = concurrent.CreatedAt.Add(-time.Second)
	s.first, _ = json.Marshal(concurrent)
	if err := s.MemoryStore.CreateDocument(ctx, key, s.first); err != nil {
		return err
	}
	return domain.ErrConflict
}

func TestInventoryPlanConcurrentFirstWriterKeepsItsSnapshot(t *testing.T) {
	storage := &racingPlanStore{MemoryStore: store.NewMemoryStore()}
	plan := requestPlan(t, plannerFixture(t, storage))
	var first InventoryPlan
	if err := json.Unmarshal(storage.first, &first); err != nil {
		t.Fatal(err)
	}
	if !plan.CreatedAt.Equal(first.CreatedAt) || plan.Checksum != first.Checksum {
		t.Fatal("concurrent plan was overwritten instead of reused")
	}
}

func TestInventoryPlanStrictAndCapabilitiesDoNotClaimProtection(t *testing.T) {
	s := plannerFixture(t, store.NewMemoryStore())
	s.Services.GatewayObserver = func(context.Context, domain.Gateway) (gateway.Capabilities, gateway.Health, error) {
		return gateway.DefaultCapabilities("fake", "test"), gateway.Health{}, nil
	}
	plan := requestPlan(t, s)
	if plan.Deployable || plan.Target.ObservationStatus != "observed" {
		t.Fatal("capability observation became enrollment authorization")
	}
	p := s.Services.policies["policy-1"]
	p.Strict = true
	p.UnknownDomainAction = policy.Block()
	p.ProxyFailureAction = policy.Block()
	p.Revision++
	s.Services.policies[p.ID] = p
	strict := requestPlan(t, s)
	if strict.Valid || strict.Deployable {
		t.Fatal("strict intent accepted without independent IPv6 coverage")
	}
	found := false
	for _, d := range strict.Diagnostics {
		if d.Code == "uncontrolled_ipv6" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing strict coverage diagnostic: %+v", strict.Diagnostics)
	}
}

func TestInventoryPlanUsesAppliedManifestOnly(t *testing.T) {
	s := plannerFixture(t, store.NewMemoryStore())
	first := requestPlan(t, s)
	data, _ := json.Marshal(first.Compilation.Manifest)
	_, err := s.Services.Journal.Create(context.Background(), deployment.Operation{ID: "desired-only", Target: deployment.Target{Kind: "gateway", ID: "gateway-1"}, Status: deployment.StatusDraft, Views: deployment.StateViews{Desired: &deployment.StateRecord{Data: data}}})
	if err != nil {
		t.Fatal(err)
	}
	if requestPlan(t, s).Previous.Status != "unavailable" {
		t.Fatal("desired manifest treated as applied")
	}
	_, err = s.Services.Journal.Create(context.Background(), deployment.Operation{ID: "applied", Target: deployment.Target{Kind: "gateway", ID: "gateway-1"}, Status: deployment.StatusApplied, Views: deployment.StateViews{Applied: &deployment.StateRecord{Data: data}}, CreatedAt: time.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	plan := requestPlan(t, s)
	if plan.Previous.OperationID != "applied" || plan.Previous.Status != "applied" || plan.Compilation.Impact.RequiresPolicyApply || len(plan.Compilation.Impact.ChangedGroups) > 0 {
		t.Fatalf("applied comparison missing: %+v", plan)
	}
	_, err = s.Services.Journal.Create(context.Background(), deployment.Operation{ID: "new-native-only", Target: deployment.Target{Kind: "gateway", ID: "gateway-1"}, Status: deployment.StatusApplied, Views: deployment.StateViews{Applied: &deployment.StateRecord{Data: json.RawMessage(`{"native_config":"routing{}"}`)}}, CreatedAt: time.Now().Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	latest := requestPlan(t, s)
	if latest.Previous.Status != "manifest_unavailable" || latest.Previous.OperationID != "new-native-only" || latest.Input.Previous != nil {
		t.Fatal("fell back to stale normalized applied manifest")
	}
	_, err = s.Services.Journal.Create(context.Background(), deployment.Operation{ID: "latest-no-applied-view", Target: deployment.Target{Kind: "gateway", ID: "gateway-1"}, Status: deployment.StatusApplied, CreatedAt: time.Now().Add(3 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	latest = requestPlan(t, s)
	if latest.Previous.Status != "manifest_unavailable" || latest.Previous.OperationID != "latest-no-applied-view" || latest.Input.Previous != nil {
		t.Fatal("nil applied view fell back to an older manifest")
	}
}

func TestInventoryPlanRejectsCallerSubstitutionAndInvalidExceptions(t *testing.T) {
	s := plannerFixture(t, store.NewMemoryStore())
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	postJSON(t, ts.URL+"/api/v1/deployments/plan", `{"gateway_id":"gateway-1","policies":[]}`, http.StatusBadRequest)
	postJSON(t, ts.URL+"/api/v1/deployments/plan", `{"gateway_id":"gateway-1","previous_operation_id":"missing"}`, http.StatusNotFound)
	for _, rules := range []string{`[{"id":"x","match":{},"action":{"kind":"direct"},"enabled":true,"native_config":"bad"}]`, `[{"id":"x","match":{},"action":{"kind":"outbound_group","outbound_group_id":"missing"},"enabled":true}]`, `[{"id":"x","match":{"destination_cidrs":["broken"]},"action":{"kind":"direct"},"enabled":true}]`} {
		postJSON(t, ts.URL+"/api/v1/devices", `{"name":"Rejected","exceptions":`+rules+`}`, http.StatusUnprocessableEntity)
	}
	data := postJSON(t, ts.URL+"/api/v1/devices", `{"name":"Saved","exceptions":[{"id":"x","match":{"transport":["udp"]},"action":{"kind":"block"},"enabled":true}]}`, http.StatusCreated)
	var device domain.Device
	if err := json.Unmarshal(data, &device); err != nil {
		t.Fatal(err)
	}
	if len(device.Exceptions) != 1 {
		t.Fatal("valid exception not persisted")
	}
}

type driftPlanStore struct {
	*store.MemoryStore
	reads int
}

func (s *driftPlanStore) ListDevices(ctx context.Context) ([]domain.Device, error) {
	s.reads++
	if s.reads == 2 {
		d, _ := s.GetDevice(ctx, "device-1")
		d.Name = "Concurrent revision"
		_, _ = s.UpdateDevice(ctx, d, d.Revision)
	}
	return s.MemoryStore.ListDevices(ctx)
}

func TestInventoryPlanRejectsInventoryDriftBeforePersisting(t *testing.T) {
	storage := &driftPlanStore{MemoryStore: store.NewMemoryStore()}
	s := plannerFixture(t, storage)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/deployments/plan", strings.NewReader(`{"gateway_id":"gateway-1"}`)))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "snapshot_changed") {
		t.Fatalf("drift response=%d %s", rec.Code, rec.Body.String())
	}
}

type failingPlanStore struct{ *store.MemoryStore }

func (s *failingPlanStore) CreateDocument(context.Context, string, json.RawMessage) error {
	return errors.New("storage unavailable")
}
func TestInventoryPlanRequiresPersistenceAcknowledgement(t *testing.T) {
	s := plannerFixture(t, &failingPlanStore{store.NewMemoryStore()})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/deployments/plan", strings.NewReader(`{"gateway_id":"gateway-1"}`)))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "plan_persistence_failed") {
		t.Fatalf("persistence response=%d %s", rec.Code, rec.Body.String())
	}
}
