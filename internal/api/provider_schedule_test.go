package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/auth"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func scheduleServer(t *testing.T, fetch providers.ProviderFetcher) (*Server, *store.MemoryStore) {
	t.Helper()
	mem := store.NewMemoryStore()
	s := NewServer(mem, nil)
	s.Services.ProviderStageEnabled = true
	s.Services.Providers = providers.NewRegistry(providers.DefaultLimits(), fetch)
	if err := s.Services.Load(context.Background(), mem, lifecycleTestVault(t, 7)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.createProvider(context.Background(), domain.Provider{ID: "scheduled-provider", Name: "scheduled", Source: "https://source.example/list?token=source-secret", Format: "links"}); err != nil {
		t.Fatal(err)
	}
	return s, mem
}

func scheduleRequest(t *testing.T, s *Server, method, body, revision string, want int) ProviderSchedule {
	t.Helper()
	r := httptest.NewRequest(method, "/api/v1/providers/scheduled-provider/schedule", strings.NewReader(body))
	if revision != "" {
		r.Header.Set("If-Match", revision)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s schedule=%d want %d: %s", method, w.Code, want, w.Body.String())
	}
	var item ProviderSchedule
	if want == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &item); err != nil {
			t.Fatal(err)
		}
	}
	return item
}

func enableSchedule(t *testing.T, s *Server) ProviderSchedule {
	return scheduleRequest(t, s, http.MethodPut, `{"enabled":true,"interval_seconds":300,"auto_apply":false}`, "0", 200)
}

func TestProviderScheduleAPIValidationAndEncryptedRestart(t *testing.T) {
	s, mem := scheduleServer(t, nil)
	initial := scheduleRequest(t, s, http.MethodGet, "", "", 200)
	if initial.Enabled || initial.Revision != 0 || !initial.Eligible || initial.AutoApply || initial.NextDueAt != nil {
		t.Fatalf("default=%+v", initial)
	}
	for _, tc := range []struct {
		body, revision string
		status         int
	}{
		{`{"enabled":true,"interval_seconds":300}`, "", 428},
		{`{"enabled":true,"interval_seconds":299}`, "0", 400},
		{`{"enabled":true,"interval_seconds":604801}`, "0", 400},
		{`{"enabled":true,"interval_seconds":300,"auto_apply":true}`, "0", 501},
		{`{"enabled":true,"interval_seconds":300,"revision":0}`, "0", 400},
		{`{"enabled":true,"interval_seconds":300}`, "9", 412},
	} {
		scheduleRequest(t, s, http.MethodPut, tc.body, tc.revision, tc.status)
	}
	saved := enableSchedule(t, s)
	if saved.Revision != 1 || !saved.Enabled || saved.NextDueAt == nil {
		t.Fatalf("save=%+v", saved)
	}
	raw, err := mem.LoadDocument(context.Background(), providerScheduleDocumentKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"scheduled-provider", "interval_seconds", "source-secret"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatalf("unencrypted schedule content %q", private)
		}
	}
	restored := NewServer(mem, nil)
	if err := restored.Services.Load(context.Background(), mem, lifecycleTestVault(t, 7)); err != nil {
		t.Fatal(err)
	}
	loaded := scheduleRequest(t, restored, http.MethodGet, "", "", 200)
	if loaded.Revision != saved.Revision || !loaded.NextDueAt.Equal(*saved.NextDueAt) || !loaded.Enabled {
		t.Fatalf("restored=%+v", loaded)
	}
	disabled := scheduleRequest(t, restored, http.MethodPut, `{"enabled":false,"interval_seconds":3600}`, "1", 200)
	if disabled.Enabled || disabled.NextDueAt != nil || disabled.Revision != 2 {
		t.Fatalf("disabled=%+v", disabled)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/providers/p/schedule", nil)
	if auth.RequiredRole(request) != auth.RoleAdmin {
		t.Fatal("schedule mutations must require admin")
	}
}

func TestProviderSchedulerStagesDurablyWithoutPublishing(t *testing.T) {
	var fetches, publishes atomic.Int64
	s, mem := scheduleServer(t, func(_ context.Context, p domain.Provider) ([]byte, error) {
		fetches.Add(1)
		if p.Source != "https://source.example/list?token=source-secret" {
			t.Errorf("fetch did not resolve private source")
		}
		return []byte("trojan://node-secret@edge.example:443#edge"), nil
	})
	s.Services.ProviderPublisher = func(context.Context, domain.Provider, providers.Revision) error { publishes.Add(1); return nil }
	cfg := enableSchedule(t, s)
	if err := s.runProviderSchedules(context.Background(), cfg.NextDueAt.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 0 {
		t.Fatal("scheduler fetched before due")
	}
	due := cfg.NextDueAt.Add(24 * time.Hour)
	if err := s.runProviderSchedules(context.Background(), due); err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 1 || publishes.Load() != 0 {
		t.Fatalf("fetches=%d publishes=%d", fetches.Load(), publishes.Load())
	}
	if err := s.runProviderSchedules(context.Background(), due); err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != 1 {
		t.Fatal("missed intervals replayed instead of coalesced")
	}
	got := scheduleRequest(t, s, http.MethodGet, "", "", 200)
	if got.Running || got.LastAttemptAt == nil || got.LastSuccessAt == nil || got.LastOperationID == "" || got.LastError != "" || got.NextDueAt == nil || !got.NextDueAt.After(due) {
		t.Fatalf("status=%+v", got)
	}
	status := s.Services.Providers.Status("scheduled-provider")
	if status.Staged != 1 || status.Active != 0 {
		t.Fatalf("provider=%+v", status)
	}
	restored := NewServices()
	if err := restored.Load(context.Background(), mem, lifecycleTestVault(t, 7)); err != nil {
		t.Fatal(err)
	}
	if restored.Providers.Status("scheduled-provider").Staged != 1 {
		t.Fatal("scheduled stage was not durable")
	}
	found := false
	for _, event := range restored.audit {
		if event.Actor == "scheduler" && event.Action == "scheduled_refresh" && event.Outcome == "staged" {
			found = true
		}
	}
	if !found {
		t.Fatal("durable scheduler audit missing")
	}
}

func TestProviderSchedulerConcurrentTicksDoNotOverlap(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int64
	s, _ := scheduleServer(t, func(ctx context.Context, _ domain.Provider) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return []byte("socks5://edge.example:1080#edge"), nil
	})
	cfg := enableSchedule(t, s)
	var wg sync.WaitGroup
	wg.Add(2)
	errorsOut := make(chan error, 2)
	go func() { defer wg.Done(); errorsOut <- s.runProviderSchedules(context.Background(), *cfg.NextDueAt) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduler never fetched")
	}
	go func() { defer wg.Done(); errorsOut <- s.runProviderSchedules(context.Background(), *cfg.NextDueAt) }()
	close(release)
	wg.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent due tick duplicated fetch: %d", calls.Load())
	}
}

func TestProviderSchedulerFailedFetchRetainsInventoryAndRecordsFailure(t *testing.T) {
	s, mem := scheduleServer(t, func(context.Context, domain.Provider) ([]byte, error) {
		return nil, errors.New("https://source.example/list?token=source-secret authorization=raw-secret")
	})
	revision, _, err := s.Services.Providers.Stage("scheduled-provider", []byte("trojan://previous-secret@edge.example:443#edge"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Services.Providers.Publish("scheduled-provider", revision.Number, 0); err != nil {
		t.Fatal(err)
	}
	cfg := enableSchedule(t, s)
	if err := s.runProviderSchedules(context.Background(), *cfg.NextDueAt); err != nil {
		t.Fatal(err)
	}
	got := scheduleRequest(t, s, http.MethodGet, "", "", 200)
	if got.LastAttemptAt == nil || got.LastSuccessAt != nil || got.LastError == "" || got.Running {
		t.Fatalf("failure status=%+v", got)
	}
	raw, _ := json.Marshal(got)
	if bytes.Contains(raw, []byte("secret")) || bytes.Contains(raw, []byte("source.example")) {
		t.Fatal("schedule leaked source error")
	}
	restored := NewServices()
	if err := restored.Load(context.Background(), mem, lifecycleTestVault(t, 7)); err != nil {
		t.Fatal(err)
	}
	status := restored.Providers.Status("scheduled-provider")
	if status.Active != revision.Number || status.LastAttemptAt == nil || status.LastError == "" {
		t.Fatalf("failure did not preserve durable inventory/status: %+v", status)
	}
	op, err := s.Services.Journal.Get(context.Background(), got.LastOperationID)
	if err != nil || op.Status != "failed" {
		t.Fatalf("failure operation=%+v %v", op, err)
	}
}

func TestManualRefreshFailureStatusAndPublicMetadataAreDurable(t *testing.T) {
	s, mem := scheduleServer(t, func(context.Context, domain.Provider) ([]byte, error) { return nil, errors.New("private failure") })
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/providers/scheduled-provider/refresh", strings.NewReader(`{}`)))
	if w.Code < 400 {
		t.Fatalf("failed fetch returned %d", w.Code)
	}
	restored := NewServer(mem, nil)
	if err := restored.Services.Load(context.Background(), mem, lifecycleTestVault(t, 7)); err != nil {
		t.Fatal(err)
	}
	if restored.Services.Providers.Status("scheduled-provider").LastAttemptAt == nil {
		t.Fatal("failed manual attempt disappeared at restart")
	}
	view := httptest.NewRecorder()
	restored.Handler().ServeHTTP(view, httptest.NewRequest(http.MethodGet, "/api/v1/providers/scheduled-provider", nil))
	var body map[string]any
	if err := json.Unmarshal(view.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["source"] != "[redacted]" || body["source_kind"] != "url" || body["refreshable"] != true || body["last_attempt_at"] == nil || body["last_error"] == nil {
		t.Fatalf("public lifecycle metadata=%s", view.Body.String())
	}
	auditFound := false
	for _, event := range restored.Services.audit {
		if event.ObjectType == "management_request" && strings.Contains(event.Action, "/providers/{id}/refresh") {
			auditFound = true
		}
	}
	if !auditFound {
		t.Fatalf("failed request audit missing template: %+v", restored.Services.audit)
	}
}

type scheduleFailDocuments struct {
	store.DocumentStore
	failKey string
}

func (d *scheduleFailDocuments) SaveDocument(ctx context.Context, key string, raw json.RawMessage) error {
	if key == d.failKey {
		return errors.New("simulated durable write failure")
	}
	return d.DocumentStore.SaveDocument(ctx, key, raw)
}

func TestProviderSchedulePersistenceFailureFreezesHTTPAndScheduler(t *testing.T) {
	var calls atomic.Int64
	s, mem := scheduleServer(t, func(context.Context, domain.Provider) ([]byte, error) {
		calls.Add(1)
		return []byte("socks5://edge.example:1080#edge"), nil
	})
	cfg := enableSchedule(t, s)
	failing := &scheduleFailDocuments{DocumentStore: mem, failKey: providerScheduleDocumentKey}
	s.Services.persistence.documents = failing
	if err := s.runProviderSchedules(context.Background(), *cfg.NextDueAt); err == nil {
		t.Fatal("ignored schedule persistence failure")
	}
	if calls.Load() != 0 {
		t.Fatal("fetched despite uncommitted attempt marker")
	}
	scheduleRequest(t, s, http.MethodPut, `{"enabled":false,"interval_seconds":300}`, "1", 503)
	// A separately built Handler must share the same failure freeze.
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/providers/scheduled-provider/refresh", strings.NewReader(`{}`)))
	if w.Code != 503 || calls.Load() != 0 {
		t.Fatalf("write freeze bypassed: status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestProviderSchedulerStartupRecoveryAndStopWaitsForPersistence(t *testing.T) {
	entered := make(chan struct{})
	s, mem := scheduleServer(t, func(ctx context.Context, _ domain.Provider) ([]byte, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	enableSchedule(t, s)
	manager, err := s.providerSchedules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	item := manager.schedules["scheduled-provider"]
	due := time.Now().Add(-time.Hour)
	item.NextDueAt = &due
	manager.schedules[item.ProviderID] = item
	manager.mu.Unlock()
	s.Services.mutationMu.Lock()
	err = s.saveProviderSchedules(context.Background(), manager)
	s.Services.mutationMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StartProviderScheduler(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not service overdue schedule")
	}
	done := make(chan struct{})
	go func() { s.StopProviderScheduler(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not cancel bounded fetch")
	}
	restored := NewServer(mem, nil)
	if err := restored.Services.Load(context.Background(), mem, lifecycleTestVault(t, 7)); err != nil {
		t.Fatal(err)
	}
	got := scheduleRequest(t, restored, http.MethodGet, "", "", 200)
	if got.Running || got.LastAttemptAt == nil || got.LastError == "" {
		t.Fatalf("stop did not persist final schedule: %+v", got)
	}
	// Simulate a hard crash after the durable attempt marker. The next interval
	// remains authoritative and is not replayed immediately.
	recoveredManager, _ := restored.providerSchedules(context.Background())
	recoveredManager.mu.Lock()
	item = recoveredManager.schedules[got.ProviderID]
	item.Running = true
	recoveredManager.schedules[got.ProviderID] = item
	recoveredManager.mu.Unlock()
	restored.Services.mutationMu.Lock()
	err = restored.saveProviderSchedules(context.Background(), recoveredManager)
	restored.Services.mutationMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	crashRestart := NewServer(mem, nil)
	if err := crashRestart.Services.Load(context.Background(), mem, lifecycleTestVault(t, 7)); err != nil {
		t.Fatal(err)
	}
	after := scheduleRequest(t, crashRestart, http.MethodGet, "", "", 200)
	if after.Running || !strings.Contains(after.LastError, "interrupted") || !after.NextDueAt.Equal(*got.NextDueAt) {
		t.Fatalf("unsafe crash recovery: %+v", after)
	}
}

func TestProviderSchedulerProtectedFetcherRejectsLocalDestination(t *testing.T) {
	var contacts atomic.Int64
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacts.Add(1)
		_, _ = w.Write([]byte("socks5://edge.example:1080#edge"))
	}))
	defer endpoint.Close()
	mem := store.NewMemoryStore()
	s := NewServer(mem, nil)
	s.Services.ProviderStageEnabled = true
	s.Services.Providers = providers.NewHTTPRegistry(providers.DefaultLimits(), providers.FetchOptions{})
	if err := s.Services.Load(context.Background(), mem, lifecycleTestVault(t, 7)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.createProvider(context.Background(), domain.Provider{ID: "scheduled-provider", Name: "local SSRF", Source: endpoint.URL, Format: "links"}); err != nil {
		t.Fatal(err)
	}
	cfg := enableSchedule(t, s)
	if err := s.runProviderSchedules(context.Background(), *cfg.NextDueAt); err != nil {
		t.Fatal(err)
	}
	got := scheduleRequest(t, s, http.MethodGet, "", "", 200)
	if contacts.Load() != 0 || got.LastError == "" || got.LastSuccessAt != nil || s.Services.Providers.Status("scheduled-provider").Staged != 0 {
		t.Fatalf("protected schedule fetch bypassed bounds: contacts=%d schedule=%+v", contacts.Load(), got)
	}
}

func TestProviderSchedulerCorruptDocumentFailsStartupAndLocalImportCannotEnable(t *testing.T) {
	s, mem := scheduleServer(t, nil)
	if err := mem.SaveDocument(context.Background(), providerScheduleDocumentKey, json.RawMessage(`{"version":99}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.StartProviderScheduler(context.Background()); err == nil {
		t.Fatal("startup ignored corrupt schedule document")
	}
	local := NewServer(store.NewMemoryStore(), nil)
	local.Services.ProviderStageEnabled = true
	if _, err := local.Store.CreateProvider(context.Background(), domain.Provider{ID: "scheduled-provider", Name: "local", Source: "inline", Format: "local"}); err != nil {
		t.Fatal(err)
	}
	got := scheduleRequest(t, local, http.MethodGet, "", "", 200)
	if got.Eligible {
		t.Fatal("inline source considered refreshable")
	}
	scheduleRequest(t, local, http.MethodPut, `{"enabled":true,"interval_seconds":300}`, "0", 409)
}

func TestProviderSchedulerDoesNotAdvertiseStageBeforeLifecycleCommit(t *testing.T) {
	s, mem := scheduleServer(t, func(context.Context, domain.Provider) ([]byte, error) {
		return []byte("socks5://edge.example:1080#edge"), nil
	})
	cfg := enableSchedule(t, s)
	s.Services.persistence.documents = &scheduleFailDocuments{DocumentStore: mem, failKey: lifecycleDocumentKey}
	if err := s.runProviderSchedules(context.Background(), *cfg.NextDueAt); err == nil {
		t.Fatal("ignored lifecycle commit failure")
	}
	operations, err := s.Services.Journal.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 0 {
		t.Fatalf("uncommitted revision advertised by durable operation: %+v", operations)
	}
	restored := NewServer(mem, nil)
	if err := restored.Services.Load(context.Background(), mem, lifecycleTestVault(t, 7)); err != nil {
		t.Fatal(err)
	}
	if restored.Services.Providers.Status("scheduled-provider").Staged != 0 {
		t.Fatal("failed stage commit restored unexpectedly")
	}
	got := scheduleRequest(t, restored, http.MethodGet, "", "", 200)
	if got.Running || !strings.Contains(got.LastError, "interrupted") || got.LastOperationID != "" {
		t.Fatalf("unsafe recovery after failed stage commit: %+v", got)
	}
}
