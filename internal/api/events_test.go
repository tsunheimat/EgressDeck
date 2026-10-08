package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

// Decode the public wire contract independently of the implementation structs.
type eventsWireItem struct {
	ID           string    `json:"id"`
	Sequence     uint64    `json:"sequence"`
	Type         string    `json:"type"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Action       string    `json:"action"`
	Status       string    `json:"status"`
	OperationID  string    `json:"operation_id,omitempty"`
	OccurredAt   time.Time `json:"occurred_at"`
}

type eventsWirePage struct {
	Items      []eventsWireItem `json:"items"`
	NextCursor string           `json:"next_cursor"`
	HasMore    bool             `json:"has_more"`
	Resumable  bool             `json:"resumable"`
	Durable    bool             `json:"durable"`
}

func requestEvents(t *testing.T, handler http.Handler, query string) (eventsWirePage, []byte) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events"+query, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET events%s status=%d body=%s", query, recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("event feed may be cached: %v", recorder.Header())
	}
	var page eventsWirePage
	decoder := json.NewDecoder(bytes.NewReader(recorder.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&page); err != nil {
		t.Fatal(err)
	}
	if page.Items == nil || page.NextCursor == "" || !page.Resumable {
		t.Fatalf("response lacks resumable array/cursor contract: %s", recorder.Body.String())
	}
	return page, append([]byte(nil), recorder.Body.Bytes()...)
}

func eventsCursorQuery(cursor string) string { return "?cursor=" + url.QueryEscape(cursor) }

func newEventsOperation(t *testing.T, journal deployment.Journal, id string) deployment.Operation {
	t.Helper()
	op, err := journal.Create(context.Background(), deployment.Operation{
		ID: id, Target: deployment.Target{Kind: "gateway", ID: "gateway-1"}, Action: "apply",
		Status: deployment.StatusDraft, CreatedAt: time.Date(2026, 10, 8, 1, 2, 3, 0, time.UTC),
		IdempotencyKey: "private-idempotency", RequestHash: "private-request-hash",
		Error: "private-operation-error", OriginalError: "private-original-error",
		Steps: []deployment.Step{{Name: "private-step", Message: "private-step-message"}},
		Views: deployment.StateViews{Desired: &deployment.StateRecord{Data: json.RawMessage(`{"password":"private-state-password"}`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func TestEventsEmptyCursorResumesChangesAndDeduplicates(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	handler := server.Handler()
	empty, _ := requestEvents(t, handler, "")
	if len(empty.Items) != 0 || empty.HasMore || empty.Durable {
		t.Fatalf("unexpected empty memory feed: %+v", empty)
	}
	op := newEventsOperation(t, server.Services.Journal, "operation-1")
	server.Services.record("private-actor@example.invalid", "policy", "policy-1", "create", "accepted")
	first, raw := requestEvents(t, handler, eventsCursorQuery(empty.NextCursor))
	if len(first.Items) != 2 || first.HasMore || first.Durable {
		t.Fatalf("new records not delivered after empty cursor: %+v", first)
	}
	operation, audit := first.Items[0], first.Items[1]
	if operation.Type != "operation.changed" || operation.ResourceType != "gateway" || operation.ResourceID != "gateway-1" || operation.OperationID != op.ID || operation.Action != "apply" || operation.Status != "draft" || !operation.OccurredAt.Equal(op.CreatedAt) {
		t.Fatalf("operation projection=%+v", operation)
	}
	if audit.Type != "audit.recorded" || audit.ResourceType != "policy" || audit.ResourceID != "policy-1" || audit.Action != "create" || audit.Status != "accepted" || audit.OperationID != "" || audit.OccurredAt.IsZero() {
		t.Fatalf("audit projection=%+v", audit)
	}
	if operation.Sequence != 1 || audit.Sequence != 2 || operation.ID == audit.ID || first.NextCursor != audit.ID {
		t.Fatalf("unexpected sequence/cursor identity: %+v", first)
	}
	if bytes.Contains(raw, []byte("private-")) {
		t.Fatalf("private source fields leaked through the public projection: %s", raw)
	}
	idle, _ := requestEvents(t, handler, eventsCursorQuery(first.NextCursor))
	if len(idle.Items) != 0 || idle.HasMore || idle.NextCursor != first.NextCursor {
		t.Fatalf("unchanged records duplicated or tail cursor lost: %+v", idle)
	}
	// The source journal permits a new status with the same timestamp. A
	// timestamp-only identity would silently lose this observed transition.
	op.Status = deployment.StatusValidated
	if err := server.Services.Journal.Save(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	changed, _ := requestEvents(t, handler, eventsCursorQuery(first.NextCursor))
	if len(changed.Items) != 1 || changed.Items[0].Status != "validated" || changed.Items[0].OperationID != op.ID || changed.Items[0].Sequence != 3 || !changed.Items[0].OccurredAt.Equal(operation.OccurredAt) {
		t.Fatalf("same-timestamp operation change was lost: %+v", changed)
	}
	if changed.Items[0].ID == operation.ID || changed.NextCursor != changed.Items[0].ID {
		t.Fatalf("changed operation reused its old event identity: %+v", changed)
	}
	replay, _ := requestEvents(t, handler, eventsCursorQuery(empty.NextCursor))
	if len(replay.Items) != 3 || replay.Items[0] != operation || replay.Items[1] != audit || replay.Items[2] != changed.Items[0] {
		t.Fatalf("observed historical transition was replaced by latest source state: %+v", replay)
	}
}

func TestEventsRedactsUntrustedSourceLabelsAndIdentifiers(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	_, err := server.Services.Journal.Create(context.Background(), deployment.Operation{
		ID: "https://private-operation-token@example.invalid/", Action: "private-action-password",
		Target: deployment.Target{Kind: "private-kind-password", ID: "https://private-target-token@example.invalid/"},
		Status: deployment.Status("private-status-password"),
	})
	if err != nil {
		t.Fatal(err)
	}
	server.Services.record("private-actor-password", "private-type-password", "https://private-resource-token@example.invalid/", "private-audit-action", "private-audit-outcome")
	page, raw := requestEvents(t, server.Handler(), "")
	if len(page.Items) != 2 || bytes.Contains(raw, []byte("private-")) || bytes.Contains(raw, []byte("example.invalid")) {
		t.Fatalf("untrusted source metadata leaked through the event projection: %s", raw)
	}
	for _, event := range page.Items {
		if event.ResourceType != "unknown" || event.ResourceID != "redacted" || event.Action != "unknown" || event.Status != "unknown" {
			t.Fatalf("untrusted metadata was not redacted: %+v", event)
		}
		if event.Type == "operation.changed" && event.OperationID != "redacted" {
			t.Fatalf("untrusted operation ID escaped redaction: %+v", event)
		}
	}
}

func TestEventsPaginationLimitsAndCursorValidation(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	handler := server.Handler()
	for i := 0; i < 205; i++ {
		server.Services.record("actor", "device", fmt.Sprintf("device-%03d", i), "create", "accepted")
	}
	first, _ := requestEvents(t, handler, "")
	second, _ := requestEvents(t, handler, eventsCursorQuery(first.NextCursor))
	last, _ := requestEvents(t, handler, eventsCursorQuery(second.NextCursor))
	if len(first.Items) != 100 || len(second.Items) != 100 || len(last.Items) != 5 || !first.HasMore || !second.HasMore || last.HasMore {
		t.Fatalf("default pagination lengths=%d/%d/%d more=%v/%v/%v", len(first.Items), len(second.Items), len(last.Items), first.HasMore, second.HasMore, last.HasMore)
	}
	all := append(append(append([]eventsWireItem{}, first.Items...), second.Items...), last.Items...)
	seen := map[string]bool{}
	for i, event := range all {
		if event.Sequence != uint64(i+1) || seen[event.ID] || event.ID == "" {
			t.Fatalf("pagination repeated or skipped an event: index=%d event=%+v", i, event)
		}
		seen[event.ID] = true
	}
	maximum, _ := requestEvents(t, handler, "?limit=500")
	if !reflect.DeepEqual(maximum.Items, all) || maximum.HasMore || maximum.NextCursor != last.NextCursor {
		t.Fatal("page size changed event order or cursor identity")
	}
	replay, _ := requestEvents(t, handler, eventsCursorQuery(first.NextCursor))
	if !reflect.DeepEqual(replay, second) {
		t.Fatal("retrying a page changed its content")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(last.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 3 || parts[0] != "v1" || parts[2] != "205" {
		t.Fatalf("unexpected cursor version: %q", decoded)
	}
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	for name, query := range map[string]string{
		"zero limit": "?limit=0", "negative limit": "?limit=-1", "over max": "?limit=501", "text limit": "?limit=abc",
		"duplicate limit": "?limit=1&limit=2", "duplicate cursor": eventsCursorQuery(first.NextCursor) + "&cursor=" + first.NextCursor,
		"bad base64": "?cursor=%21%21%21", "wrong version": eventsCursorQuery(encode("v2:" + parts[1] + ":1")),
		"negative sequence": eventsCursorQuery(encode("v1:" + parts[1] + ":-1")), "noncanonical sequence": eventsCursorQuery(encode("v1:" + parts[1] + ":01")),
		"future sequence": eventsCursorQuery(encode("v1:" + parts[1] + ":206")), "overflow sequence": eventsCursorQuery(encode("v1:" + parts[1] + ":18446744073709551616")),
		"too long": eventsCursorQuery(strings.Repeat("a", 300)),
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events"+query, nil))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
	foreign := NewServer(store.NewMemoryStore(), nil)
	other, _ := requestEvents(t, foreign.Handler(), "")
	assertEventsError(t, handler, eventsCursorQuery(other.NextCursor), http.StatusGone, "cursor_stream_changed")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/events", nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != "GET" {
		t.Fatalf("POST events status=%d allow=%q", recorder.Code, recorder.Header().Get("Allow"))
	}
}

func openEventsFileServer(t *testing.T, path, journalPath string, vault *secrets.Vault) *Server {
	t.Helper()
	documents, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := deployment.OpenFileJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(documents, nil)
	server.Services.Journal = journal
	server.Services.Runner = deployment.NewRunner(journal)
	if err := server.Services.Load(context.Background(), documents, vault); err != nil {
		t.Fatal(err)
	}
	return server
}

func TestEventsEncryptedHistoryAndCursorSurviveFileStoreRestart(t *testing.T) {
	dir := t.TempDir()
	path, journalPath := filepath.Join(dir, "controller.json"), filepath.Join(dir, "operations.json")
	vault := lifecycleTestVault(t, 8)
	server := openEventsFileServer(t, path, journalPath, vault)
	handler := server.Handler()
	empty, _ := requestEvents(t, handler, "")
	if !empty.Durable {
		t.Fatal("configured FileStore feed does not report durability")
	}
	// Even a cursor issued before the first event must survive restart.
	server = openEventsFileServer(t, path, journalPath, vault)
	handler = server.Handler()
	afterEmptyRestart, _ := requestEvents(t, handler, eventsCursorQuery(empty.NextCursor))
	if afterEmptyRestart.NextCursor != empty.NextCursor || len(afterEmptyRestart.Items) != 0 {
		t.Fatal("empty stream changed identity across restart")
	}
	op := newEventsOperation(t, server.Services.Journal, "operation-history-private-id")
	first, _ := requestEvents(t, handler, eventsCursorQuery(empty.NextCursor))
	op.Status = deployment.StatusApplied
	if err := server.Services.Journal.Save(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	server.Services.record("private-actor", "provider", "provider-history-private-id", "publish", "applied")
	// An in-memory audit mutation must not enter a feed claiming durability
	// before the lifecycle snapshot acknowledges it.
	beforePersist, _ := requestEvents(t, handler, eventsCursorQuery(first.NextCursor))
	if len(beforePersist.Items) != 1 || beforePersist.Items[0].Type != "operation.changed" {
		t.Fatalf("uncommitted audit escaped its durability boundary: %+v", beforePersist)
	}
	if err := server.Services.Persist(context.Background()); err != nil {
		t.Fatal(err)
	}
	audit, _ := requestEvents(t, handler, eventsCursorQuery(beforePersist.NextCursor))
	if len(audit.Items) != 1 || audit.Items[0].Type != "audit.recorded" {
		t.Fatalf("committed audit missing: %+v", audit)
	}
	before, _ := requestEvents(t, handler, eventsCursorQuery(empty.NextCursor))
	if len(before.Items) != 3 || before.Items[0].Status != "draft" || before.Items[1].Status != "applied" {
		t.Fatalf("operation transition history missing: %+v", before)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{op.ID, "provider-history-private-id", "private-actor", empty.NextCursor, before.NextCursor, "operation.changed", "audit.recorded"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatalf("event/lifecycle plaintext %q leaked into the controller file", private)
		}
	}
	restarted := openEventsFileServer(t, path, journalPath, vault)
	restored, _ := requestEvents(t, restarted.Handler(), eventsCursorQuery(empty.NextCursor))
	if !reflect.DeepEqual(restored, before) {
		t.Fatalf("restart changed history or re-emitted source snapshots: before=%+v after=%+v", before, restored)
	}
	idle, _ := requestEvents(t, restarted.Handler(), eventsCursorQuery(before.NextCursor))
	if len(idle.Items) != 0 || idle.NextCursor != before.NextCursor || !idle.Durable {
		t.Fatalf("restart lost deduplication or tail cursor: %+v", idle)
	}
	op.Status = deployment.StatusPartiallyApplied
	if err := restarted.Services.Journal.Save(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	continued, _ := requestEvents(t, restarted.Handler(), eventsCursorQuery(before.NextCursor))
	if len(continued.Items) != 1 || continued.Items[0].Sequence != 4 || continued.Items[0].Status != "partially_applied" {
		t.Fatalf("restart did not continue the durable sequence: %+v", continued)
	}
}

func TestEventsRetentionExpiresOnlyCursorsBeforeRetainedHistory(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	handler := server.Handler()
	empty, _ := requestEvents(t, handler, "")
	server.Services.record("actor", "device", "device-first", "create", "accepted")
	first, _ := requestEvents(t, handler, eventsCursorQuery(empty.NextCursor))
	for i := 0; i < 5000; i++ {
		server.Services.record("actor", "device", "device-"+strconv.Itoa(i), "create", "accepted")
	}
	page, _ := requestEvents(t, handler, eventsCursorQuery(first.NextCursor)+"&limit=500")
	if len(page.Items) != 500 || page.Items[0].Sequence != 2 {
		t.Fatalf("cursor immediately before retained history should remain usable: %+v", page)
	}
	assertEventsError(t, handler, eventsCursorQuery(empty.NextCursor), http.StatusGone, "cursor_expired")
	count := len(page.Items)
	previous := uint64(1)
	for {
		for _, event := range page.Items {
			if event.Sequence != previous+1 {
				t.Fatalf("retention reindexed/skipped events: previous=%d next=%d", previous, event.Sequence)
			}
			previous = event.Sequence
		}
		if !page.HasMore {
			break
		}
		page, _ = requestEvents(t, handler, eventsCursorQuery(page.NextCursor)+"&limit=500")
		count += len(page.Items)
	}
	if count != 5000 || previous != 5001 {
		t.Fatalf("retained count=%d tail=%d", count, previous)
	}
	idle, _ := requestEvents(t, handler, eventsCursorQuery(page.NextCursor))
	if len(idle.Items) != 0 || idle.NextCursor != page.NextCursor {
		t.Fatal("retention caused dedup markers to re-emit retained source records")
	}
}

func assertEventsError(t *testing.T, handler http.Handler, query string, status int, code string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events"+query, nil))
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	decodeErr := json.Unmarshal(recorder.Body.Bytes(), &envelope)
	if recorder.Code != status || decodeErr != nil || envelope.Error.Code != code {
		t.Fatalf("events error status=%d body=%s; want status=%d code=%s", recorder.Code, recorder.Body.String(), status, code)
	}
	if strings.Contains(recorder.Body.String(), "private-") {
		t.Fatalf("storage error leaked source details: %s", recorder.Body.String())
	}
}

type eventsFailingJournal struct {
	deployment.Journal
	failure error
}

func (j *eventsFailingJournal) List(ctx context.Context) ([]deployment.Operation, error) {
	if j.failure != nil {
		return nil, j.failure
	}
	return j.Journal.List(ctx)
}

type eventsFailingDocuments struct {
	store.DocumentStore
	failLoad, failSave bool
}

func (d *eventsFailingDocuments) LoadDocument(ctx context.Context, key string) (json.RawMessage, error) {
	if d.failLoad {
		return nil, errors.New("private-load-password")
	}
	return d.DocumentStore.LoadDocument(ctx, key)
}

func (d *eventsFailingDocuments) SaveDocument(ctx context.Context, key string, value json.RawMessage) error {
	if d.failSave {
		return errors.New("private-save-password")
	}
	return d.DocumentStore.SaveDocument(ctx, key, value)
}

func TestEventsSourceAndPersistenceFailuresDoNotAcknowledgeLostEvents(t *testing.T) {
	t.Run("journal", func(t *testing.T) {
		server := NewServer(store.NewMemoryStore(), nil)
		journal := &eventsFailingJournal{Journal: server.Services.Journal}
		server.Services.Journal = journal
		server.Services.Runner = deployment.NewRunner(journal)
		handler := server.Handler()
		empty, _ := requestEvents(t, handler, "")
		newEventsOperation(t, journal, "operation-1")
		journal.failure = errors.New("private-journal-password")
		assertEventsError(t, handler, eventsCursorQuery(empty.NextCursor), http.StatusServiceUnavailable, "events_unavailable")
		journal.failure = nil
		recovered, _ := requestEvents(t, handler, eventsCursorQuery(empty.NextCursor))
		if len(recovered.Items) != 1 || recovered.Items[0].Sequence != 1 {
			t.Fatalf("source failure lost/advanced an event: %+v", recovered)
		}
	})
	for _, failure := range []string{"load", "save"} {
		t.Run(failure, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "controller.json")
			underlying, err := store.NewFileStore(path)
			if err != nil {
				t.Fatal(err)
			}
			documents := &eventsFailingDocuments{DocumentStore: underlying}
			server := NewServer(underlying, nil)
			if err := server.Services.Load(context.Background(), documents, lifecycleTestVault(t, 4)); err != nil {
				t.Fatal(err)
			}
			handler := server.Handler()
			empty, _ := requestEvents(t, handler, "")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			newEventsOperation(t, server.Services.Journal, "operation-1")
			documents.failLoad, documents.failSave = failure == "load", failure == "save"
			assertEventsError(t, handler, eventsCursorQuery(empty.NextCursor), http.StatusServiceUnavailable, "events_unavailable")
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("failed projection changed its acknowledged durable document: %v", err)
			}
			documents.failLoad, documents.failSave = false, false
			recovered, _ := requestEvents(t, handler, eventsCursorQuery(empty.NextCursor))
			if len(recovered.Items) != 1 || recovered.Items[0].Sequence != 1 || !recovered.Durable {
				t.Fatalf("failed persistence acknowledged or duplicated an event: %+v", recovered)
			}
		})
	}
	t.Run("save after observed transition", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "controller.json")
		underlying, err := store.NewFileStore(path)
		if err != nil {
			t.Fatal(err)
		}
		documents := &eventsFailingDocuments{DocumentStore: underlying}
		server := NewServer(underlying, nil)
		if err := server.Services.Load(context.Background(), documents, lifecycleTestVault(t, 4)); err != nil {
			t.Fatal(err)
		}
		handler := server.Handler()
		empty, _ := requestEvents(t, handler, "")
		op := newEventsOperation(t, server.Services.Journal, "operation-1")
		first, _ := requestEvents(t, handler, eventsCursorQuery(empty.NextCursor))
		if len(first.Items) != 1 || first.Items[0].Status != "draft" || first.Items[0].Sequence != 1 {
			t.Fatalf("initial operation was not acknowledged: %+v", first)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		op.Status = deployment.StatusValidated
		if err := server.Services.Journal.Save(context.Background(), op); err != nil {
			t.Fatal(err)
		}
		documents.failSave = true
		assertEventsError(t, handler, eventsCursorQuery(first.NextCursor), http.StatusServiceUnavailable, "events_unavailable")
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("failed transition projection changed acknowledged durable history: %v", err)
		}
		documents.failSave = false
		recovered, _ := requestEvents(t, handler, eventsCursorQuery(first.NextCursor))
		if len(recovered.Items) != 1 || recovered.Items[0].Sequence != 2 || recovered.Items[0].Status != "validated" || recovered.Items[0].OperationID != op.ID {
			t.Fatalf("failed transition save advanced deduplication or lost/duplicated the change: %+v", recovered)
		}
		replay, _ := requestEvents(t, handler, eventsCursorQuery(empty.NextCursor))
		if len(replay.Items) != 2 || replay.Items[0] != first.Items[0] || replay.Items[1] != recovered.Items[0] {
			t.Fatalf("failed transition save altered acknowledged history: %+v", replay)
		}
		idle, _ := requestEvents(t, handler, eventsCursorQuery(recovered.NextCursor))
		if len(idle.Items) != 0 || idle.HasMore || idle.NextCursor != recovered.NextCursor {
			t.Fatalf("recovered transition was delivered again: %+v", idle)
		}
	})
}

func TestEventsUnreadableEncryptedStreamDoesNotResetItsCursor(t *testing.T) {
	dir := t.TempDir()
	path, journalPath := filepath.Join(dir, "controller.json"), filepath.Join(dir, "operations.json")
	vault := lifecycleTestVault(t, 3)
	server := openEventsFileServer(t, path, journalPath, vault)
	empty, _ := requestEvents(t, server.Handler(), "")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// No lifecycle snapshot exists yet, so its startup loader cannot detect
	// the wrong key. Reading the existing encrypted event stream must fail.
	wrongKey := openEventsFileServer(t, path, journalPath, lifecycleTestVault(t, 9))
	assertEventsError(t, wrongKey.Handler(), eventsCursorQuery(empty.NextCursor), http.StatusServiceUnavailable, "events_unavailable")
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("unreadable event stream was overwritten: %v", err)
	}
	reopened := openEventsFileServer(t, path, journalPath, vault)
	page, _ := requestEvents(t, reopened.Handler(), eventsCursorQuery(empty.NextCursor))
	if page.NextCursor != empty.NextCursor || len(page.Items) != 0 {
		t.Fatalf("failed decrypt reset the durable stream: %+v", page)
	}
}

func TestEventsConcurrentPollsAssignOneSequencePerObservedChange(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	handler := server.Handler()
	empty, _ := requestEvents(t, handler, "")
	newEventsOperation(t, server.Services.Journal, "operation-1")
	const clients = 12
	responses := make([]*httptest.ResponseRecorder, clients)
	var group sync.WaitGroup
	for i := range responses {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/events"+eventsCursorQuery(empty.NextCursor), nil))
			responses[index] = recorder
		}(i)
	}
	group.Wait()
	first := responses[0]
	for i, response := range responses {
		if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), first.Body.Bytes()) {
			t.Fatalf("concurrent poll %d did not return the same acknowledged event: status=%d body=%s", i, response.Code, response.Body.String())
		}
	}
	page, _ := requestEvents(t, handler, "")
	if len(page.Items) != 1 || page.Items[0].Sequence != 1 {
		t.Fatalf("concurrent polls duplicated an observed change: %+v", page)
	}
}
