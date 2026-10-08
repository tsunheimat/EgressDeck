package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

type collectionTestPage struct {
	Items []json.RawMessage `json:"items"`
	Limit int               `json:"limit"`
	Total int               `json:"total"`
	Next  string            `json:"next_cursor"`
}

func collectionTestGet(t *testing.T, handler http.Handler, path string, status int) collectionTestPage {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != status {
		t.Fatalf("GET %s: status=%d want=%d body=%s", path, rec.Code, status, rec.Body.String())
	}
	var page collectionTestPage
	if status == http.StatusOK && json.Unmarshal(rec.Body.Bytes(), &page) != nil {
		t.Fatalf("invalid page: %s", rec.Body.String())
	}
	return page
}

func TestCollectionPaginationTraversesMoreThanOneDefaultPage(t *testing.T) {
	mem := store.NewMemoryStore()
	for i := 220; i >= 0; i-- {
		_, err := mem.CreateDevice(context.Background(), domain.Device{ID: fmt.Sprintf("device-%03d", i), Name: fmt.Sprintf("Device %d", i)})
		if err != nil {
			t.Fatal(err)
		}
	}
	handler := NewServer(mem, nil).Handler()
	first := collectionTestGet(t, handler, "/api/v1/devices", 200)
	if len(first.Items) != 100 || first.Limit != 100 || first.Total != 221 || first.Next == "" {
		t.Fatalf("bad first page: %+v", first)
	}
	all, cursor := first.Items, first.Next
	for cursor != "" {
		page := collectionTestGet(t, handler, "/api/v1/devices?cursor="+url.QueryEscape(cursor), 200)
		all, cursor = append(all, page.Items...), page.Next
	}
	if len(all) != 221 {
		t.Fatalf("got %d rows", len(all))
	}
	for i, raw := range all {
		var item domain.Device
		_ = json.Unmarshal(raw, &item)
		if item.ID != fmt.Sprintf("device-%03d", i) {
			t.Fatalf("row %d out of order or duplicate: %s", i, item.ID)
		}
	}
}

func TestCollectionPaginationRejectsMutationAndCursorScopeChanges(t *testing.T) {
	mem := store.NewMemoryStore()
	for _, id := range []string{"a", "b", "c"} {
		if _, err := mem.CreateDevice(context.Background(), domain.Device{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewServer(mem, nil).Handler()
	first := collectionTestGet(t, handler, "/api/v1/devices?limit=1", 200)
	cursor := url.QueryEscape(first.Next)
	collectionTestGet(t, handler, "/api/v1/device-groups?limit=1&cursor="+cursor, 400)
	collectionTestGet(t, handler, "/api/v1/devices?limit=2&cursor="+cursor, 400)
	collectionTestGet(t, handler, "/api/v1/devices?limit=1&filter=other&cursor="+cursor, 400)
	collectionTestGet(t, handler, "/api/v1/devices?limit=1&cursor="+cursor+"x", 400)
	if _, err := mem.CreateDevice(context.Background(), domain.Device{ID: "aa", Name: "inserted"}); err != nil {
		t.Fatal(err)
	}
	collectionTestGet(t, handler, "/api/v1/devices?limit=1&cursor="+cursor, 409)
}

func TestCollectionPaginationBoundsAndExpiresBeforeReading(t *testing.T) {
	key := []byte("fixed-key-for-parser-tests-only")
	request, status, _ := parseCollectionRequest(httptest.NewRequest("GET", "/api/v1/devices?limit=1", nil), key)
	if status != 0 {
		t.Fatal(status)
	}
	expired := encodeCollectionCursor(collectionCursor{Version: 1, Route: request.route, Snapshot: strings.Repeat("a", 64), After: strings.Repeat("b", 64), Limit: 1, Issued: time.Now().Add(-collectionCursorTTL - time.Second).Unix()}, key)
	_, status, _ = parseCollectionRequest(httptest.NewRequest("GET", "/api/v1/devices?limit=1&cursor="+expired, nil), key)
	if status != 409 {
		t.Fatalf("expired cursor status %d", status)
	}
	handler := NewServer(store.NewMemoryStore(), nil).Handler()
	for _, query := range []string{"limit=%zz", "limit=0", "limit=501", "limit=-1", "limit=nope", "limit=1&limit=2", "cursor=", "cursor=x", "cursor=x&cursor=y", "cursor=" + strings.Repeat("a", 4097)} {
		collectionTestGet(t, handler, "/api/v1/devices?"+query, 400)
	}
	page := collectionTestGet(t, handler, "/api/v1/devices?limit=500", 200)
	if page.Items == nil || page.Limit != 500 || page.Next != "" {
		t.Fatalf("bad empty page: %+v", page)
	}
}

func TestCollectionPaginationAllowsChangingGatewayObservation(t *testing.T) {
	mem := store.NewMemoryStore()
	for i := 0; i < 101; i++ {
		if _, err := mem.CreateGateway(context.Background(), domain.Gateway{ID: fmt.Sprintf("g-%03d", i), Name: "Gateway", Endpoint: "https://gateway.example", Adapter: "dae"}); err != nil {
			t.Fatal(err)
		}
	}
	server := NewServer(mem, nil)
	var calls atomic.Int64
	server.Services.GatewayObserver = func(context.Context, domain.Gateway) (gateway.Capabilities, gateway.Health, error) {
		n := calls.Add(1)
		return gateway.Capabilities{Version: "test"}, gateway.Health{Status: fmt.Sprintf("observed-%d", n)}, nil
	}
	handler := server.Handler()
	first := collectionTestGet(t, handler, "/api/v1/gateways", 200)
	second := collectionTestGet(t, handler, "/api/v1/gateways?cursor="+url.QueryEscape(first.Next), 200)
	if len(first.Items) != 100 || len(second.Items) != 1 || second.Next != "" {
		t.Fatalf("bad observation pages %d/%d", len(first.Items), len(second.Items))
	}
	if calls.Load() < 202 {
		t.Fatal("gateway observer did not refresh")
	}
}

func TestCollectionPaginationPageByteLimitAndMetadata(t *testing.T) {
	type value struct {
		ID      string `json:"id"`
		Content string `json:"content"`
	}
	values := []value{{ID: "a", Content: strings.Repeat("x", 3<<20)}, {ID: "b", Content: strings.Repeat("y", 3<<20)}}
	paginate := newCollectionPagination()
	handler := paginate("/api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		writeCollection(w, r, values, map[string]any{"adapter_configured": true})
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/devices", nil))
	if rec.Code != 200 || rec.Body.Len() > collectionMaxPageBytes {
		t.Fatalf("status=%d bytes=%d", rec.Code, rec.Body.Len())
	}
	var page collectionTestPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Next == "" || !strings.Contains(rec.Body.String(), `"adapter_configured":true`) {
		t.Fatal("missing byte paging or envelope metadata")
	}
	second := collectionTestGet(t, handler, "/api/v1/devices?cursor="+url.QueryEscape(page.Next), 200)
	if len(second.Items) != 1 || second.Next != "" {
		t.Fatal("second byte page is wrong")
	}
	values = []value{{ID: "huge", Content: strings.Repeat("x", collectionMaxPageBytes)}}
	collectionTestGet(t, handler, "/api/v1/devices", 413)
}

func TestCollectionPaginationNumericRevisionOrderAndDetails(t *testing.T) {
	type revision struct {
		Number int64    `json:"number"`
		Nodes  []string `json:"nodes"`
	}
	values := []revision{{Number: 10, Nodes: []string{"ten"}}, {Number: 2, Nodes: []string{"two"}}, {Number: 1, Nodes: []string{"one"}}}
	paginate := newCollectionPagination()
	handler := paginate("/api/v1/providers/{id}/revisions", func(w http.ResponseWriter, r *http.Request) { writeCollection(w, r, values, nil) })
	first := collectionTestGet(t, handler, "/api/v1/providers/p1/revisions?limit=2", 200)
	var one, two revision
	_ = json.Unmarshal(first.Items[0], &one)
	_ = json.Unmarshal(first.Items[1], &two)
	if one.Number != 1 || two.Number != 2 || len(two.Nodes) != 1 || two.Nodes[0] != "two" {
		t.Fatalf("wrong revisions %+v %+v", one, two)
	}
	collectionTestGet(t, handler, "/api/v1/providers/p2/revisions?limit=2&cursor="+url.QueryEscape(first.Next), 400)
	last := collectionTestGet(t, handler, "/api/v1/providers/p1/revisions?limit=2&cursor="+url.QueryEscape(first.Next), 200)
	var ten revision
	_ = json.Unmarshal(last.Items[0], &ten)
	if ten.Number != 10 {
		t.Fatal(ten.Number)
	}
}

func TestCollectionPaginationRejectsSameIdentityRevisionChange(t *testing.T) {
	type value struct {
		ID       string `json:"id"`
		Revision int    `json:"revision"`
		Name     string `json:"name"`
	}
	values := []value{{ID: "a", Revision: 1, Name: "original"}, {ID: "b", Revision: 1, Name: "B"}}
	paginate := newCollectionPagination()
	handler := paginate("/api/v1/devices", func(w http.ResponseWriter, r *http.Request) { writeCollection(w, r, values, nil) })
	first := collectionTestGet(t, handler, "/api/v1/devices?limit=1", 200)
	values[1].Revision = 2
	values[1].Name = "changed"
	collectionTestGet(t, handler, "/api/v1/devices?limit=1&cursor="+url.QueryEscape(first.Next), 409)
}

func TestCollectionPaginationFirewallObservationDoesNotChangeSnapshot(t *testing.T) {
	values := []FirewallBindingView{{ID: "a", Alias: "one", ObservationStatus: "fresh"}, {ID: "b", Alias: "two", ObservationStatus: "fresh"}}
	paginate := newCollectionPagination()
	handler := paginate("/api/v1/firewall-bindings", func(w http.ResponseWriter, r *http.Request) { writeCollection(w, r, values, nil) })
	first := collectionTestGet(t, handler, "/api/v1/firewall-bindings?limit=1", 200)
	at := time.Now()
	values[1].ObservationStatus = "stale"
	values[1].LastAttemptAt = &at
	path := "/api/v1/firewall-bindings?limit=1&cursor=" + url.QueryEscape(first.Next)
	collectionTestGet(t, handler, path, 200)
	values[1].Alias = "changed"
	collectionTestGet(t, handler, path, 409)
}
