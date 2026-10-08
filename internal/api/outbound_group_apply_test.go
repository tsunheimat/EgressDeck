package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func TestOutboundGroupApplyIdempotencyAndUnknownFence(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	group, err := server.Services.Outbounds.Create(outbounds.Group{ID: "g", Name: "edge", GatewayID: "gw", NodeIDs: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	server.Services.GroupPublisher = func(ctx context.Context, g outbounds.Group) (gateway.Snapshot, error) {
		calls++
		if identity, ok := gateway.MutationIdentityFromContext(ctx); !ok || identity.ID == "" || identity.FenceToken == 0 {
			t.Fatal("publication lacks durable operation correlation")
		}
		return gateway.Snapshot{Generation: 5, Groups: map[string]gateway.OutboundGroup{g.ID: {ID: g.ID, Revision: g.Revision, NodeIDs: g.NodeIDs}}}, nil
	}
	server.Services.GroupReadback = server.Services.GroupPublisher
	request := func(key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/outbound-groups/g/apply", strings.NewReader(`{}`))
		r.Header.Set("If-Match", "1")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	first := request("apply-one")
	if first.Code != http.StatusAccepted {
		t.Fatal(first.Body.String())
	}
	second := request("apply-one")
	if second.Code != http.StatusAccepted || calls != 1 {
		t.Fatalf("replay sent mutation: calls=%d %s", calls, second.Body.String())
	}
	var a, b struct {
		OperationID string `json:"operation_id"`
	}
	_ = json.Unmarshal(first.Body.Bytes(), &a)
	_ = json.Unmarshal(second.Body.Bytes(), &b)
	if a.OperationID == "" || a.OperationID != b.OperationID {
		t.Fatal("idempotency operation changed")
	}
	updated, _ := server.Services.Outbounds.Get(group.ID)
	if updated.AppliedRevision != 1 {
		t.Fatalf("no applied readback: %+v", updated)
	}
	_, err = server.Services.Journal.Create(context.Background(), deployment.Operation{Target: deployment.Target{Kind: "outbound_group", ID: "g"}, Action: "selection", Status: deployment.StatusOutcomeUnknown})
	if err != nil {
		t.Fatal(err)
	}
	blocked := request("apply-two")
	if blocked.Code != http.StatusConflict || calls != 1 {
		t.Fatalf("unresolved target mutated: %d %s", blocked.Code, blocked.Body.String())
	}
}

func TestPendingProviderOperationQuarantinesAffectedGroupEdit(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	provider, err := server.Store.CreateProvider(context.Background(), domain.Provider{ID: "provider", Name: "p", Source: "inline", Format: "local"})
	if err != nil {
		t.Fatal(err)
	}
	revision, _, err := server.Services.Providers.Stage(provider.ID, []byte("socks5://host.example:1080#node"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	group, err := server.Services.Outbounds.Create(outbounds.Group{ID: "g", Name: "edge", GatewayID: "gw", NodeIDs: []string{revision.Nodes[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.Services.Journal.Create(context.Background(), deployment.Operation{Target: deployment.Target{Kind: "provider", ID: provider.ID}, Action: "publish", Status: deployment.StatusOutcomeUnknown})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/outbound-groups/g", strings.NewReader(`{"name":"changed","gateway_id":"gw","node_ids":["`+revision.Nodes[0].ID+`"]}`))
	request.Header.Set("If-Match", "1")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "outcome_unknown") {
		t.Fatalf("affected edit was accepted: %d %s", response.Code, response.Body.String())
	}
	current, _ := server.Services.Outbounds.Get(group.ID)
	if current.Revision != group.Revision || current.Name != group.Name {
		t.Fatal("quarantined edit changed desired group")
	}
}

func TestUnknownGroupApplyReplaysOriginalOperationWithoutSending(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	_, err := server.Services.Outbounds.Create(outbounds.Group{ID: "g", Name: "edge", GatewayID: "gw", NodeIDs: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	server.Services.GroupPublisher = func(context.Context, outbounds.Group) (gateway.Snapshot, error) {
		calls++
		return gateway.Snapshot{}, gateway.ErrOutcomeUnknown
	}
	server.Services.GroupReadback = server.Services.GroupPublisher
	request := func(key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/outbound-groups/g/apply", strings.NewReader(`{}`))
		r.Header.Set("If-Match", "1")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	a, b := request("same"), request("same")
	var first, second struct {
		OperationID string `json:"operation_id"`
		Status      string `json:"status"`
	}
	_ = json.Unmarshal(a.Body.Bytes(), &first)
	_ = json.Unmarshal(b.Body.Bytes(), &second)
	if a.Code != 202 || b.Code != 202 || first.OperationID == "" || first != second || first.Status != "outcome_unknown" || calls != 1 {
		t.Fatalf("unknown retry lost identity: %d %s / %d %s calls=%d", a.Code, a.Body.String(), b.Code, b.Body.String(), calls)
	}
	if c := request("new"); c.Code != 409 || calls != 1 {
		t.Fatalf("new key escaped unresolved target: %d %s", c.Code, c.Body.String())
	}
}
