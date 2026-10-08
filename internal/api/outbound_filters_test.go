package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func TestOutboundFiltersAreMaterializedFromDisplayedInventory(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemoryStore()
	server := NewServer(mem, nil)
	if _, err := mem.CreateGateway(ctx, domain.Gateway{ID: "gw", Name: "gw", Endpoint: "https://gateway.invalid"}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"first", "second"} {
		if _, err := mem.CreateProvider(ctx, domain.Provider{ID: id, Name: id, Source: "inline", Format: "local"}); err != nil {
			t.Fatal(err)
		}
	}
	active, _, err := server.Services.Providers.Stage("first", []byte("socks5://old.example:1080#old"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Services.Providers.Publish("first", active.Number, 0); err != nil {
		t.Fatal(err)
	}
	staged, _, err := server.Services.Providers.Stage("first", []byte("socks5://new.example:1080#new"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := server.Services.Providers.Stage("second", []byte("socks5://other.example:1080#other"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	request := func(method, path string, group outbounds.Group, expected string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(group)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		if expected != "" {
			req.Header.Set("If-Match", expected)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	group := outbounds.Group{ID: "filtered", Name: "filtered", GatewayID: "gw", NodeIDs: []string{active.Nodes[0].ID, other.Nodes[0].ID}, SourceFilters: &outbounds.SourceFilters{ProviderIDs: []string{"first"}}}
	created := request(http.MethodPost, "/api/v1/outbound-groups", group, "")
	if created.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", created.Code, created.Body.String())
	}
	var result outbounds.Group
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.NodeIDs, []string{staged.Nodes[0].ID}) {
		t.Fatalf("client cache overrode filters: %v", result.NodeIDs)
	}
	group.SourceFilters = &outbounds.SourceFilters{ProviderIDs: []string{"second"}}
	group.NodeIDs = []string{staged.Nodes[0].ID}
	updated := request(http.MethodPut, "/api/v1/outbound-groups/filtered", group, "1")
	if updated.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", updated.Code, updated.Body.String())
	}
	if err := json.Unmarshal(updated.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.NodeIDs, []string{other.Nodes[0].ID}) || result.Revision != 2 {
		t.Fatalf("update filter not materialized: %+v", result)
	}
	for _, filter := range []*outbounds.SourceFilters{{ProviderIDs: []string{"missing"}}, {ProviderIDs: []string{"first"}, ExcludeProviderIDs: []string{"missing"}}, {ProviderIDs: []string{"first"}, IncludeNames: []string{"old"}}} {
		group.SourceFilters = filter
		group.NodeIDs = []string{other.Nodes[0].ID}
		before, _ := server.Services.Outbounds.ExportState()
		rejected := request(http.MethodPut, "/api/v1/outbound-groups/filtered", group, "2")
		if rejected.Code != http.StatusUnprocessableEntity {
			t.Fatalf("filter %+v status=%d body=%s", filter, rejected.Code, rejected.Body.String())
		}
		after, _ := server.Services.Outbounds.ExportState()
		if !bytes.Equal(before, after) {
			t.Fatal("rejected filter changed stored candidates")
		}
	}
}
