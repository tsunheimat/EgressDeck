package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func TestDeviceUpdateRetainsVerificationOnlyForSameAddress(t *testing.T) {
	mem := store.NewMemoryStore()
	server := NewServer(mem, nil)
	verified := time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC)
	created, err := mem.CreateDevice(context.Background(), domain.Device{ID: "device", Name: "device", EnrollmentState: domain.EnrollmentEnrolled, Addresses: []domain.DeviceAddress{{Address: "2001:db8::1", VerifiedAt: &verified}, {Address: "192.0.2.4", VerifiedAt: &verified}}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/devices/"+created.ID, strings.NewReader(`{"name":"updated","addresses":[{"address":"2001:0db8:0:0::1"},{"address":"192.0.2.5"}]}`))
	request.Header.Set("If-Match", "1")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var updated domain.Device
	if err := json.Unmarshal(recorder.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.EnrollmentState != domain.EnrollmentEnrolled || updated.Addresses[0].VerifiedAt == nil || !updated.Addresses[0].VerifiedAt.Equal(verified) || updated.Addresses[1].VerifiedAt != nil {
		t.Fatalf("incorrect observations: %+v", updated)
	}
}

func TestOutboundInventoryRejectsUnsupportedIntent(t *testing.T) {
	mem := store.NewMemoryStore()
	server := NewServer(mem, nil)
	ctx := context.Background()
	if _, err := mem.CreateGateway(ctx, domain.Gateway{ID: "gateway", Name: "gateway", Endpoint: "https://gateway.invalid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := mem.CreateProvider(ctx, domain.Provider{ID: "provider", Name: "provider", Source: "inline", Format: "local"}); err != nil {
		t.Fatal(err)
	}
	revision, _, err := server.Services.Providers.Stage("provider", []byte("socks5://proxy.example:1080#edge"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, gateway, mode, node string }{
		{"missing gateway", "missing", "manual", revision.Nodes[0].ID},
		{"automatic unavailable", "gateway", "automatic", revision.Nodes[0].ID},
		{"unknown node", "gateway", "manual", "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, _ := json.Marshal(map[string]any{"name": "outbound", "gateway_id": tc.gateway, "mode": tc.mode, "node_ids": []string{tc.node}})
			request := httptest.NewRequest(http.MethodPost, "/api/v1/outbound-groups", strings.NewReader(string(payload)))
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if len(server.Services.Outbounds.List()) != 0 {
				t.Fatal("invalid group was retained")
			}
		})
	}
}
