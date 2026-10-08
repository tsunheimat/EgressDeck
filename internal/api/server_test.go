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
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func TestDeviceAPIRevisionAndAddressValidation(t *testing.T) {
	s := NewServer(store.NewMemoryStore(), nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	response, err := http.Post(ts.URL+"/api/v1/devices", "application/json", strings.NewReader(`{"name":"builder","addresses":[{"address":"192.0.2.20"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d", response.StatusCode)
	}
	var created struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	get, err := http.Get(ts.URL + "/api/v1/devices/" + created.ID)
	if err != nil {
		t.Fatal(err)
	}
	get.Body.Close()
	if get.StatusCode != http.StatusOK {
		t.Fatalf("get status=%d", get.StatusCode)
	}
	request, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/devices/"+created.ID, strings.NewReader(`{"name":"builder-2"}`))
	request.Header.Set("If-Match", "999")
	conflict, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	conflict.Body.Close()
	if conflict.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("conflict status=%d", conflict.StatusCode)
	}
}

func TestHealthIsPublic(t *testing.T) {
	s := NewServer(store.NewMemoryStore(), nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestDeviceAPIRejectsCallerDerivedStateAndManagedDeletion(t *testing.T) {
	mem := store.NewMemoryStore()
	server := NewServer(mem, nil)
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	postJSON(t, ts.URL+"/api/v1/devices", `{"name":"spoof","enrollment_state":"enrolled"}`, http.StatusUnprocessableEntity)
	postJSON(t, ts.URL+"/api/v1/devices", `{"name":"spoof","addresses":[{"address":"192.0.2.1","verified_at":"2026-10-08T00:00:00Z"}]}`, http.StatusUnprocessableEntity)
	verified := time.Now().UTC()
	managed, err := mem.CreateDevice(context.Background(), domain.Device{Name: "managed", EnrollmentState: domain.EnrollmentEnrolled, Addresses: []domain.DeviceAddress{{Address: "192.0.2.2", VerifiedAt: &verified}}})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/devices/"+managed.ID, nil)
	req.Header.Set("If-Match", "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("delete status=%d", resp.StatusCode)
	}
	if _, err := mem.GetDevice(context.Background(), managed.ID); err != nil {
		t.Fatalf("managed device was deleted: %v", err)
	}
}
