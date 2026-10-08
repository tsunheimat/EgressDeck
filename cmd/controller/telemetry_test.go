package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func telemetryController(t *testing.T, server *api.Server) http.Handler {
	t.Helper()
	configureTelemetry(server)
	handler, err := newControllerHTTP(context.Background(), server.Handler(), httpConfig{
		AuthMode:             "header",
		SessionSecret:        []byte(controllerTestSecret),
		IdentityHeaderSecret: []byte(controllerTestSecret),
		StaticDir:            staticFixture(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func telemetryRequest(t *testing.T, handler http.Handler, cookies []*http.Cookie, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func requireMetricLine(t *testing.T, body, line string) {
	t.Helper()
	if !strings.Contains("\n"+body, "\n"+line+"\n") {
		t.Fatalf("metric line %q missing from:\n%s", line, body)
	}
}

func TestControllerTelemetryRequiresViewerSession(t *testing.T) {
	handler := telemetryController(t, api.NewServer(store.NewMemoryStore(), nil))
	rec := telemetryRequest(t, handler, nil, "/api/v1/metrics")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "authentication required") || strings.Contains(rec.Body.String(), "egressdeck_controller_") {
		t.Fatalf("unauthenticated scrape status=%d body=%s", rec.Code, rec.Body.String())
	}
	cookies := loginController(t, handler, "viewer")
	rec = telemetryRequest(t, handler, cookies, "/api/v1/metrics")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("viewer scrape status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	requireMetricLine(t, rec.Body.String(), "egressdeck_controller_operation_snapshot_success 1")
	if strings.Contains(rec.Body.String(), "status_class=\"4xx\"") {
		t.Fatalf("authentication rejection was counted as an authenticated API request:\n%s", rec.Body.String())
	}
	// The scrape itself becomes a completed request only after this response.
	rec = telemetryRequest(t, handler, cookies, "/api/v1/metrics")
	requireMetricLine(t, rec.Body.String(), `egressdeck_controller_http_requests_total{method="GET",route="/api/v1/metrics",status_class="2xx"} 1`)
}

func TestControllerTelemetryAggregatesTemplatesWithoutRequestSecrets(t *testing.T) {
	handler := telemetryController(t, api.NewServer(store.NewMemoryStore(), nil))
	cookies := loginController(t, handler, "viewer")
	for _, target := range []string{
		"http://credential-user:credential-pass@controller.example/api/v1/devices/private-device-alpha?token=query-secret-alpha",
		"/api/v1/devices/private-device-beta?source=https%3A%2F%2Fprovider.example%2Fsubscription-secret-beta",
		"/api/v1/private-path-alpha?token=query-secret-gamma",
		"/api/v1/private-path-beta?token=query-secret-delta",
	} {
		rec := telemetryRequest(t, handler, cookies, target)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("fixture request %q status=%d body=%s", target, rec.Code, rec.Body.String())
		}
	}
	rec := telemetryRequest(t, handler, cookies, "/api/v1/metrics")
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, route := range []string{"/api/v1/devices/{id}", "unmatched"} {
		labels := fmt.Sprintf(`method="GET",route=%q,status_class="4xx"`, route)
		requireMetricLine(t, body, "egressdeck_controller_http_requests_total{"+labels+"} 2")
		requireMetricLine(t, body, "egressdeck_controller_http_request_duration_seconds_count{"+labels+"} 2")
		requireMetricLine(t, body, "egressdeck_controller_http_request_duration_seconds_bucket{"+labels+`,le="+Inf"} 2`)
	}
	for _, secret := range []string{
		"credential-user", "credential-pass", "controller.example", "private-device-alpha", "private-device-beta",
		"private-path-alpha", "private-path-beta", "query-secret-", "subscription-secret-beta", "provider.example", "alice",
	} {
		if strings.Contains(body, secret) {
			t.Errorf("request identity or secret %q leaked into metrics", secret)
		}
	}
}

func TestControllerTelemetryCountsJournalStatesWithoutOperationDetails(t *testing.T) {
	journal := deployment.NewMemoryJournal()
	states := []deployment.Status{
		deployment.StatusDraft, deployment.StatusDraft, deployment.StatusValidated,
		deployment.StatusStaged, deployment.StatusApplying, deployment.StatusVerifying,
		deployment.StatusApplied, deployment.StatusPartiallyApplied, deployment.StatusFailed,
		deployment.StatusOutcomeUnknown, deployment.StatusOutcomeUnknown, "private-status-secret",
	}
	var failed deployment.Operation
	for i, state := range states {
		op, err := journal.Create(context.Background(), deployment.Operation{
			ID:             fmt.Sprintf("private-operation-%d", i),
			Target:         deployment.Target{Kind: "private-target-kind", ID: "private-target-id"},
			Action:         "private-action",
			Status:         state,
			IdempotencyKey: fmt.Sprintf("private-idempotency-%d", i),
			RequestHash:    "private-request-hash",
			Error:          "private-error https://user:password@provider.example/private-subscription",
			OriginalError:  "private-original-error",
			Views:          deployment.StateViews{Desired: &deployment.StateRecord{Data: json.RawMessage(`{"token":"private-view-secret"}`)}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if state == deployment.StatusFailed {
			failed = op
		}
	}
	server := api.NewServer(store.NewMemoryStore(), nil)
	server.Services.Journal = journal
	handler := telemetryController(t, server)
	cookies := loginController(t, handler, "viewer")
	rec := telemetryRequest(t, handler, cookies, "/api/v1/metrics")
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	requireMetricLine(t, body, "egressdeck_controller_operation_snapshot_success 1")
	for state, count := range map[string]int{
		"draft": 2, "validated": 1, "staged": 1, "applying": 1, "verifying": 1,
		"applied": 1, "partially_applied": 1, "failed": 1, "outcome_unknown": 2, "other": 1,
	} {
		requireMetricLine(t, body, fmt.Sprintf("egressdeck_controller_operations{state=%q} %d", state, count))
	}
	for _, secret := range []string{"private-", "provider.example", "user:password"} {
		if strings.Contains(body, secret) {
			t.Errorf("operation detail %q leaked into metrics", secret)
		}
	}
	failed.Status = deployment.StatusApplied
	if err := journal.Save(context.Background(), failed); err != nil {
		t.Fatal(err)
	}
	rec = telemetryRequest(t, handler, cookies, "/api/v1/metrics")
	requireMetricLine(t, rec.Body.String(), `egressdeck_controller_operations{state="failed"} 0`)
	requireMetricLine(t, rec.Body.String(), `egressdeck_controller_operations{state="applied"} 2`)
}

type unavailableTelemetryJournal struct{ deployment.Journal }

func (unavailableTelemetryJournal) List(context.Context) ([]deployment.Operation, error) {
	return nil, errors.New("private-journal-error: postgres://private-user:private-password@database/private-db")
}

func TestControllerTelemetryReportsJournalFailureWithoutExposingError(t *testing.T) {
	server := api.NewServer(store.NewMemoryStore(), nil)
	server.Services.Journal = unavailableTelemetryJournal{deployment.NewMemoryJournal()}
	handler := telemetryController(t, server)
	cookies := loginController(t, handler, "viewer")
	rec := telemetryRequest(t, handler, cookies, "/api/v1/metrics")
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status=%d body=%s", rec.Code, rec.Body.String())
	}
	requireMetricLine(t, rec.Body.String(), "egressdeck_controller_operation_snapshot_success 0")
	if strings.Contains(rec.Body.String(), "egressdeck_controller_operations{") || strings.Contains(rec.Body.String(), "private-") {
		t.Fatalf("failed journal snapshot exposed false state counts or error details:\n%s", rec.Body.String())
	}
}
