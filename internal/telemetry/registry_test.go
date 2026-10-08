package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func scrape(t *testing.T, registry *Registry) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	registry.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil))
	if recorder.Code != 200 || recorder.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("invalid exposition response: status=%d headers=%v", recorder.Code, recorder.Header())
	}
	return recorder.Body.String()
}

func metricValue(t *testing.T, body, name string) float64 {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name+" ") {
			value, err := strconv.ParseFloat(strings.TrimPrefix(line, name+" "), 64)
			if err != nil {
				t.Fatal(err)
			}
			return value
		}
	}
	t.Fatalf("missing metric %s in %s", name, body)
	return 0
}

func TestRouteTemplatesAggregateAndOmitRequestSecrets(t *testing.T) {
	registry := New(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/providers/{id}", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	handler := registry.Instrument(mux, "GET /api/v1/providers/{id}")
	for i := 0; i < 100; i++ {
		r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("https://private-domain.example/api/v1/providers/private-id-%d?token=private-query", i), nil)
		r.RemoteAddr = "10.99.88.77:30000"
		r.Header.Set("Authorization", "Bearer private-credential")
		r.Header.Set("X-Auth-Request-User", "private-person")
		handler.ServeHTTP(httptest.NewRecorder(), r)
	}
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest(fmt.Sprintf("SECRET%d", i), fmt.Sprintf("/private-path-%d", i), nil)
		handler.ServeHTTP(httptest.NewRecorder(), r)
	}
	body := scrape(t, registry)
	for _, private := range []string{"private-", "10.99.88.77", "SECRET", "token="} {
		if strings.Contains(body, private) {
			t.Fatalf("exposition exposed %q: %s", private, body)
		}
	}
	if got := metricValue(t, body, `egressdeck_controller_http_requests_total{method="GET",route="/api/v1/providers/{id}",status_class="4xx"}`); got != 100 {
		t.Fatalf("template counter=%g", got)
	}
	if got := metricValue(t, body, `egressdeck_controller_http_requests_total{method="OTHER",route="unmatched",status_class="4xx"}`); got != 20 {
		t.Fatalf("unmatched counter=%g", got)
	}
	if len(registry.requests) != 2 {
		t.Fatalf("unbounded request cardinality: %d", len(registry.requests))
	}
}

func TestConcurrentRequestsAndScrapesPreserveHistogram(t *testing.T) {
	registry := New(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/devices/{id}", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	handler := registry.Instrument(mux, "/api/v1/devices/{id}")
	var group sync.WaitGroup
	for worker := 0; worker < 20; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for i := 0; i < 25; i++ {
				handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", fmt.Sprintf("/api/v1/devices/%d-%d", worker, i), nil))
				registry.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/metrics", nil))
			}
		}(worker)
	}
	group.Wait()
	body := scrape(t, registry)
	labels := `method="GET",route="/api/v1/devices/{id}",status_class="2xx"`
	if got := metricValue(t, body, "egressdeck_controller_http_requests_total{"+labels+"}"); got != 500 {
		t.Fatalf("lost requests: %g", got)
	}
	if got := metricValue(t, body, "egressdeck_controller_http_request_duration_seconds_count{"+labels+"}"); got != 500 {
		t.Fatalf("histogram count=%g", got)
	}
	if got := metricValue(t, body, "egressdeck_controller_http_request_duration_seconds_sum{"+labels+"}"); got < 0 {
		t.Fatalf("negative histogram sum=%g", got)
	}
	previous := 0.0
	for _, bound := range append(append([]float64(nil), latencyBounds[:]...), 1e100) {
		label := strconv.FormatFloat(bound, 'g', -1, 64)
		if bound == 1e100 {
			label = "+Inf"
		}
		count := metricValue(t, body, "egressdeck_controller_http_request_duration_seconds_bucket{"+labels+`,le="`+label+`"}`)
		if count < previous || count > 500 {
			t.Fatalf("invalid cumulative bucket %s=%g, previous=%g", label, count, previous)
		}
		previous = count
	}
	if previous != 500 {
		t.Fatalf("infinite bucket=%g", previous)
	}
}

func TestOperationSnapshotFailureDoesNotExposeErrorOrFalseZeros(t *testing.T) {
	registry := New(func(ctx context.Context) (OperationCounts, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("snapshot missing timeout")
		}
		return OperationCounts{Applied: 7}, errors.New("postgres://admin:secret@private-host/database")
	})
	body := scrape(t, registry)
	if metricValue(t, body, "egressdeck_controller_operation_snapshot_success") != 0 {
		t.Fatal("failed snapshot reported success")
	}
	for _, forbidden := range []string{"egressdeck_controller_operations{", "secret", "private-host", "postgres://"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("failed snapshot exposed %q", forbidden)
		}
	}
}

func TestOperationSnapshotPublishesFixedStates(t *testing.T) {
	registry := New(func(context.Context) (OperationCounts, error) {
		return OperationCounts{Applied: 3, Failed: 2, Other: 1}, nil
	})
	body := scrape(t, registry)
	for _, tc := range []struct {
		state string
		count float64
	}{{"draft", 0}, {"applied", 3}, {"failed", 2}, {"other", 1}} {
		if got := metricValue(t, body, `egressdeck_controller_operations{state="`+tc.state+`"}`); got != tc.count {
			t.Fatalf("state=%s count=%g", tc.state, got)
		}
	}
	if metricValue(t, body, "egressdeck_controller_operation_snapshot_success") != 1 {
		t.Fatal("valid snapshot reported failure")
	}
}

func TestMetricsHeadAndMethodHandlingAvoidSnapshot(t *testing.T) {
	called := false
	registry := New(func(context.Context) (OperationCounts, error) { called = true; return OperationCounts{}, nil })
	for _, method := range []string{http.MethodHead, http.MethodPost} {
		rec := httptest.NewRecorder()
		registry.ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/metrics", nil))
		if method == http.MethodHead && (rec.Code != 200 || rec.Body.Len() != 0) {
			t.Fatalf("HEAD response=%d %s", rec.Code, rec.Body.String())
		}
		if method == http.MethodPost && (rec.Code != 405 || rec.Header().Get("Allow") != "GET, HEAD") {
			t.Fatalf("POST response=%d headers=%v", rec.Code, rec.Header())
		}
	}
	if called {
		t.Fatal("method without exposition invoked snapshot")
	}
}

func TestResponseWriterPreservesStatusAndFlush(t *testing.T) {
	registry := New(nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusInternalServerError) // An emitted 200 is final.
		_, _ = w.Write([]byte("event\n"))
	})
	rec := httptest.NewRecorder()
	registry.Instrument(mux, "/stream").ServeHTTP(rec, httptest.NewRequest("GET", "/stream", nil))
	if rec.Code != 200 || !rec.Flushed || rec.Body.String() != "event\n" {
		t.Fatalf("stream changed: code=%d flushed=%v body=%s", rec.Code, rec.Flushed, rec.Body.String())
	}
	if metricValue(t, scrape(t, registry), `egressdeck_controller_http_requests_total{method="GET",route="/stream",status_class="2xx"}`) != 1 {
		t.Fatal("wrong emitted status")
	}
}
