// Package telemetry exposes controller-local Prometheus metrics. Its labels
// are restricted to registered route templates, HTTP methods/status classes,
// and the fixed operation lifecycle. It never accepts object identities or
// traffic observations as labels.
package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var latencyBounds = [...]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// OperationCounts contains persisted controller records, not claims that a
// gateway or firewall currently matches those records.
type OperationCounts struct {
	Draft, Validated, Staged, Applying, Verifying            uint64
	Applied, PartiallyApplied, Failed, OutcomeUnknown, Other uint64
}

// Snapshot reads local durable state. Implementations must honor cancellation
// and must not contact gateways or firewalls during a scrape.
type Snapshot func(context.Context) (OperationCounts, error)

type requestLabels struct{ method, route, statusClass string }
type observation struct {
	count   uint64
	seconds float64
	buckets [len(latencyBounds)]uint64
}

type Registry struct {
	mu       sync.Mutex
	requests map[requestLabels]observation
	snapshot Snapshot
}

func New(snapshot Snapshot) *Registry {
	return &Registry{requests: make(map[requestLabels]observation), snapshot: snapshot}
}

// Instrument measures completed requests reaching next. Patterns must be
// static ServeMux registrations supplied by the application. Unmatched
// requests use one "unmatched" label; paths, queries and request headers are
// never inspected. Place recovery inside this middleware so panics report
// the status actually returned to the caller.
func (m *Registry) Instrument(next http.Handler, patterns ...string) http.Handler {
	routes := make(map[string]string, len(patterns))
	for _, pattern := range patterns {
		route := pattern
		if _, suffix, ok := strings.Cut(pattern, " "); ok {
			route = suffix
		}
		routes[pattern] = route
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		response := &responseWriter{ResponseWriter: w}
		defer func() {
			route, ok := routes[r.Pattern]
			if !ok {
				route = "unmatched"
			}
			status := response.status
			if status == 0 {
				status = http.StatusOK
			}
			labels := requestLabels{method: normalizedMethod(r.Method), route: route, statusClass: statusClass(status)}
			seconds := time.Since(start).Seconds()
			m.mu.Lock()
			item := m.requests[labels]
			item.count++
			item.seconds += seconds
			for i, bound := range latencyBounds {
				if seconds <= bound {
					item.buckets[i]++
				}
			}
			m.requests[labels] = item
			m.mu.Unlock()
		}()
		next.ServeHTTP(response, r)
	})
}

func normalizedMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}

func statusClass(status int) string {
	if status >= 100 && status < 600 {
		return strconv.Itoa(status/100) + "xx"
	}
	return "other"
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *responseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	if status >= 200 || status == http.StatusSwitchingProtocols {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *responseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
func (w *responseWriter) FlushError() error {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func (w *responseWriter) Flush() { _ = w.FlushError() }

// ServeHTTP renders Prometheus text format 0.0.4. The application owns
// authentication; controller wiring mounts this under its viewer boundary.
func (m *Registry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	m.mu.Lock()
	items := make(map[requestLabels]observation, len(m.requests))
	keys := make([]requestLabels, 0, len(m.requests))
	for key, value := range m.requests {
		keys = append(keys, key)
		items[key] = value
	}
	m.mu.Unlock()
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.route != b.route {
			return a.route < b.route
		}
		if a.method != b.method {
			return a.method < b.method
		}
		return a.statusClass < b.statusClass
	})
	fmt.Fprintln(w, "# HELP egressdeck_controller_http_requests_total Completed requests reaching the controller API handler (after authentication for protected routes).")
	fmt.Fprintln(w, "# TYPE egressdeck_controller_http_requests_total counter")
	for _, key := range keys {
		fmt.Fprintf(w, "egressdeck_controller_http_requests_total{%s} %d\n", labels(key), items[key].count)
	}
	fmt.Fprintln(w, "# HELP egressdeck_controller_http_request_duration_seconds Duration of completed controller API requests.")
	fmt.Fprintln(w, "# TYPE egressdeck_controller_http_request_duration_seconds histogram")
	for _, key := range keys {
		item, label := items[key], labels(key)
		for i, bound := range latencyBounds {
			fmt.Fprintf(w, "egressdeck_controller_http_request_duration_seconds_bucket{%s,le=%q} %d\n", label, strconv.FormatFloat(bound, 'g', -1, 64), item.buckets[i])
		}
		fmt.Fprintf(w, "egressdeck_controller_http_request_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n", label, item.count)
		fmt.Fprintf(w, "egressdeck_controller_http_request_duration_seconds_sum{%s} %s\n", label, strconv.FormatFloat(item.seconds, 'g', -1, 64))
		fmt.Fprintf(w, "egressdeck_controller_http_request_duration_seconds_count{%s} %d\n", label, item.count)
	}
	if m.snapshot == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	counts, err := m.snapshot(ctx)
	fmt.Fprintln(w, "# HELP egressdeck_controller_operation_snapshot_success Whether the local operation journal snapshot could be read.")
	fmt.Fprintln(w, "# TYPE egressdeck_controller_operation_snapshot_success gauge")
	if err != nil {
		fmt.Fprintln(w, "egressdeck_controller_operation_snapshot_success 0")
		return
	}
	fmt.Fprintln(w, "egressdeck_controller_operation_snapshot_success 1")
	fmt.Fprintln(w, "# HELP egressdeck_controller_operations Current persisted controller operation records by state; not live gateway verification.")
	fmt.Fprintln(w, "# TYPE egressdeck_controller_operations gauge")
	for _, state := range []struct {
		name  string
		count uint64
	}{
		{"draft", counts.Draft}, {"validated", counts.Validated}, {"staged", counts.Staged},
		{"applying", counts.Applying}, {"verifying", counts.Verifying}, {"applied", counts.Applied},
		{"partially_applied", counts.PartiallyApplied}, {"failed", counts.Failed},
		{"outcome_unknown", counts.OutcomeUnknown}, {"other", counts.Other},
	} {
		fmt.Fprintf(w, "egressdeck_controller_operations{state=%q} %d\n", state.name, state.count)
	}
}

func labels(key requestLabels) string {
	return fmt.Sprintf("method=%q,route=%q,status_class=%q", key.method, key.route, key.statusClass)
}
