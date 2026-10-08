package api

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const maxProviderRefreshFlights = 128
const maxProviderRefreshWaiters = 128

type providerRefreshFlight struct {
	done     chan struct{}
	response *bufferedResponse
	waiters  int
}
type providerRefreshFlights struct {
	mu    sync.Mutex
	calls map[string]*providerRefreshFlight
}

// coalesceProviderRefresh joins only simultaneous unkeyed manual refreshes for
// the same actor and current provider settings. Completed entries are removed
// immediately: a later intentional refresh always makes a fresh attempt.
// It wraps the write lock so duplicate requests can join during network I/O.
func (s *Server) coalesceProviderRefresh(next http.Handler) http.Handler {
	services := s.servicesOrDefault()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != "" {
			next.ServeHTTP(w, r)
			return
		}
		parts := strings.Split(r.URL.EscapedPath(), "/")
		if len(parts) != 6 || parts[1] != "api" || parts[2] != "v1" || parts[3] != "providers" || parts[4] == "" || parts[5] != "refresh" {
			next.ServeHTTP(w, r)
			return
		}
		id, err := url.PathUnescape(parts[4])
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		// Consume this endpoint's ignored, bounded body before waiting. net/http
		// can then watch the connection for a disconnected/cancelled joiner.
		body := http.MaxBytesReader(w, r.Body, 2<<20)
		_, bodyErr := io.Copy(io.Discard, body)
		_ = body.Close()
		if bodyErr != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "refresh request body could not be read within limits")
			return
		}
		provider, err := s.Store.GetProvider(r.Context(), id)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		flights := &services.refreshFlights
		key := privateRequestHash(struct {
			Actor    string
			Provider any
		}{requestActor(r), provider})
		flights.mu.Lock()
		if call := flights.calls[key]; call != nil {
			if call.waiters >= maxProviderRefreshWaiters {
				flights.mu.Unlock()
				writeError(w, 503, "refresh_busy", "too many requests are waiting for this refresh")
				return
			}
			call.waiters++
			flights.mu.Unlock()
			defer func() { flights.mu.Lock(); call.waiters--; flights.mu.Unlock() }()
			select {
			case <-r.Context().Done():
				writeError(w, http.StatusRequestTimeout, "request_cancelled", "refresh wait was cancelled")
			case <-call.done:
				copyRefreshResponse(w, call.response)
			}
			return
		}
		if len(flights.calls) >= maxProviderRefreshFlights {
			flights.mu.Unlock()
			writeError(w, 503, "refresh_busy", "too many provider refreshes are pending")
			return
		}
		if flights.calls == nil {
			flights.calls = make(map[string]*providerRefreshFlight)
		}
		call := &providerRefreshFlight{done: make(chan struct{}), response: &bufferedResponse{header: make(http.Header)}}
		flights.calls[key] = call
		flights.mu.Unlock()
		// Always release joiners, even if an adapter unexpectedly panics. The outer
		// recoverer records the panic and gives the leader its own request identity.
		defer func() {
			recovered := recover()
			if recovered != nil {
				call.response = &bufferedResponse{header: make(http.Header)}
				writeError(call.response, 500, "internal_error", "internal server error")
			}
			flights.mu.Lock()
			delete(flights.calls, key)
			close(call.done)
			flights.mu.Unlock()
			if recovered != nil {
				panic(recovered)
			}
		}()
		next.ServeHTTP(call.response, r)
		copyRefreshResponse(w, call.response)
	})
}

func copyRefreshResponse(w http.ResponseWriter, response *bufferedResponse) {
	for key, values := range response.header {
		if !strings.EqualFold(key, "X-Request-ID") {
			w.Header()[key] = append([]string(nil), values...)
		}
	}
	status := response.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(response.body.Bytes())
}
