package api

import (
	"bytes"
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// bufferedResponse keeps a successful management response private until its
// durable lifecycle snapshot is acknowledged. A failed persistence boundary
// returns 503 and freezes writes until restart restores the last committed
// snapshot; it never reports volatile state as durable success.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }
func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}
func (b *bufferedResponse) Write(data []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(data)
}

func (s *Server) durableMutations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		services := s.servicesOrDefault()
		services.mutationMu.Lock()
		defer services.mutationMu.Unlock()
		if services.mutationBlocked {
			writeError(w, http.StatusServiceUnavailable, "persistence_failed", "controller writes are paused after a persistence failure; restore storage and restart")
			return
		}
		buffer := &bufferedResponse{header: make(http.Header)}
		next.ServeHTTP(buffer, r)
		status := buffer.status
		if status == 0 {
			status = http.StatusOK
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/") {
			pattern := r.Pattern
			if pattern == "" {
				pattern = "unmatched"
			}
			services.record(requestActor(r), "management_request", "", r.Method+" "+pattern, strconv.Itoa(status))
		}
		// Failed refreshes still mutate attempt/error metadata. Commit them and their
		// audit result before returning; cancellation does not discard a completed attempt.
		persistCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		if err := services.Persist(persistCtx); err != nil {
			services.mutationBlocked = true
			if s.Logger != nil {
				s.Logger.Printf("lifecycle persistence failed: %v", err)
			}
			writeError(w, http.StatusServiceUnavailable, "persistence_failed", "management state could not be persisted; controller writes are paused")
			return
		}
		for key, values := range buffer.header {
			w.Header()[key] = append([]string(nil), values...)
		}
		w.WriteHeader(status)
		_, _ = w.Write(buffer.body.Bytes())
	})
}
