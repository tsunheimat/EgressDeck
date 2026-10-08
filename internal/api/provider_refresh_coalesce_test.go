package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/auth"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

type refreshHTTPResult struct {
	status    int
	body      []byte
	requestID string
	err       error
}

func refreshHTTP(ctx context.Context, endpoint, actor string) <-chan refreshHTTPResult {
	result := make(chan refreshHTTPResult, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/v1/providers/scheduled-provider/refresh", strings.NewReader(`{}`))
		req.Header.Set("X-Test-Actor", actor)
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			result <- refreshHTTPResult{err: err}
			return
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(response.Body)
		result <- refreshHTTPResult{response.StatusCode, raw, response.Header.Get("X-Request-ID"), err}
	}()
	return result
}
func waitRefreshState(t *testing.T, s *Server, wantCalls, wantWaiters int) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		s.Services.refreshFlights.mu.Lock()
		calls, waiters := len(s.Services.refreshFlights.calls), 0
		for _, call := range s.Services.refreshFlights.calls {
			waiters += call.waiters
		}
		s.Services.refreshFlights.mu.Unlock()
		if calls == wantCalls && waiters == wantWaiters {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("refresh flight state calls=%d waiters=%d want=%d/%d", calls, waiters, wantCalls, wantWaiters)
		case <-ticker.C:
		}
	}
}
func readRefreshResult(t *testing.T, result <-chan refreshHTTPResult) refreshHTTPResult {
	t.Helper()
	select {
	case value := <-result:
		if value.err != nil || value.status != 202 {
			t.Fatalf("refresh response=%+v body=%s", value, value.body)
		}
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("refresh HTTP response timed out")
		return refreshHTTPResult{}
	}
}

func TestConcurrentHTTPRefreshesShareOperationAndPreserveRequestIDs(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var fetches atomic.Int64
	s, _ := scheduleServer(t, func(ctx context.Context, _ domain.Provider) ([]byte, error) {
		if fetches.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return []byte("socks5://edge.example:1080#edge"), nil
	})
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	first := refreshHTTP(context.Background(), server.URL, "")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("leader never fetched")
	}
	second := refreshHTTP(context.Background(), server.URL, "")
	waitRefreshState(t, s, 1, 1)
	close(release)
	a, b := readRefreshResult(t, first), readRefreshResult(t, second)
	if string(a.body) != string(b.body) || a.requestID == "" || b.requestID == "" || a.requestID == b.requestID {
		t.Fatalf("coalesced response/request identities incorrect: first=%+v second=%+v", a, b)
	}
	if fetches.Load() != 1 {
		t.Fatalf("overlapping identical HTTP requests fetched %d times", fetches.Load())
	}
	var decoded map[string]any
	if err := json.Unmarshal(a.body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["operation_id"] == nil {
		t.Fatal("coalesced response lost durable operation")
	}
	readRefreshResult(t, refreshHTTP(context.Background(), server.URL, ""))
	if fetches.Load() != 2 {
		t.Fatal("later intentional refresh was suppressed")
	}
}

func TestCancelledHTTPRefreshJoinerDoesNotCancelLeader(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var fetches atomic.Int64
	s, _ := scheduleServer(t, func(ctx context.Context, _ domain.Provider) ([]byte, error) {
		fetches.Add(1)
		close(entered)
		select {
		case <-release:
			return []byte("socks5://edge.example:1080#edge"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	first := refreshHTTP(context.Background(), server.URL, "")
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	second := refreshHTTP(ctx, server.URL, "")
	waitRefreshState(t, s, 1, 1)
	cancel()
	select {
	case result := <-second:
		if result.err == nil {
			t.Fatalf("joiner cancellation=%+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("joiner cancellation blocked")
	}
	waitRefreshState(t, s, 1, 0)
	close(release)
	readRefreshResult(t, first)
	if fetches.Load() != 1 {
		t.Fatalf("cancelled joiner affected leader fetches=%d", fetches.Load())
	}
}

func TestHTTPRefreshCoalescingSeparatesActorsAndConfigRevisions(t *testing.T) {
	for _, separation := range []string{"actor", "provider_revision"} {
		t.Run(separation, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var fetches atomic.Int64
			s, mem := scheduleServer(t, func(ctx context.Context, _ domain.Provider) ([]byte, error) {
				if fetches.Add(1) == 1 {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return []byte("socks5://edge.example:1080#edge"), nil
			})
			handler := s.Handler()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.ServeHTTP(w, r.WithContext(auth.ContextWithSession(r.Context(), auth.Session{Subject: r.Header.Get("X-Test-Actor")})))
			}))
			defer server.Close()
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			first := refreshHTTP(context.Background(), server.URL, "actor-one")
			<-entered
			secondActor := "actor-one"
			if separation == "actor" {
				secondActor = "actor-two"
			} else {
				// Simulate the inventory revision observed before a queued HTTP mutation
				// acquires the write lock. The admission key must bind the revision it read.
				provider, err := mem.GetProvider(context.Background(), "scheduled-provider")
				if err != nil {
					t.Fatal(err)
				}
				provider.Name = "updated settings"
				if _, err := mem.UpdateProvider(context.Background(), provider, provider.Revision); err != nil {
					t.Fatal(err)
				}
			}
			second := refreshHTTP(context.Background(), server.URL, secondActor)
			waitRefreshState(t, s, 2, 0)
			close(release)
			a, b := readRefreshResult(t, first), readRefreshResult(t, second)
			if fetches.Load() != 2 || string(a.body) == string(b.body) {
				t.Fatalf("distinct %s refreshes joined: fetches=%d", separation, fetches.Load())
			}
		})
	}
}
