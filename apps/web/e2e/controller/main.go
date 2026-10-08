// Command controller is a loopback-only browser-test fixture. It uses the real
// controller handlers, parser, state services, sessions, authorization and CSRF.
// Only external provider and gateway operations are deterministic test adapters.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/auth"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

// These keys are public test fixtures. This command never listens off loopback.
const identitySecret = "egressdeck-e2e-identity-secret-public-fixture"

func main() {
	logger := log.New(os.Stdout, "browser-fixture ", log.LstdFlags)
	s := api.NewServer(store.NewMemoryStore(), logger)
	s.Services.Providers = providers.NewRegistry(providers.DefaultLimits(), func(_ context.Context, p domain.Provider) ([]byte, error) {
		if strings.Contains(p.Source, "fetch-failure") {
			return nil, errors.New("fixture provider fetch failed")
		}
		return []byte("socks5://fixture:password@edge-a.example:1080#Fixture%20edge%20A\nsocks5://fixture:password@edge-b.example:1080#Fixture%20edge%20B\n"), nil
	})
	s.Services.ProviderStageEnabled = true
	var publicationMutex sync.Mutex
	published := map[string]int64{}
	s.Services.ProviderPublisher = func(_ context.Context, p domain.Provider, revision providers.Revision) error {
		if strings.Contains(p.Name, "publication-failure") {
			return errors.New("fixture gateway publication failed")
		}
		publicationMutex.Lock()
		published[p.ID] = revision.Number
		publicationMutex.Unlock()
		return nil
	}
	s.Services.ProviderReadback = func(_ context.Context, p domain.Provider) (int64, error) {
		publicationMutex.Lock()
		defer publicationMutex.Unlock()
		return published[p.ID], nil
	}
	s.Services.SelectionApplier = func(_ context.Context, g outbounds.Group, selection outbounds.Selection) (outbounds.Selection, error) {
		if _, err := s.Services.Outbounds.MarkApplied(g.ID, selection.Scope, selection.DesiredNodeID, 1); err != nil {
			return outbounds.Selection{}, err
		}
		return s.Services.Outbounds.Observe(g.ID, selection.Scope, selection.DesiredNodeID, 1)
	}
	if _, err := s.Store.CreateGateway(context.Background(), domain.Gateway{ID: "fixture-gateway", Name: "Fixture gateway", Endpoint: "https://fixture-gateway.invalid", Adapter: "test"}); err != nil {
		logger.Fatal(err)
	}
	seedPolicy(s.Handler(), logger)

	sessions := auth.NewSessionManager([]byte("egressdeck-e2e-session-secret-public-fixture"), auth.WithSecureCookies(false), auth.WithIdentityHeaderSecret([]byte(identitySecret)))
	middleware, authHTTP := auth.NewMiddleware(sessions), auth.NewHTTP(sessions)
	apiHandler := s.Handler()
	viewer := middleware.Require(auth.RoleViewer)(middleware.CSRF(apiHandler))
	operator := middleware.Require(auth.RoleOperator)(middleware.CSRF(apiHandler))
	admin := middleware.Require(auth.RoleAdmin)(middleware.CSRF(apiHandler))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", authHTTP.Login)
	mux.Handle("GET /api/v1/auth/session", middleware.Require(auth.RoleViewer)(http.HandlerFunc(authHTTP.Session)))
	mux.Handle("POST /api/v1/auth/logout", middleware.Require(auth.RoleViewer)(middleware.CSRF(http.HandlerFunc(authHTTP.Logout))))
	mux.HandleFunc("GET /healthz", apiHandler.ServeHTTP)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch auth.RequiredRole(r) {
		case auth.RoleViewer:
			viewer.ServeHTTP(w, r)
		case auth.RoleOperator:
			operator.ServeHTTP(w, r)
		default:
			admin.ServeHTTP(w, r)
		}
	})
	server := &http.Server{Addr: "127.0.0.1:18080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Printf("listening on %s; external adapters are test fixtures", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal(err)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func seedPolicy(handler http.Handler, logger *log.Logger) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(`{"id":"fixture-policy","name":"Fixture direct policy","default_action":{"kind":"direct"},"unknown_domain_action":{"kind":"direct"},"proxy_failure_action":{"kind":"block"}}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		logger.Fatalf("seed policy: status=%d body=%s", response.Code, response.Body.String())
	}
}
