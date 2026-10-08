// Package api exposes the explicit controller contract. It deliberately does
// not mimic an upstream dae API: frontend and adapters use this versioned
// management API and capability responses describe what a gateway can do.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
	"github.com/egressdeck/homelab-proxy-controller/internal/telemetry"
)

type Server struct {
	Store       store.Store
	Services    *Services
	Logger      *log.Logger
	Telemetry   *telemetry.Registry
	schedulerMu sync.Mutex
	scheduler   *providerScheduler
}

func NewServer(s store.Store, logger *log.Logger) *Server {
	return &Server{Store: s, Services: NewServices(), Logger: logger, Telemetry: telemetry.New(nil)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	var patterns []string
	paginate := newCollectionPagination()
	handle := func(pattern string, handler http.HandlerFunc) {
		patterns = append(patterns, pattern)
		mux.HandleFunc(pattern, paginate(pattern, handler))
	}
	handle("GET /healthz", s.health)
	handle("GET /readyz", s.ready)
	handle("GET /api/v1/capabilities", s.capabilities)
	handle("/api/v1/overview", s.overview)
	handle("/api/v1/devices", s.devices)
	handle("/api/v1/devices/{id}", s.device)
	handle("/api/v1/device-groups", s.deviceGroups)
	handle("/api/v1/device-groups/{id}", s.deviceGroup)
	handle("/api/v1/providers", s.providers)
	handle("/api/v1/providers/{id}", s.provider)
	handle("/api/v1/gateways", s.gateways)
	handle("/api/v1/gateways/{id}", s.gateway)
	handle("/api/v1/gateways/{id}/capabilities", s.gatewayCapabilities)
	s.registerDiagnostics(handle)
	handle("/api/v1/nodes", s.nodes)
	handle("/api/v1/outbound-groups", s.outboundGroups)
	handle("/api/v1/outbound-groups/{id}", s.outboundGroup)
	handle("/api/v1/outbound-groups/{id}/selection", s.selection)
	handle("/api/v1/providers/{id}/revisions", s.providerRevisions)
	handle("/api/v1/providers/{id}/refresh", s.providerRefresh)
	handle("/api/v1/providers/{id}/schedule", s.providerSchedule)
	handle("/api/v1/providers/{id}/revisions/{revision}/apply", s.providerApply)
	handle("/api/v1/policies", s.policiesCRUD)
	handle("/api/v1/policies/{id}", s.policyCRUD)
	handle("/api/v1/rule-sets", s.ruleSetsCRUD)
	handle("/api/v1/rule-sets/{id}", s.ruleSetCRUD)
	handle("/api/v1/deployments/preview", s.preview)
	handle("/api/v1/deployments/plan", s.plan)
	handle("/api/v1/deployments/plans/{id}", s.getPlan)
	handle("/api/v1/deployments/enrollment", s.enroll)
	handle("/api/v1/policies/explain", s.explain)
	handle("/api/v1/operations", s.operations)
	handle("/api/v1/operations/{id}", s.operation)
	handle("/api/v1/audit-events", s.auditEvents)
	handle("/api/v1/events", s.eventsFeed)
	handle("/api/v1/firewall-bindings", s.firewallBindings)
	handle("/api/v1/firewall-bindings/{id}", s.firewallBinding)
	handle("/api/v1/firewall-bindings/{id}/readback", s.firewallReadback)
	handle("/api/v1/providers/{id}/stage", s.providerStage)
	if s.Telemetry != nil {
		handle("GET /api/v1/metrics", s.Telemetry.ServeHTTP)
	}
	var handler http.Handler = requestID(recoverer(s.coalesceProviderRefresh(s.durableMutations(mux)), s.Logger))
	if s.Telemetry != nil {
		handler = s.Telemetry.Instrument(handler, patterns...)
	}
	return handler
}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if w.Header().Get("X-Request-ID") == "" {
			w.Header().Set("X-Request-ID", domain.NewID())
		}
		next.ServeHTTP(w, r)
	})
}
func recoverer(next http.Handler, logger *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if logger != nil {
					logger.Printf("panic request=%s: %v", r.URL.Path, v)
				}
				writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "store is unavailable")
		return
	}
	if checker, ok := s.Store.(store.HealthChecker); ok {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := checker.CheckHealth(ctx); err != nil {
			writeError(w, http.StatusServiceUnavailable, "not_ready", "controller storage is unavailable")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
func (s *Server) capabilities(w http.ResponseWriter, _ *http.Request) {
	services := s.servicesOrDefault()
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "v1", "capabilities": map[string]bool{
		"inventory.read":             true,
		"provider.stage":             services.ProviderStageEnabled,
		"provider.publish_hot":       services.ProviderPublisher != nil && services.ProviderReadback != nil,
		"selection.set_runtime":      services.SelectionApplier != nil,
		"selection.persist_restart":  services.SelectionPersistence,
		"policy.validate":            true,
		"policy.apply_generation":    services.PolicyApplyEnabled,
		"probe.node":                 services.GatewayDiagnostics != nil,
		"probe.group":                services.GatewayDiagnostics != nil,
		"connections.observe":        services.GatewayDiagnostics != nil,
		"connections.close_filtered": false,
		"traffic.proxy_counters":     services.GatewayDiagnostics != nil,
		"traffic.direct_counters":    services.GatewayDiagnostics != nil,
		"events.resume":              true,
	}})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		out, err := s.Store.ListDevices(r.Context())
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeCollection(w, r, out, nil)
		return
	}
	if r.Method == http.MethodPost {
		var d domain.Device
		if !decodeJSON(w, r, &d) {
			return
		}
		if !s.validateDeviceIntent(w, d) {
			return
		}
		out, err := s.Store.CreateDevice(r.Context(), d)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
		return
	}
	if r.Method != http.MethodPatch && r.Method != http.MethodDelete {
		methodNotAllowed(w, "GET, POST, PATCH, DELETE")
		return
	}
	id := pathID(r.URL.Path, "/api/v1/devices/")
	if id == "" {
		methodNotAllowed(w, "GET, POST")
		return
	}
	expected, ok := expectedRevision(r)
	if !ok {
		writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match or revision query is required")
		return
	}
	if r.Method == http.MethodDelete {
		old, err := s.Store.GetDevice(r.Context(), id)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if old.EnrollmentState != domain.EnrollmentUnenrolled {
			writeError(w, http.StatusConflict, "disposition_required", "managed device deletion requires a retain, block, or bypass deployment disposition")
			return
		}
		if err := s.Store.DeleteDevice(r.Context(), id, expected); err != nil {
			writeStoreError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var d domain.Device
	if !decodeJSON(w, r, &d) {
		return
	}
	if !s.validateDeviceIntent(w, d) {
		return
	}
	d.ID = id
	if old, err := s.Store.GetDevice(r.Context(), id); err == nil {
		preserveDeviceObservations(old, &d)
	}
	out, err := s.Store.UpdateDevice(r.Context(), d, expected)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) device(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if r.Method == http.MethodGet {
		out, err := s.Store.GetDevice(r.Context(), id)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	expected, ok := expectedRevision(r)
	if !ok {
		writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match or revision query is required")
		return
	}
	if r.Method == http.MethodDelete {
		old, err := s.Store.GetDevice(r.Context(), id)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if old.EnrollmentState != domain.EnrollmentUnenrolled {
			writeError(w, http.StatusConflict, "disposition_required", "managed device deletion requires a retain, block, or bypass deployment disposition")
			return
		}
		if err := s.Store.DeleteDevice(r.Context(), id, expected); err != nil {
			writeStoreError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPatch && r.Method != http.MethodPut {
		methodNotAllowed(w, "GET, PATCH, PUT, DELETE")
		return
	}
	var d domain.Device
	if !decodeJSON(w, r, &d) {
		return
	}
	if !s.validateDeviceIntent(w, d) {
		return
	}
	d.ID = id
	if old, err := s.Store.GetDevice(r.Context(), id); err == nil {
		preserveDeviceObservations(old, &d)
	}
	out, err := s.Store.UpdateDevice(r.Context(), d, expected)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) deviceGroups(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if pathID(r.URL.Path, "/api/v1/device-groups/") != "" {
			out, err := s.Store.GetDeviceGroup(r.Context(), pathID(r.URL.Path, "/api/v1/device-groups/"))
			if err != nil {
				writeStoreError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		out, err := s.Store.ListDeviceGroups(r.Context())
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeCollection(w, r, out, nil)
		return
	}
	if r.Method == http.MethodPost {
		var g domain.DeviceGroup
		if !decodeJSON(w, r, &g) {
			return
		}
		out, err := s.Store.CreateDeviceGroup(r.Context(), g)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
		return
	}
	if r.Method == http.MethodPatch {
		id := pathID(r.URL.Path, "/api/v1/device-groups/")
		expected, ok := expectedRevision(r)
		if id == "" {
			methodNotAllowed(w, "GET, POST")
			return
		}
		if !ok {
			writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match or revision query is required")
			return
		}
		var g domain.DeviceGroup
		if !decodeJSON(w, r, &g) {
			return
		}
		g.ID = id
		out, err := s.Store.UpdateDeviceGroup(r.Context(), g, expected)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	methodNotAllowed(w, "GET, POST, PATCH")
}

func (s *Server) deviceGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if r.Method == http.MethodGet {
		out, err := s.Store.GetDeviceGroup(r.Context(), id)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	if r.Method != http.MethodPatch && r.Method != http.MethodPut {
		methodNotAllowed(w, "GET, PATCH, PUT")
		return
	}
	expected, ok := expectedRevision(r)
	if !ok {
		writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match or revision query is required")
		return
	}
	var g domain.DeviceGroup
	if !decodeJSON(w, r, &g) {
		return
	}
	g.ID = id
	out, err := s.Store.UpdateDeviceGroup(r.Context(), g, expected)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) providers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if id := pathID(r.URL.Path, "/api/v1/providers/"); id != "" {
			out, err := s.Store.GetProvider(r.Context(), id)
			if err != nil {
				writeStoreError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, s.providerView(r.Context(), out))
			return
		}
		out, err := s.Store.ListProviders(r.Context())
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeCollection(w, r, s.providerViews(r.Context(), out), nil)
		return
	}
	if r.Method == http.MethodPost {
		var p domain.Provider
		if !decodeJSON(w, r, &p) {
			return
		}
		out, err := s.createProvider(r.Context(), p)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, s.providerView(r.Context(), out))
		return
	}
	methodNotAllowed(w, "GET, POST")
}

func (s *Server) provider(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPatch || r.Method == http.MethodPut {
		s.updateProvider(w, r, r.PathValue("id"))
		return
	}
	if r.Method == http.MethodDelete {
		s.deleteProvider(w, r, r.PathValue("id"))
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET, PATCH, PUT, DELETE")
		return
	}
	out, err := s.Store.GetProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.providerView(r.Context(), out))
}

func (s *Server) gateways(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if id := pathID(r.URL.Path, "/api/v1/gateways/"); id != "" {
			out, err := s.Store.GetGateway(r.Context(), id)
			if err != nil {
				writeStoreError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, s.gatewayView(r.Context(), out))
			return
		}
		out, err := s.Store.ListGateways(r.Context())
		if err != nil {
			writeStoreError(w, err)
			return
		}
		views := make([]GatewayView, 0, len(out))
		for _, item := range out {
			views = append(views, s.gatewayView(r.Context(), item))
		}
		writeCollection(w, r, views, nil)
		return
	}
	if r.Method == http.MethodPost {
		var g domain.Gateway
		if !decodeJSON(w, r, &g) {
			return
		}
		out, err := s.Store.CreateGateway(r.Context(), g)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
		return
	}
	methodNotAllowed(w, "GET, POST")
}

func (s *Server) gateway(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	out, err := s.Store.GetGateway(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.gatewayView(r.Context(), out))
}

func pathID(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	id := strings.Trim(strings.TrimPrefix(path, prefix), "/")
	if strings.Contains(id, "/") {
		return ""
	}
	return id
}
func expectedRevision(r *http.Request) (int64, bool) {
	raw := r.Header.Get("If-Match")
	if raw == "" {
		raw = r.URL.Query().Get("revision")
	}
	raw = strings.Trim(raw, "\"")
	if raw == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	return n, err == nil && n > 0
}

func expectedRuntimeRevision(r *http.Request) (int64, bool) {
	raw := strings.Trim(r.Header.Get("If-Match"), "\"")
	if raw == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	return n, err == nil && n >= 0
}
func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain one JSON value")
		return false
	}
	return true
}
func methodNotAllowed(w http.ResponseWriter, methods string) {
	w.Header().Set("Allow", methods)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method is not supported")
}
func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, domain.ErrConflict):
		writeError(w, http.StatusPreconditionFailed, "revision_conflict", err.Error())
	case errors.Is(err, domain.ErrAddressConflict):
		writeError(w, http.StatusConflict, "address_conflict", err.Error())
	default:
		var ve *domain.ValidationError
		if errors.As(err, &ve) {
			writeError(w, http.StatusUnprocessableEntity, "validation_error", ve.Error())
		} else {
			writeError(w, http.StatusBadRequest, "request_error", err.Error())
		}
	}
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) Shutdown(ctx context.Context) error { _ = ctx; return nil }

func (s *Server) validateDeviceIntent(w http.ResponseWriter, d domain.Device) bool {
	if d.EnrollmentState != "" && d.EnrollmentState != domain.EnrollmentUnenrolled {
		writeError(w, http.StatusUnprocessableEntity, "derived_state_read_only", "enrollment state is set by verified deployment operations")
		return false
	}
	for _, address := range d.Addresses {
		if address.VerifiedAt != nil {
			writeError(w, http.StatusUnprocessableEntity, "derived_state_read_only", "address verification timestamps are read-only")
			return false
		}
	}
	return s.validateDeviceExceptions(w, d)
}

var _ = time.Now
