package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/opnsense"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
)

const firewallObservationTTL = 5 * time.Minute

// Observation cache is intentionally transient. Restored binding intent must
// be read back before the UI displays counts or a known drift state again.
type firewallObservation struct {
	Readback    *opnsense.Readback
	LastAttempt time.Time
	Error       string
}

// FirewallBindingView separates cached observation from durable attachment.
// Missing counts/drift mean unknown; zero and false are only emitted when an
// actual successful readback established those values.
type FirewallBindingView struct {
	ID                string                 `json:"id"`
	GatewayID         string                 `json:"gateway_id"`
	Alias             string                 `json:"alias"`
	AliasUUID         string                 `json:"alias_uuid,omitempty"`
	AddressFamily     opnsense.AddressFamily `json:"address_family"`
	InterfaceScope    string                 `json:"interface_scope"`
	RuleIDs           []string               `json:"rule_ids"`
	DesiredCount      int                    `json:"desired_count"`
	PersistedCount    *int                   `json:"persisted_count,omitempty"`
	ActiveCount       *int                   `json:"active_count,omitempty"`
	Drift             *bool                  `json:"drift,omitempty"`
	State             string                 `json:"state"`
	ObservationStatus string                 `json:"observation_status"`
	ObservationError  string                 `json:"observation_error,omitempty"`
	ObservedAt        *time.Time             `json:"observed_at,omitempty"`
	LastAttemptAt     *time.Time             `json:"last_attempt_at,omitempty"`
	Verified          bool                   `json:"verified"`
}

func firewallView(binding opnsense.Binding, observation firewallObservation, now time.Time) FirewallBindingView {
	view := FirewallBindingView{ID: binding.ID, GatewayID: binding.GatewayID, Alias: binding.Alias.Name, AliasUUID: binding.Alias.UUID, AddressFamily: binding.Family, InterfaceScope: binding.InterfaceScope, RuleIDs: append([]string{}, binding.RuleIDs...), DesiredCount: len(binding.ManagedAddresses), State: "desired", ObservationStatus: "never_read"}
	if !observation.LastAttempt.IsZero() {
		at := observation.LastAttempt
		view.LastAttemptAt = &at
	}
	if observation.Readback != nil && !observation.Readback.ReadAt.IsZero() {
		readback := observation.Readback
		persisted, active, drift, at := len(readback.Persisted.Addresses), len(readback.Active.Addresses), readback.Drift.Drifted, readback.ReadAt
		view.PersistedCount, view.ActiveCount, view.Drift, view.ObservedAt = &persisted, &active, &drift, &at
		view.State, view.ObservationStatus = "observed", "fresh"
		if now.Before(at) || now.Sub(at) > firewallObservationTTL {
			view.ObservationStatus = "stale"
		}
	}
	if observation.Error != "" {
		view.ObservationStatus = "error"
		view.ObservationError = observation.Error
	}
	return view
}

// firewallBindingViews supplies the same observation projection to list and
// overview, so neither endpoint invents empty or verified firewall state.
func (s *Services) firewallBindingViews(now time.Time) []FirewallBindingView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]FirewallBindingView, 0, len(s.bindings))
	for _, binding := range s.bindings {
		items = append(items, firewallView(binding, s.firewallObservations[binding.ID], now))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

func (s *Services) firewallBindingView(id string, now time.Time) (FirewallBindingView, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	binding, ok := s.bindings[id]
	return firewallView(binding, s.firewallObservations[id], now), ok
}

func (s *Services) beginFirewallReadback(id string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.firewallObservations == nil {
		s.firewallObservations = map[string]firewallObservation{}
	}
	observation := s.firewallObservations[id]
	at := time.Now().UTC()
	if !at.After(observation.LastAttempt) {
		at = observation.LastAttempt.Add(time.Nanosecond)
	}
	observation.LastAttempt = at
	s.firewallObservations[id] = observation
	return at
}

func (s *Services) finishFirewallReadback(id string, started time.Time, readback *opnsense.Readback, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	observation := s.firewallObservations[id]
	// A slow earlier response must not replace a newer attempt's result.
	if !observation.LastAttempt.Equal(started) {
		return
	}
	observation.Error = message
	if readback != nil {
		observation.Readback = readback
	}
	s.firewallObservations[id] = observation
}

func firewallError(err error) (int, string, string) {
	switch {
	case errors.Is(err, opnsense.ErrNotFound):
		return http.StatusNotFound, "firewall_object_not_found", "The configured firewall alias or table was not found."
	case errors.Is(err, opnsense.ErrAuthentication):
		return http.StatusBadGateway, "firewall_authentication_failed", "The firewall rejected its configured credentials or privileges."
	case errors.Is(err, opnsense.ErrInvalidBinding):
		return http.StatusUnprocessableEntity, "invalid_firewall_binding", "The binding address family, gateway, alias, or interface scope is invalid."
	case errors.Is(err, opnsense.ErrShapeChanged), errors.Is(err, opnsense.ErrDrift):
		return http.StatusConflict, "firewall_drift", "The firewall alias shape or contents differ from the registered binding."
	case errors.Is(err, opnsense.ErrScope):
		return http.StatusUnprocessableEntity, "firewall_scope_invalid", "The requested alias is outside the configured firewall scope."
	case errors.Is(err, opnsense.ErrVersion), errors.Is(err, opnsense.ErrUnsupported):
		return http.StatusNotImplemented, "firewall_unsupported", "The configured firewall cannot provide this operation."
	default:
		return http.StatusBadGateway, "firewall_readback_failed", "Firewall readback failed. Check the configured connection and try again."
	}
}

func (s *Server) firewallBindings(w http.ResponseWriter, r *http.Request) {
	services := s.servicesOrDefault()
	if r.Method == http.MethodGet {
		w.Header().Set("Cache-Control", "no-store")
		writeCollection(w, r, services.firewallBindingViews(time.Now().UTC()), map[string]any{"adapter_configured": services.Firewall != nil})
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "GET, POST")
		return
	}
	if services.Firewall == nil {
		writeUnsupported(w, "firewall.attach", "no OPNsense adapter is configured")
		return
	}
	var request opnsense.AttachRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if _, err := s.Store.GetGateway(r.Context(), request.GatewayID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusUnprocessableEntity, "gateway_not_registered", "Register the selected gateway before attaching a firewall binding.")
		} else {
			writeStoreError(w, err)
		}
		return
	}
	if request.ID == "" {
		request.ID = domain.NewID()
	}
	services.mu.RLock()
	duplicate := false
	for id, existing := range services.bindings {
		if id == request.ID || existing.Alias.Name == request.Alias || (request.AliasUUID != "" && existing.Alias.UUID == request.AliasUUID) {
			duplicate = true
			break
		}
	}
	services.mu.RUnlock()
	if duplicate {
		writeError(w, http.StatusConflict, "firewall_binding_exists", "This binding ID or firewall alias is already attached. Read back the existing binding.")
		return
	}
	binding, readback, err := services.Firewall.Attach(r.Context(), request)
	if err != nil {
		status, code, message := firewallError(err)
		writeError(w, status, code, message)
		return
	}
	services.mu.Lock()
	services.bindings[binding.ID] = binding
	if services.firewallObservations == nil {
		services.firewallObservations = map[string]firewallObservation{}
	}
	services.firewallObservations[binding.ID] = firewallObservation{Readback: &readback, LastAttempt: time.Now().UTC()}
	services.mu.Unlock()
	services.record(requestActor(r), "firewall_binding", binding.ID, "attach", "observed")
	view, _ := services.firewallBindingView(binding.ID, time.Now().UTC())
	w.Header().Set("Location", "/api/v1/firewall-bindings/"+url.PathEscape(binding.ID))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{"binding": binding, "observed": readback, "verified": false, "view": view})
}

func (s *Server) firewallBinding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	services := s.servicesOrDefault()
	view, ok := services.firewallBindingView(r.PathValue("id"), time.Now().UTC())
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "firewall binding not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) firewallReadback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w, "GET, POST")
		return
	}
	services := s.servicesOrDefault()
	services.mu.RLock()
	binding, ok := services.bindings[r.PathValue("id")]
	services.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "firewall binding not found")
		return
	}
	started := services.beginFirewallReadback(binding.ID)
	if services.Firewall == nil {
		services.finishFirewallReadback(binding.ID, started, nil, "No firewall connection is configured. Previous observations are cached.")
		writeUnsupported(w, "firewall.readback", "no OPNsense adapter is configured")
		return
	}
	readback, err := services.Firewall.Readback(r.Context(), binding)
	if err != nil {
		status, code, message := firewallError(err)
		services.finishFirewallReadback(binding.ID, started, nil, message)
		writeError(w, status, code, message)
		return
	}
	services.finishFirewallReadback(binding.ID, started, &readback, "")
	view, _ := services.firewallBindingView(binding.ID, time.Now().UTC())
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"desired": binding, "observed": readback, "verified": false, "view": view})
}

func (s *Server) providerStage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	services := s.servicesOrDefault()
	provider, err := s.Store.GetProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var request struct {
		Content string           `json:"content"`
		Format  providers.Format `json:"format"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Format == "" {
		request.Format = providers.Format(provider.Format)
	}
	requestHash := privateRequestHash(request)
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		if old, e := services.Journal.FindByIdempotency(r.Context(), deployment.Target{Kind: "provider", ID: provider.ID}, key); e == nil {
			if old.Action != "stage" || old.RequestHash != requestHash {
				writeError(w, http.StatusConflict, "idempotency_conflict", "idempotency key is bound to another provider action")
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": old.ID, "status": old.Status})
			return
		}
	}
	revision, changes, err := services.Providers.Stage(provider.ID, []byte(request.Content), request.Format)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	services.record(requestActor(r), "provider", provider.ID, "stage", "staged")
	desired, _ := json.Marshal(map[string]any{"revision": revision, "changes": changes})
	op, err := services.Journal.Create(r.Context(), deployment.Operation{Target: deployment.Target{Kind: "provider", ID: provider.ID}, Action: "stage", RequestHash: requestHash, IdempotencyKey: r.Header.Get("Idempotency-Key"), Status: deployment.StatusStaged, Views: deployment.StateViews{Desired: &deployment.StateRecord{Revision: strconv.FormatInt(revision.Number, 10), Status: "staged", Data: desired, At: time.Now().UTC()}}})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": op.ID, "revision": revision, "changes": changes, "status": "staged"})
}
