package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

// GatewayDiagnostics is the read/probe subset of a configured gateway. Its
// implementation retains operator-configured endpoints and credentials.
// Browser requests supply inventory IDs only, never a probe destination.
type GatewayDiagnostics interface {
	Capabilities(context.Context) (gateway.Capabilities, error)
	ProbeNode(context.Context, string) (gateway.ProbeResult, error)
	ProbeGroup(context.Context, string) (gateway.ProbeResult, error)
	ObserveConnections(context.Context) ([]gateway.Connection, error)
	Counters(context.Context) (gateway.Counters, error)
}

type gatewayDiagnosticSource struct {
	GatewayID   string    `json:"gateway_id"`
	GatewayName string    `json:"gateway_name"`
	ObservedAt  time.Time `json:"observed_at"`
}
type diagnosticProbeResult struct {
	Target     string    `json:"target"`
	OK         bool      `json:"ok"`
	LatencyMS  float64   `json:"latency_ms"`
	ObservedAt time.Time `json:"observed_at"`
	Error      string    `json:"error,omitempty"`
}

// Decimal strings preserve uint64 counters in browser clients. Omitted values
// mean unavailable; the string "0" is an observed zero.
type diagnosticCounter struct {
	Available bool   `json:"available"`
	Bytes     string `json:"bytes,omitempty"`
	Packets   string `json:"packets,omitempty"`
}

func (s *Server) registerDiagnostics(handle func(string, http.HandlerFunc)) {
	register := func(path string, next http.HandlerFunc) {
		handle(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			next(w, r)
		})
	}
	register("/api/v1/gateways/{id}/probes/nodes/{nodeId}", s.gatewayProbeNode)
	register("/api/v1/gateways/{id}/probes/groups/{groupId}", s.gatewayProbeGroup)
	register("/api/v1/gateways/{id}/connections", s.gatewayConnections)
	register("/api/v1/gateways/{id}/counters", s.gatewayCounters)
}

func (s *Server) diagnosticGateway(w http.ResponseWriter, r *http.Request, capability gateway.CapabilityName) (domain.Gateway, GatewayDiagnostics, gateway.Capabilities, bool) {
	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "gateway diagnostics do not accept query parameters")
		return domain.Gateway{}, nil, gateway.Capabilities{}, false
	}
	registered, err := s.Store.GetGateway(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return domain.Gateway{}, nil, gateway.Capabilities{}, false
	}
	services := s.servicesOrDefault()
	if services.GatewayDiagnostics == nil {
		writeUnsupported(w, string(capability), "gateway diagnostics are not configured")
		return domain.Gateway{}, nil, gateway.Capabilities{}, false
	}
	engine, err := services.GatewayDiagnostics(r.Context(), registered)
	if err != nil || engine == nil {
		if err == nil {
			err = gateway.ErrUnsupported
		}
		writeDiagnosticError(w, string(capability), err)
		return domain.Gateway{}, nil, gateway.Capabilities{}, false
	}
	caps, err := engine.Capabilities(r.Context())
	if err != nil {
		writeDiagnosticError(w, string(capability), err)
		return domain.Gateway{}, nil, gateway.Capabilities{}, false
	}
	if capability != "traffic.counters" && !caps.Has(capability) || capability == "traffic.counters" && !caps.Has(gateway.CapabilityProxyCounters) && !caps.Has(gateway.CapabilityDirectCounters) {
		writeUnsupported(w, string(capability), "the selected gateway does not support this diagnostic")
		return domain.Gateway{}, nil, gateway.Capabilities{}, false
	}
	return registered, engine, caps, true
}

func (s *Server) gatewayProbeNode(w http.ResponseWriter, r *http.Request) {
	s.gatewayProbe(w, r, "node", r.PathValue("nodeId"), gateway.CapabilityProbeNode)
}
func (s *Server) gatewayProbeGroup(w http.ResponseWriter, r *http.Request) {
	s.gatewayProbe(w, r, "group", r.PathValue("groupId"), gateway.CapabilityProbeGroup)
}
func (s *Server) gatewayProbe(w http.ResponseWriter, r *http.Request, kind, target string, capability gateway.CapabilityName) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	if !emptyProbeRequest(w, r) {
		return
	}
	// Membership is controller inventory authority: a supplied ID cannot probe
	// an arbitrary target or a group assigned to another gateway.
	services := s.servicesOrDefault()
	member := false
	for _, group := range services.Outbounds.List() {
		if group.GatewayID != r.PathValue("id") {
			continue
		}
		if kind == "group" && group.ID == target {
			member = true
			break
		}
		if kind == "node" {
			for _, id := range group.NodeIDs {
				if id == target {
					member = true
					break
				}
			}
		}
	}
	if !member {
		writeError(w, http.StatusNotFound, "not_found", "probe target is not assigned to the selected gateway")
		return
	}
	registered, engine, _, ok := s.diagnosticGateway(w, r, capability)
	if !ok {
		return
	}
	var result gateway.ProbeResult
	var err error
	if kind == "node" {
		result, err = engine.ProbeNode(r.Context(), target)
	} else {
		result, err = engine.ProbeGroup(r.Context(), target)
	}
	if err != nil {
		services.record(requestActor(r), "gateway", registered.ID, string(capability), "failed")
		writeDiagnosticError(w, string(capability), err)
		return
	}
	if result.Target != target || result.Observed.IsZero() || result.Latency < 0 {
		writeDiagnosticError(w, string(capability), gateway.ErrProtocol)
		return
	}
	probe := diagnosticProbeResult{Target: result.Target, OK: result.OK, LatencyMS: float64(result.Latency) / float64(time.Millisecond), ObservedAt: result.Observed}
	// Native adapter error strings can include credential-bearing URLs.
	if !result.OK {
		probe.Error = "Gateway probe did not succeed"
	}
	outcome := "failed"
	if result.OK {
		outcome = "observed"
	}
	services.record(requestActor(r), "gateway", registered.ID, string(capability), outcome)
	writeJSON(w, http.StatusOK, struct {
		gatewayDiagnosticSource
		TargetKind string                `json:"target_kind"`
		TargetID   string                `json:"target_id"`
		Probe      diagnosticProbeResult `json:"probe"`
	}{gatewayDiagnosticSource{registered.ID, registered.Name, time.Now().UTC()}, kind, target, probe})
}

func emptyProbeRequest(w http.ResponseWriter, r *http.Request) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "probe request must be empty or an empty JSON object")
		return false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return true
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(data, &body); err != nil || body == nil || len(body) != 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "probe request must be empty or an empty JSON object")
		return false
	}
	return true
}

func (s *Server) gatewayConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	registered, engine, _, ok := s.diagnosticGateway(w, r, gateway.CapabilityConnectionsObserve)
	if !ok {
		return
	}
	items, err := engine.ObserveConnections(r.Context())
	if err != nil {
		writeDiagnosticError(w, string(gateway.CapabilityConnectionsObserve), err)
		return
	}
	if items == nil {
		items = []gateway.Connection{}
	}
	writeJSON(w, http.StatusOK, struct {
		gatewayDiagnosticSource
		Items []gateway.Connection `json:"items"`
	}{gatewayDiagnosticSource{registered.ID, registered.Name, time.Now().UTC()}, items})
}

func (s *Server) gatewayCounters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	registered, engine, caps, ok := s.diagnosticGateway(w, r, "traffic.counters")
	if !ok {
		return
	}
	counters, err := engine.Counters(r.Context())
	if err != nil {
		writeDiagnosticError(w, "traffic.counters", err)
		return
	}
	proxy, direct := diagnosticCounter{}, diagnosticCounter{}
	if caps.Has(gateway.CapabilityProxyCounters) {
		proxy = diagnosticCounter{true, strconv.FormatUint(counters.ProxyBytes, 10), strconv.FormatUint(counters.ProxyPackets, 10)}
	}
	if caps.Has(gateway.CapabilityDirectCounters) {
		direct = diagnosticCounter{true, strconv.FormatUint(counters.DirectBytes, 10), strconv.FormatUint(counters.DirectPackets, 10)}
	}
	writeJSON(w, http.StatusOK, struct {
		gatewayDiagnosticSource
		Proxy         diagnosticCounter `json:"proxy"`
		Direct        diagnosticCounter `json:"direct"`
		ProviderQuota diagnosticCounter `json:"provider_quota"`
	}{gatewayDiagnosticSource{registered.ID, registered.Name, time.Now().UTC()}, proxy, direct, diagnosticCounter{}})
}

func writeDiagnosticError(w http.ResponseWriter, capability string, err error) {
	if errors.Is(err, gateway.ErrUnsupported) {
		writeUnsupported(w, capability, "the selected gateway does not support this diagnostic")
		return
	}
	if errors.Is(err, gateway.ErrProtocol) {
		writeError(w, http.StatusBadGateway, "invalid_gateway_response", "the gateway returned an invalid diagnostic response")
		return
	}
	writeError(w, http.StatusBadGateway, "gateway_unavailable", "the selected gateway could not complete this diagnostic")
}
