package api

import (
	"context"
	"net/http"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

type GatewayView struct {
	domain.Gateway
	Health       string `json:"health"`
	Version      string `json:"version,omitempty"`
	Capabilities struct {
		Supported    []string          `json:"supported"`
		Restrictions map[string]string `json:"restrictions,omitempty"`
	} `json:"capabilities"`
	ObservationStatus string `json:"observation_status"`
}

func (s *Server) gatewayView(ctx context.Context, value domain.Gateway) GatewayView {
	view := GatewayView{Gateway: value, Health: "unknown", ObservationStatus: "unavailable"}
	view.Capabilities.Supported = []string{}
	services := s.servicesOrDefault()
	if services.GatewayObserver == nil {
		return view
	}
	caps, health, err := services.GatewayObserver(ctx, value)
	if err != nil {
		view.Health = "offline"
		view.ObservationStatus = "failed"
		return view
	}
	view.Health = health.Status
	view.Version = caps.Version
	view.ObservationStatus = "observed"
	view.Capabilities.Restrictions = map[string]string{}
	for _, capability := range caps.Items {
		if capability.Supported {
			view.Capabilities.Supported = append(view.Capabilities.Supported, string(capability.Name))
		}
		if len(capability.Restrictions) > 0 {
			view.Capabilities.Restrictions[string(capability.Name)] = capability.Restrictions[0]
		}
	}
	return view
}

func (s *Server) gatewayCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	value, err := s.Store.GetGateway(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.gatewayView(r.Context(), value))
}
