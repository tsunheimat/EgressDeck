package main

import (
	"net/http"

	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

func (a *agent) publishGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req gateway.GroupPublishRequest
	if err := decode(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	publisher, ok := a.engine.(gateway.GroupPublisher)
	if !ok {
		writeEngineError(w, &gateway.Error{Code: "unsupported", Operation: string(gateway.CapabilityGroupPublish), Cause: gateway.ErrUnsupported})
		return
	}
	value, err := publisher.PublishGroup(r.Context(), req.Publication, req.ExpectedGeneration)
	if err != nil {
		writeEngineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "published", "snapshot": value})
}
