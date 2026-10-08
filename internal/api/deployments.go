package api

import (
	"net/http"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
)

// Enrollment requests use the typed, reviewed composite manifest. The UI must
// obtain policy/hash and alias contents from preview/readback; this endpoint
// cannot invent a production guard or claim remote enrollment without one.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	services := s.servicesOrDefault()
	var manifest deployment.EnrollmentManifest
	if !decodeJSON(w, r, &manifest) {
		return
	}
	request, err := deployment.EnrollmentRequest(r.Header.Get("Idempotency-Key"), manifest)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if !services.EnrollmentEnabled || services.ExecutorFactory == nil {
		writeUnsupported(w, "policy.apply_generation", "qualified enrollment executor is unavailable")
		return
	}
	executor := services.ExecutorFactory(request.Target)
	if executor == nil {
		writeUnsupported(w, "policy.apply_generation", "qualified enrollment executor is unavailable for gateway")
		return
	}
	operation, err := services.Runner.Submit(r.Context(), request, executor)
	if err != nil && operation.ID == "" {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": operation.ID, "status": operation.Status})
}
