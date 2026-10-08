package auth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// HTTP exposes the authentication endpoints that sit beside the controller
// API. Login is for explicit, authenticated proxy-header mode only. Production
// OIDC mode uses OIDC.Login and OIDC.Callback instead.
type HTTP struct{ Sessions *SessionManager }

func NewHTTP(sessions *SessionManager) *HTTP { return &HTTP{Sessions: sessions} }

func (h *HTTP) Login(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		authJSONError(w, 405, "method_not_allowed", "use POST")
		return
	}
	if h == nil || h.Sessions == nil {
		authJSONError(w, http.StatusInternalServerError, "auth_unavailable", "authentication is unavailable")
		return
	}
	if !h.Sessions.VerifyIdentityHeaders(r) {
		authJSONError(w, http.StatusUnauthorized, "authentication_required", "the identity provider assertion is invalid")
		return
	}
	subject := strings.TrimSpace(r.Header.Get("X-Auth-Request-User"))
	if subject == "" {
		authJSONError(w, http.StatusUnauthorized, "authentication_required", "the identity provider did not authenticate this request")
		return
	}
	role, ok := ParseRole(r.Header.Get("X-Auth-Request-Role"))
	if !ok {
		role = RoleViewer
	}
	session, err := h.Sessions.Issue(subject, role)
	if err != nil {
		authJSONError(w, http.StatusInternalServerError, "session_error", "could not issue session")
		return
	}
	if err := h.Sessions.SetSession(w, session); err != nil {
		authJSONError(w, http.StatusInternalServerError, "session_error", "could not persist session")
		return
	}
	authJSON(w, http.StatusCreated, map[string]any{"subject": session.Subject, "roles": session.Roles, "expires_at": session.ExpiresAt})
}

func (h *HTTP) Logout(w http.ResponseWriter, _ *http.Request) {
	noStore(w)
	if h != nil && h.Sessions != nil {
		h.Sessions.Clear(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTP) Session(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if h == nil || h.Sessions == nil {
		authJSONError(w, http.StatusInternalServerError, "auth_unavailable", "authentication is unavailable")
		return
	}
	session, err := h.Sessions.Read(r)
	if err != nil {
		authJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	authJSON(w, http.StatusOK, map[string]any{"subject": session.Subject, "email": session.Email, "name": session.Name, "roles": session.Roles, "expires_at": session.ExpiresAt})
}

func authJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func authJSONError(w http.ResponseWriter, status int, code, message string) {
	authJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
