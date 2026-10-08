package auth

import (
	"encoding/json"
	"net/http"
)

// Middleware applies session authentication, role checks, and CSRF checks to
// net/http handlers. It emits small JSON errors so API callers never need to
// parse an HTML error page.
type Middleware struct {
	Sessions *SessionManager
}

func NewMiddleware(sessions *SessionManager) *Middleware {
	return &Middleware{Sessions: sessions}
}

func (m *Middleware) manager() (*SessionManager, bool) {
	if m == nil || m.Sessions == nil {
		return nil, false
	}
	return m.Sessions, true
}

func writeAuthError(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}

// Authenticate loads a session from the cookie and places it in the request
// context. It does not require a particular role; use Require for that.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions, ok := m.manager()
		if !ok {
			writeAuthError(w, http.StatusInternalServerError, "auth_unavailable", "authentication is unavailable")
			return
		}
		session, err := sessions.Read(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", "Session")
			writeAuthError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithSession(r.Context(), session)))
	})
}

// OptionalAuthentication loads a valid session when present and leaves the
// context empty for anonymous requests. Invalid cookies are discarded from
// the request context and do not grant any permission.
func (m *Middleware) OptionalAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions, ok := m.manager()
		if !ok {
			writeAuthError(w, http.StatusInternalServerError, "auth_unavailable", "authentication is unavailable")
			return
		}
		session, err := sessions.Read(r)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithSession(r.Context(), session)))
	})
}

// Require authenticates a request and verifies that its strongest role grants
// required. Admin, operator, and viewer checks are hierarchical.
func (m *Middleware) Require(required Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessions, ok := m.manager()
			if !ok {
				writeAuthError(w, http.StatusInternalServerError, "auth_unavailable", "authentication is unavailable")
				return
			}
			session, err := sessions.Read(r)
			if err != nil {
				w.Header().Set("WWW-Authenticate", "Session")
				writeAuthError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}
			if !HasRole(session.Roles, required) {
				writeAuthError(w, http.StatusForbidden, "forbidden", "insufficient role")
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithSession(r.Context(), session)))
		})
	}
}

// RequireAny allows endpoints that have equivalent permissions for multiple
// roles while retaining the same authentication and context behavior.
func (m *Middleware) RequireAny(required ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessions, ok := m.manager()
			if !ok {
				writeAuthError(w, http.StatusInternalServerError, "auth_unavailable", "authentication is unavailable")
				return
			}
			session, err := sessions.Read(r)
			if err != nil {
				w.Header().Set("WWW-Authenticate", "Session")
				writeAuthError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}
			allowed := false
			for _, role := range required {
				if HasRole(session.Roles, role) {
					allowed = true
					break
				}
			}
			if !allowed {
				writeAuthError(w, http.StatusForbidden, "forbidden", "insufficient role")
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithSession(r.Context(), session)))
		})
	}
}

// CSRF validates a state-changing request after authentication. It accepts a
// session loaded by Authenticate/Require, but also reads it directly when this
// middleware is used on its own.
func (m *Middleware) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessions, ok := m.manager()
		if !ok {
			writeAuthError(w, http.StatusInternalServerError, "auth_unavailable", "authentication is unavailable")
			return
		}
		session, present := SessionFromContext(r.Context())
		if !present {
			var err error
			session, err = sessions.Read(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}
			r = r.WithContext(ContextWithSession(r.Context(), session))
		}
		if err := sessions.ValidateCSRF(r, session); err != nil {
			writeAuthError(w, http.StatusForbidden, "csrf_failed", "csrf validation failed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireRole is a function-form helper for code that does not need a
// Middleware value, such as websocket or event-stream handlers.
func RequireRole(r *http.Request, required Role) bool {
	session, ok := SessionFromContext(r.Context())
	return ok && HasRole(session.Roles, required)
}

// Authorize is a context-independent convenience helper for handlers that
// already obtained a Session through another transport.
func Authorize(session Session, required Role) bool {
	return HasRole(session.Roles, required)
}
