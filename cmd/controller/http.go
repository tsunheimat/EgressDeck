package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/egressdeck/homelab-proxy-controller/internal/auth"
)

type httpConfig struct {
	AuthMode             string
	SessionSecret        []byte
	IdentityHeaderSecret []byte
	CookieSecure         bool
	StaticDir            string
	OIDC                 auth.OIDCConfig
}

func loadHTTPConfig() (httpConfig, error) {
	cfg := httpConfig{
		AuthMode:             env("AUTH_MODE", "session"),
		SessionSecret:        []byte(os.Getenv("SESSION_SECRET")),
		IdentityHeaderSecret: []byte(os.Getenv("IDENTITY_HEADER_SECRET")),
		StaticDir:            env("STATIC_DIR", "/usr/share/egressdeck/web"),
		OIDC: auth.OIDCConfig{
			IssuerURL:    env("OIDC_ISSUER_URL", ""),
			ClientID:     env("OIDC_CLIENT_ID", ""),
			ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
			RedirectURL:  env("OIDC_REDIRECT_URL", ""),
			GroupsClaim:  env("OIDC_GROUPS_CLAIM", "groups"),
			SuccessPath:  env("OIDC_SUCCESS_PATH", "/"),
			Scopes:       strings.Fields(os.Getenv("OIDC_SCOPES")),
		},
	}
	var err error
	if cfg.CookieSecure, err = strconv.ParseBool(env("COOKIE_SECURE", "true")); err != nil {
		return cfg, errors.New("COOKIE_SECURE must be true or false")
	}
	if raw := env("OIDC_GROUP_ROLES", ""); raw != "" {
		if err := json.Unmarshal([]byte(raw), &cfg.OIDC.GroupRoles); err != nil {
			return cfg, errors.New("OIDC_GROUP_ROLES must be a JSON object mapping group names to viewer, operator, or admin")
		}
		for group, role := range cfg.OIDC.GroupRoles {
			parsed, ok := auth.ParseRole(string(role))
			if strings.TrimSpace(group) == "" || !ok {
				return cfg, errors.New("OIDC_GROUP_ROLES contains an empty group or unknown role")
			}
			cfg.OIDC.GroupRoles[group] = parsed
		}
	}
	return cfg, cfg.validate()
}

func (cfg httpConfig) validate() error {
	switch cfg.AuthMode {
	case "disabled", "development":
		return nil
	case "session", "header":
		if len(cfg.SessionSecret) < 32 {
			return errors.New("SESSION_SECRET must contain at least 32 bytes")
		}
	default:
		return fmt.Errorf("unsupported AUTH_MODE %q", cfg.AuthMode)
	}
	if cfg.AuthMode == "header" {
		if len(cfg.IdentityHeaderSecret) < 32 {
			return errors.New("AUTH_MODE=header requires IDENTITY_HEADER_SECRET with at least 32 bytes")
		}
		return nil
	}
	if cfg.OIDC.IssuerURL == "" || cfg.OIDC.ClientID == "" || cfg.OIDC.RedirectURL == "" {
		return errors.New("AUTH_MODE=session requires OIDC_ISSUER_URL, OIDC_CLIENT_ID, and OIDC_REDIRECT_URL; use AUTH_MODE=header for signed identity headers")
	}
	redirect, err := url.Parse(cfg.OIDC.RedirectURL)
	if err != nil || redirect.Path == "" || redirect.Path == "/" || redirect.Path == "/healthz" || redirect.Path == "/readyz" || redirect.Path == "/api/v1/auth/login" || redirect.Path == "/api/v1/auth/session" || redirect.Path == "/api/v1/auth/logout" || redirect.Path == "/api/v1/auth/oidc/login" {
		return errors.New("OIDC_REDIRECT_URL must have a distinct callback path")
	}
	return nil
}

func newControllerHTTP(ctx context.Context, apiHandler http.Handler, cfg httpConfig) (http.Handler, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	static, err := newSPAHandler(cfg.StaticDir)
	if err != nil {
		return nil, err
	}
	authMux := http.NewServeMux()
	protected := apiHandler
	callbackPath := ""
	var callback http.Handler
	if cfg.AuthMode == "disabled" || cfg.AuthMode == "development" {
		authMux.HandleFunc("GET /api/v1/auth/session", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"subject": "development", "roles": []auth.Role{auth.RoleAdmin}, "auth_mode": cfg.AuthMode, "authentication_disabled": true})
		})
		authMux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		})
	} else {
		options := []auth.SessionOption{auth.WithSecureCookies(cfg.CookieSecure)}
		if cfg.AuthMode == "header" {
			options = append(options, auth.WithIdentityHeaderSecret(cfg.IdentityHeaderSecret))
		}
		sessions := auth.NewSessionManager(cfg.SessionSecret, options...)
		mw := auth.NewMiddleware(sessions)
		httpAuth := auth.NewHTTP(sessions)
		authMux.Handle("GET /api/v1/auth/session", mw.Require(auth.RoleViewer)(http.HandlerFunc(httpAuth.Session)))
		authMux.Handle("POST /api/v1/auth/logout", mw.Require(auth.RoleViewer)(mw.CSRF(http.HandlerFunc(httpAuth.Logout))))
		if cfg.AuthMode == "header" {
			authMux.HandleFunc("POST /api/v1/auth/login", httpAuth.Login)
		} else {
			oidc, err := auth.NewOIDC(ctx, cfg.OIDC, sessions)
			if err != nil {
				return nil, fmt.Errorf("configure OIDC: %w", err)
			}
			redirect, _ := url.Parse(cfg.OIDC.RedirectURL)
			callbackPath = redirect.Path
			callback = http.HandlerFunc(oidc.Callback)
			authMux.HandleFunc("GET /api/v1/auth/oidc/login", oidc.Login)
		}
		viewer := mw.Require(auth.RoleViewer)(mw.CSRF(apiHandler))
		operator := mw.Require(auth.RoleOperator)(mw.CSRF(apiHandler))
		admin := mw.Require(auth.RoleAdmin)(mw.CSRF(apiHandler))
		protected = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch auth.RequiredRole(r) {
			case auth.RoleViewer:
				viewer.ServeHTTP(w, r)
			case auth.RoleOperator:
				operator.ServeHTTP(w, r)
			default:
				admin.ServeHTTP(w, r)
			}
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		switch {
		case r.URL.Path == "/healthz" || r.URL.Path == "/readyz":
			apiHandler.ServeHTTP(w, r)
		case callbackPath != "" && r.URL.Path == callbackPath:
			// ServeMux patterns interpret braces and trailing slashes. Match
			// the exact configured callback separately from route patterns.
			callback.ServeHTTP(w, r)
		case r.URL.Path == "/api/v1/auth" || strings.HasPrefix(r.URL.Path, "/api/v1/auth/"):
			authMux.ServeHTTP(w, r)
		case r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/"):
			protected.ServeHTTP(w, r)
		default:
			static.ServeHTTP(w, r)
		}
	}), nil
}
