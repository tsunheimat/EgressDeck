package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const loginCookieName = "egressdeck_oidc_state"

// OIDCConfig describes a single, explicitly configured identity provider.
// GroupRoles maps exact identity-provider group names to application roles;
// unmapped users get viewer access. RedirectURL is never derived from headers.
type OIDCConfig struct {
	IssuerURL        string
	ClientID         string
	ClientSecret     string
	RedirectURL      string
	GroupRoles       map[string]Role
	GroupsClaim      string
	Scopes           []string
	SuccessPath      string
	LoginTTL         time.Duration
	MaxPendingLogins int
	HTTPClient       *http.Client
	// AllowInsecureLocalHTTP is only for loopback development/test issuers and
	// redirects. Remote issuer, token, JWKS and redirect URLs always need TLS.
	AllowInsecureLocalHTTP bool
}

type loginState struct {
	browserHash [32]byte
	nonce       string
	verifier    string
	expires     time.Time
}

// OIDC runs the authorization-code flow. Pending logins live only in bounded
// process memory and are consumed atomically before exchanging a code. A
// restart deliberately invalidates pending logins; existing sessions survive.
type OIDC struct {
	config   OIDCConfig
	sessions *SessionManager
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
	redirect *url.URL
	mu       sync.Mutex
	pending  map[string]loginState
}

func NewOIDC(ctx context.Context, cfg OIDCConfig, sessions *SessionManager) (*OIDC, error) {
	if sessions == nil || !sessions.secretValid {
		return nil, errors.New("OIDC requires a session manager with a secret of at least 32 bytes")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("OIDC client ID is required")
	}
	issuer, err := oidcURL(cfg.IssuerURL, cfg.AllowInsecureLocalHTTP)
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC issuer: %w", err)
	}
	if issuer.RawQuery != "" {
		return nil, errors.New("OIDC issuer cannot contain a query")
	}
	redirect, err := oidcURL(cfg.RedirectURL, cfg.AllowInsecureLocalHTTP)
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC redirect: %w", err)
	}
	if redirect.Path == "" || redirect.Path == "/" || redirect.RawQuery != "" {
		return nil, errors.New("OIDC redirect must have an exact callback path and no query")
	}
	if !sessions.httpOnly || (redirect.Scheme == "https" && !sessions.secure) {
		return nil, errors.New("OIDC requires HTTP-only sessions and secure cookies for HTTPS")
	}
	if cfg.SuccessPath == "" {
		cfg.SuccessPath = "/"
	}
	success, err := url.Parse(cfg.SuccessPath)
	if err != nil || success.IsAbs() || success.Host != "" || !strings.HasPrefix(cfg.SuccessPath, "/") || strings.HasPrefix(cfg.SuccessPath, "//") || strings.ContainsAny(cfg.SuccessPath, "\\\r\n") {
		return nil, errors.New("OIDC success path must be a local absolute path")
	}
	if strings.HasPrefix(success.Path, "//") || strings.ContainsAny(success.Path, "\\\r\n") {
		return nil, errors.New("OIDC success path must not encode an external redirect")
	}
	if cfg.LoginTTL == 0 {
		cfg.LoginTTL = 5 * time.Minute
	}
	if cfg.LoginTTL < time.Second || cfg.LoginTTL > 10*time.Minute {
		return nil, errors.New("OIDC login TTL must be between one second and ten minutes")
	}
	if cfg.MaxPendingLogins == 0 {
		cfg.MaxPendingLogins = 1024
	}
	if cfg.MaxPendingLogins < 1 || cfg.MaxPendingLogins > 10000 {
		return nil, errors.New("OIDC pending login limit must be between 1 and 10000")
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	groupRoles := make(map[string]Role, len(cfg.GroupRoles))
	for group, role := range cfg.GroupRoles {
		parsed, ok := ParseRole(string(role))
		if strings.TrimSpace(group) == "" || !ok {
			return nil, errors.New("OIDC group mapping contains an empty group or unknown role")
		}
		groupRoles[group] = parsed
	}
	cfg.GroupRoles = groupRoles
	client := &http.Client{Timeout: 15 * time.Second}
	if cfg.HTTPClient != nil {
		*client = *cfg.HTTPClient
	}
	if client.Timeout <= 0 || client.Timeout > 30*time.Second {
		client.Timeout = 15 * time.Second
	}
	// Discovery/token redirects must not move client credentials to a different
	// destination. Authentik publishes the final endpoint URLs in discovery.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	discoveryContext, cancel := context.WithTimeout(oidc.ClientContext(ctx, client), 15*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(discoveryContext, cfg.IssuerURL)
	if err != nil {
		return nil, errors.New("OIDC discovery failed")
	}
	var metadata struct {
		Authorization    string   `json:"authorization_endpoint"`
		Token            string   `json:"token_endpoint"`
		JWKS             string   `json:"jwks_uri"`
		TokenAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, errors.New("OIDC discovery metadata is invalid")
	}
	for _, endpoint := range []string{metadata.Authorization, metadata.Token, metadata.JWKS} {
		if _, err := oidcURL(endpoint, cfg.AllowInsecureLocalHTTP); err != nil {
			return nil, errors.New("OIDC discovery contains an invalid or insecure endpoint")
		}
	}
	endpoint := provider.Endpoint()
	// Select the advertised client authentication method before exchanging a
	// one-time code. oauth2 auto-detection retries failed exchanges with a
	// different method, including invalid_grant and transient failures.
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	if len(metadata.TokenAuthMethods) > 0 {
		methods := make(map[string]bool, len(metadata.TokenAuthMethods))
		for _, method := range metadata.TokenAuthMethods {
			methods[method] = true
		}
		switch {
		case methods["client_secret_basic"]:
		case methods["client_secret_post"]:
			endpoint.AuthStyle = oauth2.AuthStyleInParams
		case cfg.ClientSecret == "" && methods["none"]:
			endpoint.AuthStyle = oauth2.AuthStyleInParams
		default:
			return nil, errors.New("OIDC provider has no supported token authentication method")
		}
	}
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	for _, scope := range cfg.Scopes {
		if strings.TrimSpace(scope) != scope || scope == "" || strings.ContainsAny(scope, "\t\r\n ") {
			return nil, errors.New("invalid OIDC scope")
		}
		found := false
		for _, existing := range scopes {
			if existing == scope {
				found = true
				break
			}
		}
		if !found {
			scopes = append(scopes, scope)
		}
	}
	// VerifierContext preserves the configured TLS transport for later JWKS
	// fetches without retaining the short discovery request deadline.
	verifier := provider.VerifierContext(oidc.ClientContext(context.Background(), client), &oidc.Config{
		ClientID:             cfg.ClientID,
		SupportedSigningAlgs: []string{oidc.RS256, oidc.RS384, oidc.RS512, oidc.ES256, oidc.ES384, oidc.ES512, oidc.PS256, oidc.PS384, oidc.PS512},
	})
	return &OIDC{config: cfg, sessions: sessions, oauth: oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: cfg.RedirectURL, Endpoint: endpoint, Scopes: scopes}, verifier: verifier, client: client, redirect: redirect, pending: make(map[string]loginState)}, nil
}

func oidcURL(raw string, allowLocal bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("URL must be absolute without credentials or fragment")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if !allowLocal || u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, errors.New("URL requires HTTPS")
		}
	}
	return u, nil
}

func (o *OIDC) loginCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: loginCookieName, Value: value, Path: o.redirect.Path, Secure: o.sessions.secure, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// Login starts a new, browser-bound login. The only redirect destination is
// the configured provider; user-supplied next/redirect URL parameters are not
// honored.
func (o *OIDC) Login(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		authJSONError(w, 405, "method_not_allowed", "use GET or POST")
		return
	}
	values := make([]string, 4)
	for i := range values {
		value, err := randomSessionToken(32)
		if err != nil {
			authJSONError(w, 503, "auth_unavailable", "could not start login")
			return
		}
		values[i] = value
	}
	state, browser, nonce, pkce := values[0], values[1], values[2], values[3]
	now := o.sessions.now()
	o.mu.Lock()
	for key, pending := range o.pending {
		if !now.Before(pending.expires) {
			delete(o.pending, key)
		}
	}
	if len(o.pending) >= o.config.MaxPendingLogins {
		o.mu.Unlock()
		authJSONError(w, 503, "login_busy", "too many pending logins")
		return
	}
	o.pending[state] = loginState{browserHash: sha256.Sum256([]byte(browser)), nonce: nonce, verifier: pkce, expires: now.Add(o.config.LoginTTL)}
	o.mu.Unlock()
	http.SetCookie(w, o.loginCookie(browser, int(o.config.LoginTTL.Seconds())))
	http.Redirect(w, r, o.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce)), http.StatusFound)
}

// Callback consumes a login state once and exchanges the authorization code
// server-side. No OAuth access/refresh/ID tokens enter the browser session.
func (o *OIDC) Callback(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		authJSONError(w, 405, "method_not_allowed", "use GET")
		return
	}
	if r.Host != o.redirect.Host || r.URL.EscapedPath() != o.redirect.EscapedPath() {
		authJSONError(w, 400, "invalid_callback", "callback does not match configured redirect")
		return
	}
	query := r.URL.Query()
	if values, ok := query["iss"]; ok && (len(values) != 1 || values[0] != o.config.IssuerURL) {
		authJSONError(w, 400, "invalid_callback", "authorization response issuer mismatch")
		return
	}
	if len(query["state"]) != 1 || len(query["code"]) > 1 || len(query["error"]) > 1 {
		authJSONError(w, 400, "invalid_login_state", "invalid login state")
		return
	}
	state := query.Get("state")
	cookie, err := r.Cookie(loginCookieName)
	if err != nil || len(state) > 128 || len(cookie.Value) > 128 {
		authJSONError(w, 400, "invalid_login_state", "invalid or expired login state")
		return
	}
	browserHash := sha256.Sum256([]byte(cookie.Value))
	o.mu.Lock()
	pending, found := o.pending[state]
	valid := found && o.sessions.now().Before(pending.expires) && hmac.Equal(browserHash[:], pending.browserHash[:])
	if valid || (found && !o.sessions.now().Before(pending.expires)) {
		delete(o.pending, state)
	}
	o.mu.Unlock()
	if !valid {
		authJSONError(w, 400, "invalid_login_state", "invalid or expired login state")
		return
	}
	http.SetCookie(w, o.loginCookie("", -1))
	if query.Get("error") != "" || query.Get("code") == "" {
		authJSONError(w, 401, "login_failed", "identity provider denied login")
		return
	}
	ctx, cancel := context.WithTimeout(oidc.ClientContext(r.Context(), o.client), 15*time.Second)
	defer cancel()
	token, err := o.oauth.Exchange(ctx, query.Get("code"), oauth2.VerifierOption(pending.verifier))
	if err != nil {
		authJSONError(w, 401, "login_failed", "authorization code exchange failed")
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		authJSONError(w, 401, "login_failed", "identity provider returned no ID token")
		return
	}
	id, err := o.verifier.Verify(ctx, rawID)
	if err != nil || id.Subject == "" || id.IssuedAt.IsZero() || id.IssuedAt.After(time.Now().Add(time.Minute)) || !hmac.Equal([]byte(id.Nonce), []byte(pending.nonce)) {
		authJSONError(w, 401, "login_failed", "ID token validation failed")
		return
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
		authJSONError(w, 401, "login_failed", "access token binding failed")
		return
	}
	var claims map[string]json.RawMessage
	if err := id.Claims(&claims); err != nil {
		authJSONError(w, 401, "login_failed", "invalid identity claims")
		return
	}
	var azp string
	if value, exists := claims["azp"]; exists {
		if json.Unmarshal(value, &azp) != nil || azp != o.config.ClientID {
			authJSONError(w, 401, "login_failed", "invalid authorized party")
			return
		}
	} else if len(id.Audience) > 1 {
		authJSONError(w, 401, "login_failed", "missing authorized party")
		return
	}
	var groups []string
	if value, exists := claims[o.config.GroupsClaim]; exists {
		if json.Unmarshal(value, &groups) != nil {
			authJSONError(w, 401, "login_failed", "invalid group claim")
			return
		}
	}
	role := RoleViewer
	for _, group := range groups {
		mapped := o.config.GroupRoles[group]
		if mapped.level() > role.level() {
			role = mapped
		}
	}
	session, err := o.sessions.Issue(id.Subject, role)
	if err != nil {
		authJSONError(w, 503, "auth_unavailable", "could not create session")
		return
	}
	_ = json.Unmarshal(claims["name"], &session.Name)
	var emailVerified bool
	_ = json.Unmarshal(claims["email_verified"], &emailVerified)
	if emailVerified {
		_ = json.Unmarshal(claims["email"], &session.Email)
	}
	if len(session.Name) > 256 {
		session.Name = ""
	}
	if len(session.Email) > 320 {
		session.Email = ""
	}
	if len(session.Subject) > 512 {
		authJSONError(w, 401, "login_failed", "invalid subject")
		return
	}
	if err := o.sessions.SetSession(w, session); err != nil {
		authJSONError(w, 503, "auth_unavailable", "could not persist session")
		return
	}
	http.Redirect(w, r, o.config.SuccessPath, http.StatusSeeOther)
}
