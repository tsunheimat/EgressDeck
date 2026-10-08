package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const oidcTestRedirect = "https://controller.example/api/v1/auth/callback"

type oidcTestCode struct {
	nonce     string
	challenge string
}

// This issuer exercises discovery, authorization, JWKS, and token HTTP
// boundaries. It rejects any exchange that loses the exact redirect or PKCE
// binding established by the browser's authorization request.
type oidcTestIssuer struct {
	server     *httptest.Server
	key        *rsa.PrivateKey
	mu         sync.Mutex
	codes      map[string]oidcTestCode
	nextCode   int
	tokenCalls int
	variant    string
	groups     any
	failures   []string
}

func newOIDCTestIssuer(t *testing.T) *oidcTestIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &oidcTestIssuer{key: key, codes: make(map[string]oidcTestCode), groups: []string{"egress-operators"}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(func() {
		f.server.Close()
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, failure := range f.failures {
			t.Error(failure)
		}
	})
	return f
}

func (f *oidcTestIssuer) fail(w http.ResponseWriter, message string) {
	f.mu.Lock()
	f.failures = append(f.failures, message)
	f.mu.Unlock()
	http.Error(w, message, http.StatusBadRequest)
}

func (f *oidcTestIssuer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize",
			"token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case "/jwks":
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "fixture-key",
			"n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
		}}})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("client_id") != "controller-client" || q.Get("response_type") != "code" || q.Get("redirect_uri") != oidcTestRedirect || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || q.Get("nonce") == "" || q.Get("state") == "" || !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
			f.fail(w, "authorization request omitted exact redirect, nonce, state, or PKCE S256")
			return
		}
		f.mu.Lock()
		f.nextCode++
		code := fmt.Sprintf("authorization-code-%d", f.nextCode)
		f.codes[code] = oidcTestCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge")}
		f.mu.Unlock()
		callback, _ := url.Parse(oidcTestRedirect)
		callback.RawQuery = url.Values{"state": {q.Get("state")}, "code": {code}}.Encode()
		http.Redirect(w, r, callback.String(), http.StatusFound)
	case "/token":
		f.mu.Lock()
		f.tokenCalls++
		f.mu.Unlock()
		if r.Method != http.MethodPost || r.ParseForm() != nil {
			f.fail(w, "token exchange must use a form POST")
			return
		}
		client, secret, basic := r.BasicAuth()
		if !basic || client != "controller-client" || secret != "fixture-client-secret" || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != oidcTestRedirect {
			f.fail(w, "token exchange omitted client authentication or exact redirect")
			return
		}
		f.mu.Lock()
		code, found := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		variant, groups := f.variant, f.groups
		f.mu.Unlock()
		verifier := r.PostForm.Get("code_verifier")
		digest := sha256.Sum256([]byte(verifier))
		if !found || len(verifier) < 43 || len(verifier) > 128 || base64.RawURLEncoding.EncodeToString(digest[:]) != code.challenge {
			f.fail(w, "token exchange did not preserve authorization code and PKCE binding")
			return
		}
		claims := map[string]any{
			"iss": f.server.URL, "sub": "alice-subject", "aud": "controller-client",
			"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"nonce": code.nonce, "groups": groups, "name": "Alice", "email": "alice@example.com", "email_verified": true,
		}
		if variant == "token_error" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "private-provider-error-secret"})
			return
		}
		switch variant {
		case "issued_in_future":
			claims["iat"] = time.Now().Add(time.Hour).Unix()
		case "missing_issued_at":
			delete(claims, "iat")
		case "nonce":
			claims["nonce"] = "nonce-from-another-login"
		case "missing_nonce":
			delete(claims, "nonce")
		case "issuer":
			claims["iss"] = "https://other-issuer.example"
		case "audience":
			claims["aud"] = "another-client"
		case "expired":
			claims["exp"] = time.Now().Add(-time.Hour).Unix()
		case "subject":
			delete(claims, "sub")
		case "access_hash":
			claims["at_hash"] = "different-access-token-hash"
		case "azp":
			claims["azp"] = "another-client"
		case "multi_audience_no_azp":
			claims["aud"] = []string{"controller-client", "another-client"}
		case "multi_audience":
			claims["aud"] = []string{"controller-client", "another-client"}
			claims["azp"] = "controller-client"
		case "unverified_email":
			claims["email_verified"] = false
		case "custom_groups":
			claims["permissions"] = groups
			claims["groups"] = []string{"egress-admins"}
		}
		raw, err := f.sign(claims)
		if err != nil {
			f.fail(w, "sign ID token: "+err.Error())
			return
		}
		if variant == "signature" {
			parts := strings.Split(raw, ".")
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			sig[0] ^= 1
			raw = parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
		}
		response := map[string]any{"token_type": "Bearer", "access_token": "private-oauth-access-token", "refresh_token": "private-oauth-refresh-token", "expires_in": 3600}
		if variant != "missing_id_token" {
			response["id_token"] = raw
		}
		_ = json.NewEncoder(w).Encode(response)
	default:
		http.NotFound(w, r)
	}
}

func (f *oidcTestIssuer) sign(claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "fixture-key"})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), err
}

func (f *oidcTestIssuer) exchanges() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenCalls
}

func newOIDCTestFlow(t *testing.T, f *oidcTestIssuer, configure func(*OIDCConfig)) (*OIDC, *SessionManager) {
	t.Helper()
	sessions := NewSessionManager([]byte("01234567890123456789012345678901"))
	cfg := OIDCConfig{
		IssuerURL: f.server.URL, ClientID: "controller-client", ClientSecret: "fixture-client-secret",
		RedirectURL: oidcTestRedirect, HTTPClient: f.server.Client(),
		GroupRoles: map[string]Role{"egress-operators": RoleOperator, "egress-admins": RoleAdmin},
	}
	if configure != nil {
		configure(&cfg)
	}
	flow, err := NewOIDC(context.Background(), cfg, sessions)
	if err != nil {
		t.Fatal(err)
	}
	return flow, sessions
}

func startOIDCTestLogin(t *testing.T, f *oidcTestIssuer, flow *OIDC) (*http.Cookie, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://controller.example/api/v1/auth/login?next=https://attacker.example", nil)
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	req.Header.Set("X-Forwarded-Proto", "http")
	rec := httptest.NewRecorder()
	flow.Login(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("start login: %d %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != loginCookieName || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/api/v1/auth/callback" || cookies[0].MaxAge <= 0 {
		t.Fatalf("login cookie lacks required scope or flags: %#v", cookies)
	}
	client := *f.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Get(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("issuer rejected authorization request: %d", response.StatusCode)
	}
	return cookies[0], response.Header.Get("Location")
}

func callOIDCTestCallback(flow *OIDC, callback string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, callback, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	flow.Callback(rec, req)
	return rec
}

func assertOIDCTestNoSession(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == defaultSessionCookie || cookie.Name == defaultCSRFCookie {
			t.Fatalf("failed login issued an application cookie: %s", cookie.Name)
		}
	}
}

func TestOIDCAuthenticatesThroughTLSIssuerAndMapsExactGroups(t *testing.T) {
	f := newOIDCTestIssuer(t)
	for _, tc := range []struct {
		name, variant string
		groups        any
		role          Role
	}{
		{"operator", "", []string{"egress-operators"}, RoleOperator},
		{"strongest", "", []string{"egress-operators", "egress-admins"}, RoleAdmin},
		{"unmapped", "", []string{"admin", "EGRESS-ADMINS", "egress-admins-extra"}, RoleViewer},
		{"no_groups", "", nil, RoleViewer},
		{"custom_claim", "custom_groups", []string{"egress-operators"}, RoleOperator},
		{"multiple_audiences", "multi_audience", []string{"egress-operators"}, RoleOperator},
		{"unverified_email", "unverified_email", []string{"egress-operators"}, RoleOperator},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.mu.Lock()
			f.variant, f.groups = tc.variant, tc.groups
			f.mu.Unlock()
			flow, sessions := newOIDCTestFlow(t, f, func(cfg *OIDCConfig) {
				if tc.variant == "custom_groups" {
					cfg.GroupsClaim = "permissions"
				}
			})
			cookie, callback := startOIDCTestLogin(t, f, flow)
			before := f.exchanges()
			rec := callOIDCTestCallback(flow, callback, cookie)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("callback: %d %s", rec.Code, rec.Body.String())
			}
			if f.exchanges() != before+1 {
				t.Fatal("successful callback did not perform exactly one code exchange")
			}
			request := httptest.NewRequest(http.MethodGet, "https://controller.example/api/v1/auth/session", nil)
			clearedState := false
			for _, responseCookie := range rec.Result().Cookies() {
				request.AddCookie(responseCookie)
				if responseCookie.Name == loginCookieName && responseCookie.MaxAge < 0 {
					clearedState = true
				}
				if responseCookie.Name == defaultSessionCookie && (!responseCookie.Secure || !responseCookie.HttpOnly) {
					t.Fatal("application session cookie is not secure and HTTP-only")
				}
			}
			session, err := sessions.Read(request)
			if err != nil || session.Subject != "alice-subject" || HighestRole(session.Roles) != tc.role || session.Name != "Alice" || session.CSRFToken == "" || !clearedState {
				t.Fatalf("session: %#v, %v, state cleared=%v", session, err, clearedState)
			}
			if (tc.variant == "unverified_email" && session.Email != "") || (tc.variant != "unverified_email" && session.Email != "alice@example.com") {
				t.Fatalf("unexpected verified email handling: %q", session.Email)
			}
			payload, _ := json.Marshal(session)
			for _, secret := range []string{"private-oauth-access-token", "private-oauth-refresh-token", "fixture-client-secret", "authorization-code-", "id_token"} {
				if strings.Contains(string(payload), secret) || strings.Contains(rec.Body.String(), secret) {
					t.Fatalf("OAuth secret %q escaped into application state", secret)
				}
			}
			replay := callOIDCTestCallback(flow, callback, cookie)
			if replay.Code != http.StatusBadRequest || f.exchanges() != before+1 {
				t.Fatal("replay performed another exchange or issued a session")
			}
			assertOIDCTestNoSession(t, replay)
		})
	}
}

func TestOIDCRejectsInvalidTokensAndConsumesFailedLogin(t *testing.T) {
	f := newOIDCTestIssuer(t)
	for _, variant := range []string{"token_error", "issued_in_future", "missing_issued_at", "nonce", "missing_nonce", "signature", "issuer", "audience", "expired", "subject", "missing_id_token", "access_hash", "azp", "multi_audience_no_azp", "malformed_groups"} {
		t.Run(variant, func(t *testing.T) {
			f.mu.Lock()
			f.variant, f.groups = variant, []string{"egress-admins"}
			if variant == "malformed_groups" {
				f.groups = "egress-admins"
			}
			f.mu.Unlock()
			flow, _ := newOIDCTestFlow(t, f, nil)
			cookie, callback := startOIDCTestLogin(t, f, flow)
			before := f.exchanges()
			rec := callOIDCTestCallback(flow, callback, cookie)
			if rec.Code != http.StatusUnauthorized || f.exchanges() != before+1 {
				t.Fatalf("invalid %s: status=%d body=%s exchanges=%d", variant, rec.Code, rec.Body.String(), f.exchanges()-before)
			}
			assertOIDCTestNoSession(t, rec)
			if strings.Contains(rec.Body.String(), "private-provider-error-secret") {
				t.Fatal("token endpoint error leaked")
			}
			replay := callOIDCTestCallback(flow, callback, cookie)
			if replay.Code != http.StatusBadRequest || f.exchanges() != before+1 {
				t.Fatalf("failed %s login state was reusable", variant)
			}
			assertOIDCTestNoSession(t, replay)
		})
	}
}

func TestOIDCRequiresBrowserBoundStateAndExactCallback(t *testing.T) {
	f := newOIDCTestIssuer(t)
	flow, _ := newOIDCTestFlow(t, f, nil)
	cookie, callback := startOIDCTestLogin(t, f, flow)
	otherCookie, _ := startOIDCTestLogin(t, f, flow)
	for _, tc := range []struct {
		name   string
		edit   func(*url.URL)
		cookie *http.Cookie
	}{
		{"no_cookie", nil, nil},
		{"different_browser", nil, otherCookie},
		{"unknown_state", func(u *url.URL) { q := u.Query(); q.Set("state", "unknown"); u.RawQuery = q.Encode() }, cookie},
		{"missing_state", func(u *url.URL) { q := u.Query(); q.Del("state"); u.RawQuery = q.Encode() }, cookie},
		{"duplicate_state", func(u *url.URL) { q := u.Query(); q.Add("state", q.Get("state")); u.RawQuery = q.Encode() }, cookie},
		{"duplicate_code", func(u *url.URL) { q := u.Query(); q.Add("code", q.Get("code")); u.RawQuery = q.Encode() }, cookie},
		{"wrong_host", func(u *url.URL) { u.Host = "attacker.example" }, cookie},
		{"wrong_path", func(u *url.URL) { u.Path += "/other" }, cookie},
		{"wrong_response_issuer", func(u *url.URL) {
			q := u.Query()
			q.Set("iss", "https://other-issuer.example")
			u.RawQuery = q.Encode()
		}, cookie},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := url.Parse(callback)
			if tc.edit != nil {
				tc.edit(u)
			}
			rec := callOIDCTestCallback(flow, u.String(), tc.cookie)
			if rec.Code != http.StatusBadRequest || f.exchanges() != 0 {
				t.Fatalf("invalid callback reached token exchange: %d %s", rec.Code, rec.Body.String())
			}
			assertOIDCTestNoSession(t, rec)
		})
	}
	// Invalid browser binding must not let an attacker consume another
	// browser's pending state before its legitimate callback arrives.
	if rec := callOIDCTestCallback(flow, callback, cookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("legitimate browser could not finish after rejected attempts: %d %s", rec.Code, rec.Body.String())
	}
}

func TestOIDCProviderDenialConsumesStateWithoutExchange(t *testing.T) {
	f := newOIDCTestIssuer(t)
	flow, _ := newOIDCTestFlow(t, f, nil)
	cookie, callback := startOIDCTestLogin(t, f, flow)
	u, _ := url.Parse(callback)
	q := u.Query()
	q.Del("code")
	q.Set("error", "access_denied")
	u.RawQuery = q.Encode()
	rec := callOIDCTestCallback(flow, u.String(), cookie)
	if rec.Code != http.StatusUnauthorized || f.exchanges() != 0 {
		t.Fatalf("provider denial: %d %s", rec.Code, rec.Body.String())
	}
	assertOIDCTestNoSession(t, rec)
	if replay := callOIDCTestCallback(flow, callback, cookie); replay.Code != http.StatusBadRequest || f.exchanges() != 0 {
		t.Fatal("provider-denied login could be retried with its original code")
	}
}

func TestOIDCConcurrentCallbacksExchangeCodeOnlyOnce(t *testing.T) {
	f := newOIDCTestIssuer(t)
	flow, _ := newOIDCTestFlow(t, f, nil)
	cookie, callback := startOIDCTestLogin(t, f, flow)
	const attempts = 12
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			<-start
			results <- callOIDCTestCallback(flow, callback, cookie)
		}()
	}
	close(start)
	succeeded := 0
	for i := 0; i < attempts; i++ {
		rec := <-results
		if rec.Code == http.StatusSeeOther {
			succeeded++
			continue
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("concurrent callback: %d %s", rec.Code, rec.Body.String())
		}
		assertOIDCTestNoSession(t, rec)
	}
	if succeeded != 1 || f.exchanges() != 1 {
		t.Fatalf("concurrent callbacks issued %d sessions from %d exchanges", succeeded, f.exchanges())
	}
}

func TestOIDCPendingLoginsExpireAndHaveBoundedCapacity(t *testing.T) {
	f := newOIDCTestIssuer(t)
	flow, sessions := newOIDCTestFlow(t, f, func(cfg *OIDCConfig) { cfg.MaxPendingLogins = 1; cfg.LoginTTL = time.Second })
	now := time.Now()
	sessions.now = func() time.Time { return now }
	cookie, callback := startOIDCTestLogin(t, f, flow)
	rec := httptest.NewRecorder()
	flow.Login(rec, httptest.NewRequest(http.MethodGet, "https://controller.example/api/v1/auth/login", nil))
	if rec.Code != http.StatusServiceUnavailable || len(rec.Result().Cookies()) != 0 {
		t.Fatal("pending login bound allowed another login")
	}
	now = now.Add(time.Second)
	rec = callOIDCTestCallback(flow, callback, cookie)
	if rec.Code != http.StatusBadRequest || f.exchanges() != 0 {
		t.Fatal("expired state reached token exchange")
	}
	assertOIDCTestNoSession(t, rec)
	startOIDCTestLogin(t, f, flow)
}

func TestOIDCRejectsUnsafeConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*OIDCConfig, *SessionManager)
	}{
		{"short_session_secret", func(_ *OIDCConfig, s *SessionManager) { s.secretValid = false }},
		{"empty_client", func(c *OIDCConfig, _ *SessionManager) { c.ClientID = "" }},
		{"remote_http_issuer", func(c *OIDCConfig, _ *SessionManager) { c.IssuerURL = "http://issuer.example" }},
		{"issuer_query", func(c *OIDCConfig, _ *SessionManager) { c.IssuerURL += "?x=y" }},
		{"redirect_userinfo", func(c *OIDCConfig, _ *SessionManager) {
			c.RedirectURL = "https://user:password@controller.example/callback"
		}},
		{"redirect_query", func(c *OIDCConfig, _ *SessionManager) { c.RedirectURL += "?redirect=https://attacker.example" }},
		{"insecure_cookie", func(_ *OIDCConfig, s *SessionManager) { s.secure = false }},
		{"script_readable_session", func(_ *OIDCConfig, s *SessionManager) { s.httpOnly = false }},
		{"external_success", func(c *OIDCConfig, _ *SessionManager) { c.SuccessPath = "//attacker.example" }},
		{"encoded_external_success", func(c *OIDCConfig, _ *SessionManager) { c.SuccessPath = "/%2fattacker.example" }},
		{"unknown_role", func(c *OIDCConfig, _ *SessionManager) { c.GroupRoles = map[string]Role{"admins": "superuser"} }},
		{"unbounded_state", func(c *OIDCConfig, _ *SessionManager) { c.MaxPendingLogins = 10001 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := OIDCConfig{IssuerURL: "https://issuer.example", ClientID: "controller-client", RedirectURL: oidcTestRedirect}
			sessions := NewSessionManager([]byte("01234567890123456789012345678901"))
			tc.edit(&cfg, sessions)
			if _, err := NewOIDC(context.Background(), cfg, sessions); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}
}
