package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/auth"
)

const controllerTestSecret = "controller-session-signing-secret-at-least-32-bytes"

func staticFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "assets"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"index.html": "<!doctype html><title>EgressDeck</title>", "assets/app-hash.js": "console.log('EgressDeck')", ".env": "private value"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func controllerFixture(t *testing.T, cfg httpConfig) http.Handler {
	t.Helper()
	if cfg.StaticDir == "" {
		cfg.StaticDir = staticFixture(t)
	}
	handler, err := newControllerHTTP(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/unknown" {
			w.WriteHeader(http.StatusNotFound)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"handled_by": "api"})
	}), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestControllerServesPublicSPAWithoutAPIHTMLFallback(t *testing.T) {
	handler := controllerFixture(t, httpConfig{AuthMode: "header", SessionSecret: []byte(controllerTestSecret), IdentityHeaderSecret: []byte(controllerTestSecret)})
	for _, tc := range []struct {
		method, path string
		status       int
		body         string
	}{
		{"GET", "/", 200, "<!doctype html>"},
		{"GET", "/devices/group-1", 200, "<!doctype html>"},
		{"HEAD", "/devices/group-1", 200, ""},
		{"GET", "/assets/app-hash.js", 200, "console.log"},
		{"HEAD", "/assets/app-hash.js", 200, ""},
		{"POST", "/", 405, "method not allowed"},
		{"GET", "/assets/missing.js", 404, "404"},
		{"GET", "/missing.css", 404, "404"},
		{"GET", "/assets", 404, "404"},
		{"GET", "/.env", 404, "404"},
		{"GET", "/api", 401, "authentication required"},
		{"GET", "//api", 404, "404"},
		{"GET", "//api/v1/providers", 404, "404"},
		{"GET", "/api/v1/providers", 401, "authentication required"},
		{"GET", "/api/v1/auth/session", 401, "authentication required"},
		{"GET", "/api/v1/auth/missing", 404, "404"},
		{"GET", "/healthz", 200, `"handled_by":"api"`},
		{"GET", "/readyz", 200, `"handled_by":"api"`},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.status || (tc.method != "HEAD" && !strings.Contains(rec.Body.String(), tc.body)) || (tc.method == "HEAD" && rec.Body.Len() != 0) {
				t.Fatalf("status=%d body=%q, want %d containing %q", rec.Code, rec.Body.String(), tc.status, tc.body)
			}
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("nosniff header missing")
			}
		})
	}
}

func TestStaticFilesRejectTraversalAndSymlinkEscapes(t *testing.T) {
	root := staticFixture(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	handler, err := newSPAHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/../secret.txt", "/%2e%2e/secret.txt", "/escape/secret.txt", "/assets/../index.html", "/api/v1/missing", "/assets\\secret.txt"} {
		t.Run(target, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest("GET", target, nil))
			if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "outside-secret") {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	if _, err := newSPAHandler(t.TempDir()); err == nil {
		t.Fatal("missing frontend entrypoint accepted")
	}
}

func loginController(t *testing.T, handler http.Handler, role string) []*http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.Header.Set("X-Auth-Request-User", "alice")
	req.Header.Set("X-Auth-Request-Role", role)
	mac := hmac.New(sha256.New, []byte(controllerTestSecret))
	_, _ = mac.Write([]byte("alice\x00" + role))
	req.Header.Set("X-Auth-Request-Signature", base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("login status=%d body=%s", rec.Code, rec.Body.String())
	}
	return rec.Result().Cookies()
}

func TestControllerEnforcesRolesAndCSRFAtAPIBoundary(t *testing.T) {
	handler := controllerFixture(t, httpConfig{AuthMode: "header", SessionSecret: []byte(controllerTestSecret), IdentityHeaderSecret: []byte(controllerTestSecret)})
	for _, tc := range []struct {
		role, method, path string
		csrf               bool
		status             int
	}{
		{"viewer", "GET", "/api/v1/providers", false, 200},
		{"viewer", "GET", "/api/v1/gateways", false, 200},
		{"viewer", "POST", "/api/v1/providers", true, 403},
		{"viewer", "PUT", "/api/v1/outbound-groups/group-1/selection", true, 403},
		{"operator", "PUT", "/api/v1/outbound-groups/group-1/selection", false, 403},
		{"operator", "PUT", "/api/v1/outbound-groups/group-1/selection", true, 200},
		{"operator", "POST", "/api/v1/providers/provider-1/revisions/2/apply", true, 200},
		{"operator", "POST", "/api/v1/deployments/preview", true, 200},
		{"viewer", "POST", "/api/v1/operations", true, 403},
		{"operator", "POST", "/api/v1/operations", false, 403},
		{"operator", "POST", "/api/v1/operations", true, 200},
		{"operator", "POST", "/api/v1/probes/node", true, 200},
		{"operator", "POST", "/api/v1/providers", true, 403},
		{"operator", "POST", "/api/v1/providers/provider-1/refresh", true, 403},
		{"operator", "POST", "/api/v1/gateways", true, 403},
		{"operator", "POST", "/api/v1/devices", true, 403},
		{"operator", "PUT", "/api/v1/policies/policy-1", true, 403},
		{"operator", "DELETE", "/api/v1/outbound-groups/group-1/selection", true, 403},
		{"operator", "POST", "/api/v1/providers/provider-1/revisions/2/apply/more", true, 403},
		{"operator", "POST", "/api/v1/new-mutation", true, 403},
		{"admin", "POST", "/api/v1/devices", false, 403},
		{"admin", "POST", "/api/v1/devices", true, 200},
		{"viewer", "GET", "/api/v1/unknown", false, 404},
	} {
		t.Run(tc.role+" "+tc.method+" "+tc.path+" csrf="+map[bool]string{true: "yes", false: "no"}[tc.csrf], func(t *testing.T) {
			cookies := loginController(t, handler, tc.role)
			req := httptest.NewRequest(tc.method, tc.path, nil)
			for _, cookie := range cookies {
				req.AddCookie(cookie)
				if tc.csrf && cookie.Name == "egressdeck_csrf" {
					req.Header.Set("X-CSRF-Token", cookie.Value)
				}
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status || strings.Contains(rec.Body.String(), "<!doctype") {
				t.Fatalf("status=%d body=%s want=%d", rec.Code, rec.Body.String(), tc.status)
			}
		})
	}
	unsigned := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	unsigned.Header.Set("X-Auth-Request-User", "attacker")
	unsigned.Header.Set("X-Auth-Request-Role", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, unsigned)
	if rec.Code != 401 || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("unsigned identity accepted: status=%d cookies=%v", rec.Code, rec.Result().Cookies())
	}
}

func TestDisabledAuthenticationReportsExplicitDevelopmentIdentity(t *testing.T) {
	handler := controllerFixture(t, httpConfig{AuthMode: "disabled"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/auth/session", nil))
	var session struct {
		Subject                string      `json:"subject"`
		Roles                  []auth.Role `json:"roles"`
		AuthenticationDisabled bool        `json:"authentication_disabled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || !session.AuthenticationDisabled || session.Subject != "development" || !auth.HasRole(session.Roles, auth.RoleAdmin) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("development session: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOperatorCannotMutateObjectThroughEncodedActionPath(t *testing.T) {
	mutations := 0
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /api/v1/outbound-groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		mutations++
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/v1/providers/{id}", func(w http.ResponseWriter, r *http.Request) {
		mutations++
		w.WriteHeader(http.StatusNoContent)
	})
	handler, err := newControllerHTTP(context.Background(), mux, httpConfig{AuthMode: "header", SessionSecret: []byte(controllerTestSecret), IdentityHeaderSecret: []byte(controllerTestSecret), StaticDir: staticFixture(t)})
	if err != nil {
		t.Fatal(err)
	}
	cookies := loginController(t, handler, "operator")
	for _, tc := range []struct{ method, path string }{
		{"PUT", "/api/v1/outbound-groups/group-1%2Fselection"},
		{"POST", "/api/v1/providers/provider-1%2Frevisions%2F2%2Fapply"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
			if cookie.Name == "egressdeck_csrf" {
				req.Header.Set("X-CSRF-Token", cookie.Value)
			}
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || mutations != 0 {
			t.Fatalf("encoded path %s reached administrator mutation: status=%d mutations=%d", tc.path, rec.Code, mutations)
		}
	}
}

func TestConfigurationRequiresExplicitSecureAuthentication(t *testing.T) {
	for _, name := range []string{"AUTH_MODE", "SESSION_SECRET", "IDENTITY_HEADER_SECRET", "COOKIE_SECURE", "STATIC_DIR", "OIDC_ISSUER_URL", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_REDIRECT_URL", "OIDC_GROUPS_CLAIM", "OIDC_SUCCESS_PATH", "OIDC_GROUP_ROLES", "OIDC_SCOPES"} {
		t.Setenv(name, "")
	}
	cfg, err := loadHTTPConfig()
	if cfg.AuthMode != "session" || err == nil {
		t.Fatalf("default auth=%q error=%v", cfg.AuthMode, err)
	}
	t.Setenv("SESSION_SECRET", controllerTestSecret)
	t.Setenv("IDENTITY_HEADER_SECRET", controllerTestSecret)
	if _, err := loadHTTPConfig(); err == nil {
		t.Fatal("signed headers silently substituted for OIDC session mode")
	}
	t.Setenv("AUTH_MODE", "header")
	if _, err := loadHTTPConfig(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IDENTITY_HEADER_SECRET", "short")
	if _, err := loadHTTPConfig(); err == nil {
		t.Fatal("short header secret accepted")
	}
	t.Setenv("AUTH_MODE", "session")
	t.Setenv("OIDC_ISSUER_URL", "https://identity.example/application/o/egressdeck/")
	t.Setenv("OIDC_CLIENT_ID", "egressdeck")
	t.Setenv("OIDC_REDIRECT_URL", "https://controller.example/api/v1/auth/callback")
	t.Setenv("OIDC_GROUP_ROLES", `{"network-admins":"administrator","network-operators":"operator"}`)
	cfg, err = loadHTTPConfig()
	if err != nil || !cfg.CookieSecure || cfg.OIDC.GroupRoles["network-admins"] != auth.RoleAdmin || cfg.StaticDir != "/usr/share/egressdeck/web" {
		t.Fatalf("OIDC config=%+v error=%v", cfg, err)
	}
	t.Setenv("OIDC_GROUP_ROLES", `{"network-admins":"superuser"}`)
	if _, err := loadHTTPConfig(); err == nil {
		t.Fatal("unknown mapped role accepted")
	}
}

func TestOIDCRoutesUseExactConfiguredCallback(t *testing.T) {
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer.URL, "authorization_endpoint": issuer.URL + "/authorize", "token_endpoint": issuer.URL + "/token", "jwks_uri": issuer.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
	}))
	defer issuer.Close()
	handler := controllerFixture(t, httpConfig{
		AuthMode: "session", SessionSecret: []byte(controllerTestSecret), IdentityHeaderSecret: []byte(controllerTestSecret), CookieSecure: true,
		OIDC: auth.OIDCConfig{IssuerURL: issuer.URL, ClientID: "controller", RedirectURL: "https://controller.example/signin/callback", HTTPClient: issuer.Client()},
	})
	login := httptest.NewRecorder()
	handler.ServeHTTP(login, httptest.NewRequest("GET", "https://controller.example/api/v1/auth/oidc/login", nil))
	if login.Code != 302 || !strings.HasPrefix(login.Header().Get("Location"), issuer.URL+"/authorize?") {
		t.Fatalf("OIDC login status=%d body=%s location=%q", login.Code, login.Body.String(), login.Header().Get("Location"))
	}
	callback := httptest.NewRecorder()
	handler.ServeHTTP(callback, httptest.NewRequest("GET", "https://controller.example/signin/callback", nil))
	if callback.Code != 400 || !strings.Contains(callback.Body.String(), "invalid_login_state") || strings.Contains(callback.Body.String(), "<!doctype") {
		t.Fatalf("callback went to SPA: status=%d body=%s", callback.Code, callback.Body.String())
	}
	for _, target := range []string{"/api/v1/auth/login", "/api/v1/auth/callback", "/api/v1/auth/oidc/missing"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("POST", "https://controller.example"+target, nil))
		if rec.Code != 404 {
			t.Fatalf("unexpected legacy route at %s: status=%d body=%s", target, rec.Code, rec.Body.String())
		}
	}
}

func TestControllerStartupRequiresEncryptionKey(t *testing.T) {
	if os.Getenv("EGRESSDECK_TEST_STARTUP") == "1" {
		main()
		return
	}
	for _, key := range []string{"", "not-base64", base64.StdEncoding.EncodeToString([]byte("short"))} {
		root := t.TempDir()
		command := exec.Command(os.Args[0], "-test.run=^TestControllerStartupRequiresEncryptionKey$")
		command.Env = append(os.Environ(), "EGRESSDECK_TEST_STARTUP=1", "AUTH_MODE=disabled", "COOKIE_SECURE=true", "OIDC_GROUP_ROLES=", "APP_ENCRYPTION_KEY="+key, "STORAGE_PATH="+filepath.Join(root, "store.json"))
		output, err := command.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "APP_ENCRYPTION_KEY must be a base64-encoded 32-byte encryption key") {
			t.Fatalf("startup with invalid key: error=%v output=%s", err, output)
		}
		if _, err := os.Stat(filepath.Join(root, "store.json")); !os.IsNotExist(err) {
			t.Fatalf("startup touched persistence before validating encryption key: %v", err)
		}
	}
}
