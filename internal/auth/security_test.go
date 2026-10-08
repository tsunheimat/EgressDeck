package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testManager(t *testing.T) *SessionManager {
	t.Helper()
	return NewSessionManager([]byte("test-secret-that-is-long-enough-for-aes"), WithSecureCookies(false))
}

func TestRolesAreHierarchicalAndNormalized(t *testing.T) {
	if got, ok := ParseRole(" ADMIN "); !ok || got != RoleAdmin {
		t.Fatalf("ParseRole(admin) = %q, %v", got, ok)
	}
	roles := NormalizeRoles([]Role{"unknown", RoleViewer, RoleAdmin, RoleViewer, Role("administrator")})
	if !reflect.DeepEqual(roles, []Role{RoleAdmin, RoleViewer}) {
		t.Fatalf("normalized roles = %#v", roles)
	}
	if !HasRole(roles, RoleViewer) || !HasRole(roles, RoleAdmin) || HasRole([]Role{RoleViewer}, RoleAdmin) {
		t.Fatal("role hierarchy is incorrect")
	}
}

func TestSessionRoundTripAndTamperRejection(t *testing.T) {
	m := testManager(t)
	session, err := m.Issue("alice", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	if err := m.SetSession(response, session); err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 2 || !cookies[0].HttpOnly || cookies[0].Secure || cookies[1].HttpOnly {
		t.Fatalf("session/csrf cookie flags = %#v", cookies)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	got, err := m.Read(req)
	if err != nil || got.Subject != "alice" || !HasRole(got.Roles, RoleOperator) {
		t.Fatalf("round trip = %#v, %v", got, err)
	}
	bad := *cookies[0]
	bad.Value = strings.TrimSuffix(bad.Value, "a") + "b"
	tampered := httptest.NewRequest(http.MethodGet, "/", nil)
	tampered.AddCookie(&bad)
	if _, err := m.Read(tampered); err == nil {
		t.Fatal("tampered cookie accepted")
	}
}

func TestCSRFRequiresMatchingCookieHeaderAndSession(t *testing.T) {
	m := testManager(t)
	session, err := m.Issue("alice", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	if err := m.SetSession(response, session); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", nil)
	for _, cookie := range response.Result().Cookies() {
		req.AddCookie(cookie)
	}
	if err := m.ValidateRequestCSRF(req); err == nil {
		t.Fatal("missing CSRF header accepted")
	}
	req.Header.Set(m.CSRFHeaderName(), session.CSRFToken)
	if err := m.ValidateRequestCSRF(req); err != nil {
		t.Fatalf("valid CSRF rejected: %v", err)
	}
	if err := m.ValidateCSRF(httptest.NewRequest(http.MethodGet, "/", nil), session); err != nil {
		t.Fatalf("safe request rejected: %v", err)
	}
}

func TestMiddlewareRoleAndCSRFResponses(t *testing.T) {
	m := testManager(t)
	session, err := m.Issue("alice", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRecorder()
	if err := m.SetSession(login, session); err != nil {
		t.Fatal(err)
	}
	request := func(method string) *http.Request {
		r := httptest.NewRequest(method, "/api/v1/devices", nil)
		for _, cookie := range login.Result().Cookies() {
			r.AddCookie(cookie)
		}
		return r
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	record := httptest.NewRecorder()
	NewMiddleware(m).Require(RoleOperator)(next).ServeHTTP(record, request(http.MethodGet))
	if record.Code != http.StatusForbidden {
		t.Fatalf("viewer allowed as operator: %d", record.Code)
	}
	record = httptest.NewRecorder()
	NewMiddleware(m).Require(RoleViewer)(next).ServeHTTP(record, request(http.MethodGet))
	if record.Code != http.StatusNoContent {
		t.Fatalf("viewer denied viewer endpoint: %d", record.Code)
	}
	record = httptest.NewRecorder()
	NewMiddleware(m).CSRF(next).ServeHTTP(record, request(http.MethodPost))
	if record.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF accepted: %d", record.Code)
	}
}

func TestRedactionDoesNotMutateInputs(t *testing.T) {
	input := map[string]any{"name": "gateway", "token": "s3cret", "nested": map[string]any{"password": "pw"}}
	redacted := RedactMap(input)
	if redacted["token"] != RedactedValue() || redacted["nested"].(map[string]any)["password"] != RedactedValue() {
		t.Fatalf("redacted = %#v", redacted)
	}
	if input["token"] != "s3cret" || input["nested"].(map[string]any)["password"] != "pw" {
		t.Fatal("redaction mutated source")
	}
	h := http.Header{"Authorization": {"Bearer abc"}, "X-Trace": {"one", "two"}}
	hidden := RedactHeaders(h)
	if hidden.Get("Authorization") != RedactedValue() || !reflect.DeepEqual(hidden.Values("X-Trace"), []string{"one", "two"}) {
		t.Fatalf("redacted headers = %#v", hidden)
	}
	u := RedactURL("https://user:pw@example.test/path?token=abc&name=ok")
	if strings.Contains(u, "pw") || strings.Contains(u, "abc") || !strings.Contains(u, "name=ok") {
		t.Fatalf("redacted URL = %q", u)
	}
	if got := RedactQuery(url.Values{"password": {"pw"}, "x": {"1"}}).Get("password"); got != RedactedValue() {
		t.Fatalf("redacted query = %q", got)
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	m := NewSessionManager([]byte("test-secret-that-is-long-enough-for-aes"), WithSecureCookies(false), WithClock(func() time.Time { return now }), WithSessionTTL(time.Minute))
	session, err := m.Issue("alice", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := m.SessionCookie(session); err != ErrSessionExpired {
		t.Fatalf("expired session error = %v", err)
	}
}

func TestSignedIdentityHeaderBoundary(t *testing.T) {
	secret := []byte("proxy-identity-signing-secret-at-least-32-bytes")
	m := NewSessionManager([]byte("test-secret-that-is-long-enough-for-aes"), WithSecureCookies(false), WithIdentityHeaderSecret(secret))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.Header.Set("X-Auth-Request-User", "alice")
	req.Header.Set("X-Auth-Request-Role", "operator")
	if m.VerifyIdentityHeaders(req) {
		t.Fatal("unsigned identity headers accepted")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("alice\x00operator"))
	req.Header.Set("X-Auth-Request-Signature", base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	if !m.VerifyIdentityHeaders(req) {
		t.Fatal("valid identity assertion rejected")
	}
	req.Header.Set("X-Auth-Request-Role", "admin")
	if m.VerifyIdentityHeaders(req) {
		t.Fatal("role substitution accepted")
	}
}
