package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"testing"
)

func TestHTTPLoginRequiresTrustedIdentityHeader(t *testing.T) {
	m := NewSessionManager([]byte("01234567890123456789012345678901"), WithSecureCookies(false))
	h := NewHTTP(m)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != 401 {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestHTTPLoginIssuesSessionAndCSRFCookie(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	m := NewSessionManager(secret, WithSecureCookies(false), WithIdentityHeaderSecret(secret))
	h := NewHTTP(m)
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.Header.Set("X-Auth-Request-User", "alice")
	req.Header.Set("X-Auth-Request-Role", "operator")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("alice\x00operator"))
	req.Header.Set("X-Auth-Request-Signature", base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != 201 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies=%d", len(cookies))
	}
	if cookies[0].Name != defaultSessionCookie || cookies[1].Name != defaultCSRFCookie {
		t.Fatalf("cookies=%v", cookies)
	}
}

func TestHTTPRejectsUnsignedIdentityEvenWithSubjectAndRole(t *testing.T) {
	h := NewHTTP(NewSessionManager([]byte("01234567890123456789012345678901")))
	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.Header.Set("X-Auth-Request-User", "attacker")
	req.Header.Set("X-Auth-Request-Role", "admin")
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	if rec.Code != 401 || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("unsigned login: %d %s", rec.Code, rec.Body.String())
	}
}
