package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	defaultSessionCookie = "egressdeck_session"
	defaultCSRFCookie    = "egressdeck_csrf"
	defaultCSRFHeader    = "X-CSRF-Token"
	defaultSessionTTL    = 12 * time.Hour
)

var (
	ErrNoSession      = errors.New("authentication required")
	ErrInvalidSession = errors.New("invalid session")
	ErrSessionExpired = errors.New("session expired")
	ErrCSRF           = errors.New("csrf validation failed")
	ErrInvalidCSRF    = errors.New("invalid csrf token")
	ErrInvalidRole    = errors.New("session has no recognized role")
)

// Session is the authenticated application identity. It is serialized into
// an encrypted, authenticated cookie; OPNsense or gateway credentials must
// never be put in this value.
type Session struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	Email     string    `json:"email,omitempty"`
	Name      string    `json:"name,omitempty"`
	Roles     []Role    `json:"roles"`
	CSRFToken string    `json:"csrf_token"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s Session) ValidAt(now time.Time) error {
	if strings.TrimSpace(s.ID) == "" || strings.TrimSpace(s.Subject) == "" {
		return ErrInvalidSession
	}
	if strings.TrimSpace(s.CSRFToken) == "" {
		return ErrInvalidSession
	}
	if s.ExpiresAt.IsZero() || !now.Before(s.ExpiresAt) {
		return ErrSessionExpired
	}
	if !s.IssuedAt.IsZero() && s.IssuedAt.After(now.Add(5*time.Minute)) {
		return ErrInvalidSession
	}
	if len(NormalizeRoles(s.Roles)) == 0 {
		return ErrInvalidRole
	}
	return nil
}

// SessionManager issues encrypted cookies and validates their expiry and
// integrity. It is stateless by default, which permits a controller restart
// without invalidating already issued sessions; applications that need
// immediate revocation should add a short TTL and a revocation check around
// Authenticate.
type SessionManager struct {
	key         [32]byte
	secretValid bool
	cookieName  string
	csrfName    string
	csrfHeader  string
	ttl         time.Duration
	path        string
	domain      string
	secure      bool
	httpOnly    bool
	sameSite    http.SameSite
	identityMAC []byte
	now         func() time.Time
}

type SessionOption func(*SessionManager)

func WithSessionCookieName(name string) SessionOption {
	return func(m *SessionManager) {
		if strings.TrimSpace(name) != "" {
			m.cookieName = name
		}
	}
}
func WithCSRFCookieName(name string) SessionOption {
	return func(m *SessionManager) {
		if strings.TrimSpace(name) != "" {
			m.csrfName = name
		}
	}
}
func WithCSRFHeader(name string) SessionOption {
	return func(m *SessionManager) {
		if strings.TrimSpace(name) != "" {
			m.csrfHeader = name
		}
	}
}
func WithSessionTTL(ttl time.Duration) SessionOption {
	return func(m *SessionManager) {
		if ttl > 0 {
			m.ttl = ttl
		}
	}
}
func WithCookiePath(path string) SessionOption {
	return func(m *SessionManager) {
		if path != "" {
			m.path = path
		}
	}
}
func WithCookieDomain(domain string) SessionOption {
	return func(m *SessionManager) { m.domain = domain }
}
func WithSecureCookies(secure bool) SessionOption {
	return func(m *SessionManager) { m.secure = secure }
}
func WithHTTPOnlySessionCookie(httpOnly bool) SessionOption {
	return func(m *SessionManager) { m.httpOnly = httpOnly }
}
func WithSameSite(sameSite http.SameSite) SessionOption {
	return func(m *SessionManager) { m.sameSite = sameSite }
}

// WithIdentityHeaderSecret enables a signed reverse-proxy identity boundary.
// The proxy must send X-Auth-Request-Signature containing an HMAC-SHA256 over
// `subject + "\\x00" + role`.
func WithIdentityHeaderSecret(secret []byte) SessionOption {
	return func(m *SessionManager) {
		if len(secret) > 0 {
			m.identityMAC = append([]byte(nil), secret...)
		}
	}
}
func WithClock(now func() time.Time) SessionOption {
	return func(m *SessionManager) {
		if now != nil {
			m.now = now
		}
	}
}

// NewSessionManager creates a manager. It requires at least 32 secret bytes;
// issuing or reading sessions with a shorter key fails closed. The secret is
// hashed to an AES-256 key to support larger key material.
func NewSessionManager(secret []byte, options ...SessionOption) *SessionManager {
	m := &SessionManager{
		key:         sha256.Sum256(secret),
		secretValid: len(secret) >= 32,
		cookieName:  defaultSessionCookie,
		csrfName:    defaultCSRFCookie,
		csrfHeader:  defaultCSRFHeader,
		ttl:         defaultSessionTTL,
		path:        "/",
		secure:      true,
		httpOnly:    true,
		sameSite:    http.SameSiteLaxMode,
		now:         time.Now,
	}
	for _, option := range options {
		if option != nil {
			option(m)
		}
	}
	return m
}

func randomSessionToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Issue creates a new authenticated session with the configured lifetime.
func (m *SessionManager) Issue(subject string, roles ...Role) (Session, error) {
	if m == nil || !m.secretValid {
		return Session{}, errors.New("session secret must contain at least 32 bytes")
	}
	if strings.TrimSpace(subject) == "" || len(subject) > 512 {
		return Session{}, fmt.Errorf("subject must contain between 1 and 512 bytes")
	}
	normalized := NormalizeRoles(roles)
	if len(normalized) == 0 {
		return Session{}, ErrInvalidRole
	}
	id, err := randomSessionToken(24)
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomSessionToken(32)
	if err != nil {
		return Session{}, err
	}
	now := m.now().UTC()
	return Session{ID: id, Subject: subject, Roles: normalized, CSRFToken: csrf, IssuedAt: now, ExpiresAt: now.Add(m.ttl)}, nil
}

type encodedSession struct {
	Session
}

func (m *SessionManager) seal(s Session) (string, error) {
	if !m.secretValid {
		return "", ErrInvalidSession
	}
	block, err := aes.NewCipher(m.key[:])
	if err != nil {
		return "", fmt.Errorf("initialize session cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("initialize session AEAD: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate session nonce: %w", err)
	}
	payload, err := json.Marshal(encodedSession{Session: s})
	if err != nil {
		return "", fmt.Errorf("encode session: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, payload, []byte("egressdeck/session/v1"))
	value := append(nonce, ciphertext...)
	return "v1." + base64.RawURLEncoding.EncodeToString(value), nil
}

func (m *SessionManager) open(raw string) (Session, error) {
	if !m.secretValid {
		return Session{}, ErrInvalidSession
	}
	if !strings.HasPrefix(raw, "v1.") {
		return Session{}, ErrInvalidSession
	}
	value, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(raw, "v1."))
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	block, err := aes.NewCipher(m.key[:])
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(value) < gcm.NonceSize() {
		return Session{}, ErrInvalidSession
	}
	nonce, ciphertext := value[:gcm.NonceSize()], value[gcm.NonceSize():]
	payload, err := gcm.Open(nil, nonce, ciphertext, []byte("egressdeck/session/v1"))
	if err != nil {
		return Session{}, ErrInvalidSession
	}
	var wrapped encodedSession
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		return Session{}, ErrInvalidSession
	}
	s := wrapped.Session
	s.Roles = NormalizeRoles(s.Roles)
	if err := s.ValidAt(m.now().UTC()); err != nil {
		return Session{}, err
	}
	return s, nil
}

func (m *SessionManager) cookie(value string, maxAge int, httpOnly bool) *http.Cookie {
	return &http.Cookie{Name: m.cookieName, Value: value, Path: m.path, Domain: m.domain, Secure: m.secure, HttpOnly: httpOnly, SameSite: m.sameSite, MaxAge: maxAge}
}

func (m *SessionManager) csrfCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: m.csrfName, Value: value, Path: m.path, Domain: m.domain, Secure: m.secure, HttpOnly: false, SameSite: m.sameSite, MaxAge: maxAge}
}

// SessionCookie returns the HTTP-only cookie for s after validating its
// claims. Call SetSession to emit both the session and readable CSRF cookies.
func (m *SessionManager) SessionCookie(s Session) (*http.Cookie, error) {
	if err := s.ValidAt(m.now().UTC()); err != nil {
		return nil, err
	}
	value, err := m.seal(s)
	if err != nil {
		return nil, err
	}
	if len(value) > 3800 {
		return nil, errors.New("session exceeds cookie size limit")
	}
	seconds := int(s.ExpiresAt.Sub(m.now().UTC()) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return m.cookie(value, seconds, m.httpOnly), nil
}

// SetSession sets the secure HTTP-only session and non-HTTP-only CSRF cookie.
func (m *SessionManager) SetSession(w http.ResponseWriter, s Session) error {
	cookie, err := m.SessionCookie(s)
	if err != nil {
		return err
	}
	http.SetCookie(w, cookie)
	http.SetCookie(w, m.csrfCookie(s.CSRFToken, cookie.MaxAge))
	return nil
}

// Read extracts and verifies the session cookie from a request.
func (m *SessionManager) Read(r *http.Request) (Session, error) {
	if r == nil {
		return Session{}, ErrNoSession
	}
	cookie, err := r.Cookie(m.cookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return Session{}, ErrNoSession
		}
		return Session{}, ErrInvalidSession
	}
	return m.open(cookie.Value)
}

// ParseCookie verifies a raw session-cookie value. It is useful for websocket
// handshakes and tests that already extracted a cookie.
func (m *SessionManager) ParseCookie(value string) (Session, error) { return m.open(value) }

// Clear removes both cookies. It is safe to call after a failed read.
func (m *SessionManager) Clear(w http.ResponseWriter) {
	dead := m.cookie("", -1, m.httpOnly)
	dead.Expires = time.Unix(1, 0).UTC()
	http.SetCookie(w, dead)
	csrf := m.csrfCookie("", -1)
	csrf.Expires = dead.Expires
	http.SetCookie(w, csrf)
}

func (m *SessionManager) CSRFToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	if c, err := r.Cookie(m.csrfName); err == nil {
		return c.Value
	}
	return ""
}

func (m *SessionManager) csrfHeaderValue(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Header.Get(m.csrfHeader)
}

// ValidateCSRF applies the double-submit-token check to state-changing
// requests. Safe methods are allowed without a token. A token must match the
// authenticated session claim, the readable cookie, and the request header.
func (m *SessionManager) ValidateCSRF(r *http.Request, s Session) error {
	if r == nil {
		return ErrCSRF
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return nil
	}
	if err := s.ValidAt(m.now().UTC()); err != nil {
		return ErrCSRF
	}
	cookieToken, headerToken := m.CSRFToken(r), m.csrfHeaderValue(r)
	if cookieToken == "" || headerToken == "" || !hmac.Equal([]byte(cookieToken), []byte(headerToken)) || !hmac.Equal([]byte(cookieToken), []byte(s.CSRFToken)) {
		return ErrCSRF
	}
	return nil
}

func (m *SessionManager) ValidateRequestCSRF(r *http.Request) error {
	s, err := m.Read(r)
	if err != nil {
		return err
	}
	return m.ValidateCSRF(r, s)
}

// SessionCookieName and CSRFCookieName expose configured names to integrations
// that need to construct a browser client or clear cookies manually.
func (m *SessionManager) SessionCookieName() string { return m.cookieName }
func (m *SessionManager) CSRFCookieName() string    { return m.csrfName }
func (m *SessionManager) CSRFHeaderName() string    { return m.csrfHeader }

// VerifyIdentityHeaders verifies a reverse-proxy identity assertion when an
// identity header secret of at least 32 bytes was configured. Unconfigured
// header authentication fails closed; network placement alone is not proof
// that a caller may assert an identity.
func (m *SessionManager) VerifyIdentityHeaders(r *http.Request) bool {
	if m == nil || r == nil {
		return false
	}
	if len(m.identityMAC) < 32 {
		return false
	}
	subject := strings.TrimSpace(r.Header.Get("X-Auth-Request-User"))
	role := strings.TrimSpace(r.Header.Get("X-Auth-Request-Role"))
	provided := strings.TrimSpace(r.Header.Get("X-Auth-Request-Signature"))
	if subject == "" || role == "" || provided == "" {
		return false
	}
	mac := hmac.New(sha256.New, m.identityMAC)
	_, _ = mac.Write([]byte(subject + "\x00" + role))
	signature, err := base64.RawURLEncoding.DecodeString(provided)
	if err != nil {
		return false
	}
	return hmac.Equal(signature, mac.Sum(nil))
}

type contextKey uint8

const sessionContextKey contextKey = iota

func ContextWithSession(ctx context.Context, session Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, session)
}

func SessionFromContext(ctx context.Context) (Session, bool) {
	if ctx == nil {
		return Session{}, false
	}
	session, ok := ctx.Value(sessionContextKey).(Session)
	return session, ok
}

func RoleFromContext(ctx context.Context) (Role, bool) {
	session, ok := SessionFromContext(ctx)
	if !ok {
		return "", false
	}
	role := HighestRole(session.Roles)
	return role, role != ""
}
