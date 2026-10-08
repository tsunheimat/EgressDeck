package auth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const redactedValue = "[REDACTED]"

var sensitiveNames = map[string]struct{}{
	"authorization": {}, "proxy-authorization": {}, "cookie": {}, "set-cookie": {},
	"password": {}, "passwd": {}, "passphrase": {}, "secret": {}, "client_secret": {},
	"client-secret": {}, "token": {}, "access_token": {}, "access-token": {},
	"refresh_token": {}, "refresh-token": {}, "id_token": {}, "id-token": {},
	"api_key": {}, "api-key": {}, "apikey": {}, "private_key": {}, "private-key": {},
	"credential": {}, "credentials": {}, "session": {}, "session_id": {}, "session-id": {},
	"csrf": {}, "csrf_token": {}, "csrf-token": {}, "certificate": {}, "cert": {},
	"x-auth-request-signature": {}, "code": {}, "state": {}, "code_verifier": {},
}

func sensitiveName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if _, ok := sensitiveNames[name]; ok {
		return true
	}
	for _, marker := range []string{"password", "secret", "token", "credential", "private_key", "private-key", "api_key", "api-key"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// IsSensitiveKey reports whether a map/header/query key should be hidden in
// diagnostics and audit records.
func IsSensitiveKey(key string) bool { return sensitiveName(key) }

func RedactedValue() string { return redactedValue }

// RedactString replaces a secret value with a stable marker. Empty values stay
// empty so diagnostics can still distinguish an absent field from a present,
// empty field.
func RedactString(value string) string {
	if value == "" {
		return ""
	}
	return redactedValue
}

// Redact recursively clones common JSON-compatible values. It never mutates
// the caller's map/slice, which is important when the same object is passed to
// persistence and audit logging.
func Redact(value any) any {
	switch v := value.(type) {
	case url.URL:
		return RedactURL(v.String())
	case *url.URL:
		if v == nil {
			return (*url.URL)(nil)
		}
		return RedactURL(v.String())
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			if sensitiveName(key) {
				if item == nil {
					out[key] = nil
				} else {
					out[key] = redactedValue
				}
				continue
			}
			out[key] = Redact(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i := range v {
			out[i] = Redact(v[i])
		}
		return out
	case []string:
		return append([]string(nil), v...)
	case string, bool, float64, float32, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, nil:
		return value
	default:
		// Structs and custom values are converted through JSON so exported
		// fields receive the same key treatment. On marshal failure retain no
		// potentially sensitive representation.
		raw, err := json.Marshal(value)
		if err != nil {
			return redactedValue
		}
		var generic any
		if err := json.Unmarshal(raw, &generic); err != nil {
			return redactedValue
		}
		return Redact(generic)
	}
}

// RedactMap is a typed convenience wrapper around Redact.
func RedactMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	return Redact(input).(map[string]any)
}

// RedactStringMap preserves the map's concrete type for common string-only
// metadata such as audit labels.
func RedactStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		if sensitiveName(key) {
			out[key] = redactedValue
		} else {
			out[key] = value
		}
	}
	return out
}

// RedactJSON returns compact JSON with sensitive fields hidden. It can be
// used as an audit diff or structured log field.
func RedactJSON(value any) ([]byte, error) {
	if raw, ok := value.([]byte); ok {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, err
		}
		return json.Marshal(Redact(decoded))
	}
	return json.Marshal(Redact(value))
}

// RedactHeaders clones a header map and hides credentials, cookies, and token
// headers while preserving unrelated values and repeated-header ordering.
func RedactHeaders(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	out := make(http.Header, len(headers))
	for key, values := range headers {
		if sensitiveName(key) {
			if len(values) == 0 {
				out[key] = nil
			} else {
				out[key] = []string{redactedValue}
			}
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	return out
}

// RedactURL removes credentials and sensitive query parameters while
// preserving deterministic ordering for audit comparisons.
func RedactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return redactedURLString(raw)
	}
	if parsed.User != nil {
		parsed.User = url.User(redactedValue)
	}
	query := parsed.Query()
	for key := range query {
		if sensitiveName(key) {
			query.Set(key, redactedValue)
		}
	}
	// url.Values.Encode sorts keys, which keeps audit output stable.
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func redactedURLString(raw string) string {
	// URL parsing fails for malformed/partially secret input. Still avoid
	// exposing obvious key=value credentials in this fallback.
	parts := strings.Split(raw, "?")
	if len(parts) != 2 {
		return raw
	}
	params := strings.Split(parts[1], "&")
	for i, param := range params {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) == 2 && sensitiveName(kv[0]) {
			params[i] = kv[0] + "=" + redactedValue
		}
	}
	return parts[0] + "?" + strings.Join(params, "&")
}

// RedactQuery returns a copy of values with sensitive entries replaced.
func RedactQuery(values url.Values) url.Values {
	if values == nil {
		return nil
	}
	out := make(url.Values, len(values))
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if sensitiveName(key) {
			if len(values[key]) == 0 {
				out[key] = nil
			} else {
				out[key] = []string{redactedValue}
			}
		} else {
			out[key] = append([]string(nil), values[key]...)
		}
	}
	return out
}
