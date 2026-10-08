package nodes

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DaeLink renders the connection subset consumed without loss by the outbound
// dependency pinned by engine/dae (cc86ced2e683). The result contains plaintext
// or reversibly encoded credentials: it is private engine input, never API,
// audit, or log data. The engine must also have global allow_insecure disabled.
//
// A successful generic import does not guarantee native engine compatibility.
// In particular, the pinned Trojan and TCP V2Ray constructors ignore ALPN, and
// the HTTPS link adapter drops it. Reject those definitions instead of silently
// changing their handshake. Unknown extension fields are likewise rejected.
func DaeLink(node Node) (string, error) {
	if !node.Supported || node.UnsupportedReason != "" {
		return "", errors.New("node is not supported by dae")
	}
	d, err := Normalize(node.Definition)
	if err != nil {
		// Normalize may include an untrusted protocol in its diagnostic.
		return "", errors.New("invalid dae node definition")
	}
	if strings.ContainsAny(d.Host, "/\\@#?%[]") || strings.ContainsFunc(d.Host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) || strings.Contains(d.Host, ":") && net.ParseIP(d.Host) == nil {
		return "", errors.New("invalid dae node host")
	}
	if len(d.Headers) != 0 || len(d.Extra) != 0 || d.Fingerprint != "" || d.Path != "" || d.Service != "" || d.Network != "" && d.Network != "tcp" {
		return "", errors.New("unsupported dae node transport or extension")
	}
	if len(d.ALPN) != 0 {
		return "", errors.New("explicit ALPN is unsupported by the pinned dae link adapter")
	}
	if !d.TLS && d.SNI != "" {
		return "", errors.New("dae node SNI requires TLS")
	}
	if strings.ContainsFunc(d.SNI, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) || strings.ContainsAny(d.SNI, "/\\@#?%[]") {
		return "", errors.New("invalid dae node SNI")
	}
	u := url.URL{Scheme: string(d.Protocol), Host: net.JoinHostPort(d.Host, strconv.Itoa(d.Port)), Fragment: node.Name}
	q := url.Values{}
	if d.SNI != "" {
		q.Set("sni", d.SNI)
	}
	switch d.Protocol {
	case ProtocolShadowsocks:
		if d.TLS || d.Username != "" || d.UUID != "" || d.Password == "" {
			return "", errors.New("invalid dae Shadowsocks authentication or TLS options")
		}
		switch d.Method {
		case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20", "chacha20-ietf", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb":
		default:
			return "", errors.New("unsupported dae Shadowsocks cipher")
		}
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(d.Method + ":" + d.Password)))
	case ProtocolTrojan:
		if !d.TLS || d.Password == "" || d.Username != "" || d.UUID != "" || d.Method != "" {
			return "", errors.New("invalid dae Trojan authentication or TLS options")
		}
		u.User = url.User(d.Password)
	case ProtocolHTTP, ProtocolHTTPS, ProtocolSOCKS5:
		if d.UUID != "" || d.Method != "" || d.TLS != (d.Protocol == ProtocolHTTPS) || d.Username == "" && d.Password != "" {
			return "", errors.New("invalid dae proxy authentication or TLS options")
		}
		// Native HTTP reconstructs userinfo only for a nonempty username;
		// native SOCKS offers authentication only for a 1..255-byte username.
		if d.Protocol == ProtocolSOCKS5 && (len(d.Username) > 255 || len(d.Password) > 255) {
			return "", errors.New("dae SOCKS credentials exceed protocol limits")
		}
		if (d.Protocol == ProtocolHTTP || d.Protocol == ProtocolHTTPS) && strings.Contains(d.Username, ":") {
			return "", errors.New("invalid dae HTTP authentication username")
		}
		if d.Username != "" {
			u.User = url.UserPassword(d.Username, d.Password)
		}
	case ProtocolVLess, ProtocolVMess:
		if d.Username != "" || d.Password != "" || d.Method != "" || !daeUUIDValid(d.UUID) {
			return "", errors.New("invalid dae V2Ray authentication options")
		}
		if d.Protocol == ProtocolVMess {
			if !utf8.ValidString(d.UUID) || !utf8.ValidString(node.Name) || !utf8.ValidString(d.Host) || !utf8.ValidString(d.SNI) {
				return "", errors.New("invalid UTF-8 in dae VMess definition")
			}
			tls := "none"
			if d.TLS {
				tls = "tls"
			}
			payload, err := json.Marshal(map[string]string{
				"v": "2", "ps": node.Name, "add": d.Host, "port": strconv.Itoa(d.Port),
				"id": d.UUID, "aid": "0", "net": "tcp", "type": "none", "tls": tls, "sni": d.SNI,
			})
			if err != nil {
				return "", errors.New("cannot encode dae VMess definition")
			}
			return "vmess://" + base64.StdEncoding.EncodeToString(payload), nil
		}
		// The pinned VLESS parser consumes User.String(), not Username().
		// Reject aliases requiring escaping, which would change the credential.
		u.User = url.User(d.UUID)
		if u.User.String() != d.UUID {
			return "", errors.New("dae VLESS credential cannot be preserved by the native parser")
		}
		q.Set("type", "tcp")
		q.Set("encryption", "none")
		q.Set("security", "none")
		if d.TLS {
			q.Set("security", "tls")
		}
	default:
		return "", errors.New("unsupported dae node protocol")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// The pinned VMess/VLESS implementations map opaque aliases outside the UUID
// length range to UUIDv5. Within that range they require a hexadecimal UUID.
func daeUUIDValid(id string) bool {
	if id == "" {
		return false
	}
	if len(id) < 32 || len(id) > 36 {
		return true
	}
	if len(id) != 32 && (len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-') {
		return false
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	return err == nil && len(raw) == 16
}
