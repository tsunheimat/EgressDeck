package nodes

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestDaeLinkPreservesCredentialsAndTLS(t *testing.T) {
	const password = " exact:@/?#% secret\n"
	for _, protocol := range []Protocol{ProtocolShadowsocks, ProtocolTrojan, ProtocolSOCKS5, ProtocolHTTP, ProtocolHTTPS, ProtocolVLess} {
		t.Run(string(protocol), func(t *testing.T) {
			d := Definition{Protocol: protocol, Host: "2001:db8::1", Port: 443}
			switch protocol {
			case ProtocolShadowsocks:
				d.Method, d.Password = "aes-256-gcm", password
			case ProtocolTrojan:
				d.TLS, d.SNI, d.Password = true, "certificate.example", password
			case ProtocolSOCKS5, ProtocolHTTP, ProtocolHTTPS:
				d.Username, d.Password = " account@/?#% ", password
				if protocol == ProtocolHTTPS {
					d.TLS, d.SNI = true, "certificate.example"
				}
			case ProtocolVLess:
				d.TLS, d.SNI, d.UUID = true, "certificate.example", "5b197368-d100-422c-8383-310805b02092"
			}
			n := Node{Supported: true, Name: "quoted ' node -> #\n next", Definition: d}
			link, err := DaeLink(n)
			if err != nil {
				t.Fatal(err)
			}
			if strings.ContainsAny(link, "\r\n") || strings.Contains(link, "->") {
				t.Fatal("renderer allowed a line or chain delimiter in native input")
			}
			u, err := url.Parse(link)
			if err != nil {
				t.Fatal("renderer produced an invalid URI")
			}
			if u.Scheme != string(protocol) || u.Hostname() != d.Host || u.Port() != "443" || u.Fragment != n.Name {
				t.Fatal("native link changed endpoint or name")
			}
			if u.Query().Get("sni") != d.SNI {
				t.Fatal("native link changed SNI")
			}
			switch protocol {
			case ProtocolShadowsocks:
				plain, err := base64.RawURLEncoding.DecodeString(u.User.Username())
				if err != nil || string(plain) != d.Method+":"+password {
					t.Fatal("native link changed Shadowsocks credentials")
				}
			case ProtocolTrojan:
				if u.User.Username() != password {
					t.Fatal("native link changed Trojan credentials")
				}
			case ProtocolVLess:
				// Native ParseVlessURL uses User.String(), including escaping.
				if u.User.String() != d.UUID || u.Query().Get("security") != "tls" || u.Query().Get("type") != "tcp" || u.Query().Get("encryption") != "none" {
					t.Fatal("native VLESS parser would change credentials or TLS")
				}
			default:
				gotPassword, ok := u.User.Password()
				if !ok || u.User.Username() != d.Username || gotPassword != d.Password {
					t.Fatal("native link changed proxy credentials")
				}
			}
			if !reflect.DeepEqual(n.Definition, d) {
				t.Fatal("rendering changed the caller's definition")
			}
		})
	}
}

func TestDaeLinkVMessPreservesOpaqueValues(t *testing.T) {
	n := Node{Supported: true, Name: "node\n -> quoted", Definition: Definition{
		Protocol: ProtocolVMess, Host: "2001:db8::2", Port: 443,
		UUID: "credential:@/ with whitespace\n", TLS: true, SNI: "tls.example", Network: "tcp",
	}}
	link, err := DaeLink(n)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		t.Fatal("invalid native VMess base64")
	}
	var payload map[string]string
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal("invalid native VMess JSON")
	}
	for key, want := range map[string]string{
		"v": "2", "ps": n.Name, "add": n.Definition.Host, "port": "443", "id": n.Definition.UUID,
		"aid": "0", "net": "tcp", "type": "none", "tls": "tls", "sni": n.Definition.SNI,
	} {
		if payload[key] != want {
			t.Fatalf("VMess field %s changed", key)
		}
	}
}

func TestDaeLinkRejectsIgnoredOrInvalidFieldsWithoutSecrets(t *testing.T) {
	const secret = "never-echo-secret"
	base := Definition{Protocol: ProtocolTrojan, Host: "example.com", Port: 443, TLS: true, Password: secret}
	for name, change := range map[string]func(*Node){
		"unsupported status":   func(n *Node) { n.Supported = false },
		"unsupported reason":   func(n *Node) { n.UnsupportedReason = secret },
		"unknown protocol":     func(n *Node) { n.Definition.Protocol = Protocol(secret) },
		"unsupported protocol": func(n *Node) { n.Definition.Protocol = ProtocolHysteria2 },
		"invalid endpoint":     func(n *Node) { n.Definition.Host = secret + "@example.com" },
		"invalid port":         func(n *Node) { n.Definition.Port = 0 },
		"invalid SNI":          func(n *Node) { n.Definition.SNI = "host " + secret },
		"ignored ALPN":         func(n *Node) { n.Definition.ALPN = []string{"h2", "http/1.1"} },
		"headers":              func(n *Node) { n.Definition.Headers = map[string]string{"Authorization": secret} },
		"extra":                func(n *Node) { n.Definition.Extra = map[string]string{"allowInsecure": secret} },
		"fingerprint":          func(n *Node) { n.Definition.Fingerprint = secret },
		"path":                 func(n *Node) { n.Definition.Path = "/" + secret },
		"service":              func(n *Node) { n.Definition.Service = secret },
		"transport":            func(n *Node) { n.Definition.Network = secret },
		"ignored username":     func(n *Node) { n.Definition.Username = secret },
		"ignored UUID":         func(n *Node) { n.Definition.UUID = secret },
		"ignored method":       func(n *Node) { n.Definition.Method = secret },
		"TLS downgrade":        func(n *Node) { n.Definition.TLS = false },
		"missing credential":   func(n *Node) { n.Definition.Password = "" },
	} {
		t.Run(name, func(t *testing.T) {
			n := Node{Supported: true, Name: secret, Definition: base}
			change(&n)
			link, err := DaeLink(n)
			if err == nil || link != "" {
				t.Fatal("invalid native definition was accepted")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error included untrusted definition data")
			}
		})
	}
}

func TestDaeLinkRejectsNativeAuthenticationLoss(t *testing.T) {
	for name, d := range map[string]Definition{
		"VLESS escaped alias":             {Protocol: ProtocolVLess, UUID: "has space"},
		"VLESS invalid UUID":              {Protocol: ProtocolVLess, UUID: strings.Repeat("z", 36)},
		"VMess invalid UUID":              {Protocol: ProtocolVMess, UUID: strings.Repeat("z", 32)},
		"VMess invalid UTF8":              {Protocol: ProtocolVMess, UUID: "alias\xff"},
		"HTTP password without username":  {Protocol: ProtocolHTTP, Password: "secret"},
		"HTTP ambiguous username":         {Protocol: ProtocolHTTP, Username: "a:b", Password: "secret"},
		"SOCKS password without username": {Protocol: ProtocolSOCKS5, Password: "secret"},
		"SOCKS oversized username":        {Protocol: ProtocolSOCKS5, Username: strings.Repeat("u", 256)},
		"SOCKS oversized password":        {Protocol: ProtocolSOCKS5, Username: "u", Password: strings.Repeat("p", 256)},
		"SOCKS ignored TLS":               {Protocol: ProtocolSOCKS5, TLS: true},
		"HTTP ignored TLS":                {Protocol: ProtocolHTTP, TLS: true},
		"HTTPS requires TLS":              {Protocol: ProtocolHTTPS},
		"Shadowsocks invalid cipher":      {Protocol: ProtocolShadowsocks, Password: "secret", Method: "none"},
		"Shadowsocks ignored TLS":         {Protocol: ProtocolShadowsocks, Password: "secret", Method: "aes-256-gcm", TLS: true},
	} {
		t.Run(name, func(t *testing.T) {
			d.Host, d.Port = "example.com", 443
			if link, err := DaeLink(Node{Supported: true, Definition: d}); err == nil || link != "" {
				t.Fatal("native authentication or TLS loss was allowed")
			}
		})
	}
}

func TestDaeLinkAllowsPlainAndAnonymousProxyDefinitions(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolHTTP, ProtocolHTTPS, ProtocolSOCKS5, ProtocolVLess, ProtocolVMess} {
		t.Run(string(protocol), func(t *testing.T) {
			d := Definition{Protocol: protocol, Host: "proxy.example", Port: 1080, TLS: protocol == ProtocolHTTPS}
			if protocol == ProtocolVLess || protocol == ProtocolVMess {
				d.UUID = "id"
			}
			if _, err := DaeLink(Node{Supported: true, Definition: d}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDaeLinkRejectsALPNForEveryNativeTLSAdapter(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolTrojan, ProtocolHTTPS, ProtocolVLess, ProtocolVMess} {
		t.Run(string(protocol), func(t *testing.T) {
			d := Definition{Protocol: protocol, Host: "proxy.example", Port: 443, TLS: true, ALPN: []string{"http/1.1", "h2"}}
			if protocol == ProtocolTrojan {
				d.Password = "secret"
			}
			if protocol == ProtocolVLess || protocol == ProtocolVMess {
				d.UUID = "id"
			}
			if link, err := DaeLink(Node{Supported: true, Definition: d}); err == nil || link != "" {
				t.Fatal("native adapter would drop explicit ALPN")
			}
		})
	}
}
