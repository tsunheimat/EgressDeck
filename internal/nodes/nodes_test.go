package nodes

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestIdentityIgnoresNameAndContentHashIncludesSecret(t *testing.T) {
	d := Definition{Protocol: ProtocolVLess, Host: "Example.COM.", Port: 443, UUID: "u", TLS: true, SNI: "Example.COM"}
	a, err := New("p", "first", d, "provider-id")
	if err != nil {
		t.Fatal(err)
	}
	b, err := New("p", "renamed", d, "provider-id")
	if err != nil {
		t.Fatal(err)
	}
	if a.Identity != b.Identity {
		t.Fatalf("rename changed identity: %s != %s", a.Identity, b.Identity)
	}
	c, err := a.WithRevision(Definition{Protocol: ProtocolVLess, Host: "example.com", Port: 443, UUID: "other", TLS: true, SNI: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Identity != a.Identity || c.ContentHash == a.ContentHash {
		t.Fatal("connection revision did not change as expected")
	}
	ssA, _ := New("p", "ss", Definition{Protocol: ProtocolShadowsocks, Host: "x", Port: 1, Method: "aes", Password: "one"}, "stable")
	ssB, _ := ssA.WithRevision(Definition{Protocol: ProtocolShadowsocks, Host: "x", Port: 1, Method: "aes", Password: "two"})
	if ssA.ContentHash == ssB.ContentHash {
		t.Fatal("credential rotation did not change content hash")
	}
}

func TestNormalizeRejectsUnsupportedAndInvalidPort(t *testing.T) {
	if _, err := Normalize(Definition{Protocol: "made-up", Host: "x", Port: 1}); err == nil {
		t.Fatal("unsupported protocol accepted")
	}
	if _, err := Normalize(Definition{Protocol: ProtocolHTTP, Host: "x", Port: 0}); err == nil {
		t.Fatal("invalid port accepted")
	}
}

func TestPrivateIdentityPreservesAccountsAndNameInvariance(t *testing.T) {
	d := Definition{Protocol: ProtocolSOCKS5, Host: "Example.COM.", Port: 1080, Username: "account-a", Password: "password-a", ALPN: []string{"h2", "http/1.1"}}
	first, err := New("provider-a", "First", d, "")
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := New("provider-a", "Renamed", d, "")
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity != renamed.Identity || first.ContentHash != renamed.ContentHash {
		t.Fatal("display name changed private connection identity")
	}
	if first.ID == renamed.ID || first.ID == first.Identity || strings.Contains(first.ID, first.ContentHash) {
		t.Fatal("public IDs must be independently random, not derived from credentials")
	}
	for name, change := range map[string]func(*Definition){
		"username":          func(d *Definition) { d.Username = "account-b" },
		"password":          func(d *Definition) { d.Password = "password-b" },
		"uuid":              func(d *Definition) { d.UUID = "uuid-b" },
		"header credential": func(d *Definition) { d.Headers = map[string]string{"Authorization": "Bearer token"} },
		"extra credential":  func(d *Definition) { d.Extra = map[string]string{"token": "value"} },
		"ALPN preference":   func(d *Definition) { d.ALPN = []string{"http/1.1", "h2"} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := Clone(first).Definition
			change(&changed)
			other, err := New("provider-a", "First", changed, "")
			if err != nil {
				t.Fatal(err)
			}
			if first.Identity == other.Identity || first.ContentHash == other.ContentHash {
				t.Fatal("connection change did not affect private fingerprints")
			}
		})
	}
	if first.Identity == IdentityFingerprint("provider-b", d) {
		t.Fatal("identity was not scoped by provider")
	}
}

func TestNormalizePreservesOpaqueValuesAndALPNOrder(t *testing.T) {
	d := Definition{
		Protocol: ProtocolTrojan, Host: " Example.COM. ", Port: 443,
		Username: " account ", Password: "\t exact secret \n", UUID: " credential ",
		ALPN: []string{"http/1.1", "h2", "Custom", "h2"}, Path: " /exact ", Service: " service ",
		Headers: map[string]string{"X-Exact": "  header secret  "},
		Extra:   map[string]string{"CaseSensitiveKey": "  extra secret  "},
	}
	normalized, err := Normalize(d)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Host != "example.com" {
		t.Fatal("host was not canonicalized")
	}
	want := d
	want.Host = "example.com"
	if !reflect.DeepEqual(normalized, want) {
		t.Fatal("normalization changed opaque connection values or ALPN order")
	}
	normalized.ALPN[0] = "changed"
	normalized.Headers["X-Exact"] = "changed"
	normalized.Extra["CaseSensitiveKey"] = "changed"
	if d.ALPN[0] != "http/1.1" || d.Headers["X-Exact"] != "  header secret  " || d.Extra["CaseSensitiveKey"] != "  extra secret  " {
		t.Fatal("normalized definition aliases caller state")
	}
}

func TestPublicJSONHasNoCredentialsOrCredentialDigests(t *testing.T) {
	n, err := New("provider", "node", Definition{
		Protocol: ProtocolVLess, Host: "example.com", Port: 443,
		Username: "secret-username", Password: "secret-password", UUID: "secret-uuid",
		Headers: map[string]string{"Authorization": "secret-header"}, Extra: map[string]string{"token": "secret-extra"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret-username", "secret-password", "secret-uuid", "secret-header", "secret-extra", n.Identity, n.ContentHash, `"identity"`, `"content_hash"`, `"username"`, `"password"`, `"uuid"`, `"headers"`, `"extra"`} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("public JSON exposed a credential or credential-derived value")
		}
	}
	if !strings.Contains(string(raw), n.ID) {
		t.Fatal("public JSON is missing opaque node ID")
	}
}

func TestCloneSeparatesDefinitionState(t *testing.T) {
	n, err := New("provider", "node", Definition{
		Protocol: ProtocolHTTP, Host: "example.com", Port: 80,
		ALPN: []string{"h2"}, Headers: map[string]string{"Authorization": "original"}, Extra: map[string]string{"token": "original"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	cloned := Clone(n)
	cloned.Definition.ALPN[0] = "http/1.1"
	cloned.Definition.Headers["Authorization"] = "changed"
	cloned.Definition.Extra["token"] = "changed"
	if n.Definition.ALPN[0] != "h2" || n.Definition.Headers["Authorization"] != "original" || n.Definition.Extra["token"] != "original" {
		t.Fatal("cloned node aliases its original definition")
	}
}

func TestPrivateSnapshotRoundTrip(t *testing.T) {
	n, err := New("provider", "node", Definition{
		Protocol: ProtocolVLess, Host: "example.com", Port: 443,
		Username: " account ", Password: " secret ", UUID: " uuid ", TLS: true,
		SNI: "sni.example.com", ALPN: []string{"http/1.1", "h2"}, Network: "grpc",
		Path: " /path ", Service: " service ", Method: "method", Fingerprint: "fingerprint",
		Headers: map[string]string{"Authorization": " Bearer secret "}, Extra: map[string]string{"token": " extra secret "},
	}, "logical-id")
	if err != nil {
		t.Fatal(err)
	}
	n.Revision = 7
	raw, err := MarshalPrivate([]Node{n})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := UnmarshalPrivate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored, []Node{n}) {
		t.Fatal("private snapshot did not restore all node metadata and connection fields")
	}
	for _, raw := range []string{`{`, `{"version":2,"nodes":[]}`, `{"version":1,"nodes":[{}]}`} {
		if _, err := UnmarshalPrivate([]byte(raw)); err == nil {
			t.Fatal("invalid private snapshot was accepted")
		}
	}
}
