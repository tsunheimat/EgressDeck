package providers

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseLinksAndBase64(t *testing.T) {
	content := "vless://uuid@example.com:443?security=tls&sni=example.com#one\ntrojan://secret@example.net:443#two\nmadeup://x:1"
	p, err := Parse("provider", []byte(content), FormatAuto, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 2 || len(p.Report.Unsupported) != 1 {
		t.Fatalf("nodes=%d unsupported=%d", len(p.Nodes), len(p.Report.Unsupported))
	}
	b64 := base64.StdEncoding.EncodeToString([]byte("socks5://user:pass@example.org:1080#socks"))
	p, err = Parse("provider", []byte(b64), FormatAuto, DefaultLimits())
	if err != nil || len(p.Nodes) != 1 {
		t.Fatalf("base64 parse: nodes=%d err=%v", len(p.Nodes), err)
	}
	legacy := "ss://" + base64.RawStdEncoding.EncodeToString([]byte("chacha20:secret@example.org:8388")) + "#legacy"
	p, err = Parse("provider", []byte(legacy), FormatLinks, DefaultLimits())
	if err != nil || len(p.Nodes) != 1 || p.Nodes[0].Definition.Method != "chacha20" {
		t.Fatalf("legacy ss parse: %#v %v", p, err)
	}
}

func TestParseSIP008(t *testing.T) {
	p, err := Parse("provider", []byte(`{"version":1,"servers":[{"server":"ss.example","server_port":443,"method":"aes-128-gcm","password":"secret"}]}`), FormatSIP008, DefaultLimits())
	if err != nil || len(p.Nodes) != 1 || p.Nodes[0].Definition.Protocol != "ss" {
		t.Fatalf("SIP008 parse: %#v %v", p, err)
	}
}

func TestParseClashSubsetAndBounds(t *testing.T) {
	yaml := `mixed-port: 7890
proxies:
  - name: edge
    type: vmess
    server: edge.example
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    tls: true
  - name: direct
    type: unsupported
    server: x
    port: 1
`
	p, err := Parse("p", []byte(yaml), FormatClash, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 1 || len(p.Report.Unsupported) != 1 {
		t.Fatalf("nodes=%d unsupported=%d report=%+v", len(p.Nodes), len(p.Report.Unsupported), p.Report)
	}
	if !strings.Contains(p.Nodes[0].Name, "edge") {
		t.Fatal("name not parsed")
	}
	if _, err := Parse("p", []byte("ss://x"), FormatLinks, Limits{MaxBodyBytes: 2}); err == nil {
		t.Fatal("body bound ignored")
	}
}

func TestProviderRenameIsNoopHash(t *testing.T) {
	one, err := Parse("p", []byte("trojan://secret@example.org:443#one"), FormatLinks, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	two, err := Parse("p", []byte("trojan://secret@example.org:443#renamed"), FormatLinks, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if one.ContentHash != two.ContentHash || one.Nodes[0].Identity != two.Nodes[0].Identity {
		t.Fatal("rename should preserve normalized revision identity")
	}
}
