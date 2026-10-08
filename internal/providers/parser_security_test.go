package providers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestUnsupportedSecurityAndTransportIsNeverDropped(t *testing.T) {
	for _, link := range []string{
		"trojan://secret@example.org:443?allowInsecure=1",
		"vless://id@example.org:443?security=reality&pbk=key",
		"vless://id@example.org:443?security=tls&type=ws&path=%2Fws",
		"vless://id@example.org:443?security=tls&security=none",
		"ss://aes-128-gcm:secret@example.org:8388?plugin=v2ray-plugin",
		"ss://invented:secret@example.org:8388",
		"vless://id@example.org:443?secret-option=token",
		"socks5://user:secret@example.org:1080/ignored",
	} {
		t.Run(link, func(t *testing.T) {
			p, err := Parse("p", []byte(link), FormatLinks, DefaultLimits())
			if !errors.Is(err, ErrNoNodes) || len(p.Report.Unsupported) != 1 {
				t.Fatalf("unsafe options accepted: report=%+v err=%v", p.Report, err)
			}
			if strings.Contains(p.Report.Unsupported[0].Reason, "token") || strings.Contains(p.Report.Unsupported[0].Reason, "secret") {
				t.Fatal("unsupported report exposed payload")
			}
		})
	}
}

func TestClashRejectsUnknownAndNestedSecurityOptions(t *testing.T) {
	for _, option := range []string{
		"skip-cert-verify: true", "flow: xtls-rprx-vision", "network: ws", "ws-opts: {path: /ws}", "plugin: obfs", "unknown: credential", "uuid: id", "tls: false", "alpn: h2", "password: duplicate",
	} {
		t.Run(option, func(t *testing.T) {
			body := "proxies:\n  - name: edge\n    type: trojan\n    server: edge.example\n    port: 443\n    password: secret\n    " + option + "\n"
			parsed, err := Parse("p", []byte(body), FormatClash, DefaultLimits())
			if err == nil || len(parsed.Nodes) > 0 {
				t.Fatalf("accepted unsupported option %q", option)
			}
		})
	}
}

func TestDocumentRejectsAliasDuplicateDepthAndSecondDocument(t *testing.T) {
	valid := "proxies: [{name: edge, type: trojan, server: edge.example, port: 443, password: secret}]"
	for name, body := range map[string]string{
		"alias":     "proxies: [&node {name: edge, type: trojan, server: edge.example, port: 443, password: secret}, *node]",
		"duplicate": "proxies: []\nproxies: [{type: trojan, server: x, port: 443, password: secret}]",
		"second":    valid + "\n---\nproxies: []",
		"tag":       "proxies: [!custom {type: trojan, server: x, port: 443, password: secret}]",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse("p", []byte(body), FormatClash, DefaultLimits()); err == nil {
				t.Fatal("unsafe document accepted")
			}
		})
	}
	limits := DefaultLimits()
	limits.MaxParserDepth = 3
	if _, err := Parse("p", []byte(valid), FormatClash, limits); err == nil {
		t.Fatal("depth bound ignored")
	}
	if _, err := Parse("p", []byte(valid), FormatJSON, DefaultLimits()); err == nil {
		t.Fatal("non JSON accepted as JSON")
	}
}

func TestClashFlowMappingPreservesPasswordAndALPN(t *testing.T) {
	body := `dns: {nameserver: [127.0.0.1]}
external-controller: 127.0.0.1:9090
proxies:
  - {name: "edge # one", type: trojan, server: edge.example, port: 443, password: "  Secret # : Value  ", alpn: ["h2", "http/1.1", "H2"]}
rules: [MATCH,DIRECT]
`
	p, err := Parse("p", []byte(body), FormatAuto, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 1 || p.Nodes[0].Name != "edge # one" || p.Nodes[0].Definition.Password != "  Secret # : Value  " || !reflect.DeepEqual(p.Nodes[0].Definition.ALPN, []string{"h2", "http/1.1", "H2"}) {
		t.Fatal("connection semantics were changed")
	}
	encoded, _ := json.Marshal(p)
	for _, secret := range []string{p.Nodes[0].Definition.Password, p.Nodes[0].Identity, p.Nodes[0].ContentHash, p.ContentHash} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("public parse result exposes secret or credential digest")
		}
	}
}

func TestTwoAccountsSameEndpointRemainDistinct(t *testing.T) {
	p, err := Parse("p", []byte("socks5://alice:one@example.org:1080#same\nsocks5://bob:two@example.org:1080#same"), FormatLinks, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 2 || p.Nodes[0].ID == p.Nodes[1].ID || p.Nodes[0].Identity == p.Nodes[1].Identity {
		t.Fatal("accounts merged")
	}
}

func TestVMessRejectsUnimplementedOptions(t *testing.T) {
	for _, addition := range []string{`,"aid":"4"`, `,"net":"ws"`, `,"allowInsecure":true`, `,"scy":"none"`, `,"v":"9"`} {
		body := `{"add":"edge.example","port":443,"id":"secret-id"` + addition + `}`
		link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(body))
		if _, err := Parse("p", []byte(link), FormatLinks, DefaultLimits()); err == nil {
			t.Fatalf("VMess option accepted %s", addition)
		}
	}
}

func TestParserCountsRejectedNodesAndReportsPartialInventory(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxNodes = 1
	if _, err := Parse("p", []byte("unknown://bad\ntrojan://secret@example.org:443"), FormatLinks, limits); err == nil {
		t.Fatal("rejected entries bypassed count bound")
	}
	p, err := Parse("p", []byte("trojan://secret@example.org:443\nvless://id@example.org:443?security=reality"), FormatLinks, DefaultLimits())
	if err != nil || len(p.Nodes) != 1 || len(p.Report.Unsupported) != 1 {
		t.Fatalf("partial import report missing: %+v %v", p.Report, err)
	}
}
