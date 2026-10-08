package providers

import (
	"encoding/json"
	"errors"
	"testing"
)

// This exercises the untrusted subscription boundary, including format
// detection and YAML/JSON/link decoding, under tighter production-like bounds.
func FuzzParseSubscription(f *testing.F) {
	for _, seed := range []string{
		"",
		"ss://YWVzLTEyOC1nY206c2VjcmV0@proxy.example:443#node",
		`{"servers":[{"server":"proxy.example","server_port":443,"method":"aes-128-gcm","password":"secret"}]}`,
		"proxies:\n  - name: node\n    type: ss\n    server: proxy.example\n    port: 443\n    cipher: aes-128-gcm\n    password: secret\n",
		"proxies: &loop [*loop]\n",
		`{"proxies":[null,{"port":65536},[[]]]}`,
	} {
		f.Add([]byte(seed), uint8(0))
	}
	formats := []Format{FormatAuto, FormatNative, FormatLinks, FormatBase64, FormatClash, FormatSIP008, FormatJSON}
	limits := Limits{MaxBodyBytes: 64 << 10, MaxDecodedBytes: 128 << 10, MaxNodes: 32, MaxLineBytes: 16 << 10, MaxParserDepth: 16}
	f.Fuzz(func(t *testing.T, body []byte, formatIndex uint8) {
		parsed, err := Parse("fuzz-provider", body, formats[int(formatIndex)%len(formats)], limits)
		if len(body) > int(limits.MaxBodyBytes) && !errors.Is(err, ErrBodyTooLarge) {
			t.Fatal("oversized source bypassed the body limit")
		}
		if len(parsed.Nodes) > limits.MaxNodes {
			t.Fatal("parsed inventory exceeds node limit")
		}
		seen := map[string]bool{}
		for _, node := range parsed.Nodes {
			if node.ProviderID != "fuzz-provider" || node.ID == "" || seen[node.ID] {
				t.Fatal("invalid normalized node identity")
			}
			seen[node.ID] = true
		}
		// All success and partial-report objects must remain safe JSON values,
		// even when names and transport options contain arbitrary input bytes.
		if _, marshalErr := json.Marshal(parsed); marshalErr != nil {
			t.Fatalf("public parse result is not serializable: %v", marshalErr)
		}
	})
}
