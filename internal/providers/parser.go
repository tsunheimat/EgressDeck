// Package providers implements bounded subscription fetching and import. It
// intentionally returns normalized nodes and a parse report: unsupported or
// malformed entries are visible to callers and never silently dropped.
package providers

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
	"gopkg.in/yaml.v3"
)

type Format string

const (
	FormatAuto   Format = "auto"
	FormatNative Format = "native"
	FormatBase64 Format = "base64"
	FormatLinks  Format = "links"
	FormatSIP008 Format = "sip008"
	FormatClash  Format = "clash"
	FormatJSON   Format = "json"
)

type Limits struct {
	MaxBodyBytes    int64
	MaxDecodedBytes int64
	MaxNodes        int
	MaxLineBytes    int
	MaxParserDepth  int
	MaxRedirects    int
	RequestTimeout  time.Duration
	AllowHTTP       bool
}

func DefaultLimits() Limits {
	return Limits{MaxBodyBytes: 8 << 20, MaxDecodedBytes: 16 << 20, MaxNodes: 5000, MaxLineBytes: 1 << 20, MaxParserDepth: 32, MaxRedirects: 5, RequestTimeout: 30 * time.Second}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = d.MaxBodyBytes
	}
	if l.MaxDecodedBytes <= 0 {
		l.MaxDecodedBytes = d.MaxDecodedBytes
	}
	if l.MaxNodes <= 0 {
		l.MaxNodes = d.MaxNodes
	}
	if l.MaxLineBytes <= 0 {
		l.MaxLineBytes = d.MaxLineBytes
	}
	if l.MaxParserDepth <= 0 {
		l.MaxParserDepth = d.MaxParserDepth
	}
	if l.MaxRedirects <= 0 {
		l.MaxRedirects = d.MaxRedirects
	}
	if l.RequestTimeout <= 0 {
		l.RequestTimeout = d.RequestTimeout
	}
	return l
}

type Unsupported struct {
	Index  int    `json:"index"`
	Name   string `json:"name,omitempty"`
	Reason string `json:"reason"`
}
type ParseReport struct {
	Format      Format        `json:"format"`
	Warnings    []string      `json:"warnings,omitempty"`
	Errors      []string      `json:"errors,omitempty"`
	Unsupported []Unsupported `json:"unsupported,omitempty"`
	Skipped     int           `json:"skipped"`
}
type Parsed struct {
	ProviderID  string       `json:"provider_id"`
	ContentHash string       `json:"-"`
	Nodes       []nodes.Node `json:"nodes"`
	Report      ParseReport  `json:"report"`
}

var (
	ErrBodyTooLarge = errors.New("provider body exceeds configured limit")
	ErrNoNodes      = errors.New("provider contains no supported nodes")
	ErrFetch        = errors.New("provider fetch failed")
)

// Parse imports bounded content. The source format hint is advisory; auto
// detection always inspects the content and never trusts a filename.

func Parse(providerID string, content []byte, hint Format, limits Limits) (Parsed, error) {
	limits = limits.withDefaults()
	p := Parsed{ProviderID: providerID}
	if int64(len(content)) > limits.MaxBodyBytes {
		return p, ErrBodyTooLarge
	}
	if len(bytes.TrimSpace(content)) == 0 {
		return p, ErrNoNodes
	}
	format, body, err := detect(content, hint, limits)
	if err != nil {
		return p, err
	}
	p.Report.Format = format
	var raw []rawNode
	switch format {
	case FormatNative, FormatLinks, FormatBase64:
		raw, err = parseLinks(body, limits, &p.Report)
	case FormatClash, FormatSIP008, FormatJSON:
		if format != FormatClash && !json.Valid(body) {
			return p, errors.New("invalid subscription JSON")
		}
		raw, err = parseDocument(body, limits, &p.Report)
	default:
		return p, errors.New("unsupported subscription format")
	}
	if err != nil {
		return p, err
	}
	seen := map[string]bool{}
	for _, item := range raw {
		if err := validateSubset(item.definition); err != nil {
			p.Report.Unsupported = append(p.Report.Unsupported, Unsupported{Index: item.index, Name: safeName(item.name), Reason: err.Error()})
			continue
		}
		n, err := nodes.New(providerID, item.name, item.definition, "")
		if err != nil {
			p.Report.Unsupported = append(p.Report.Unsupported, Unsupported{Index: item.index, Name: safeName(item.name), Reason: "invalid or unsupported connection definition"})
			continue
		}
		if seen[n.Identity] {
			p.Report.Skipped++
			p.Report.Warnings = append(p.Report.Warnings, "identical provider entry deduplicated")
			continue
		}
		seen[n.Identity] = true
		p.Nodes = append(p.Nodes, n)
	}
	if len(p.Nodes) == 0 {
		return p, ErrNoNodes
	}
	keys := make([]string, 0, len(p.Nodes)+len(p.Report.Unsupported))
	for _, n := range p.Nodes {
		keys = append(keys, n.Identity+"\x00"+n.ContentHash)
	}
	for _, u := range p.Report.Unsupported {
		keys = append(keys, "unsupported\x00"+u.Name+"\x00"+u.Reason)
	}
	sort.Strings(keys)
	digest := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	p.ContentHash = hex.EncodeToString(digest[:])
	return p, nil
}

type rawNode struct {
	name       string
	definition nodes.Definition
	index      int
}

func safeName(s string) string {
	if len(s) > 120 {
		return s[:120]
	}
	return s
}
func detect(content []byte, hint Format, l Limits) (Format, []byte, error) {
	b := bytes.TrimSpace(content)
	switch hint {
	case FormatLinks, FormatClash, FormatSIP008, FormatJSON:
		return hint, b, nil
	case FormatBase64:
		d, e := decodeBase64(b, l.MaxDecodedBytes)
		return FormatBase64, d, e
	case FormatNative:
		format, payload, err := detect(b, FormatAuto, l)
		if format == FormatLinks {
			format = FormatNative
		}
		return format, payload, err
	case "", FormatAuto:
	default:
		return "", nil, errors.New("unsupported subscription format")
	}
	if b[0] == '{' || b[0] == '[' {
		return FormatJSON, b, nil
	}
	if bytes.Contains(b, []byte("proxies:")) {
		return FormatClash, b, nil
	}
	if bytes.Contains(b, []byte("://")) {
		return FormatLinks, b, nil
	}
	if d, e := decodeBase64(b, l.MaxDecodedBytes); e == nil && bytes.Contains(d, []byte("://")) {
		return FormatBase64, d, nil
	}
	return FormatLinks, b, nil
}
func decodeBase64(b []byte, max int64) ([]byte, error) {
	s := strings.Map(func(r rune) rune {
		if strings.ContainsRune(" \n\t\r", r) {
			return -1
		}
		return r
	}, string(b))
	if int64(len(s)) > max*2 {
		return nil, ErrBodyTooLarge
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(s)
		if err == nil {
			if int64(len(decoded)) > max {
				return nil, ErrBodyTooLarge
			}
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64 subscription")
}
func parseLinks(b []byte, l Limits, report *ParseReport) ([]rawNode, error) {
	out := []rawNode{}
	scan := bufio.NewScanner(bytes.NewReader(b))
	scan.Buffer(make([]byte, min(1024, l.MaxLineBytes)), l.MaxLineBytes)
	count := 0
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
		if count > l.MaxNodes {
			return nil, errors.New("subscription exceeds node count limit")
		}
		item, err := parseLink(line, l)
		if err != nil {
			report.Unsupported = append(report.Unsupported, Unsupported{Index: count - 1, Reason: err.Error()})
			continue
		}
		item.index = count - 1
		out = append(out, item)
	}
	if scan.Err() != nil {
		return nil, errors.New("node link exceeds line limit")
	}
	return out, nil
}
func parseLink(line string, l Limits) (rawNode, error) {
	scheme, tail, ok := strings.Cut(line, "://")
	if !ok {
		return rawNode{}, errors.New("invalid node link")
	}
	scheme = strings.ToLower(scheme)
	if scheme == "vmess" {
		decoded, e := decodeBase64([]byte(tail), l.MaxDecodedBytes)
		if e != nil {
			return rawNode{}, errors.New("invalid VMess payload")
		}
		return parseVMess(decoded, l)
	}
	if scheme == "ss" && !strings.Contains(strings.Split(tail, "#")[0], "@") {
		payload, fragment, _ := strings.Cut(tail, "#")
		decoded, e := decodeBase64([]byte(payload), l.MaxDecodedBytes)
		if e != nil {
			return rawNode{}, errors.New("invalid Shadowsocks payload")
		}
		credentials, address, ok := cutLast(string(decoded), "@")
		if !ok {
			return rawNode{}, errors.New("invalid Shadowsocks address")
		}
		method, password, ok := strings.Cut(credentials, ":")
		if !ok {
			return rawNode{}, errors.New("invalid Shadowsocks credentials")
		}
		u, e := url.Parse("ss://" + address)
		if e != nil {
			return rawNode{}, errors.New("invalid Shadowsocks address")
		}
		u.User = url.UserPassword(method, password)
		u.Fragment = fragment
		return nodeFromURL(u)
	}
	u, e := url.Parse(line)
	if e != nil {
		return rawNode{}, errors.New("invalid node link")
	}
	return nodeFromURL(u)
}
func cutLast(s, sep string) (string, string, bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(sep):], true
}
func nodeFromURL(u *url.URL) (rawNode, error) {
	protocol := strings.ToLower(u.Scheme)
	switch protocol {
	case "ss", "vless", "trojan", "socks5", "http", "https":
	default:
		return rawNode{}, errors.New("unsupported node protocol")
	}
	if u.Path != "" && u.Path != "/" {
		return rawNode{}, errors.New("unsupported node URI path")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil {
		return rawNode{}, errors.New("node port is required")
	}
	d := nodes.Definition{Protocol: nodes.Protocol(protocol), Host: u.Hostname(), Port: port, TLS: protocol == "trojan" || protocol == "https"}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return rawNode{}, errors.New("invalid node query")
	}
	// This subset supports TLS SNI and ordered ALPN only. Every other option is
	// rejected rather than discarding transport or certificate semantics.
	for k, v := range query {
		if len(v) != 1 {
			return rawNode{}, errors.New("duplicate node option")
		}
		switch k {
		case "sni":
			if protocol != "trojan" && protocol != "vless" && protocol != "https" {
				return rawNode{}, errors.New("TLS option is unsupported by node protocol")
			}
			d.SNI = v[0]
		case "security":
			if protocol != "vless" || (v[0] != "tls" && v[0] != "none") {
				return rawNode{}, errors.New("unsupported node security")
			}
			d.TLS = v[0] == "tls"
		case "type":
			if protocol != "vless" || v[0] != "tcp" {
				return rawNode{}, errors.New("unsupported node transport")
			}
			d.Network = "tcp"
		case "encryption":
			if protocol != "vless" || v[0] != "none" {
				return rawNode{}, errors.New("unsupported node encryption")
			}
		case "alpn":
			if protocol != "trojan" && protocol != "vless" && protocol != "https" {
				return rawNode{}, errors.New("ALPN unsupported by node protocol")
			}
			d.ALPN = strings.Split(v[0], ",")
		default:
			return rawNode{}, errors.New("unsupported node option")
		}
	}
	if u.User != nil {
		d.Username = u.User.Username()
		d.Password, _ = u.User.Password()
	}
	switch protocol {
	case "vless":
		if u.User == nil {
			return rawNode{}, errors.New("missing node credential")
		}
		if _, ok := u.User.Password(); ok {
			return rawNode{}, errors.New("unexpected node credential")
		}
		d.UUID = d.Username
		d.Username = ""
	case "trojan":
		if u.User == nil {
			return rawNode{}, errors.New("missing node credential")
		}
		if _, ok := u.User.Password(); ok {
			return rawNode{}, errors.New("unexpected node credential")
		}
		d.Password = d.Username
		d.Username = ""
	case "ss":
		if u.User == nil {
			return rawNode{}, errors.New("missing node credential")
		}
		if _, present := u.User.Password(); !present {
			plain, e := decodeBase64([]byte(d.Username), 1<<20)
			if e != nil {
				return rawNode{}, errors.New("invalid Shadowsocks credentials")
			}
			var ok bool
			d.Username, d.Password, ok = strings.Cut(string(plain), ":")
			if !ok {
				return rawNode{}, errors.New("invalid Shadowsocks credentials")
			}
		}
		d.Method = d.Username
		d.Username = ""
	}
	if (protocol == "ss" || protocol == "trojan") && d.Password == "" || protocol == "vless" && d.UUID == "" {
		return rawNode{}, errors.New("missing node credential")
	}
	if !d.TLS && (d.SNI != "" || len(d.ALPN) > 0) {
		return rawNode{}, errors.New("TLS options require TLS")
	}
	name := u.Fragment
	if name == "" {
		name = d.Host
	}
	return rawNode{name: name, definition: d}, nil
}

func parseVMess(body []byte, l Limits) (rawNode, error) {
	if !json.Valid(body) {
		return rawNode{}, errors.New("invalid VMess JSON")
	}
	root, err := decodeDocument(body, l)
	if err != nil {
		return rawNode{}, errors.New("invalid VMess JSON")
	}
	if root.Kind != yaml.MappingNode {
		return rawNode{}, errors.New("invalid VMess object")
	}
	m, err := scalarMap(root)
	if err != nil {
		return rawNode{}, err
	}
	allowed := map[string]bool{"v": true, "ps": true, "add": true, "port": true, "id": true, "aid": true, "scy": true, "net": true, "type": true, "host": true, "path": true, "tls": true, "sni": true, "alpn": true}
	for k := range m {
		if !allowed[k] {
			return rawNode{}, errors.New("unsupported VMess option")
		}
	}
	if m["v"] != "" && m["v"] != "2" {
		return rawNode{}, errors.New("unsupported VMess version")
	}
	if m["aid"] != "" && m["aid"] != "0" || m["scy"] != "" && m["scy"] != "auto" || m["net"] != "" && m["net"] != "tcp" || m["type"] != "" && m["type"] != "none" || m["path"] != "" || m["host"] != "" {
		return rawNode{}, errors.New("unsupported VMess transport or cipher")
	}
	if m["tls"] != "" && m["tls"] != "tls" && m["tls"] != "none" {
		return rawNode{}, errors.New("unsupported VMess TLS setting")
	}
	port, err := strconv.Atoi(m["port"])
	if err != nil {
		return rawNode{}, errors.New("invalid VMess port")
	}
	d := nodes.Definition{Protocol: nodes.ProtocolVMess, Host: m["add"], Port: port, UUID: m["id"], TLS: m["tls"] == "tls", SNI: m["sni"], Network: "tcp"}
	if d.UUID == "" {
		return rawNode{}, errors.New("missing VMess credential")
	}
	if m["alpn"] != "" {
		d.ALPN = strings.Split(m["alpn"], ",")
	}
	if !d.TLS && (d.SNI != "" || len(d.ALPN) > 0) {
		return rawNode{}, errors.New("TLS options require TLS")
	}
	return rawNode{name: first(m["ps"], d.Host), definition: d}, nil
}

// Decode to a YAML AST before converting mappings so alias expansion,
// duplicate keys, depth and nonstandard tags are rejected consistently for
// both YAML and JSON documents.
func decodeDocument(body []byte, l Limits) (*yaml.Node, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(body))
	if dec.Decode(&doc) != nil {
		return nil, errors.New("invalid subscription document")
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("subscription must contain one document")
	}
	if len(doc.Content) != 1 {
		return nil, errors.New("empty subscription document")
	}
	if err := validateYAML(&doc, 0, l.MaxParserDepth); err != nil {
		return nil, err
	}
	return doc.Content[0], nil
}
func validateYAML(n *yaml.Node, depth, maxDepth int) error {
	if depth > maxDepth {
		return errors.New("subscription exceeds parser depth limit")
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return errors.New("YAML anchors and aliases are unsupported")
	}
	if n.Kind == yaml.MappingNode && n.Tag != "!!map" || n.Kind == yaml.SequenceNode && n.Tag != "!!seq" {
		return errors.New("unsupported YAML tag")
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				return errors.New("mapping keys must be strings")
			}
			if seen[k.Value] {
				return errors.New("duplicate mapping key")
			}
			seen[k.Value] = true
		}
	}
	if n.Kind == yaml.ScalarNode {
		switch n.Tag {
		case "!!str", "!!int", "!!bool", "!!null", "!!float":
		default:
			return errors.New("unsupported YAML tag")
		}
	}
	for _, c := range n.Content {
		if err := validateYAML(c, depth+1, maxDepth); err != nil {
			return err
		}
	}
	return nil
}
func parseDocument(body []byte, l Limits, report *ParseReport) ([]rawNode, error) {
	root, err := decodeDocument(body, l)
	if err != nil {
		return nil, err
	}
	var list *yaml.Node
	if root.Kind == yaml.SequenceNode {
		list = root
	} else if root.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == "proxies" || root.Content[i].Value == "servers" {
				if list != nil {
					return nil, errors.New("ambiguous inventory lists")
				}
				list = root.Content[i+1]
			}
		}
	}
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil, errors.New("subscription has no node inventory list")
	}
	if len(list.Content) > l.MaxNodes {
		return nil, errors.New("subscription exceeds node count limit")
	}
	out := []rawNode{}
	for i, item := range list.Content {
		r, e := nodeFromMapping(item)
		if e != nil {
			report.Unsupported = append(report.Unsupported, Unsupported{Index: i, Name: nodeDisplayName(item), Reason: e.Error()})
			continue
		}
		r.index = i
		out = append(out, r)
	}
	return out, nil
}

func nodeDisplayName(n *yaml.Node) string {
	if n.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "name" && n.Content[i+1].Kind == yaml.ScalarNode {
			return safeName(n.Content[i+1].Value)
		}
	}
	return ""
}
func scalarMap(n *yaml.Node) (map[string]string, error) {
	if n.Kind != yaml.MappingNode {
		return nil, errors.New("node must be a mapping")
	}
	m := map[string]string{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		v := n.Content[i+1]
		if v.Kind != yaml.ScalarNode {
			return nil, errors.New("unsupported nested node option")
		}
		m[n.Content[i].Value] = v.Value
	}
	return m, nil
}
func nodeFromMapping(n *yaml.Node) (rawNode, error) {
	if n.Kind != yaml.MappingNode {
		return rawNode{}, errors.New("node must be a mapping")
	}
	// ALPN is the only sequence supported inside this conservative subset.
	fields := map[string]*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		fields[n.Content[i].Value] = n.Content[i+1]
	}
	allowed := map[string]bool{"name": true, "remarks": true, "type": true, "server": true, "port": true, "server_port": true, "uuid": true, "username": true, "password": true, "tls": true, "servername": true, "sni": true, "network": true, "cipher": true, "method": true, "alpn": true}
	m := map[string]string{}
	for k, v := range fields {
		if !allowed[k] {
			return rawNode{}, errors.New("unsupported node option")
		}
		if k == "alpn" {
			continue
		}
		if v.Kind != yaml.ScalarNode {
			return rawNode{}, errors.New("unsupported nested node option")
		}
		if k != "port" && k != "server_port" && k != "tls" && v.Tag != "!!str" {
			return rawNode{}, errors.New("node text fields must be strings")
		}
		if k == "tls" && v.Tag != "!!bool" {
			return rawNode{}, errors.New("TLS flag must be boolean")
		}
		m[k] = v.Value
	}
	for _, pair := range [][2]string{{"port", "server_port"}, {"servername", "sni"}, {"cipher", "method"}} {
		if _, ok := fields[pair[0]]; ok {
			if _, other := fields[pair[1]]; other {
				return rawNode{}, errors.New("ambiguous node options")
			}
		}
	}
	protocol := m["type"]
	if protocol == "" && (m["cipher"] != "" || m["method"] != "") {
		protocol = "ss"
	}
	switch protocol {
	case "ss", "vmess", "vless", "trojan", "http", "https", "socks5":
	default:
		return rawNode{}, errors.New("unsupported node protocol")
	}
	// Reject even understood fields when the protocol cannot consume them.
	if protocol != "ss" && (m["cipher"] != "" || m["method"] != "") {
		return rawNode{}, errors.New("cipher is unsupported by node protocol")
	}
	if protocol != "vmess" && protocol != "vless" && m["uuid"] != "" {
		return rawNode{}, errors.New("UUID is unsupported by node protocol")
	}
	if m["network"] != "" && m["network"] != "tcp" {
		return rawNode{}, errors.New("unsupported node transport")
	}
	if m["network"] != "" && protocol != "vmess" && protocol != "vless" {
		return rawNode{}, errors.New("transport is unsupported by node protocol")
	}
	port, err := strconv.Atoi(first(m["port"], m["server_port"]))
	if err != nil {
		return rawNode{}, errors.New("invalid node port")
	}
	tls := protocol == "https" || protocol == "trojan"
	if v, ok := m["tls"]; ok {
		var e error
		tls, e = strconv.ParseBool(v)
		if e != nil {
			return rawNode{}, errors.New("invalid TLS flag")
		}
		if (protocol == "trojan" || protocol == "https") && !tls {
			return rawNode{}, errors.New("node protocol requires TLS")
		}
	}
	d := nodes.Definition{Protocol: nodes.Protocol(protocol), Host: m["server"], Port: port, UUID: m["uuid"], Username: m["username"], Password: m["password"], TLS: tls, SNI: first(m["servername"], m["sni"]), Network: m["network"], Method: first(m["cipher"], m["method"])}
	if a := fields["alpn"]; a != nil {
		if a.Kind != yaml.SequenceNode {
			return rawNode{}, errors.New("ALPN must be an ordered string list")
		}
		for _, v := range a.Content {
			if v.Kind != yaml.ScalarNode || v.Tag != "!!str" {
				return rawNode{}, errors.New("ALPN must be an ordered string list")
			}
			d.ALPN = append(d.ALPN, v.Value)
		}
	}
	if !d.TLS && (d.SNI != "" || len(d.ALPN) > 0) {
		return rawNode{}, errors.New("TLS options require TLS")
	}
	if protocol == "ss" && d.TLS {
		return rawNode{}, errors.New("TLS unsupported by Shadowsocks subset")
	}
	if (protocol == "ss" || protocol == "trojan") && d.Password == "" || (protocol == "vmess" || protocol == "vless") && d.UUID == "" {
		return rawNode{}, errors.New("missing node credential")
	}
	if (protocol == "vmess" || protocol == "vless") && (d.Password != "" || d.Username != "") || protocol == "trojan" && d.Username != "" {
		return rawNode{}, errors.New("unsupported authentication option")
	}
	return rawNode{name: first(m["name"], m["remarks"], d.Host), definition: d}, nil
}
func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Every accepted connection field has a concrete meaning in this subset.
// Advanced transports/ciphers require their own adapter qualification before
// they can be admitted; retaining unknown strings is not semantic support.
func validateSubset(d nodes.Definition) error {
	if strings.ContainsAny(d.Host, " /\\\t\r\n@#?") {
		return errors.New("invalid node host")
	}
	for _, alpn := range d.ALPN {
		if len(alpn) == 0 || len(alpn) > 255 {
			return errors.New("invalid ALPN identifier")
		}
	}
	if d.Protocol == nodes.ProtocolShadowsocks {
		allowed := map[string]bool{"aes-128-gcm": true, "aes-256-gcm": true, "chacha20-ietf-poly1305": true, "chacha20": true, "chacha20-ietf": true, "aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true}
		if !allowed[d.Method] {
			return errors.New("unsupported Shadowsocks cipher")
		}
	}
	if d.Protocol == nodes.ProtocolHTTP && d.TLS || d.Protocol == nodes.ProtocolSOCKS5 && d.TLS {
		return errors.New("TLS unsupported by node protocol subset")
	}
	return nil
}
