// Package nodes contains the provider-independent representation of a proxy
// node. Provider adapters normalize their input into this representation before
// a node is made available to an outbound group.
package nodes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

// Protocol is intentionally a string. New protocols can be reported as
// unsupported without changing the storage schema.
type Protocol string

const (
	ProtocolShadowsocks Protocol = "ss"
	ProtocolVMess       Protocol = "vmess"
	ProtocolVLess       Protocol = "vless"
	ProtocolTrojan      Protocol = "trojan"
	ProtocolHTTP        Protocol = "http"
	ProtocolHTTPS       Protocol = "https"
	ProtocolSOCKS5      Protocol = "socks5"
	ProtocolHysteria2   Protocol = "hysteria2"
)

var supportedProtocols = map[Protocol]bool{
	ProtocolShadowsocks: true, ProtocolVMess: true, ProtocolVLess: true,
	ProtocolTrojan: true, ProtocolHTTP: true, ProtocolHTTPS: true,
	ProtocolSOCKS5: true, ProtocolHysteria2: true,
}

// Definition is a normalized connection definition. Passwords and tokens are
// kept in memory for the adapter but are omitted by the public Node JSON form.
type Definition struct {
	Protocol Protocol `json:"protocol"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"-"`
	Password string   `json:"-"`
	// UUID is a connection credential and is retained only inside the adapter.
	UUID        string   `json:"-"`
	TLS         bool     `json:"tls,omitempty"`
	SNI         string   `json:"sni,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Network     string   `json:"network,omitempty"`
	Path        string   `json:"path,omitempty"`
	Service     string   `json:"service,omitempty"`
	Method      string   `json:"method,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	// Provider-specific fields may contain credentials and are not public API data.
	Headers map[string]string `json:"-"`
	Extra   map[string]string `json:"-"`
}

// Node is the stable logical identity plus the current connection revision.
// Identity excludes display name and ordering; ContentHash includes all
// security-relevant connection fields (including credentials).
type Node struct {
	ID                string     `json:"id"`
	ProviderID        string     `json:"provider_id"`
	Name              string     `json:"name"`
	Identity          string     `json:"-"`
	Revision          int64      `json:"revision"`
	ContentHash       string     `json:"-"`
	Definition        Definition `json:"definition"`
	Supported         bool       `json:"supported"`
	UnsupportedReason string     `json:"unsupported_reason,omitempty"`
}

var (
	ErrProtocolUnsupported = errors.New("unsupported node protocol")
	ErrInvalidDefinition   = errors.New("invalid node definition")
)

func normalizeProtocol(p string) Protocol {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "socks" || p == "socks5h" {
		return ProtocolSOCKS5
	}
	if p == "http+tls" {
		return ProtocolHTTPS
	}
	return Protocol(p)
}

// Normalize validates and canonicalizes a connection definition.
func Normalize(d Definition) (Definition, error) {
	d.Protocol = normalizeProtocol(string(d.Protocol))
	d.Host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.Host)), ".")
	if d.Host == "" {
		return Definition{}, fmt.Errorf("%w: host is required", ErrInvalidDefinition)
	}
	if ip := net.ParseIP(d.Host); ip != nil {
		d.Host = ip.String()
	}
	if d.Port < 1 || d.Port > 65535 {
		return Definition{}, fmt.Errorf("%w: port must be between 1 and 65535", ErrInvalidDefinition)
	}
	if d.Protocol == "" {
		return Definition{}, fmt.Errorf("%w: protocol is required", ErrInvalidDefinition)
	}
	if !supportedProtocols[d.Protocol] {
		return d, fmt.Errorf("%w: %s", ErrProtocolUnsupported, d.Protocol)
	}
	d.SNI, d.Network, d.Method, d.Fingerprint = strings.TrimSpace(strings.ToLower(d.SNI)), strings.TrimSpace(strings.ToLower(d.Network)), strings.TrimSpace(strings.ToLower(d.Method)), strings.TrimSpace(d.Fingerprint)
	// Credentials, header values, paths, and protocol-specific fields are opaque.
	// ALPN values are case-sensitive, and their order carries preference.
	d.ALPN = cloneStrings(d.ALPN)
	d.Headers = cloneMap(d.Headers)
	d.Extra = cloneMap(d.Extra)
	return d, nil
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// IdentityFingerprint returns a private provider-scoped fingerprint of the
// complete connection definition, including all credentials. It must not be
// exposed publicly: a digest of a weak credential can support offline guessing.
func IdentityFingerprint(providerID string, d Definition) string {
	n, err := Normalize(d)
	if err != nil {
		n = d
	}
	identity := struct {
		Provider   string            `json:"provider"`
		Definition privateDefinition `json:"definition"`
	}{providerID, definitionForSnapshot(n)}
	b, _ := json.Marshal(identity)
	sum := sha256.Sum256(b)
	return "n-" + hex.EncodeToString(sum[:])
}

// ContentFingerprint hashes the complete normalized connection definition.
// This credential-derived digest is private and must not appear in public APIs.
func ContentFingerprint(d Definition) string {
	n, err := Normalize(d)
	if err != nil {
		n = d
	}
	b, _ := json.Marshal(definitionForSnapshot(n))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// New constructs a node with a random public ID. stableID may be supplied only
// when the caller has a trustworthy provider-issued logical node ID; a protocol
// credential such as a VMess UUID is not such an ID. Without stableID, complete
// connection data determines private identity. Registries retain the public ID
// when reconciling a matching private identity across provider revisions.
func New(providerID, name string, d Definition, stableID string) (Node, error) {
	n, err := Normalize(d)
	if err != nil {
		return Node{}, err
	}
	identity := IdentityFingerprint(providerID, n)
	if stableID != "" {
		raw, _ := json.Marshal([2]string{providerID, stableID})
		sum := sha256.Sum256(raw)
		identity = "n-" + hex.EncodeToString(sum[:])
	}
	return Node{ID: domain.NewID(), ProviderID: providerID, Name: strings.TrimSpace(name), Identity: identity, Revision: 1, ContentHash: ContentFingerprint(n), Definition: n, Supported: true}, nil
}

// Clone returns a node whose definition has no mutable data shared with n.
func Clone(n Node) Node {
	n.Definition.ALPN = cloneStrings(n.Definition.ALPN)
	n.Definition.Headers = cloneMap(n.Definition.Headers)
	n.Definition.Extra = cloneMap(n.Definition.Extra)
	return n
}

// WithRevision updates a node's connection revision while retaining logical
// identity. The caller can use this when credential/transport fields change.
func (n Node) WithRevision(d Definition) (Node, error) {
	normalized, err := Normalize(d)
	if err != nil {
		return Node{}, err
	}
	if n.Identity == "" {
		return Node{}, errors.New("node identity is required")
	}
	n.Definition, n.ContentHash, n.Revision = normalized, ContentFingerprint(normalized), n.Revision+1
	if n.Revision < 1 {
		n.Revision = 1
	}
	return n, nil
}

func (n Node) ProtocolName() string { return string(n.Definition.Protocol) }
func (n Node) Address() string {
	return net.JoinHostPort(n.Definition.Host, strconv.Itoa(n.Definition.Port))
}
func (n Node) SecretConfigured() bool {
	return n.Definition.Password != "" || n.Definition.UUID != "" || n.Definition.Username != ""
}
