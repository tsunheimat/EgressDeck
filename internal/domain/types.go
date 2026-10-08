// Package domain contains the controller's storage-independent model and
// invariants. Adapters should translate their native objects into these types
// instead of exposing provider-specific payloads to the API.
package domain

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

type Action string

const (
	ActionDirect   Action = "direct"
	ActionProxy    Action = "proxy"
	ActionBlock    Action = "block"
	ActionOutbound Action = "outbound_group"
)

type EnrollmentState string

const (
	EnrollmentUnenrolled EnrollmentState = "unenrolled"
	EnrollmentPending    EnrollmentState = "pending"
	EnrollmentEnrolled   EnrollmentState = "enrolled"
	EnrollmentBlocked    EnrollmentState = "blocked"
)

type AddressFamily string

const (
	IPv4 AddressFamily = "ipv4"
	IPv6 AddressFamily = "ipv6"
)

type DeviceAddress struct {
	Address    string        `json:"address"`
	Family     AddressFamily `json:"family"`
	Provenance string        `json:"provenance,omitempty"`
	VerifiedAt *time.Time    `json:"verified_at,omitempty"`
}

type Device struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	PrimaryGroupID  string            `json:"primary_group_id,omitempty"`
	Addresses       []DeviceAddress   `json:"addresses"`
	Exceptions      []json.RawMessage `json:"exceptions,omitempty"`
	EnrollmentState EnrollmentState   `json:"enrollment_state"`
	Revision        int64             `json:"revision"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

type Rule struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	DomainSuffix    []string `json:"domain_suffix,omitempty"`
	DestinationIP   []string `json:"destination_ip,omitempty"`
	Ports           []string `json:"ports,omitempty"`
	Transport       []string `json:"transport,omitempty"`
	Action          Action   `json:"action"`
	OutboundGroupID string   `json:"outbound_group_id,omitempty"`
	Enabled         bool     `json:"enabled"`
}

type Policy struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Entries             []Rule `json:"entries"`
	DefaultAction       Action `json:"default_action"`
	UnknownDomainAction Action `json:"unknown_domain_action"`
	ProxyFailureAction  Action `json:"proxy_failure_action"`
	Revision            int64  `json:"revision"`
}

type DeviceGroup struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	GatewayID string    `json:"gateway_id"`
	PolicyID  string    `json:"policy_id"`
	Enabled   bool      `json:"enabled"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Provider struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Source         string    `json:"source"`
	Format         string    `json:"format"`
	FetchRoute     string    `json:"fetch_route"`
	ActiveRevision int64     `json:"active_revision"`
	Revision       int64     `json:"revision"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Node struct {
	ID         string `json:"id"`
	ProviderID string `json:"provider_id"`
	Name       string `json:"name"`
	Identity   string `json:"identity"`
	Revision   int64  `json:"revision"`
}

type OutboundGroup struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	NodeIDs       []string `json:"node_ids"`
	SelectionMode string   `json:"selection_mode"`
	Revision      int64    `json:"revision"`
}

type Gateway struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Endpoint           string    `json:"endpoint"`
	Adapter            string    `json:"adapter"`
	ObservedGeneration int64     `json:"observed_generation"`
	Revision           int64     `json:"revision"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type DeploymentPreview struct {
	Valid      bool     `json:"valid"`
	Warnings   []string `json:"warnings,omitempty"`
	Errors     []string `json:"errors,omitempty"`
	Impact     []string `json:"impact,omitempty"`
	SourceHash string   `json:"source_hash,omitempty"`
}

var (
	ErrNotFound        = errors.New("resource not found")
	ErrConflict        = errors.New("resource revision conflict")
	ErrAddressConflict = errors.New("address is already owned by another device")
)

type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string { return strings.Join(e.Problems, "; ") }

func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is exceptional; a timestamp-based value keeps the
		// API usable while preserving uniqueness within one process.
		return fmt.Sprintf("id-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[0:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}

func NormalizeAddress(raw string) (string, AddressFamily, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", "", fmt.Errorf("invalid IP address %q", raw)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), IPv4, nil
	}
	return ip.String(), IPv6, nil
}

func (d *Device) Validate() error {
	problems := make([]string, 0)
	if strings.TrimSpace(d.Name) == "" {
		problems = append(problems, "name is required")
	}
	if len(d.Name) > 200 {
		problems = append(problems, "name exceeds 200 characters")
	}
	if d.EnrollmentState == "" {
		d.EnrollmentState = EnrollmentUnenrolled
	}
	if d.EnrollmentState != EnrollmentUnenrolled && d.EnrollmentState != EnrollmentPending && d.EnrollmentState != EnrollmentEnrolled && d.EnrollmentState != EnrollmentBlocked {
		problems = append(problems, "invalid enrollment_state")
	}
	seen := map[string]struct{}{}
	for i := range d.Addresses {
		normalized, family, err := NormalizeAddress(d.Addresses[i].Address)
		if err != nil {
			problems = append(problems, fmt.Sprintf("addresses[%d]: %v", i, err))
			continue
		}
		if _, ok := seen[normalized]; ok {
			problems = append(problems, fmt.Sprintf("addresses[%d]: duplicate address", i))
		}
		seen[normalized] = struct{}{}
		d.Addresses[i].Address, d.Addresses[i].Family = normalized, family
	}
	for i, raw := range d.Exceptions {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || object == nil {
			problems = append(problems, fmt.Sprintf("exceptions[%d]: must be a JSON object", i))
			continue
		}
		// File snapshots are indented JSON. Normalize whitespace on both writes
		// and reloads so the in-memory representation survives a restart.
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err == nil {
			d.Exceptions[i] = append(json.RawMessage(nil), compact.Bytes()...)
		}
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

func (g *DeviceGroup) Validate() error {
	problems := make([]string, 0)
	if strings.TrimSpace(g.Name) == "" {
		problems = append(problems, "name is required")
	}
	if strings.TrimSpace(g.GatewayID) == "" {
		problems = append(problems, "gateway_id is required")
	}
	if strings.TrimSpace(g.PolicyID) == "" {
		problems = append(problems, "policy_id is required")
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

func (p *Provider) Validate() error {
	problems := make([]string, 0)
	if strings.TrimSpace(p.Name) == "" {
		problems = append(problems, "name is required")
	}
	if strings.TrimSpace(p.Source) == "" {
		problems = append(problems, "source is required")
	}
	if p.Format == "" {
		p.Format = "auto"
	}
	if p.FetchRoute == "" {
		p.FetchRoute = "direct"
	}
	if !strings.HasPrefix(strings.ToLower(p.Source), "https://") && !strings.HasPrefix(strings.ToLower(p.Source), "http://") && p.Format != "local" && !regexp.MustCompile(`^secret_[0-9a-f]{32}$`).MatchString(p.Source) {
		problems = append(problems, "source must be an http(s) URL or local format")
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

func (g *Gateway) Validate() error {
	problems := make([]string, 0)
	if strings.TrimSpace(g.Name) == "" {
		problems = append(problems, "name is required")
	}
	if strings.TrimSpace(g.Endpoint) == "" {
		problems = append(problems, "endpoint is required")
	}
	if strings.TrimSpace(g.Adapter) == "" {
		g.Adapter = "dae"
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}
