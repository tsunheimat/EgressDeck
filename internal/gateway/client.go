package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrProtocol       = errors.New("gateway returned an invalid response")
	ErrOutcomeUnknown = errors.New("gateway mutation outcome is unknown; readback required")
	ErrUnauthorized   = errors.New("gateway authentication or authorization failed")
)

// ClientOptions is operator-supplied connection configuration, not a provider
// subscription URL. TLSConfig must verify the server and include a client
// identity. LoadClientTLS constructs a suitable configuration from PEM files.
type ClientOptions struct {
	Endpoint         string
	Token            string
	TLSConfig        *tls.Config
	Timeout          time.Duration
	MaxResponseBytes int64
}

type remoteStage struct {
	revision   ProviderRevision
	generation int64
}

// Client implements exactly this repository's gateway-agent HTTP protocol.
// Requests never follow redirects or retry mutations. A lost mutation response
// yields ErrOutcomeUnknown; reconciliation must observe state before retrying.
type Client struct {
	endpoint         string
	token            string
	http             *http.Client
	maxResponseBytes int64
	mu               sync.Mutex
	stages           map[string]remoteStage
}

func NewClient(options ClientOptions) (*Client, error) {
	u, err := url.Parse(options.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("gateway endpoint must be an HTTPS URL without credentials, query, or fragment")
	}
	if strings.ContainsAny(options.Token, "\r\n") || strings.TrimSpace(options.Token) == "" {
		return nil, fmt.Errorf("gateway bearer token is required and must not contain newlines")
	}
	if options.TLSConfig == nil || options.TLSConfig.InsecureSkipVerify || options.TLSConfig.RootCAs == nil || len(options.TLSConfig.Certificates) == 0 {
		return nil, fmt.Errorf("gateway client requires verified TLS roots and a client certificate")
	}
	tlsConfig := options.TLSConfig.Clone()
	tlsConfig.MinVersion = tls.VersionTLS13
	if tlsConfig.MaxVersion != 0 && tlsConfig.MaxVersion < tls.VersionTLS13 {
		return nil, fmt.Errorf("gateway client requires TLS 1.3")
	}
	if options.Timeout <= 0 {
		options.Timeout = 20 * time.Second
	}
	if options.MaxResponseBytes <= 0 {
		options.MaxResponseBytes = 8 << 20
	}
	if options.MaxResponseBytes > 32<<20 {
		return nil, fmt.Errorf("gateway response limit exceeds 32 MiB")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DialContext: (&net.Dialer{Timeout: options.Timeout, KeepAlive: 30 * time.Second}).DialContext, TLSHandshakeTimeout: options.Timeout, ResponseHeaderTimeout: options.Timeout, IdleConnTimeout: 60 * time.Second, MaxIdleConns: 8, MaxIdleConnsPerHost: 4, MaxResponseHeaderBytes: 64 << 10, DisableCompression: true}
	httpClient := &http.Client{Transport: transport, Timeout: options.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{endpoint: strings.TrimRight(u.String(), "/"), token: options.Token, http: httpClient, maxResponseBytes: options.MaxResponseBytes, stages: map[string]remoteStage{}}, nil
}

func (c *Client) CloseIdleConnections() { c.http.CloseIdleConnections() }

func clientFailure(op, code, detail string, cause error) error {
	return &Error{Code: code, Operation: op, Detail: detail, Cause: cause}
}

func (c *Client) request(ctx context.Context, method, path, op string, input, output any, expected int, mutation bool) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return clientFailure(op, "invalid_request", "request could not be encoded", ErrValidation)
		}
		if len(data) > 8<<20 {
			return clientFailure(op, "invalid_request", "request exceeds 8 MiB", ErrValidation)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return clientFailure(op, "invalid_request", "could not construct gateway request", ErrValidation)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if identity, ok := MutationIdentityFromContext(ctx); ok {
		if err := identity.Validate(); err != nil {
			return clientFailure(op, "invalid_request", "mutation identity is invalid", ErrValidation)
		}
		setMutationIdentityHeaders(req, identity)
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// net/http may replay GET on an idle connection, but mutation bodies must
	// never become replayable even if a caller adds an idempotency header later.
	if mutation {
		req.GetBody = nil
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if mutation {
			return clientFailure(op, "outcome_unknown", "gateway mutation response was not received; read back before retrying", ErrOutcomeUnknown)
		}
		if ctx.Err() != nil {
			return clientFailure(op, "unavailable", "gateway request canceled", ctx.Err())
		}
		return clientFailure(op, "unavailable", "gateway connection, certificate verification, or deadline failed", ErrUnavailable)
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes+1))
	if readErr != nil || int64(len(data)) > c.maxResponseBytes {
		if mutation {
			return clientFailure(op, "outcome_unknown", "gateway mutation response was incomplete or exceeded the response limit; read back before retrying", ErrOutcomeUnknown)
		}
		return clientFailure(op, "invalid_response", "gateway response was incomplete or exceeded the response limit", ErrProtocol)
	}
	if resp.StatusCode != expected {
		failure := remoteStatusError(op, resp.StatusCode, mutation)
		if mutation {
			if identity, present := MutationIdentityFromContext(ctx); present && matchesMutationRejection(data, identity) {
				return RejectBeforeMutation("request_rejected", "gateway rejected this mutation before execution", failure)
			}
		}
		return failure
	}
	if output == nil {
		return nil
	}
	if !validResponseShape(op, data) {
		if mutation {
			return clientFailure(op, "outcome_unknown", "gateway mutation acknowledgement is missing required fields; read back before retrying", ErrOutcomeUnknown)
		}
		return clientFailure(op, "invalid_response", "gateway response is missing required contract fields", ErrProtocol)
	}
	if err := json.Unmarshal(data, output); err != nil {
		if mutation {
			return clientFailure(op, "outcome_unknown", "gateway mutation acknowledgement was malformed; read back before retrying", ErrOutcomeUnknown)
		}
		return clientFailure(op, "invalid_response", "gateway response was not valid JSON for this contract", ErrProtocol)
	}
	return nil
}

func validResponseShape(op string, data []byte) bool {
	var required []string
	switch op {
	case "inventory.read", "policy.apply_generation":
		required = []string{"generation"}
	case "probe.node", "probe.group":
		required = []string{"target", "ok", "observed_at"}
	case "traffic.counters":
		required = []string{"proxy_bytes", "direct_bytes", "proxy_packets", "direct_packets"}
	case "connections.close_filtered":
		required = []string{"closed"}
	case "policy.validate":
		required = []string{"valid"}
	default:
		return true
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil {
		return false
	}
	for _, key := range required {
		value, ok := object[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func remoteStatusError(op string, status int, mutation bool) error {
	// Never include remote bodies, URLs, transport errors, or echoed credentials
	// in errors returned to the controller. HTTP status is sufficient to map
	// this agent contract's typed failures without trusting arbitrary text.
	switch status {
	case http.StatusNotImplemented:
		return clientFailure(op, "unsupported", "remote gateway does not support this operation", ErrUnsupported)
	case http.StatusConflict, http.StatusPreconditionFailed:
		return clientFailure(op, "conflict", "remote gateway rejected the expected generation or revision", ErrConflict)
	case http.StatusUnauthorized, http.StatusForbidden:
		return clientFailure(op, "unauthorized", "remote gateway authentication or authorization failed", ErrUnauthorized)
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return clientFailure(op, "validation_failed", "remote gateway rejected the request", ErrValidation)
	case http.StatusNotFound:
		return clientFailure(op, "not_found", "remote gateway resource was not found", ErrStageNotFound)
	case http.StatusTooManyRequests:
		return clientFailure(op, "busy", "remote gateway is busy", ErrBusy)
	}
	if mutation {
		return clientFailure(op, "outcome_unknown", "remote gateway returned an unexpected mutation acknowledgement; read back before retrying", ErrOutcomeUnknown)
	}
	return clientFailure(op, "invalid_response", fmt.Sprintf("unexpected gateway HTTP status %d", status), ErrProtocol)
}

func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	var out Capabilities
	err := c.request(ctx, http.MethodGet, "/v1/capabilities", "capabilities", nil, &out, http.StatusOK, false)
	if err == nil && (out.Implementation == "" || out.Items == nil) {
		err = clientFailure("capabilities", "invalid_response", "capability response is missing implementation or capability entries", ErrProtocol)
	}
	return out, err
}
func (c *Client) Health(ctx context.Context) (Health, error) {
	var out Health
	err := c.request(ctx, http.MethodGet, "/v1/health", "health", nil, &out, http.StatusOK, false)
	if err == nil && (out.Status == "" || out.ObservedAt.IsZero()) {
		err = clientFailure("health", "invalid_response", "health response is missing status or observation time", ErrProtocol)
	}
	return out, err
}
func (c *Client) Inventory(ctx context.Context) (Snapshot, error) {
	var out Snapshot
	err := c.request(ctx, http.MethodGet, "/v1/inventory", "inventory.read", nil, &out, http.StatusOK, false)
	return out, err
}
func (c *Client) Readback(ctx context.Context) (Snapshot, error) {
	var out Snapshot
	err := c.request(ctx, http.MethodGet, "/v1/readback", "inventory.read", nil, &out, http.StatusOK, false)
	return out, err
}
func (c *Client) JournalEntries(ctx context.Context) ([]JournalEntry, error) {
	var out []JournalEntry
	err := c.request(ctx, http.MethodGet, "/v1/journal", "journal.read", nil, &out, http.StatusOK, false)
	return out, err
}

func (c *Client) StageProvider(ctx context.Context, revision ProviderRevision, expected int64) (string, error) {
	input := NewProviderStageRequest(revision, expected)
	var out struct {
		StageID        string `json:"stage_id"`
		ProviderID     string `json:"provider_id"`
		Revision       int64  `json:"revision"`
		ContentHash    string `json:"content_hash"`
		BaseGeneration int64  `json:"base_generation"`
		Status         string `json:"status"`
	}
	if err := c.request(ctx, http.MethodPost, "/v1/providers/stage", "provider.stage", input, &out, http.StatusCreated, true); err != nil {
		return "", err
	}
	if out.StageID == "" || out.Status != "staged" || out.ProviderID != revision.ProviderID || out.Revision != revision.Revision || out.BaseGeneration != expected || (revision.ContentHash != "" && out.ContentHash != revision.ContentHash) {
		return "", clientFailure("provider.stage", "outcome_unknown", "staging acknowledgement did not match the submitted revision and generation", ErrOutcomeUnknown)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// One retained stage per provider mirrors the agent staging contract.
	for id, stage := range c.stages {
		if stage.revision.ProviderID == revision.ProviderID {
			delete(c.stages, id)
		}
	}
	revision.ContentHash = out.ContentHash
	c.stages[out.StageID] = remoteStage{cloneRevision(revision), out.BaseGeneration}
	return out.StageID, nil
}
func (c *Client) StageInfo(id string) (ProviderRevision, int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	stage, ok := c.stages[id]
	return cloneRevision(stage.revision), stage.generation, ok
}
func (c *Client) PublishProvider(ctx context.Context, id string) (Snapshot, error) {
	c.mu.Lock()
	stage, ok := c.stages[id]
	c.mu.Unlock()
	if !ok {
		return Snapshot{}, clientFailure("provider.publish_hot", "not_found", "stage generation unavailable; use explicit persisted staging receipt", ErrStageNotFound)
	}
	return c.PublishStaged(ctx, id, stage.generation)
}

// PublishStaged permits reconciliation after controller restart using the
// durably stored stage ID and base generation. It never guesses the generation.
func (c *Client) PublishStaged(ctx context.Context, id string, expected int64) (Snapshot, error) {
	input := struct {
		StageID            string `json:"stage_id"`
		ExpectedGeneration int64  `json:"expected_generation"`
	}{id, expected}
	var out struct {
		Status   string    `json:"status"`
		Snapshot *Snapshot `json:"snapshot"`
	}
	if err := c.request(ctx, http.MethodPost, "/v1/providers/publish", "provider.publish_hot", input, &out, http.StatusOK, true); err != nil {
		return Snapshot{}, err
	}
	if (out.Status != "published" && out.Status != "noop") || out.Snapshot == nil {
		return Snapshot{}, clientFailure("provider.publish_hot", "outcome_unknown", "publication acknowledgement is incomplete; readback required", ErrOutcomeUnknown)
	}
	c.mu.Lock()
	delete(c.stages, id)
	c.mu.Unlock()
	return *out.Snapshot, nil
}
func (c *Client) SetRuntimeSelection(ctx context.Context, scope SelectionScope, node string, expected int64) (Selection, error) {
	return c.selection(ctx, scope, node, expected, false)
}
func (c *Client) PersistSelection(ctx context.Context, scope SelectionScope, node string, expected int64) (Selection, error) {
	return c.selection(ctx, scope, node, expected, true)
}
func (c *Client) selection(ctx context.Context, scope SelectionScope, node string, expected int64, persist bool) (Selection, error) {
	input := struct {
		Scope            SelectionScope `json:"scope"`
		DesiredNodeID    string         `json:"desired_node_id"`
		ExpectedRevision int64          `json:"expected_revision"`
		PersistRestart   bool           `json:"persist_restart"`
	}{scope, node, expected, persist}
	var out Selection
	op := "selection.set_runtime"
	if persist {
		op = "selection.persist_restart"
	}
	err := c.request(ctx, http.MethodPut, "/v1/selections", op, input, &out, http.StatusOK, true)
	if err == nil && (out.Scope != scope || out.DesiredNodeID != node || out.ObservedNodeID != node || out.Revision <= expected) {
		err = clientFailure(op, "outcome_unknown", "selection acknowledgement does not confirm requested member and scope", ErrOutcomeUnknown)
	}
	return out, err
}
func (c *Client) ValidatePolicy(ctx context.Context, policy Policy) error {
	var out struct {
		Valid bool `json:"valid"`
	}
	if err := c.request(ctx, http.MethodPost, "/v1/policies/validate", "policy.validate", policy, &out, http.StatusOK, false); err != nil {
		return err
	}
	if !out.Valid {
		return clientFailure("policy.validate", "validation_failed", "remote policy validation was not successful", ErrValidation)
	}
	return nil
}
func (c *Client) ApplyPolicyGeneration(ctx context.Context, policy Policy, expected int64) (Snapshot, error) {
	input := struct {
		Policy             Policy `json:"policy"`
		ExpectedGeneration int64  `json:"expected_generation"`
	}{policy, expected}
	var out Snapshot
	err := c.request(ctx, http.MethodPost, "/v1/policies/apply", "policy.apply_generation", input, &out, http.StatusOK, true)
	if err == nil && out.Generation <= expected {
		err = clientFailure("policy.apply_generation", "outcome_unknown", "policy acknowledgement did not confirm a newer generation", ErrOutcomeUnknown)
	}
	return out, err
}
func (c *Client) ProbeNode(ctx context.Context, id string) (ProbeResult, error) {
	var out ProbeResult
	err := c.request(ctx, http.MethodPost, "/v1/probes/node", "probe.node", map[string]string{"node_id": id}, &out, http.StatusOK, false)
	return out, err
}
func (c *Client) ProbeGroup(ctx context.Context, id string) (ProbeResult, error) {
	var out ProbeResult
	err := c.request(ctx, http.MethodPost, "/v1/probes/group", "probe.group", map[string]string{"group_id": id}, &out, http.StatusOK, false)
	return out, err
}
func (c *Client) ObserveConnections(ctx context.Context) ([]Connection, error) {
	var out []Connection
	err := c.request(ctx, http.MethodGet, "/v1/connections", "connections.observe", nil, &out, http.StatusOK, false)
	return out, err
}
func (c *Client) CloseFiltered(ctx context.Context, filter ConnectionFilter) (int, error) {
	var out struct {
		Closed int `json:"closed"`
	}
	err := c.request(ctx, http.MethodPost, "/v1/connections/close", "connections.close_filtered", filter, &out, http.StatusOK, true)
	return out.Closed, err
}
func (c *Client) Counters(ctx context.Context) (Counters, error) {
	var out Counters
	err := c.request(ctx, http.MethodGet, "/v1/counters", "traffic.counters", nil, &out, http.StatusOK, false)
	return out, err
}
func (c *Client) ResumeEvents(ctx context.Context, after int64) ([]Event, error) {
	var out []Event
	err := c.request(ctx, http.MethodGet, "/v1/events?after="+strconv.FormatInt(after, 10), "events.resume", nil, &out, http.StatusOK, false)
	return out, err
}

var _ Engine = (*Client)(nil)
var _ HealthReader = (*Client)(nil)
