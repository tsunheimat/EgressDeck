package opnsense

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// These pins document the upstream source used to derive request and response
// formats. They are not a claim of real-appliance or packet-path qualification.
const (
	SupportedRelease = "26.7"
	SourceCommit     = "821598263289e177b40971600f06f5a91d9faef3"
)

var (
	ErrAuthentication = errors.New("opnsense authentication or privilege denied")
	ErrProtocol       = errors.New("unexpected opnsense API response")
	ErrVersion        = errors.New("unsupported opnsense release")
	ErrScope          = errors.New("opnsense mutation outside reviewed scope")
	ErrTransport      = errors.New("opnsense transport failed")
)

// HTTPConfig intentionally offers no insecure TLS mode, ambient proxy, custom
// transport, or arbitrary endpoint. An empty ManagedAliases makes a read-only
// client. RootCAs can contain a private appliance CA.
type HTTPConfig struct {
	BaseURL          string
	APIKey           string
	APISecret        string
	Release          string
	RootCAs          *x509.CertPool
	Timeout          time.Duration
	MaxResponseBytes int64
	MaxRows          int
	ManagedAliases   []ManagedAlias
}

// HTTPClient implements the pinned native OPNsense API. Each batch is
// serialized and each individual mutation checks alias/rule shape and reads
// both persisted configuration and active state. The appliance still lacks an
// object CAS: a concurrent administrator edit can race a request; callers must
// retain the operation journal and post-write readback.
type HTTPClient struct {
	base     string
	key      string
	secret   string
	http     *http.Client
	maxBytes int64
	maxRows  int
	managed  map[string]ManagedAlias
	mu       sync.Mutex
}

var aliasNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,30}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func NewHTTPClient(cfg HTTPConfig) (*HTTPClient, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return nil, fmt.Errorf("%w: an HTTPS origin without userinfo, query, or path is required", ErrScope)
	}
	if cfg.Release != SupportedRelease {
		return nil, fmt.Errorf("%w: select the source-inspected release %s", ErrVersion, SupportedRelease)
	}
	if cfg.APIKey == "" || cfg.APISecret == "" || strings.ContainsAny(cfg.APIKey, ":\r\n") || strings.ContainsAny(cfg.APISecret, "\r\n") {
		return nil, fmt.Errorf("%w: API key and secret are required", ErrAuthentication)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.Timeout < 0 || cfg.Timeout > 2*time.Minute {
		return nil, fmt.Errorf("%w: invalid request timeout", ErrScope)
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 4 << 20
	}
	if cfg.MaxResponseBytes < 1 || cfg.MaxResponseBytes > 32<<20 {
		return nil, fmt.Errorf("%w: invalid response limit", ErrScope)
	}
	if cfg.MaxRows == 0 {
		cfg.MaxRows = 10000
	}
	if cfg.MaxRows < 1 || cfg.MaxRows > 100000 {
		return nil, fmt.Errorf("%w: invalid row limit", ErrScope)
	}
	var roots *x509.CertPool
	if cfg.RootCAs != nil {
		roots = cfg.RootCAs.Clone()
	}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: cfg.Timeout, ResponseHeaderTimeout: cfg.Timeout,
		IdleConnTimeout: 30 * time.Second, MaxConnsPerHost: 4, MaxIdleConnsPerHost: 2,
		MaxResponseHeaderBytes: 64 << 10, DisableCompression: true,
	}
	c := &HTTPClient{base: strings.TrimSuffix(u.String(), "/"), key: cfg.APIKey, secret: cfg.APISecret, maxBytes: cfg.MaxResponseBytes, maxRows: cfg.MaxRows, managed: map[string]ManagedAlias{}}
	c.http = &http.Client{Transport: transport, Timeout: cfg.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, managed := range cfg.ManagedAliases {
		if err := managed.Validate(); err != nil {
			return nil, err
		}
		if _, exists := c.managed[managed.Shape.Name]; exists {
			return nil, fmt.Errorf("%w: duplicate managed alias", ErrScope)
		}
		managed.Rules = append([]RuleExpectation(nil), managed.Rules...)
		c.managed[managed.Shape.Name] = managed
	}
	return c, nil
}

func (c *HTTPClient) Close() { c.http.CloseIdleConnections() }

// VerifyConnection performs a read-only version/auth/TLS check. Privileges
// are checked by the real endpoints when used, never inferred from this check.
func (c *HTTPClient) VerifyConnection(ctx context.Context) error {
	var result struct {
		ProductID string `json:"product_id"`
		Version   string `json:"product_version"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/core/firmware/info", nil, &result); err != nil {
		return err
	}
	if result.ProductID != "opnsense" || result.Version != SupportedRelease {
		return fmt.Errorf("%w: appliance does not match the source-inspected release", ErrVersion)
	}
	return nil
}

func (c *HTTPClient) request(ctx context.Context, method, path string, payload any, out any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("%w: invalid request", ErrProtocol)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return fmt.Errorf("%w: invalid request", ErrProtocol)
	}
	req.SetBasicAuth(c.key, c.secret)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Do not return URL errors, request bodies, credentials, or appliance
		// response text through logs or public API errors.
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return fmt.Errorf("%w: request timed out", ErrTransport)
		}
		return ErrTransport
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrAuthentication
	}
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP status %d", ErrProtocol, resp.StatusCode)
	}
	if resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity" {
		return fmt.Errorf("%w: compressed response not supported", ErrProtocol)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return fmt.Errorf("%w: incomplete response", ErrTransport)
	}
	if int64(len(data)) > c.maxBytes {
		return fmt.Errorf("%w: response limit exceeded", ErrProtocol)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%w: invalid JSON", ErrProtocol)
	}
	return nil
}

// rows requests all records with an explicit bound and refuses a truncated
// response. Native rowCount=-1 is supported by searchRecordsetBase; the bound
// is enforced in bytes and rows, rather than accepting the implicit 9999 cap.
func (c *HTTPClient) rows(ctx context.Context, path, search string) ([]json.RawMessage, error) {
	var result struct {
		Total   *int               `json:"total"`
		Current *int               `json:"current"`
		Rows    *[]json.RawMessage `json:"rows"`
	}
	if err := c.request(ctx, http.MethodPost, path, map[string]any{"current": 1, "rowCount": -1, "searchPhrase": search}, &result); err != nil {
		return nil, err
	}
	if result.Total == nil || result.Current == nil || result.Rows == nil || *result.Current != 1 || *result.Total < 0 || *result.Total != len(*result.Rows) || len(*result.Rows) > c.maxRows {
		return nil, fmt.Errorf("%w: incomplete or oversized recordset", ErrProtocol)
	}
	return *result.Rows, nil
}

func (c *HTTPClient) ReadPersistedAlias(ctx context.Context, name string) (AliasRecord, error) {
	if !validAliasName(name) {
		return AliasRecord{}, ErrScope
	}
	rows, err := c.rows(ctx, "/api/firewall/alias/search_item", name)
	if err != nil {
		return AliasRecord{}, err
	}
	uuid := ""
	for _, row := range rows {
		var item struct {
			UUID string `json:"uuid"`
			Name string `json:"name"`
		}
		if json.Unmarshal(row, &item) != nil {
			return AliasRecord{}, ErrProtocol
		}
		if item.Name == name {
			if uuid != "" || !uuidPattern.MatchString(item.UUID) {
				return AliasRecord{}, ErrProtocol
			}
			uuid = item.UUID
		}
	}
	if uuid == "" {
		return AliasRecord{}, ErrNotFound
	}
	var response struct {
		Alias map[string]json.RawMessage `json:"alias"`
	}
	if err := c.request(ctx, http.MethodGet, "/api/firewall/alias/get_item/"+uuid, nil, &response); err != nil {
		return AliasRecord{}, err
	}
	fields := response.Alias
	if fields == nil {
		return AliasRecord{}, ErrNotFound
	}
	record := AliasRecord{UUID: uuid, ObservedAt: time.Now().UTC(), nativeAddresses: map[string]string{}}
	if err := decodeString(fields["name"], &record.Name); err != nil {
		return AliasRecord{}, err
	}
	if record.Name != name {
		return AliasRecord{}, ErrShapeChanged
	}
	if err := decodeString(fields["description"], &record.Description); err != nil {
		return AliasRecord{}, err
	}
	enabled, err := nativeBool(fields["enabled"])
	if err != nil {
		return AliasRecord{}, err
	}
	record.Disabled = !enabled
	kind, err := singleOption(fields["type"])
	if err != nil {
		return AliasRecord{}, err
	}
	record.Type = AliasType(kind)
	selected, err := selectedOptions(fields["content"])
	if err != nil {
		return AliasRecord{}, err
	}
	for _, address := range selected {
		if address != "" {
			canonical, _, err := CanonicalAddress(address)
			if err != nil {
				return AliasRecord{}, fmt.Errorf("%w: managed alias contains a non-address entry", ErrShapeChanged)
			}
			if _, duplicate := record.nativeAddresses[canonical]; duplicate {
				return AliasRecord{}, fmt.Errorf("%w: duplicate equivalent alias entries require review", ErrShapeChanged)
			}
			record.nativeAddresses[canonical] = address
			record.Addresses = append(record.Addresses, address)
		}
	}
	record, err = canonicalRecord(record)
	if err != nil {
		return AliasRecord{}, err
	}
	if record.Type == HostAlias {
		for _, address := range record.Addresses {
			if strings.Contains(address, "/") {
				return AliasRecord{}, fmt.Errorf("%w: Host alias contains a network", ErrShapeChanged)
			}
		}
	}
	return record, nil
}

func (c *HTTPClient) ReadActiveAlias(ctx context.Context, name string) (AliasRecord, error) {
	// PF tables do not expose a config UUID/type. Carry metadata from a new
	// persisted read, then replace only addresses with active PF observations.
	record, err := c.ReadPersistedAlias(ctx, name)
	if err != nil {
		return AliasRecord{}, err
	}
	var aliases []string
	if err := c.request(ctx, http.MethodGet, "/api/firewall/alias_util/aliases", nil, &aliases); err != nil {
		return AliasRecord{}, err
	}
	if len(aliases) > c.maxRows {
		return AliasRecord{}, ErrProtocol
	}
	found := false
	for _, alias := range aliases {
		if alias == name {
			found = true
			break
		}
	}
	// list_table.py returns an empty list even when pfctl fails. The table
	// inventory check prevents a missing table from looking like an empty one.
	if !found {
		return AliasRecord{}, fmt.Errorf("%w: active alias table", ErrNotFound)
	}
	rows, err := c.rows(ctx, "/api/firewall/alias_util/list/"+name, "")
	if err != nil {
		return AliasRecord{}, err
	}
	if len(rows) == 0 {
		// list_table.py ignores pfctl failures. Independently require an
		// explicit zero count from pftablecount.py, whose details omit the
		// table/count when PF inspection fails. Its count is max(planned,
		// active), so a nonzero result is deliberately not treated as empty.
		var sizes struct {
			Status  string `json:"status"`
			Details map[string]struct {
				Count *int `json:"count"`
			} `json:"details"`
		}
		if err := c.request(ctx, http.MethodGet, "/api/firewall/alias/get_table_size", nil, &sizes); err != nil {
			return AliasRecord{}, err
		}
		detail, ok := sizes.Details[name]
		if sizes.Status != "ok" || !ok || detail.Count == nil || *detail.Count != 0 {
			return AliasRecord{}, fmt.Errorf("%w: empty active table could not be confirmed", ErrProtocol)
		}
	}
	record.Addresses = nil
	for _, row := range rows {
		var item struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(row, &item) != nil || item.IP == "" {
			return AliasRecord{}, ErrProtocol
		}
		record.Addresses = append(record.Addresses, item.IP)
	}
	record.ObservedAt = time.Now().UTC()
	return canonicalRecord(record)
}

func (c *HTTPClient) AddAliasAddresses(ctx context.Context, name string, addresses []string) error {
	return c.mutate(ctx, "add", name, addresses)
}

func (c *HTTPClient) DeleteAliasAddresses(ctx context.Context, name string, addresses []string) error {
	return c.mutate(ctx, "delete", name, addresses)
}

func (c *HTTPClient) mutate(ctx context.Context, operation, name string, addresses []string) (resultErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	wrote := false
	defer func() {
		if wrote && resultErr != nil && !errors.Is(resultErr, ErrPartialUpdate) {
			resultErr = fmt.Errorf("%w: %w", ErrPartialUpdate, resultErr)
		}
	}()
	managed, exists := c.managed[name]
	if !exists {
		return ErrScope
	}
	canonical, err := CanonicalAddresses(addresses)
	if err != nil {
		return err
	}
	if err := validateFamily(managed.Family, canonical); err != nil {
		return err
	}
	if len(canonical) > c.maxRows {
		return ErrScope
	}
	if managed.Shape.Type == HostAlias {
		for _, address := range canonical {
			if strings.Contains(address, "/") {
				return fmt.Errorf("%w: Host aliases accept individual IPs", ErrScope)
			}
		}
	}
	if len(canonical) == 0 {
		return nil
	}
	if err := c.VerifyConnection(ctx); err != nil {
		return err
	}
	for _, address := range canonical {
		before, err := c.authorize(ctx, managed)
		if err != nil {
			return err
		}
		have := false
		for _, current := range before.Addresses {
			if current == address {
				have = true
				break
			}
		}
		if (operation == "add" && have) || (operation == "delete" && !have) {
			continue
		}
		desired := append([]string(nil), before.Addresses...)
		if operation == "add" {
			desired = append(desired, address)
		} else {
			desired = nil
			for _, current := range before.Addresses {
				if current != address {
					desired = append(desired, current)
				}
			}
		}
		desired, _ = CanonicalAddresses(desired)
		var response struct {
			Status string `json:"status"`
		}
		requestAddress := address
		if operation == "delete" {
			requestAddress = before.nativeAddresses[address]
		}
		wrote = true
		mutationErr := c.request(ctx, http.MethodPost, "/api/firewall/alias_util/"+operation+"/"+name, map[string]string{"address": requestAddress}, &response)
		if mutationErr == nil && response.Status != "done" {
			mutationErr = fmt.Errorf("%w: mutation rejected", ErrProtocol)
		}
		persisted, persistedErr := c.ReadPersistedAlias(ctx, name)
		active, activeErr := c.ReadActiveAlias(ctx, name)
		if mutationErr != nil {
			return fmt.Errorf("%w: %w", ErrPartialUpdate, mutationErr)
		}
		if persistedErr != nil || activeErr != nil {
			return fmt.Errorf("%w: mutation readback unavailable", ErrPartialUpdate)
		}
		if !shapeMatches(managed.Shape, persisted) || !shapeMatches(managed.Shape, active) || !equalStrings(desired, persisted.Addresses) || !equalStrings(desired, active.Addresses) {
			return fmt.Errorf("%w: %w after mutation", ErrPartialUpdate, ErrDrift)
		}
	}
	return nil
}

func validAliasName(name string) bool {
	return aliasNamePattern.MatchString(name) && name != "_" && !strings.HasPrefix(name, "__")
}

func decodeString(raw json.RawMessage, dst *string) error {
	if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, dst) != nil {
		return ErrProtocol
	}
	return nil
}

func nativeBool(raw json.RawMessage) (bool, error) {
	switch string(raw) {
	case `"1"`, `1`:
		return true, nil
	case `"0"`, `0`:
		return false, nil
	default:
		return false, ErrProtocol
	}
}

func selectedOptions(raw json.RawMessage) ([]string, error) {
	// PHP serializes an empty array as [] rather than {} when a list has no
	// available choices (for example categories on an unconfigured appliance).
	if string(bytes.TrimSpace(raw)) == "[]" {
		return []string{}, nil
	}
	var options map[string]struct {
		Selected json.RawMessage `json:"selected"`
	}
	if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &options) != nil {
		return nil, ErrProtocol
	}
	selected := []string{}
	for key, option := range options {
		set, err := nativeBool(option.Selected)
		if err != nil {
			return nil, err
		}
		if set {
			selected = append(selected, key)
		}
	}
	sort.Strings(selected)
	return selected, nil
}

func singleOption(raw json.RawMessage) (string, error) {
	selected, err := selectedOptions(raw)
	if err != nil || len(selected) != 1 {
		return "", ErrProtocol
	}
	return selected[0], nil
}

var _ Client = (*HTTPClient)(nil)
