package providers

// This file contains the provider download boundary.  It deliberately does
// not use http.ProxyFromEnvironment: a provider URL is untrusted input and a
// process-wide proxy can otherwise turn a direct download into an SSRF
// primitive.  Every connection resolves its hostname and dials the validated
// literal address, including connections made after redirects.

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

var (
	ErrFetchURL         = errors.New("provider source URL is not allowed")
	ErrFetchPrivate     = errors.New("provider source resolves to a private address")
	ErrFetchRoute       = errors.New("provider fetch route is not verified")
	ErrFetchRedirects   = errors.New("provider redirects exceed configured limit")
	ErrFetchCompression = errors.New("provider response uses unsupported compression")
)

// FetchError keeps the underlying typed reason available to callers while
// ensuring the source URL is always redacted in the rendered error.
type FetchError struct {
	Source string `json:"-"`
	Err    error  `json:"-"`
}

type fetchStatusError struct{ Code int }

func (e *fetchStatusError) Error() string {
	return fmt.Sprintf("unexpected HTTP status (%d)", e.Code)
}

func (e *FetchError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", RedactedSource(e.Source), redactErrorText(e.Err))
}

func (e *FetchError) Unwrap() error {
	if e == nil {
		return nil
	}
	return errors.Join(ErrFetch, e.Err)
}

// NetResolver is the small part of net.Resolver used by Fetcher.  Keeping it
// injectable makes DNS rebinding and mixed-answer behavior testable while the
// production default remains the system resolver.
type NetResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// DialContextFunc is a route-owned dial function. Fetcher passes only validated
// IP literals to it, while HTTP Host and TLS server name retain the source host.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// RouteVerifier is required for every route other than "direct".  Returning a
// nil dialer or an error fails closed; Fetcher never falls back to Direct.
type RouteVerifier interface {
	VerifyProviderFetchRoute(context.Context, string) (DialContextFunc, error)
}

// RouteVerifierFunc adapts a function to RouteVerifier.
type RouteVerifierFunc func(context.Context, string) (DialContextFunc, error)

func (f RouteVerifierFunc) VerifyProviderFetchRoute(ctx context.Context, route string) (DialContextFunc, error) {
	if f == nil {
		return nil, ErrFetchRoute
	}
	return f(ctx, route)
}

// SourceAllowlistEntry is an administrative exception for an internal source.
// Host is matched exactly (case-insensitive). Ports and CIDRs must both be
// nonempty, so an approved hostname cannot rebind to any internal address or
// service. There is no blanket "allow all private addresses" switch.
type SourceAllowlistEntry struct {
	Host  string
	Ports []int
	CIDRs []string
}

// FetchOptions controls the security boundary around a provider download.
// Limits are also accepted by NewFetcher for callers that prefer the shorter
// constructor.  Resolver is nil for the system resolver.
type FetchOptions struct {
	Limits           Limits
	Allowlist        []SourceAllowlistEntry
	Route            string
	RouteVerify      RouteVerifier
	Resolver         NetResolver
	Now              func() time.Time
	DisableRedirects bool
}

// FetchResult is the bounded source bytes plus non-secret fetch metadata.  The
// source is the original URL for callers that need to associate a result with
// a provider; errors and logs should use RedactedSource instead.
type FetchResult struct {
	Source         string `json:"-"`
	RedactedSource string
	Content        []byte `json:"-"`
	StatusCode     int
	ContentType    string
	Route          string
	ObservedAt     time.Time
}

// Fetcher downloads provider content with SSRF, redirect, timeout, and body
// bounds applied.  A zero Fetcher is valid and uses DefaultLimits and Direct.
type Fetcher struct {
	Limits           Limits
	Allowlist        []SourceAllowlistEntry
	Route            string
	RouteVerify      RouteVerifier
	Resolver         NetResolver
	Now              func() time.Time
	DisableRedirects bool
}

func NewFetcher(limits Limits, options FetchOptions) *Fetcher {
	if options.Limits != (Limits{}) {
		limits = options.Limits
	}
	allowlist := append([]SourceAllowlistEntry(nil), options.Allowlist...)
	for i := range allowlist {
		allowlist[i].Ports = append([]int(nil), allowlist[i].Ports...)
		allowlist[i].CIDRs = append([]string(nil), allowlist[i].CIDRs...)
	}
	return &Fetcher{Limits: limits, Allowlist: allowlist, Route: options.Route, RouteVerify: options.RouteVerify, Resolver: options.Resolver, Now: options.Now, DisableRedirects: options.DisableRedirects}
}

// Fetch is the direct-route convenience API.  Call FetchProvider or
// NewFetcher when an explicit allowlist or verified route is required.
func Fetch(ctx context.Context, source string, limits Limits) (FetchResult, error) {
	return (&Fetcher{Limits: limits}).Fetch(ctx, source)
}

// FetchProvider downloads the source configured on a domain Provider.  This
// helper keeps provider route selection in one place for refresh workflows.
func FetchProvider(ctx context.Context, provider domain.Provider, limits Limits, options FetchOptions) (FetchResult, error) {
	if options.Route == "" {
		options.Route = provider.FetchRoute
	}
	return NewFetcher(limits, options).Fetch(ctx, provider.Source)
}

// FetchURL is an explicit alias useful to callers that already have a URL
// object represented as text.
func FetchURL(ctx context.Context, source string, limits Limits, options FetchOptions) (FetchResult, error) {
	return NewFetcher(limits, options).Fetch(ctx, source)
}

// Fetch performs one bounded HTTP(S) request and follows only validated
// redirects.  Responses with a non-2xx status are errors and never reach the
// parser.
func (f *Fetcher) Fetch(parent context.Context, source string) (FetchResult, error) {
	limits := f.Limits.withDefaults()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, limits.RequestTimeout)
	defer cancel()

	u, err := parseFetchURL(source, limits)
	if err != nil {
		return FetchResult{}, fetchError(source, err)
	}
	route := strings.TrimSpace(f.Route)
	if route == "" {
		route = "direct"
	}
	resolver := f.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	// Validate the first destination before constructing the client.  The
	// custom dialer repeats this validation at the actual dial point, closing
	// the DNS rebinding window between request validation and connect.
	if _, err := f.validatedAddresses(ctx, resolver, u); err != nil {
		return FetchResult{}, fetchError(source, err)
	}

	dial := f.directDialer(resolver)
	if route != "direct" {
		if f.RouteVerify == nil {
			return FetchResult{}, fetchError(source, fmt.Errorf("%w: %s", ErrFetchRoute, route))
		}
		dial, err = f.RouteVerify.VerifyProviderFetchRoute(ctx, route)
		if err != nil || dial == nil {
			if err == nil {
				err = ErrFetchRoute
			}
			return FetchResult{}, fetchError(source, errors.Join(ErrFetchRoute, err))
		}
		dial = f.validatedDialer(resolver, dial)
	}

	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dial,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           2,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  limits.RequestTimeout,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	maxRedirects := limits.MaxRedirects
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if f.DisableRedirects || len(via) > maxRedirects {
			return ErrFetchRedirects
		}
		if err := validateFetchURL(req.URL, limits); err != nil {
			return err
		}
		if _, err := f.validatedAddresses(req.Context(), resolver, req.URL); err != nil {
			return err
		}
		if len(via) > 0 && !sameOrigin(via[len(via)-1].URL, req.URL) {
			// Do not let a source credential/header cross an origin boundary.
			req.Header.Del("Authorization")
			req.Header.Del("Cookie")
			req.URL.User = nil
			req.URL.RawQuery = ""
			req.URL.ForceQuery = false
		}
		req.Header.Del("Referer")
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return FetchResult{}, fetchError(source, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return FetchResult{}, fetchError(source, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return FetchResult{}, fetchError(source, &fetchStatusError{Code: resp.StatusCode})
	}
	content, err := readResponse(resp, limits)
	if err != nil {
		return FetchResult{}, fetchError(source, err)
	}
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	return FetchResult{Source: source, RedactedSource: RedactedSource(source), Content: content, StatusCode: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Route: route, ObservedAt: now().UTC()}, nil
}

func parseFetchURL(source string, limits Limits) (*url.URL, error) {
	if len(source) > 16<<10 {
		return nil, ErrFetchURL
	}
	u, err := url.Parse(strings.TrimSpace(source))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, ErrFetchURL
	}
	if err := validateFetchURL(u, limits); err != nil {
		return nil, err
	}
	return u, nil
}

func validateFetchURL(u *url.URL, limits Limits) error {
	if u == nil || u.Scheme == "" || u.Host == "" {
		return ErrFetchURL
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo is not allowed", ErrFetchURL)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !limits.AllowHTTP {
			return fmt.Errorf("%w: HTTP sources are disabled", ErrFetchURL)
		}
	default:
		return fmt.Errorf("%w: unsupported scheme", ErrFetchURL)
	}
	if u.Hostname() == "" || strings.Contains(u.Hostname(), "%") {
		return ErrFetchURL
	}
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p < 1 || p > 65535 {
			return ErrFetchURL
		}
	}
	return nil
}

func (f *Fetcher) validatedAddresses(ctx context.Context, resolver NetResolver, u *url.URL) ([]netip.Addr, error) {
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := urlPort(u)
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip.Unmap()}
	} else {
		var err error
		addresses, err = resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed: %w", err)
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("source has no resolved addresses")
	}
	for i, addr := range addresses {
		addresses[i] = addr.Unmap()
		if isRestrictedAddress(addresses[i]) && !f.allowlisted(host, port, addresses[i]) {
			return nil, fmt.Errorf("%w: %s", ErrFetchPrivate, addresses[i])
		}
	}
	return addresses, nil
}

func (f *Fetcher) allowlisted(host string, port int, ip netip.Addr) bool {
	for _, entry := range f.Allowlist {
		if len(entry.Ports) == 0 || len(entry.CIDRs) == 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(entry.Host), "."), host) {
			continue
		}
		if !containsPort(entry.Ports, port) {
			continue
		}
		for _, text := range entry.CIDRs {
			_, network, err := net.ParseCIDR(strings.TrimSpace(text))
			if err == nil && network.Contains(ip.AsSlice()) {
				return true
			}
		}
	}
	return false
}

func containsPort(ports []int, port int) bool {
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

func urlPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		v, _ := strconv.Atoi(p)
		return v
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

func (f *Fetcher) directDialer(resolver NetResolver) DialContextFunc {
	return f.validatedDialer(resolver, (&net.Dialer{}).DialContext)
}

func (f *Fetcher) validatedDialer(resolver NetResolver, dial DialContextFunc) DialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, _ := strconv.Atoi(portText)
		ips, err := f.validatedHostAddresses(ctx, resolver, strings.Trim(host, "[]"), port)
		if err != nil {
			return nil, err
		}
		var last error
		for _, ip := range ips {
			conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), portText))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
}

func (f *Fetcher) validatedHostAddresses(ctx context.Context, resolver NetResolver, host string, port int) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if isRestrictedAddress(ip) && !f.allowlisted(strings.ToLower(host), port, ip) {
			return nil, ErrFetchPrivate
		}
		return []netip.Addr{ip}, nil
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("source has no resolved addresses")
	}
	for i := range addresses {
		addresses[i] = addresses[i].Unmap()
		if isRestrictedAddress(addresses[i]) && !f.allowlisted(strings.ToLower(strings.TrimSuffix(host, ".")), port, addresses[i]) {
			return nil, ErrFetchPrivate
		}
	}
	return addresses, nil
}

func isRestrictedAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// RFC 6598 shared space, benchmark space, and the IPv4 metadata endpoint
	// are not public provider destinations.
	for _, prefix := range []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	} {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func readResponse(resp *http.Response, limits Limits) ([]byte, error) {
	if resp.ContentLength > limits.MaxBodyBytes {
		return nil, ErrBodyTooLarge
	}
	wire, err := io.ReadAll(io.LimitReader(resp.Body, limits.MaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(wire)) > limits.MaxBodyBytes {
		return nil, ErrBodyTooLarge
	}
	encoding := strings.TrimSpace(strings.ToLower(resp.Header.Get("Content-Encoding")))
	var decoded []byte
	switch encoding {
	case "", "identity":
		decoded = wire
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(wire))
		if err != nil {
			return nil, fmt.Errorf("decode gzip: %w", err)
		}
		decoded, err = io.ReadAll(io.LimitReader(reader, limits.MaxDecodedBytes+1))
		closeErr := reader.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	default:
		return nil, ErrFetchCompression
	}
	if int64(len(decoded)) > limits.MaxDecodedBytes {
		return nil, ErrBodyTooLarge
	}
	return decoded, nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// RedactedSource removes userinfo, query, fragment, and path from a source.
// It is suitable for operation errors, logs, and support bundles.
func RedactedSource(source string) string {
	u, err := url.Parse(strings.TrimSpace(source))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "<invalid-source>"
	}
	return strings.ToLower(u.Scheme) + "://" + u.Host
}

func fetchError(source string, err error) error {
	if err == nil {
		return nil
	}
	return &FetchError{Source: source, Err: err}
}

func redactErrorText(err error) string {
	if err == nil {
		return ""
	}
	for _, known := range []error{ErrFetchURL, ErrFetchPrivate, ErrFetchRoute, ErrFetchRedirects, ErrFetchCompression, ErrBodyTooLarge, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	var status *fetchStatusError
	if errors.As(err, &status) {
		return status.Error()
	}
	// Remote status lines, resolver/route errors and malformed header values
	// may echo credentials without URL syntax. Only typed local diagnostics
	// are rendered publicly; the wrapped cause remains available internally.
	return "provider download failed"
}
