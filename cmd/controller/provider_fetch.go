package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
)

const providerFetchConfigLimit = 64 << 10

// This policy is operator-owned and loaded only at startup. API callers cannot
// grant access to private destinations, enable plaintext HTTP, or bypass TLS.
type providerFetchConfig struct {
	Allowlist []providerSourceConfig `json:"allowlist"`
	Limits    providerLimitsConfig   `json:"limits,omitempty"`
}

type providerSourceConfig struct {
	Host  string   `json:"host"`
	Ports []int    `json:"ports"`
	CIDRs []string `json:"cidrs"`
}

type providerLimitsConfig struct {
	MaxBodyBytes    *int64 `json:"max_body_bytes,omitempty"`
	MaxDecodedBytes *int64 `json:"max_decoded_bytes,omitempty"`
	MaxNodes        *int   `json:"max_nodes,omitempty"`
	MaxLineBytes    *int   `json:"max_line_bytes,omitempty"`
	MaxParserDepth  *int   `json:"max_parser_depth,omitempty"`
	MaxRedirects    *int   `json:"max_redirects,omitempty"`
	RequestTimeout  *int64 `json:"request_timeout_ms,omitempty"`
}

func newProviderRegistry(configPath string) (*providers.Registry, error) {
	limits := providers.DefaultLimits()
	options := providers.FetchOptions{}
	if strings.TrimSpace(configPath) != "" {
		config, err := readProviderFetchConfig(configPath)
		if err != nil {
			return nil, err
		}
		limits, options, err = config.fetchOptions()
		if err != nil {
			return nil, err
		}
	}
	// Keep RouteVerify unset: an unqualified non-direct route must fail closed.
	return providers.NewHTTPRegistry(limits, options), nil
}

func readProviderFetchConfig(path string) (providerFetchConfig, error) {
	var config providerFetchConfig
	absPath, err := filepath.Abs(path)
	if err != nil {
		return config, errors.New("provider fetch configuration path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil || resolved != absPath {
		return config, errors.New("provider fetch configuration must exist without symlinks in its path")
	}
	before, err := os.Lstat(absPath)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > providerFetchConfigLimit {
		return config, errors.New("provider fetch configuration must be a private regular file of at most 64 KiB")
	}
	f, err := os.Open(absPath)
	if err != nil {
		return config, errors.New("provider fetch configuration cannot be opened")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0077 != 0 || after.Size() > providerFetchConfigLimit {
		return config, errors.New("provider fetch configuration changed or is not private")
	}
	data, err := io.ReadAll(io.LimitReader(f, providerFetchConfigLimit+1))
	if err != nil || len(data) > providerFetchConfigLimit {
		return config, errors.New("provider fetch configuration cannot be read or exceeds 64 KiB")
	}
	defer clear(data)
	// encoding/json normally accepts duplicate keys and null. Neither has an
	// unambiguous meaning for an operator security policy.
	if err := validateProviderConfigJSON(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return config, errors.New("provider fetch configuration must contain unambiguous JSON without null or duplicate keys")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return providerFetchConfig{}, errors.New("provider fetch configuration contains invalid or unknown fields")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return providerFetchConfig{}, errors.New("provider fetch configuration must contain exactly one JSON object")
	}
	return config, nil
}

func validateProviderConfigJSON(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("excessive nesting")
	}
	token, err := decoder.Token()
	if err != nil || token == nil {
		return errors.New("invalid value")
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[strings.ToLower(name)] {
				return errors.New("ambiguous key")
			}
			seen[strings.ToLower(name)] = true
			if err := validateProviderConfigJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := validateProviderConfigJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid delimiter")
	}
	_, err = decoder.Token()
	return err
}

func (c providerFetchConfig) fetchOptions() (providers.Limits, providers.FetchOptions, error) {
	limits := providers.DefaultLimits()
	options := providers.FetchOptions{}
	if c.Allowlist == nil || len(c.Allowlist) > 64 {
		return limits, options, errors.New("provider fetch configuration requires an allowlist array with at most 64 entries")
	}
	seen := map[string]bool{}
	for i, source := range c.Allowlist {
		host, err := normalizeProviderSourceHost(source.Host)
		if err != nil || seen[host] || len(source.Ports) == 0 || len(source.Ports) > 16 || len(source.CIDRs) == 0 || len(source.CIDRs) > 16 {
			return limits, options, fmt.Errorf("provider source %d requires a unique exact host and 1 to 16 ports and private CIDRs", i+1)
		}
		seen[host] = true
		ports := map[int]bool{}
		for _, port := range source.Ports {
			if port < 1 || port > 65535 || ports[port] {
				return limits, options, fmt.Errorf("provider source %d contains an invalid or duplicate port", i+1)
			}
			ports[port] = true
		}
		cidrs := map[string]bool{}
		for _, text := range source.CIDRs {
			prefix, err := netip.ParsePrefix(text)
			if err != nil || prefix != prefix.Masked() || !privateProviderPrefix(prefix) || cidrs[prefix.String()] {
				return limits, options, fmt.Errorf("provider source %d requires distinct canonical private CIDRs", i+1)
			}
			cidrs[prefix.String()] = true
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			contained := false
			for _, text := range source.CIDRs {
				contained = contained || netip.MustParsePrefix(text).Contains(ip)
			}
			if !contained {
				return limits, options, fmt.Errorf("provider source %d IP host must belong to its private CIDRs", i+1)
			}
		}
		options.Allowlist = append(options.Allowlist, providers.SourceAllowlistEntry{Host: host, Ports: source.Ports, CIDRs: source.CIDRs})
	}
	for _, value := range []struct {
		name string
		src  *int64
		dst  *int64
	}{
		{"max_body_bytes", c.Limits.MaxBodyBytes, &limits.MaxBodyBytes},
		{"max_decoded_bytes", c.Limits.MaxDecodedBytes, &limits.MaxDecodedBytes},
	} {
		if value.src != nil {
			if *value.src < 1 || *value.src > *value.dst {
				return limits, options, fmt.Errorf("provider %s must be positive and no larger than its secure default", value.name)
			}
			*value.dst = *value.src
		}
	}
	for _, value := range []struct {
		name string
		src  *int
		dst  *int
	}{
		{"max_nodes", c.Limits.MaxNodes, &limits.MaxNodes},
		{"max_line_bytes", c.Limits.MaxLineBytes, &limits.MaxLineBytes},
		{"max_parser_depth", c.Limits.MaxParserDepth, &limits.MaxParserDepth},
	} {
		if value.src != nil {
			if *value.src < 1 || *value.src > *value.dst {
				return limits, options, fmt.Errorf("provider %s must be positive and no larger than its secure default", value.name)
			}
			*value.dst = *value.src
		}
	}
	if value := c.Limits.MaxRedirects; value != nil {
		if *value < 0 || *value > limits.MaxRedirects {
			return limits, options, errors.New("provider max_redirects must be between 0 and 5")
		}
		limits.MaxRedirects = *value
		options.DisableRedirects = *value == 0
	}
	if value := c.Limits.RequestTimeout; value != nil {
		if *value < 1 || *value > limits.RequestTimeout.Milliseconds() {
			return limits, options, errors.New("provider request_timeout_ms must be between 1 and 30000")
		}
		limits.RequestTimeout = time.Duration(*value) * time.Millisecond
	}
	return limits, options, nil
}

func normalizeProviderSourceHost(host string) (string, error) {
	if host == "" || strings.TrimSpace(host) != host {
		return "", errors.New("invalid host")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.Is4In6() {
			return "", errors.New("invalid IP host")
		}
		return ip.String(), nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if len(host) > 253 {
		return "", errors.New("invalid host")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid host")
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
				return "", errors.New("invalid host")
			}
		}
	}
	return host, nil
}

func privateProviderPrefix(prefix netip.Prefix) bool {
	for _, network := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "198.18.0.0/15", "fc00::/7", "::1/128"} {
		allowed := netip.MustParsePrefix(network)
		if prefix.Bits() >= allowed.Bits() && allowed.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}
