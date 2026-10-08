package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/opnsense"
)

// opnsenseFileConfig is deliberately an external file. API credentials are
// never accepted from the public HTTP API or mixed into controller state.
type opnsenseFileConfig struct {
	BaseURL          string                  `json:"base_url"`
	APIKey           string                  `json:"api_key"`
	APISecret        string                  `json:"api_secret"`
	Release          string                  `json:"release"`
	RootCAFile       string                  `json:"root_ca_file,omitempty"`
	TimeoutString    string                  `json:"timeout,omitempty"`
	MaxResponseBytes int64                   `json:"max_response_bytes,omitempty"`
	MaxRows          int                     `json:"max_rows,omitempty"`
	ManagedAliases   []opnsense.ManagedAlias `json:"managed_aliases,omitempty"`
}

// configureOPNsense installs the explicitly configured, narrow OPNsense
// adapter. An empty path leaves firewall integration disabled. The returned
// cleanup closes idle HTTP connections and is safe to defer unconditionally.
func configureOPNsense(_ context.Context, server *api.Server, configPath string) (func(), error) {
	if strings.TrimSpace(configPath) == "" {
		return func() {}, nil
	}
	if server == nil || server.Services == nil {
		return nil, errors.New("controller services are required for OPNsense configuration")
	}
	var cfg opnsenseFileConfig
	if err := readSecureJSON(configPath, &cfg); err != nil {
		return nil, fmt.Errorf("read OPNsense config: %w", err)
	}
	var timeout time.Duration
	if cfg.TimeoutString != "" {
		parsed, err := time.ParseDuration(cfg.TimeoutString)
		if err != nil {
			return nil, errors.New("OPNsense timeout must be a valid duration")
		}
		timeout = parsed
	}
	var roots *x509.CertPool
	if strings.TrimSpace(cfg.RootCAFile) != "" {
		pem, err := os.ReadFile(cfg.RootCAFile)
		if err != nil {
			return nil, fmt.Errorf("read OPNsense root CA: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("read OPNsense root CA: no certificates found")
		}
	}
	client, err := opnsense.NewHTTPClient(opnsense.HTTPConfig{
		BaseURL: cfg.BaseURL, APIKey: cfg.APIKey, APISecret: cfg.APISecret,
		Release: cfg.Release, RootCAs: roots, Timeout: timeout,
		MaxResponseBytes: cfg.MaxResponseBytes, MaxRows: cfg.MaxRows,
		ManagedAliases: cfg.ManagedAliases,
	})
	if err != nil {
		return nil, fmt.Errorf("configure OPNsense client: %w", err)
	}
	adapter, err := opnsense.NewAdapter(client)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("configure OPNsense adapter: %w", err)
	}
	server.Services.Firewall = adapter
	return client.Close, nil
}

func readSecureJSON(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("configuration file must be regular")
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("configuration file mode must be 0600 (got %04o)", info.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return err
	}
	defer clear(data)
	if len(data) > 1<<20 {
		return errors.New("configuration file exceeds 1 MiB")
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("configuration file must contain one JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("configuration file contains invalid JSON or unknown fields")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("configuration file contains trailing JSON")
	}
	return nil
}
