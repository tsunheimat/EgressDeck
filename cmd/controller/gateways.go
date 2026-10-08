package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

const gatewayConfigLimit = 1 << 20

// Connection credentials belong to an operator-owned file, never inventory
// records or API request bodies. Changing this configuration requires restart.
type gatewayConnections struct {
	Gateways []gatewayConnection `json:"gateways"`
}

type gatewayConnection struct {
	ID                string               `json:"id"`
	Endpoint          string               `json:"endpoint"`
	Token             string               `json:"token"`
	ClientCert        string               `json:"client_cert"`
	ClientKey         string               `json:"client_key"`
	CAFile            string               `json:"ca_file"`
	ServerName        string               `json:"server_name,omitempty"`
	Runtime           gatewayRuntimeConfig `json:"runtime,omitempty"`
	EnablePolicyApply bool                 `json:"enable_policy_apply,omitempty"`
	PolicyFormat      string               `json:"policy_format,omitempty"`
}

type configuredGateway struct {
	endpoint          string
	client            *gateway.Client
	runtime           gatewayRuntimeConfig
	enablePolicyApply bool
	policyFormat      string
}

func configureGateways(ctx context.Context, server *api.Server, configPath string) (func(), error) {
	closeClients := func() {}
	if strings.TrimSpace(configPath) == "" {
		return closeClients, nil
	}
	if server == nil || server.Store == nil || server.Services == nil {
		return nil, errors.New("gateway connections require an initialized controller")
	}
	config, err := readGatewayConnections(configPath)
	if err != nil {
		return nil, err
	}
	clients := make(map[string]configuredGateway, len(config.Gateways))
	closeClients = func() {
		for _, connection := range clients {
			connection.client.CloseIdleConnections()
		}
	}
	// Keep a partially constructed client registry private if any entry fails.
	configured := false
	defer func() {
		if !configured {
			closeClients()
		}
	}()
	for i, connection := range config.Gateways {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if connection.ID == "" || strings.TrimSpace(connection.ID) != connection.ID {
			return nil, fmt.Errorf("gateway connection %d requires a nonblank id without surrounding whitespace", i+1)
		}
		if _, exists := clients[connection.ID]; exists {
			return nil, fmt.Errorf("gateway connection %d duplicates an id", i+1)
		}
		// TLS errors may include operator paths. Keep all configuration errors
		// free of raw credential values and credential-bearing filenames.
		tlsConfig, err := gateway.LoadClientTLS(connection.ClientCert, connection.ClientKey, connection.CAFile, connection.ServerName)
		if err != nil {
			return nil, fmt.Errorf("gateway connection %d has an invalid TLS identity or trust roots", i+1)
		}
		client, err := gateway.NewClient(gateway.ClientOptions{Endpoint: connection.Endpoint, Token: connection.Token, TLSConfig: tlsConfig, Timeout: 10 * time.Second})
		if err != nil {
			return nil, fmt.Errorf("gateway connection %d has an invalid HTTPS endpoint or bearer token", i+1)
		}
		endpoint := strings.TrimRight(connection.Endpoint, "/")
		if err := validateGatewayRuntimeConfig(connection.Runtime); err != nil {
			return nil, fmt.Errorf("gateway connection %d runtime configuration is invalid: %w", i+1, err)
		}
		clients[connection.ID] = configuredGateway{endpoint: endpoint, client: client, runtime: connection.Runtime, enablePolicyApply: connection.EnablePolicyApply, policyFormat: connection.PolicyFormat}
		registered, err := server.Store.GetGateway(ctx, connection.ID)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return nil, fmt.Errorf("gateway connection %d registration could not be read", i+1)
		}
		if err == nil && strings.TrimRight(registered.Endpoint, "/") != endpoint {
			return nil, fmt.Errorf("gateway connection %d endpoint does not match its registered endpoint", i+1)
		}
	}
	server.Services.GatewayObserver = func(ctx context.Context, registered domain.Gateway) (gateway.Capabilities, gateway.Health, error) {
		connection, ok := clients[registered.ID]
		if !ok {
			return gateway.Capabilities{}, gateway.Health{}, gateway.ErrUnsupported
		}
		stored, err := server.Store.GetGateway(ctx, registered.ID)
		if err != nil {
			return gateway.Capabilities{}, gateway.Health{}, err
		}
		if strings.TrimRight(registered.Endpoint, "/") != strings.TrimRight(stored.Endpoint, "/") || strings.TrimRight(stored.Endpoint, "/") != connection.endpoint {
			return gateway.Capabilities{}, gateway.Health{}, errors.New("gateway endpoint does not match its operator configuration")
		}
		capabilities, err := connection.client.Capabilities(ctx)
		if err != nil {
			return gateway.Capabilities{}, gateway.Health{}, err
		}
		health, err := connection.client.Health(ctx)
		if err != nil {
			return gateway.Capabilities{}, gateway.Health{}, err
		}
		return capabilities, health, nil
	}
	configureGatewayRuntime(server, clients)
	configureGatewayDiagnostics(server, clients)
	if err := configurePolicyExecutors(server, clients); err != nil {
		return nil, err
	}
	configured = true
	return closeClients, nil
}

func readGatewayConnections(path string) (gatewayConnections, error) {
	var config gatewayConnections
	absPath, err := filepath.Abs(path)
	if err != nil {
		return config, errors.New("gateway connections file path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil || resolved != absPath {
		return config, errors.New("gateway connections file must exist without symlinks in its path")
	}
	before, err := os.Lstat(absPath)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > gatewayConfigLimit {
		return config, errors.New("gateway connections file must be a private regular file of at most 1 MiB")
	}
	f, err := os.Open(absPath)
	if err != nil {
		return config, errors.New("gateway connections file cannot be opened")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm()&0077 != 0 || after.Size() > gatewayConfigLimit {
		return config, errors.New("gateway connections file changed or is not private")
	}
	data, err := io.ReadAll(io.LimitReader(f, gatewayConfigLimit+1))
	if err != nil || len(data) > gatewayConfigLimit {
		return config, errors.New("gateway connections file cannot be read or exceeds 1 MiB")
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return gatewayConnections{}, errors.New("gateway connections file must contain valid connection configuration JSON")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return gatewayConnections{}, errors.New("gateway connections file must contain exactly one JSON object")
	}
	if config.Gateways == nil || len(config.Gateways) > 128 {
		return gatewayConnections{}, errors.New("gateway connections file requires a gateways array with at most 128 entries")
	}
	return config, nil
}
