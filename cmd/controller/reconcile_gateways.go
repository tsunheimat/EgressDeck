package main

import (
	"context"
	"errors"
	"strings"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
)

// configurePolicyExecutors enables only the native artifact policy action for
// gateways explicitly opted in by operator configuration. Strict enrollment
// remains unsupported until an actual independently enforced guard and the
// CrossSystemExecutor's complete adapters are installed.
func configurePolicyExecutors(server *api.Server, clients map[string]configuredGateway) error {
	if server == nil || server.Services == nil || server.Store == nil || server.Services.Journal == nil {
		return errors.New("native policy executor requires initialized services")
	}
	executors := map[string]*deployment.GatewayPolicyExecutor{}
	for id, connection := range clients {
		if !connection.enablePolicyApply {
			continue
		}
		if connection.policyFormat != deployment.NativeDAEPolicyFormat {
			return errors.New("enabled policy application requires the native_dae artifact format")
		}
		id, connection := id, connection
		before := func(ctx context.Context) error {
			registered, err := server.Store.GetGateway(ctx, id)
			if err != nil {
				return errors.New("configured policy gateway registration is unavailable")
			}
			if strings.TrimRight(registered.Endpoint, "/") != connection.endpoint {
				return errors.New("gateway endpoint does not match operator configuration")
			}
			return nil
		}
		executors[id] = deployment.NewGatewayPolicyExecutor(server.Services.Journal, connection.client, id, deployment.GatewayPolicyOptions{EnableApply: true, Format: connection.policyFormat, BeforeRequest: before})
	}
	runtimeEnabled := false
	for _, connection := range clients {
		runtimeEnabled = runtimeEnabled || connection.runtime.EnableProviderPublish || connection.runtime.EnableSelection
	}
	if len(executors) == 0 && !runtimeEnabled {
		return nil
	}
	previous := server.Services.ExecutorFactory
	reader := &runtimeReadbackExecutor{bridge: &gatewayRuntimeBridge{server: server, connections: clients}}
	server.Services.ExecutorFactory = func(target deployment.Target) deployment.Executor {
		if runtimeEnabled && (target.Kind == "provider" || target.Kind == "outbound_group") {
			return reader
		}
		if target.Kind == "gateway" {
			if executor := executors[target.ID]; executor != nil {
				return executor
			}
		}
		if previous != nil {
			return previous(target)
		}
		return nil
	}
	return nil
}
