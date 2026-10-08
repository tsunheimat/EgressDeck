package main

import (
	"context"
	"errors"
	"strings"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

func configureGatewayDiagnostics(server *api.Server, clients map[string]configuredGateway) {
	if len(clients) == 0 {
		return
	}
	server.Services.GatewayDiagnostics = func(ctx context.Context, registered domain.Gateway) (api.GatewayDiagnostics, error) {
		connection, ok := clients[registered.ID]
		if !ok {
			return nil, gateway.ErrUnsupported
		}
		before := func(ctx context.Context) error {
			stored, err := server.Store.GetGateway(ctx, registered.ID)
			if err != nil {
				return err
			}
			if strings.TrimRight(stored.Endpoint, "/") != connection.endpoint || strings.TrimRight(registered.Endpoint, "/") != connection.endpoint {
				return errors.New("gateway endpoint does not match its operator configuration")
			}
			return nil
		}
		if err := before(ctx); err != nil {
			return nil, err
		}
		return &configuredDiagnostics{client: connection.client, before: before}, nil
	}
}

// Recheck inventory immediately before every request, including the second
// request after capability negotiation. Inventory cannot repoint credentials.
type configuredDiagnostics struct {
	client *gateway.Client
	before func(context.Context) error
}

func (d *configuredDiagnostics) Capabilities(ctx context.Context) (gateway.Capabilities, error) {
	if err := d.before(ctx); err != nil {
		return gateway.Capabilities{}, err
	}
	return d.client.Capabilities(ctx)
}
func (d *configuredDiagnostics) ProbeNode(ctx context.Context, id string) (gateway.ProbeResult, error) {
	if err := d.before(ctx); err != nil {
		return gateway.ProbeResult{}, err
	}
	return d.client.ProbeNode(ctx, id)
}
func (d *configuredDiagnostics) ProbeGroup(ctx context.Context, id string) (gateway.ProbeResult, error) {
	if err := d.before(ctx); err != nil {
		return gateway.ProbeResult{}, err
	}
	return d.client.ProbeGroup(ctx, id)
}
func (d *configuredDiagnostics) ObserveConnections(ctx context.Context) ([]gateway.Connection, error) {
	if err := d.before(ctx); err != nil {
		return nil, err
	}
	return d.client.ObserveConnections(ctx)
}
func (d *configuredDiagnostics) Counters(ctx context.Context) (gateway.Counters, error) {
	if err := d.before(ctx); err != nil {
		return gateway.Counters{}, err
	}
	return d.client.Counters(ctx)
}
