package main

import (
	"context"
	"errors"

	"github.com/egressdeck/homelab-proxy-controller/internal/api"
	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/telemetry"
)

func configureTelemetry(server *api.Server) {
	server.Telemetry = telemetry.New(func(ctx context.Context) (telemetry.OperationCounts, error) {
		var counts telemetry.OperationCounts
		if server.Services == nil || server.Services.Journal == nil {
			return counts, errors.New("operation journal unavailable")
		}
		operations, err := server.Services.Journal.List(ctx)
		if err != nil {
			return counts, err
		}
		for _, operation := range operations {
			switch operation.Status {
			case deployment.StatusDraft:
				counts.Draft++
			case deployment.StatusValidated:
				counts.Validated++
			case deployment.StatusStaged:
				counts.Staged++
			case deployment.StatusApplying:
				counts.Applying++
			case deployment.StatusVerifying:
				counts.Verifying++
			case deployment.StatusApplied:
				counts.Applied++
			case deployment.StatusPartiallyApplied:
				counts.PartiallyApplied++
			case deployment.StatusFailed:
				counts.Failed++
			case deployment.StatusOutcomeUnknown:
				counts.OutcomeUnknown++
			default:
				counts.Other++
			}
		}
		return counts, nil
	})
}
