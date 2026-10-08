package api

import (
	"context"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
)

func TestRuntimeDependencyQuarantineIsBidirectionalAndScoped(t *testing.T) {
	ctx := context.Background()
	services := NewServices()
	revision, _, err := services.Providers.Stage("p", []byte("socks5://host.example:1080#node"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	group, err := services.Outbounds.Create(outbounds.Group{ID: "g", Name: "edge", GatewayID: "gw", NodeIDs: []string{revision.Nodes[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := services.Outbounds.Create(outbounds.Group{ID: "unrelated", Name: "other", GatewayID: "gw", NodeIDs: []string{"other-node"}})
	if err != nil {
		t.Fatal(err)
	}
	groupTarget := deployment.Target{Kind: "outbound_group", ID: group.ID}
	providerTarget := deployment.Target{Kind: "provider", ID: "p"}
	for _, pair := range [][2]deployment.Target{{groupTarget, providerTarget}, {providerTarget, groupTarget}} {
		services.Journal = deployment.NewMemoryJournal()
		_, err := services.Journal.Create(ctx, deployment.Operation{Target: pair[0], Action: "mutation", Status: deployment.StatusOutcomeUnknown})
		if err != nil {
			t.Fatal(err)
		}
		if err := services.rejectUnknownTarget(ctx, pair[1]); err == nil {
			t.Fatalf("dependent target escaped pending lock: %+v", pair)
		}
		if err := services.rejectUnknownTarget(ctx, deployment.Target{Kind: "outbound_group", ID: unrelated.ID}); err != nil {
			t.Fatalf("unrelated group quarantined: %v", err)
		}
	}
	services.Journal = deployment.NewMemoryJournal()
	op, err := services.Journal.Create(ctx, deployment.Operation{Target: providerTarget, Action: "publish", Status: deployment.StatusOutcomeUnknown})
	if err != nil {
		t.Fatal(err)
	}
	prospective := outbounds.Group{ID: "new", Name: "new", GatewayID: "gw", NodeIDs: []string{revision.Nodes[0].ID}}
	if err := services.rejectPendingProviderForGroup(ctx, prospective); err == nil {
		t.Fatal("new group joined unresolved provider target")
	}
	op.Status = deployment.StatusApplied
	if err := services.Journal.Save(ctx, op); err != nil {
		t.Fatal(err)
	}
	if err := services.rejectUnknownTarget(ctx, groupTarget); err != nil {
		t.Fatalf("resolved operation retained lock: %v", err)
	}
}
