package contract_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

func TestGatewayCapabilityFixtureIsCompleteAndTyped(t *testing.T) {
	var caps gateway.Capabilities
	if err := json.Unmarshal(fixture(t, "gateway", "capabilities.json"), &caps); err != nil {
		t.Fatalf("decode capabilities fixture: %v", err)
	}
	if caps.Implementation != "egressdeck-fake-engine" || caps.Version == "" {
		t.Fatalf("invalid implementation identity: %+v", caps)
	}
	if len(caps.Items) != len(gateway.AllCapabilities) {
		t.Fatalf("capability count = %d, want %d", len(caps.Items), len(gateway.AllCapabilities))
	}
	for _, name := range gateway.AllCapabilities {
		if !caps.Has(name) {
			t.Errorf("fixture does not advertise capability %q", name)
		}
	}
}

func TestGatewaySnapshotFixtureShowsScopedHotUpdate(t *testing.T) {
	var before, after gateway.Snapshot
	if err := json.Unmarshal(fixture(t, "gateway", "before.json"), &before); err != nil {
		t.Fatalf("decode before snapshot: %v", err)
	}
	if err := json.Unmarshal(fixture(t, "gateway", "after.json"), &after); err != nil {
		t.Fatalf("decode after snapshot: %v", err)
	}
	if before.Providers["provider-primary"].Revision != 1 || after.Providers["provider-primary"].Revision != 2 {
		t.Fatalf("primary provider revision mismatch: before=%d after=%d", before.Providers["provider-primary"].Revision, after.Providers["provider-primary"].Revision)
	}
	if before.Providers["provider-unrelated"].ContentHash != after.Providers["provider-unrelated"].ContentHash {
		t.Fatal("unrelated provider changed during scoped update")
	}
	if before.Groups["outbound-unrelated"].NodeIDs[0] != after.Groups["outbound-unrelated"].NodeIDs[0] {
		t.Fatal("unrelated outbound group changed during scoped update")
	}
	selectionKey := "gateway-home\x00outbound-unrelated\x00"
	if before.Selections[selectionKey].ObservedNodeID != after.Selections[selectionKey].ObservedNodeID {
		t.Fatal("unrelated selection changed during scoped update")
	}
	if len(before.Connections) != len(after.Connections) || before.Connections[0].ID != after.Connections[0].ID {
		t.Fatal("unrelated connection was not retained")
	}
}

func TestGatewayRuntimeContractPublishesAndPersistsSelection(t *testing.T) {
	ctx := context.Background()
	engine := gateway.NewFakeEngine()
	revision := gateway.ProviderRevision{
		ProviderID:  "provider-primary",
		Revision:    1,
		ContentHash: "fixture-primary-v1",
		Nodes: []gateway.Node{
			{ID: "node-alpha", ProviderID: "provider-primary", Name: "Alpha"},
			{ID: "node-beta", ProviderID: "provider-primary", Name: "Beta"},
		},
	}
	stageID, err := engine.StageProvider(ctx, revision, 0)
	if err != nil {
		t.Fatalf("stage provider: %v", err)
	}
	if _, err := engine.PublishProvider(ctx, stageID); err != nil {
		t.Fatalf("publish provider: %v", err)
	}
	engine.AddGroup(gateway.OutboundGroup{ID: "outbound-primary", ProviderIDs: []string{"provider-primary"}, NodeIDs: []string{"node-alpha", "node-beta"}})
	scope := gateway.SelectionScope{GatewayID: "gateway-home", GroupID: "outbound-primary", Transport: "tcp"}
	selection, err := engine.PersistSelection(ctx, scope, "node-beta", 0)
	if err != nil {
		t.Fatalf("persist selection: %v", err)
	}
	if selection.DesiredNodeID != "node-beta" || selection.ObservedNodeID != "node-beta" || selection.Revision != 1 {
		t.Fatalf("unexpected persisted selection: %+v", selection)
	}
	if _, err := engine.SetRuntimeSelection(ctx, scope, "node-alpha", selection.Revision); err != nil {
		t.Fatalf("runtime selection: %v", err)
	}
	snapshot, err := engine.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := snapshot.Selections[scopeKey(scope)]
	if got.DesiredNodeID != "node-alpha" || got.ObservedNodeID != "node-alpha" || got.Revision != 2 {
		t.Fatalf("selection readback mismatch: %+v", got)
	}
}

// SelectionScope.key is intentionally private. Keep this helper in the
// contract package so the test documents the wire-compatible key shape
// without making storage details part of the exported engine API.
func scopeKey(scope gateway.SelectionScope) string {
	return scope.GatewayID + "\x00" + scope.GroupID + "\x00" + scope.Transport
}
