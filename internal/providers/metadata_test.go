package providers

import (
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
)

func TestNameFilterMembershipChangeStagesWithoutChangingActiveInventory(t *testing.T) {
	registry := NewRegistry(DefaultLimits(), nil)
	groups := outbounds.NewService()
	registry.SetMetadataImpactEvaluator(groups.ProviderMetadataImpact)
	old, _, err := registry.Stage("p", []byte("trojan://secret@example.org:443#east"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Publish("p", old.Number, 0); err != nil {
		t.Fatal(err)
	}
	group, err := groups.Create(outbounds.Group{Name: "east", GatewayID: "gw", NodeIDs: []string{old.Nodes[0].ID}, SourceFilters: &outbounds.SourceFilters{ProviderIDs: []string{"p"}, IncludeNames: []string{"east"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groups.SetDesired(group.ID, outbounds.Scope{}, old.Nodes[0].ID, 0); err != nil {
		t.Fatal(err)
	}
	renamed, changes, err := registry.Stage("p", []byte("trojan://secret@example.org:443#west"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if changes.Noop || renamed.Number == old.Number || renamed.State != RevisionStaged {
		t.Fatalf("semantic rename was not staged: %+v %+v", renamed, changes)
	}
	if renamed.Nodes[0].ID != old.Nodes[0].ID || renamed.Nodes[0].ContentHash != old.Nodes[0].ContentHash {
		t.Fatal("metadata changed connection identity")
	}
	active, _ := registry.Active("p")
	if active.Nodes[0].Name != "east" {
		t.Fatal("unapplied metadata mutated active inventory")
	}
	impact, err := groups.PreviewInventory(renamed.Nodes)
	if err != nil || len(impact) != 1 || !impact[0].RequiresBlock || len(impact[0].RemovedNodeIDs) != 1 {
		t.Fatalf("missing removal preview: %+v %v", impact, err)
	}
	current, _ := groups.Get(group.ID)
	if len(current.NodeIDs) != 1 {
		t.Fatal("preview mutated group")
	}
	again, repeated, err := registry.Stage("p", []byte("trojan://secret@example.org:443#west"), FormatLinks)
	if err != nil || again.Number != renamed.Number || !repeated.Noop {
		t.Fatalf("identical staged metadata duplicated: %+v %+v %v", again, repeated, err)
	}
}

func TestUnrelatedMetadataRenameStaysNoopWithFilterEvaluator(t *testing.T) {
	registry := NewRegistry(DefaultLimits(), nil)
	groups := outbounds.NewService()
	registry.SetMetadataImpactEvaluator(groups.ProviderMetadataImpact)
	old, _, err := registry.Stage("p", []byte("trojan://secret@example.org:443#east"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Publish("p", old.Number, 0); err != nil {
		t.Fatal(err)
	}
	_, err = groups.Create(outbounds.Group{Name: "other", GatewayID: "gw", SourceFilters: &outbounds.SourceFilters{ProviderIDs: []string{"other-provider"}, IncludeNames: []string{"east"}}})
	if err != nil {
		t.Fatal(err)
	}
	updated, changes, err := registry.Stage("p", []byte("trojan://secret@example.org:443#west"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if !changes.Noop || updated.Number != old.Number || updated.Nodes[0].Name != "west" || registry.Status("p").Staged != 0 {
		t.Fatal("unrelated rename manufactured runtime publication")
	}
}
