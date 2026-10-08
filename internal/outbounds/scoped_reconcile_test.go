package outbounds

import (
	"errors"
	"reflect"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
)

func TestScopedReconcileLeavesUnrelatedPendingProviderAndSelectionUntouched(t *testing.T) {
	s := NewService()
	first, err := s.Create(Group{Name: "first", GatewayID: "gw", NodeIDs: []string{"a"}, SourceFilters: &SourceFilters{ProviderIDs: []string{"p1"}}})
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Create(Group{Name: "pending", GatewayID: "gw", NodeIDs: []string{"pending-node"}, SourceFilters: &SourceFilters{ProviderIDs: []string{"p2"}}})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := s.SetDesired(other.ID, Scope{}, "pending-node", 0)
	if err != nil {
		t.Fatal(err)
	}
	inventory := []nodes.Node{{ID: "b", ProviderID: "p1", Supported: true}}
	if _, err := s.ReconcileGroups(inventory, map[string]int64{first.ID: first.Revision}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(other.ID)
	if err != nil || !reflect.DeepEqual(got, other) {
		t.Fatal("unrelated group changed")
	}
	choice, err := s.GetSelection(other.ID, Scope{})
	if err != nil || !reflect.DeepEqual(choice, selected) {
		t.Fatal("unrelated desired/runtime state changed")
	}
	updated, _ := s.Get(first.ID)
	if !reflect.DeepEqual(updated.NodeIDs, []string{"b"}) || updated.Revision != first.Revision+1 {
		t.Fatal("targeted group was not recomputed")
	}
	before, _ := s.ExportState()
	if _, err := s.ReconcileGroups(inventory, map[string]int64{first.ID: first.Revision}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale fence accepted: %v", err)
	}
	after, _ := s.ExportState()
	if string(before) != string(after) {
		t.Fatal("rejected fence mutated state")
	}
	if _, err := s.ReconcileGroups(nil, nil); err != nil {
		t.Fatal(err)
	}
	final, _ := s.ExportState()
	if string(after) != string(final) {
		t.Fatal("empty scope mutated groups")
	}
}
