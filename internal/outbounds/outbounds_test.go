package outbounds

import (
	"errors"
	"testing"
)

func TestSelectionRequiresMembershipAndSeparatesScopes(t *testing.T) {
	s := NewService()
	g, err := s.Create(Group{Name: "edge", GatewayID: "gw", NodeIDs: []string{"a", "b"}, Mode: SelectionManual})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetDesired(g.ID, Scope{Transport: "tcp"}, "missing", 0); err != ErrNodeNotMember {
		t.Fatalf("missing node error=%v", err)
	}
	a, err := s.SetDesired(g.ID, Scope{Transport: "tcp"}, "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.SetDesired(g.ID, Scope{Transport: "udp"}, "b", 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.DesiredNodeID != "a" || b.DesiredNodeID != "b" || len(s.Selections(g.ID)) != 2 {
		t.Fatal("transport selections were not independent")
	}
	if _, err := s.SetDesired(g.ID, Scope{GatewayID: "other"}, "a", 0); err != ErrGatewayMismatch {
		t.Fatalf("gateway mismatch=%v", err)
	}
}

func TestSelectionDesiredAppliedObservedAreSeparate(t *testing.T) {
	s := NewService()
	g, _ := s.Create(Group{Name: "edge", GatewayID: "gw", NodeIDs: []string{"a"}})
	if _, err := s.SetDesired(g.ID, Scope{}, "a", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MarkApplied(g.ID, Scope{}, "a", 8); err != nil {
		t.Fatal(err)
	}
	sel, err := s.Observe(g.ID, Scope{}, "a", 8)
	if err != nil {
		t.Fatal(err)
	}
	if sel.DesiredNodeID != "a" || sel.AppliedNodeID != "a" || sel.ObservedNodeID != "a" || sel.Generation != 8 {
		t.Fatalf("selection state=%+v", sel)
	}
}

func TestGroupConfigurationHasIndependentRevisionAndExactReadback(t *testing.T) {
	s := NewService()
	g, err := s.Create(Group{ID: "group", Name: "edge", GatewayID: "gw", NodeIDs: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := s.Update(Group{ID: g.ID, Name: g.Name, GatewayID: g.GatewayID, NodeIDs: []string{"a"}}, g.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.AppliedRevision != 0 {
		t.Fatalf("unexpected independent state: %+v", updated)
	}
	if _, err := s.ObserveConfiguration(updated.ID, updated.Revision, []string{"a", "b"}, 1); !errors.Is(err, ErrSelectionConflict) {
		t.Fatalf("stale membership accepted: %v", err)
	}
	observed, err := s.ObserveConfiguration(updated.ID, updated.Revision, []string{"a"}, 7)
	if err != nil {
		t.Fatal(err)
	}
	if observed.AppliedRevision != updated.Revision || observed.ObservedRevision != updated.Revision || observed.AppliedGeneration != 7 {
		t.Fatalf("readback not committed: %+v", observed)
	}
	reloaded := NewService()
	data, err := s.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.ImportState(data); err != nil {
		t.Fatal(err)
	}
	got, err := reloaded.Get(updated.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AppliedRevision != updated.Revision || !sameCandidateIDs(got.AppliedNodeIDs, []string{"a"}) {
		t.Fatalf("runtime state lost on restart: %+v", got)
	}
}

func TestGroupConfigurationCannotCommitRemovedSelectedNode(t *testing.T) {
	s := NewService()
	g, err := s.Create(Group{ID: "group", Name: "edge", GatewayID: "gw", NodeIDs: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetDesired(g.ID, Scope{GatewayID: "gw", Transport: "tcp"}, "b", 0); err != nil {
		t.Fatal(err)
	}
	updated, err := s.Update(Group{ID: g.ID, Name: g.Name, GatewayID: g.GatewayID, NodeIDs: []string{"a"}}, g.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ObserveConfiguration(updated.ID, updated.Revision, []string{"a"}, 1); !errors.Is(err, ErrSelectionConflict) {
		t.Fatalf("removed selected group configuration accepted: %v", err)
	}
}

func TestGroupEditPreservesSelectionRevisionAndReadbackOwnership(t *testing.T) {
	s := NewService()
	g, err := s.Create(Group{ID: "g", Name: "edge", GatewayID: "gw", NodeIDs: []string{"a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := s.SetDesired(g.ID, Scope{GatewayID: "gw", Transport: "tcp"}, "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	g, err = s.ObserveConfiguration(g.ID, g.Revision, g.NodeIDs, 2)
	if err != nil {
		t.Fatal(err)
	}
	g.NodeIDs = []string{"a"}
	g.AppliedRevision, g.ObservedRevision = 987, 987
	g.AppliedNodeIDs = []string{"forged"}
	updated, err := s.Update(g, g.Revision)
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.GetSelection(g.ID, selected.Scope)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != selected.Revision || current.DesiredNodeID != "a" {
		t.Fatalf("group edit advanced selection lifecycle: %+v", current)
	}
	if updated.AppliedRevision != 1 || updated.ObservedRevision != 1 || !sameCandidateIDs(updated.AppliedNodeIDs, []string{"a", "b"}) {
		t.Fatalf("write spoofed runtime state: %+v", updated)
	}
	updated.AppliedNodeIDs[0] = "caller-mutation"
	currentGroup, _ := s.Get(updated.ID)
	if !sameCandidateIDs(currentGroup.AppliedNodeIDs, []string{"a", "b"}) {
		t.Fatal("returned runtime members alias stored state")
	}
	if err := s.Delete(updated.ID, updated.Revision, nil); !errors.Is(err, ErrGroupInUse) {
		t.Fatalf("runtime group deleted: %v", err)
	}
	data, err := s.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restored := NewService()
	if err := restored.ImportState(data); err != nil {
		t.Fatal(err)
	}
	restoredGroup, _ := restored.Get(g.ID)
	if restoredGroup.Revision != 2 || restoredGroup.AppliedRevision != 1 {
		t.Fatalf("pending edit lost after restart: %+v", restoredGroup)
	}
}

func TestAppliedGroupCannotMoveOrDeleteWithoutRuntimeRetirement(t *testing.T) {
	s := NewService()
	g, err := s.Create(Group{ID: "g", Name: "edge", GatewayID: "gw", NodeIDs: []string{"a"}, AppliedRevision: 7, ObservedRevision: 7, AppliedGeneration: 7, ObservedGeneration: 7, AppliedNodeIDs: []string{"a"}, ObservedNodeIDs: []string{"a"}})
	if err != nil {
		t.Fatal(err)
	}
	if g.AppliedRevision != 0 || g.ObservedRevision != 0 {
		t.Fatal("create accepted caller runtime state")
	}
	g, err = s.ObserveConfiguration(g.ID, g.Revision, g.NodeIDs, 2)
	if err != nil {
		t.Fatal(err)
	}
	moved := g
	moved.GatewayID = "another-gw"
	if _, err := s.Update(moved, g.Revision); err == nil {
		t.Fatal("applied group moved without retiring prior gateway")
	}
	if err := s.Delete(g.ID, g.Revision, nil); !errors.Is(err, ErrGroupInUse) {
		t.Fatalf("unselected runtime group deleted: %v", err)
	}
}
