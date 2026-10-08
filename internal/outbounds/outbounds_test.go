package outbounds

import "testing"

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
