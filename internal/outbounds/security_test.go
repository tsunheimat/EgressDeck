package outbounds

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

func securityGroup(t *testing.T, replacement ReplacementPolicy) (*Service, Group) {
	t.Helper()
	s := NewService()
	g, err := s.Create(Group{ID: "group", Name: "edge", GatewayID: "gw", NodeIDs: []string{"a", "b"}, Replacement: replacement})
	if err != nil {
		t.Fatal(err)
	}
	return s, g
}

func TestRevisionPreconditionsCannotOverwriteExistingState(t *testing.T) {
	s, g := securityGroup(t, ReplacementBlock)
	for _, revision := range []int64{-1, 0, 2} {
		if _, err := s.Update(g, revision); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("group revision %d: %v", revision, err)
		}
	}
	for _, revision := range []int64{-1, 1} {
		if _, err := s.SetDesired(g.ID, Scope{}, "a", revision); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("initial revision %d: %v", revision, err)
		}
	}
	first, err := s.SetDesired(g.ID, Scope{}, "a", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range []int64{-1, 0, 2} {
		if _, err := s.SetDesired(g.ID, Scope{}, "b", revision); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("existing revision %d: %v", revision, err)
		}
	}
	got, _ := s.GetSelection(g.ID, Scope{})
	if got != first {
		t.Fatal("failed precondition mutated state")
	}
	if _, err := s.SetDesired(g.ID, Scope{}, "b", first.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetDesired(g.ID, Scope{}, "a", first.Revision); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("stale revision accepted")
	}
}

func TestConcurrentFirstSelectionsHaveOnlyOneWinner(t *testing.T) {
	s, g := securityGroup(t, ReplacementBlock)
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, node := range []string{"a", "b"} {
		workers.Add(1)
		go func(node string) {
			defer workers.Done()
			<-start
			_, err := s.SetDesired(g.ID, Scope{}, node, 0)
			results <- err
		}(node)
	}
	close(start)
	workers.Wait()
	close(results)
	winners, conflicts := 0, 0
	for err := range results {
		if err == nil {
			winners++
		} else if errors.Is(err, domain.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	got, err := s.GetSelection(g.ID, Scope{})
	if err != nil || winners != 1 || conflicts != 1 || got.Revision != 1 {
		t.Fatalf("concurrent first selection: winners=%d conflicts=%d state=%+v err=%v", winners, conflicts, got, err)
	}
}

func TestScopeCanonicalizationAndValidation(t *testing.T) {
	s, g := securityGroup(t, ReplacementBlock)
	first, err := s.SetDesired(g.ID, Scope{Transport: " TCP "}, "a", 0)
	if err != nil || first.Scope.Transport != "tcp" {
		t.Fatalf("canonical scope: %+v %v", first, err)
	}
	if _, err := s.SetDesired(g.ID, Scope{}, "b", 0); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("default scope bypassed CAS")
	}
	for _, scope := range []Scope{{Transport: "sctp"}, {Transport: "tcp\x00udp"}, {GatewayID: "gw\x00other", Transport: "tcp"}} {
		if _, err := s.SetDesired(g.ID, scope, "a", 0); err == nil {
			t.Fatalf("accepted scope %+v", scope)
		}
		if _, err := s.Observe(g.ID, scope, "a", 1); err == nil {
			t.Fatalf("observed invalid scope %+v", scope)
		}
		if _, err := s.MarkApplied(g.ID, scope, "a", 1); err == nil {
			t.Fatalf("applied invalid scope %+v", scope)
		}
		if _, err := s.GetSelection(g.ID, scope); err == nil {
			t.Fatalf("read invalid scope %+v", scope)
		}
	}
	if len(s.Selections(g.ID)) != 1 {
		t.Fatal("invalid scopes created records")
	}
}

func TestGroupNormalizationDoesNotMutateCallerOrStoredSlices(t *testing.T) {
	s := NewService()
	input := Group{Name: "edge", GatewayID: "gw", NodeIDs: []string{" a ", "b"}}
	created, err := s.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	if input.NodeIDs[0] != " a " || created.NodeIDs[0] != "a" {
		t.Fatal("normalization mutated caller")
	}
	created.NodeIDs[0] = "bad"
	fetched, _ := s.Get(created.ID)
	if fetched.NodeIDs[0] != "a" {
		t.Fatal("returned slice aliases service state")
	}
	fetched.NodeIDs = []string{" b "}
	if _, err := s.Update(fetched, fetched.Revision); err != nil {
		t.Fatal(err)
	}
	if fetched.NodeIDs[0] != " b " {
		t.Fatal("update mutated caller")
	}
	for _, invalid := range []Group{{ID: "g\x00x", Name: "edge", GatewayID: "gw"}, {Name: "edge", GatewayID: "gw\x00x"}, {Name: "edge", GatewayID: "gw", NodeIDs: []string{"n\x00x"}}} {
		if _, err := s.Create(invalid); err == nil {
			t.Fatal("accepted ambiguous identifier")
		}
	}
}

func TestRemovingSelectedNodeBlocksWithoutFabricatingRuntimeState(t *testing.T) {
	s, g := securityGroup(t, ReplacementBlock)
	selected, _ := s.SetDesired(g.ID, Scope{}, "a", 0)
	_, _ = s.MarkApplied(g.ID, Scope{}, "a", 4)
	_, _ = s.Observe(g.ID, Scope{}, "a", 3)
	g.NodeIDs = []string{"b"}
	updated, err := s.Update(g, g.Revision)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetSelection(g.ID, Scope{})
	if !got.Unavailable || got.DesiredNodeID != "a" || got.AppliedNodeID != "a" || got.ObservedNodeID != "a" || got.AppliedGeneration != 4 || got.ObservedGeneration != 3 {
		t.Fatalf("removed selection lost evidence or implicit fallback: %+v", got)
	}
	if _, err := s.SetDesired(g.ID, Scope{}, "b", selected.Revision); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("old group revision selection was accepted")
	}
	replacement, err := s.SetDesired(g.ID, Scope{}, "b", got.Revision)
	if err != nil || replacement.Unavailable || replacement.AppliedNodeID != "a" || replacement.ObservedNodeID != "a" {
		t.Fatalf("replacement: %+v %v", replacement, err)
	}
	updated.GatewayID = "other"
	if _, err := s.Update(updated, updated.Revision); err == nil {
		t.Fatal("migrated selection gateway implicitly")
	}
}

func TestRemovingSelectedNodeWithoutReplacementIsRejectedAtomically(t *testing.T) {
	s, g := securityGroup(t, ReplacementNone)
	_, _ = s.SetDesired(g.ID, Scope{}, "a", 0)
	before, _ := s.ExportState()
	g.NodeIDs = []string{"b"}
	if _, err := s.Update(g, g.Revision); err == nil {
		t.Fatal("removed selected node without replacement")
	}
	after, _ := s.ExportState()
	if !bytes.Equal(before, after) {
		t.Fatal("rejected update changed state")
	}
}

func TestAppliedAndObservedHaveIndependentMonotonicGenerations(t *testing.T) {
	s, g := securityGroup(t, ReplacementBlock)
	_, _ = s.SetDesired(g.ID, Scope{}, "a", 0)
	_, _ = s.MarkApplied(g.ID, Scope{}, "a", 8)
	got, err := s.Observe(g.ID, Scope{}, "b", 7)
	if err != nil {
		t.Fatal(err)
	}
	if got.DesiredNodeID != "a" || got.AppliedNodeID != "a" || got.ObservedNodeID != "b" || got.Generation != 8 || got.AppliedGeneration != 8 || got.ObservedGeneration != 7 {
		t.Fatalf("evidence merged: %+v", got)
	}
	before, _ := s.ExportState()
	if _, err := s.MarkApplied(g.ID, Scope{}, "b", 6); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("stale apply accepted")
	}
	if _, err := s.Observe(g.ID, Scope{}, "a", 6); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("stale observation accepted")
	}
	if _, err := s.Observe(g.ID, Scope{}, "direct", 9); !errors.Is(err, ErrNodeNotMember) {
		t.Fatal("implicit direct observed")
	}
	after, _ := s.ExportState()
	if !bytes.Equal(before, after) {
		t.Fatal("rejected evidence changed state")
	}
}

func TestCompensationPreservesRuntimeEvidenceAndCannotOverwriteLaterIntent(t *testing.T) {
	s, g := securityGroup(t, ReplacementBlock)
	first, _ := s.SetDesired(g.ID, Scope{}, "a", 0)
	_, _ = s.SetDesired(g.ID, Scope{}, "b", first.Revision)
	_, _ = s.Observe(g.ID, Scope{}, "b", 9)
	if err := s.RestoreDesired(g.ID, Scope{}, &first); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetSelection(g.ID, Scope{})
	if got.DesiredNodeID != "a" || got.ObservedNodeID != "b" || got.Generation != 9 || got.Revision != 3 {
		t.Fatalf("compensation overwrote evidence: %+v", got)
	}
	before, _ := s.ExportState()
	if err := s.RestoreDesired(g.ID, Scope{}, &first); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("stale compensation accepted")
	}
	after, _ := s.ExportState()
	if !bytes.Equal(before, after) {
		t.Fatal("stale compensation mutated state")
	}
	_, _ = s.SetDesired(g.ID, Scope{Transport: "udp"}, "b", 0)
	_, _ = s.Observe(g.ID, Scope{Transport: "udp"}, "b", 10)
	if err := s.RestoreDesired(g.ID, Scope{Transport: "udp"}, nil); err != nil {
		t.Fatal(err)
	}
	udp, _ := s.GetSelection(g.ID, Scope{Transport: "udp"})
	if udp.DesiredNodeID != "" || udp.ObservedNodeID != "b" || udp.Revision != 2 {
		t.Fatalf("new intent compensation lost evidence: %+v", udp)
	}
}

func TestStateRestartPreservesIndependentSelectionsAndCAS(t *testing.T) {
	s, g := securityGroup(t, ReplacementBlock)
	_, _ = s.SetDesired(g.ID, Scope{}, "a", 0)
	_, _ = s.MarkApplied(g.ID, Scope{}, "a", 8)
	_, _ = s.Observe(g.ID, Scope{}, "a", 7)
	_, _ = s.SetDesired(g.ID, Scope{Transport: "udp"}, "b", 0)
	g.NodeIDs = []string{"b"}
	_, _ = s.Update(g, g.Revision)
	encoded, err := s.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewService()
	if err := restarted.ImportState(encoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.List(), restarted.List()) || !reflect.DeepEqual(s.Selections(g.ID), restarted.Selections(g.ID)) {
		t.Fatal("restart lost state")
	}
	if _, err := restarted.SetDesired(g.ID, Scope{Transport: "udp"}, "b", 0); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("restart reset CAS")
	}
	sel, _ := restarted.GetSelection(g.ID, Scope{})
	if _, err := restarted.SetDesired(g.ID, Scope{}, "b", sel.Revision); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidSnapshotsAreRejectedWithoutReplacingState(t *testing.T) {
	s, g := securityGroup(t, ReplacementBlock)
	_, _ = s.SetDesired(g.ID, Scope{}, "a", 0)
	before, _ := s.ExportState()
	cases := map[string]func(*stateSnapshot){
		"version":                            func(v *stateSnapshot) { v.Version = 2 },
		"duplicate group":                    func(v *stateSnapshot) { v.Groups = append(v.Groups, v.Groups[0]) },
		"duplicate selection":                func(v *stateSnapshot) { v.Selections = append(v.Selections, v.Selections[0]) },
		"missing group":                      func(v *stateSnapshot) { v.Selections[0].GroupID = "missing" },
		"gateway":                            func(v *stateSnapshot) { v.Selections[0].Scope.GatewayID = "other" },
		"transport":                          func(v *stateSnapshot) { v.Selections[0].Scope.Transport = "sctp" },
		"noncanonical transport":             func(v *stateSnapshot) { v.Selections[0].Scope.Transport = " TCP " },
		"negative revision":                  func(v *stateSnapshot) { v.Selections[0].Revision = -1 },
		"negative generation":                func(v *stateSnapshot) { v.Selections[0].ObservedGeneration = -1 },
		"missing member without unavailable": func(v *stateSnapshot) { v.Selections[0].DesiredNodeID = "removed" },
		"invalid node identifier":            func(v *stateSnapshot) { v.Groups[0].NodeIDs = []string{"a\x00bad"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var snapshot stateSnapshot
			if err := json.Unmarshal(before, &snapshot); err != nil {
				t.Fatal(err)
			}
			mutate(&snapshot)
			encoded, _ := json.Marshal(snapshot)
			if err := s.ImportState(encoded); err == nil {
				t.Fatal("accepted corrupt snapshot")
			}
			after, _ := s.ExportState()
			if !bytes.Equal(before, after) {
				t.Fatal("failed restore changed live state")
			}
		})
	}
	for _, data := range [][]byte{append(append([]byte(nil), before...), []byte(" {}")...), []byte(`{"version":1,"unknown":true}`), []byte(`null`)} {
		if err := s.ImportState(data); err == nil {
			t.Fatal("accepted malformed snapshot")
		}
	}
}
