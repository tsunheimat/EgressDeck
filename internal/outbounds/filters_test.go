package outbounds

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
)

func filterNode(id, provider, name string, protocol nodes.Protocol) nodes.Node {
	return nodes.Node{ID: id, ProviderID: provider, Name: name, Definition: nodes.Definition{Protocol: protocol}, Supported: true}
}

func TestResolveCandidatesFiltersHaveDeterministicBoundedSemantics(t *testing.T) {
	inventory := []nodes.Node{
		filterNode("e", "p2", "HK", nodes.ProtocolShadowsocks),
		filterNode("c", "p1", "US", nodes.ProtocolShadowsocks),
		filterNode("a", "p1", "HK", nodes.ProtocolShadowsocks),
		filterNode("b", "p1", "HK", nodes.ProtocolTrojan),
		filterNode("d", "p1", "^HK.*", nodes.ProtocolShadowsocks),
		filterNode("f", "p1", "hk", nodes.ProtocolShadowsocks),
		filterNode("unsupported", "p1", "HK", nodes.ProtocolShadowsocks),
	}
	inventory[len(inventory)-1].Supported = false
	tests := []struct {
		name    string
		filters *SourceFilters
		want    []string
	}{
		{"explicit intersection", nil, []string{"a", "e"}},
		{"provider and protocol", &SourceFilters{ProviderIDs: []string{"p1"}, Protocols: []nodes.Protocol{nodes.ProtocolShadowsocks}}, []string{"a", "c", "d", "f"}},
		{"multiple providers", &SourceFilters{ProviderIDs: []string{"p2", "p1"}, Protocols: []nodes.Protocol{nodes.ProtocolTrojan}}, []string{"b"}},
		{"ID or exact name", &SourceFilters{ProviderIDs: []string{"p1"}, IncludeNodeIDs: []string{"c"}, IncludeNames: []string{"HK"}}, []string{"a", "b", "c"}},
		{"exclusions always win", &SourceFilters{ProviderIDs: []string{"p1"}, IncludeNodeIDs: []string{"c"}, IncludeNames: []string{"HK"}, ExcludeNodeIDs: []string{"a"}, ExcludeNames: []string{"US"}}, []string{"b"}},
		{"provider and protocol exclusions win", &SourceFilters{ProviderIDs: []string{"p1", "p2"}, Protocols: []nodes.Protocol{nodes.ProtocolShadowsocks, nodes.ProtocolTrojan}, ExcludeProviderIDs: []string{"p2"}, ExcludeProtocols: []nodes.Protocol{nodes.ProtocolShadowsocks}}, []string{"b"}},
		{"names are literals", &SourceFilters{ProviderIDs: []string{"p1"}, IncludeNames: []string{"^HK.*"}}, []string{"d"}},
		{"ID alone is a source", &SourceFilters{IncludeNodeIDs: []string{"c", "e"}}, []string{"c", "e"}},
		{"global protocol source", &SourceFilters{Protocols: []nodes.Protocol{nodes.ProtocolShadowsocks}}, []string{"a", "c", "d", "e", "f"}},
		{"empty result never falls back", &SourceFilters{ProviderIDs: []string{"removed"}}, []string{}},
		{"future protocol matches nothing", &SourceFilters{Protocols: []nodes.Protocol{"future-v2"}}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := Group{Name: "test", GatewayID: "gw", NodeIDs: []string{"e", "removed", "a", "unsupported"}, SourceFilters: tt.filters}
			got, err := ResolveCandidates(group, inventory)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("candidates=%v err=%v want=%v", got, err, tt.want)
			}
			reversed := append([]nodes.Node(nil), inventory...)
			for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
				reversed[i], reversed[j] = reversed[j], reversed[i]
			}
			again, err := ResolveCandidates(group, reversed)
			if err != nil || !reflect.DeepEqual(again, got) {
				t.Fatalf("inventory order changed candidates: %v %v", again, err)
			}
		})
	}
}

func TestFiltersRejectInvalidInputsAndAmbiguousInventory(t *testing.T) {
	tests := []SourceFilters{
		{},
		{ExcludeNodeIDs: []string{"a"}},
		{ProviderIDs: []string{"p", " p "}},
		{ProviderIDs: []string{"p\x00other"}},
		{ProviderIDs: []string{"p"}, ExcludeProviderIDs: []string{"bad\x00id"}},
		{ProviderIDs: []string{"p"}, ExcludeProtocols: []nodes.Protocol{"ss", " SS "}},
		{ProviderIDs: make([]string, maxFilterValues+1)},
		{IncludeNodeIDs: []string{strings.Repeat("n", 257)}},
		{IncludeNames: []string{"bad\nname"}},
		{IncludeNames: []string{strings.Repeat("n", 513)}},
		{Protocols: []nodes.Protocol{"ss", " SS "}},
		{Protocols: []nodes.Protocol{"ss|trojan"}},
		{Protocols: make([]nodes.Protocol, maxFilterValues+1)},
	}
	for i, filters := range tests {
		if _, err := NewService().Create(Group{Name: "test", GatewayID: "gw", SourceFilters: &filters}); err == nil {
			t.Fatalf("accepted invalid filters case %d", i)
		}
	}
	group := Group{Name: "test", GatewayID: "gw", SourceFilters: &SourceFilters{ProviderIDs: []string{"p"}}}
	good := filterNode("a", "p", "HK", nodes.ProtocolShadowsocks)
	for _, inventory := range [][]nodes.Node{
		{good, good},
		{good, filterNode("a", "other", "Other", nodes.ProtocolTrojan)},
		{filterNode("", "p", "HK", nodes.ProtocolShadowsocks)},
		{filterNode("a", "p\x00other", "HK", nodes.ProtocolShadowsocks)},
	} {
		if _, err := ResolveCandidates(group, inventory); err == nil {
			t.Fatal("accepted invalid candidate inventory")
		}
	}
}

func TestFilterNormalizationAndAllReturnsAreIndependent(t *testing.T) {
	s := NewService()
	input := Group{Name: "test", GatewayID: "gw", SourceFilters: &SourceFilters{
		ProviderIDs: []string{" p2 ", "p1"}, Protocols: []nodes.Protocol{" TROJAN ", "ss"},
		ExcludeProviderIDs: []string{" p3 "}, ExcludeProtocols: []nodes.Protocol{" VMESS "},
		IncludeNodeIDs: []string{" b ", "a"}, ExcludeNodeIDs: []string{" z "},
		IncludeNames: []string{" HK "}, ExcludeNames: []string{" US "},
	}}
	before, _ := json.Marshal(input)
	created, err := s.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(input)
	if !bytes.Equal(before, after) {
		t.Fatal("normalization mutated caller filters")
	}
	if created.SourceFilters.ProviderIDs[0] != "p1" || created.SourceFilters.Protocols[0] != "ss" || created.SourceFilters.IncludeNodeIDs[0] != "a" || created.SourceFilters.IncludeNames[0] != "HK" {
		t.Fatalf("filters were not normalized: %+v", created.SourceFilters)
	}
	mutate := func(group Group) {
		group.SourceFilters.ProviderIDs[0] = "changed"
		group.SourceFilters.Protocols[0] = "changed"
		group.SourceFilters.ExcludeProviderIDs[0] = "changed"
		group.SourceFilters.ExcludeProtocols[0] = "changed"
		group.SourceFilters.IncludeNodeIDs[0] = "changed"
		group.SourceFilters.ExcludeNodeIDs[0] = "changed"
		group.SourceFilters.IncludeNames[0] = "changed"
		group.SourceFilters.ExcludeNames[0] = "changed"
	}
	canonical, _ := json.Marshal(created)
	mutate(input)
	mutate(created)
	fetched, _ := s.Get(created.ID)
	encoded, _ := json.Marshal(fetched)
	if !bytes.Equal(canonical, encoded) {
		t.Fatal("Create shared input or output filters with stored state")
	}
	mutate(fetched)
	mutate(s.List()[0])
	fetched, _ = s.Get(created.ID)
	updated, err := s.Update(fetched, fetched.Revision)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ = json.Marshal(updated)
	mutate(fetched)
	mutate(updated)
	fetched, _ = s.Get(created.ID)
	encoded, _ = json.Marshal(fetched)
	if !bytes.Equal(canonical, encoded) {
		t.Fatal("Get/List/Update shared filter slices")
	}
}

func createFilterGroup(t *testing.T, s *Service, id, provider string, candidates []string, replacement ReplacementPolicy) Group {
	t.Helper()
	group, err := s.Create(Group{ID: id, Name: id, GatewayID: "gw", NodeIDs: candidates, SourceFilters: &SourceFilters{ProviderIDs: []string{provider}}, Replacement: replacement})
	if err != nil {
		t.Fatal(err)
	}
	return group
}

func TestInventoryReconciliationBlocksMissingIntentAndPreservesUnrelatedState(t *testing.T) {
	s := NewService()
	affected := createFilterGroup(t, s, "g1", "p1", []string{"a", "b"}, ReplacementBlock)
	unrelated := createFilterGroup(t, s, "g2", "p2", []string{"z"}, ReplacementBlock)
	_, _ = s.SetDesired(affected.ID, Scope{}, "a", 0)
	_, _ = s.MarkApplied(affected.ID, Scope{}, "a", 7)
	_, _ = s.Observe(affected.ID, Scope{}, "a", 6)
	_, _ = s.SetDesired(affected.ID, Scope{Transport: "udp"}, "b", 0)
	_, _ = s.SetDesired(unrelated.ID, Scope{}, "z", 0)
	unrelatedSelection, _ := s.GetSelection(unrelated.ID, Scope{})
	inventory := []nodes.Node{
		filterNode("c", "p1", "new", nodes.ProtocolShadowsocks),
		filterNode("b", "p1", "retained", nodes.ProtocolShadowsocks),
		filterNode("z", "p2", "unrelated", nodes.ProtocolTrojan),
	}
	before, _ := s.ExportState()
	preview, err := s.PreviewInventory(inventory)
	if err != nil || len(preview) != 1 {
		t.Fatalf("preview: %+v %v", preview, err)
	}
	impact := preview[0]
	if impact.GroupID != affected.ID || impact.ExpectedRevision != affected.Revision || !reflect.DeepEqual(impact.CandidateIDs, []string{"b", "c"}) || !reflect.DeepEqual(impact.AddedNodeIDs, []string{"c"}) || !reflect.DeepEqual(impact.RemovedNodeIDs, []string{"a"}) || !impact.RequiresBlock || impact.RemovalPrevented || len(impact.MissingSelections) != 1 || !impact.MissingSelections[0].Unavailable {
		t.Fatalf("incorrect impact: %+v", impact)
	}
	after, _ := s.ExportState()
	if !bytes.Equal(before, after) {
		t.Fatal("preview mutated controller state")
	}
	if _, err := s.ReconcileInventory(inventory, map[string]int64{affected.ID: affected.Revision}); err != nil {
		t.Fatal(err)
	}
	selected, _ := s.GetSelection(affected.ID, Scope{})
	if !selected.Unavailable || selected.DesiredNodeID != "a" || selected.AppliedNodeID != "a" || selected.ObservedNodeID != "a" || selected.AppliedGeneration != 7 || selected.ObservedGeneration != 6 {
		t.Fatalf("missing node discarded intent or runtime evidence: %+v", selected)
	}
	group, _ := s.Get(unrelated.ID)
	selection, _ := s.GetSelection(unrelated.ID, Scope{})
	if !reflect.DeepEqual(group, unrelated) || selection != unrelatedSelection {
		t.Fatal("provider refresh changed unrelated group")
	}
	group, _ = s.Get(affected.ID)
	if group.SourceFilters.ProviderIDs[0] != "p1" || group.Revision != affected.Revision+1 {
		t.Fatal("candidate refresh lost persisted source filters")
	}
	before, _ = s.ExportState()
	noChanges, err := s.ReconcileInventory(inventory, nil)
	after, _ = s.ExportState()
	if err != nil || len(noChanges) != 0 || !bytes.Equal(before, after) {
		t.Fatalf("no-op refresh mutated state: %+v %v", noChanges, err)
	}
	inventory = append(inventory, filterNode("a", "p1", "returned", nodes.ProtocolShadowsocks))
	if _, err := s.ReconcileInventory(inventory, map[string]int64{group.ID: group.Revision}); err != nil {
		t.Fatal(err)
	}
	selected, _ = s.GetSelection(group.ID, Scope{})
	if selected.Unavailable || selected.DesiredNodeID != "a" || selected.AppliedGeneration != 7 {
		t.Fatalf("reappearing node did not recover original intent: %+v", selected)
	}
}

func TestReconcileAllRevisionAndReplacementChecksAreAtomic(t *testing.T) {
	for _, test := range []struct {
		name     string
		none     bool
		expected map[string]int64
	}{
		{"missing revision", false, map[string]int64{"a": 1}},
		{"stale revision", false, map[string]int64{"a": 1, "z": 2}},
		{"unknown fenced group", false, map[string]int64{"a": 1, "z": 1, "unknown": 1}},
		{"replacement prevents removal", true, map[string]int64{"a": 1, "z": 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := NewService()
			createFilterGroup(t, s, "a", "p1", []string{"n1"}, ReplacementBlock)
			replacement := ReplacementBlock
			if test.none {
				replacement = ReplacementNone
			}
			createFilterGroup(t, s, "z", "p2", []string{"n2"}, replacement)
			_, _ = s.SetDesired("z", Scope{}, "n2", 0)
			before, _ := s.ExportState()
			impacts, err := s.ReconcileInventory(nil, test.expected)
			if err == nil || len(impacts) != 2 {
				t.Fatalf("invalid reconcile accepted: %+v %v", impacts, err)
			}
			if !test.none && !errors.Is(err, domain.ErrConflict) {
				t.Fatalf("precondition error=%v", err)
			}
			if test.none && !impacts[1].RemovalPrevented {
				t.Fatal("impact omitted replacement blocker")
			}
			after, _ := s.ExportState()
			if !bytes.Equal(before, after) {
				t.Fatal("rejected inventory reconciliation partially changed groups")
			}
		})
	}
}

func TestPreviewReportsMissingRuntimeReferenceEvenWhenDesiredNodeSurvives(t *testing.T) {
	s := NewService()
	group := createFilterGroup(t, s, "g", "p", []string{"a", "b"}, ReplacementBlock)
	_, _ = s.SetDesired(group.ID, Scope{}, "b", 0)
	_, _ = s.MarkApplied(group.ID, Scope{}, "a", 7)
	impacts, err := s.PreviewInventory([]nodes.Node{filterNode("b", "p", "retained", nodes.ProtocolTrojan)})
	if err != nil || len(impacts) != 1 || len(impacts[0].MissingSelections) != 1 || impacts[0].MissingSelections[0].Unavailable || impacts[0].RequiresBlock {
		t.Fatalf("runtime evidence must remain distinct from desired availability: %+v %v", impacts, err)
	}
}

func TestNameOnlyInventoryRenameCanChangeCandidateMembership(t *testing.T) {
	s := NewService()
	group, err := s.Create(Group{ID: "g", Name: "g", GatewayID: "gw", NodeIDs: []string{"a"}, SourceFilters: &SourceFilters{ProviderIDs: []string{"p"}, IncludeNames: []string{"HK"}}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.SetDesired(group.ID, Scope{}, "a", 0)
	impacts, err := s.ReconcileInventory([]nodes.Node{filterNode("a", "p", "US", nodes.ProtocolShadowsocks)}, map[string]int64{group.ID: group.Revision})
	if err != nil || len(impacts) != 1 || !impacts[0].RequiresBlock || len(impacts[0].CandidateIDs) != 0 {
		t.Fatalf("name-only rename bypassed filter: %+v %v", impacts, err)
	}
	if _, err := s.Candidates(group.ID); !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("empty filter membership introduced fallback: %v", err)
	}
}

func TestConcurrentInventoryReconciliationHasOneWinner(t *testing.T) {
	s := NewService()
	group := createFilterGroup(t, s, "g", "p", []string{"a"}, ReplacementBlock)
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, id := range []string{"b", "c"} {
		workers.Add(1)
		go func(id string) {
			defer workers.Done()
			<-start
			_, err := s.ReconcileInventory([]nodes.Node{filterNode(id, "p", id, nodes.ProtocolShadowsocks)}, map[string]int64{group.ID: group.Revision})
			results <- err
		}(id)
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
	if winners != 1 || conflicts != 1 {
		t.Fatalf("winners=%d conflicts=%d", winners, conflicts)
	}
}

func TestFilterSnapshotsRetainVersionOneCompatibilityAndValidateAtomically(t *testing.T) {
	legacy := NewService()
	_, _ = legacy.Create(Group{ID: "legacy", Name: "legacy", GatewayID: "gw", NodeIDs: []string{"a"}})
	oldSnapshot, _ := legacy.ExportState()
	if bytes.Contains(oldSnapshot, []byte("source_filters")) {
		t.Fatal("legacy snapshot acquired a filter")
	}
	restarted := NewService()
	if err := restarted.ImportState(oldSnapshot); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(legacy.List(), restarted.List()) {
		t.Fatal("legacy snapshot changed explicit candidates")
	}
	group := createFilterGroup(t, restarted, "filtered", "p", []string{"a"}, ReplacementBlock)
	_, _ = restarted.SetDesired(group.ID, Scope{}, "a", 0)
	_, _ = restarted.ReconcileInventory(nil, map[string]int64{group.ID: group.Revision, "legacy": 1})
	encoded, _ := restarted.ExportState()
	restored := NewService()
	if err := restored.ImportState(encoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored.List(), restarted.List()) || !reflect.DeepEqual(restored.Selections(group.ID), restarted.Selections(group.ID)) {
		t.Fatal("filter snapshot lost filters or unavailable selection state")
	}
	var corrupt stateSnapshot
	if err := json.Unmarshal(encoded, &corrupt); err != nil {
		t.Fatal(err)
	}
	corrupt.Groups[0].SourceFilters = &SourceFilters{ProviderIDs: []string{"p", "p"}}
	bad, _ := json.Marshal(corrupt)
	if err := restored.ImportState(bad); err == nil {
		t.Fatal("accepted invalid snapshot filters")
	}
	after, _ := restored.ExportState()
	if !bytes.Equal(encoded, after) {
		t.Fatal("invalid snapshot changed persisted filters")
	}
}
