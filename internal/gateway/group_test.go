package gateway

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestGroupPublicationKeepsProviderRevisionAndConnections(t *testing.T) {
	ctx := context.Background()
	journal := NewMemoryJournal()
	e := NewFakeEngine(journal)
	p := ProviderRevision{ProviderID: "p", Revision: 7, ContentHash: "same-connections", Nodes: []Node{{ID: "a", ProviderID: "p"}, {ID: "b", ProviderID: "p"}}, Groups: []PublicationGroup{{ID: "g", Name: "managed", Revision: 2, CandidateIDs: []string{"a", "b"}, SelectedNodeID: "a"}}}
	stage, err := e.StageProvider(ctx, p, 0)
	if err != nil {
		t.Fatal(err)
	}
	before, err := e.PublishProvider(ctx, stage)
	if err != nil {
		t.Fatal(err)
	}
	e.AddGroup(OutboundGroup{ID: "g", Name: "managed", Revision: 2, ProviderIDs: []string{"p"}, NodeIDs: []string{"a", "b"}})
	e.AddGroup(OutboundGroup{ID: "unrelated", Revision: 19, NodeIDs: []string{"a"}})
	e.AddConnection(Connection{ID: "old-session", GroupID: "g", ProviderID: "p", NodeID: "b", Transport: "tcp"})
	publish := GroupPublication{ProviderID: "p", ProviderRevision: 7, Group: PublicationGroup{ID: "g", Name: "managed", Revision: 3, CandidateIDs: []string{"a"}, SelectedNodeID: "a"}}
	got, err := e.PublishGroup(ctx, publish, before.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if got.Generation != before.Generation+1 || got.Providers["p"].Revision != 7 || got.Providers["p"].ContentHash != "same-connections" || !reflect.DeepEqual(before.Providers["p"].Nodes, got.Providers["p"].Nodes) {
		t.Fatalf("group publication changed provider definitions: %#v", got)
	}
	if got.Groups["g"].Revision != 3 || !reflect.DeepEqual(got.Groups["g"].NodeIDs, []string{"a"}) || got.Groups["unrelated"].Revision != 19 || len(got.Connections) != 1 || got.Connections[0].NodeID != "b" {
		t.Fatalf("group publication changed unrelated/retained state: %#v", got)
	}
	if _, err := e.SetRuntimeSelection(ctx, SelectionScope{GatewayID: "gw", GroupID: "g", Transport: "both"}, "a", 0); err != nil {
		t.Fatalf("selection after unchanged-provider group apply: %v", err)
	}
	restarted := NewFakeEngine(journal)
	restored, _ := restarted.Inventory(ctx)
	if restored.Groups["g"].Revision != 3 || !reflect.DeepEqual(restored.Groups["g"].NodeIDs, []string{"a"}) || restored.Providers["p"].Revision != 7 {
		t.Fatalf("group did not survive journal restart: %#v", restored)
	}
}

func TestGroupPublicationRejectsInvalidOrStaleCandidatesBeforeMutation(t *testing.T) {
	ctx := context.Background()
	e := NewFakeEngine()
	p := ProviderRevision{ProviderID: "p", Revision: 7, Nodes: []Node{{ID: "a"}, {ID: "b"}}, Groups: []PublicationGroup{{ID: "g", Name: "managed", Revision: 2, CandidateIDs: []string{"a", "b"}, SelectedNodeID: "a"}}}
	stage, _ := e.StageProvider(ctx, p, 0)
	before, _ := e.PublishProvider(ctx, stage)
	base := GroupPublication{ProviderID: "p", ProviderRevision: 7, Group: PublicationGroup{ID: "g", Name: "managed", Revision: 3, CandidateIDs: []string{"a"}, SelectedNodeID: "a"}}
	for _, test := range []struct {
		name   string
		mutate func(*GroupPublication, *int64)
		cause  error
	}{
		{"generation", func(_ *GroupPublication, expected *int64) { *expected = 0 }, ErrConflict},
		{"provider revision", func(p *GroupPublication, _ *int64) { p.ProviderRevision = 6 }, ErrConflict},
		{"group revision", func(p *GroupPublication, _ *int64) { p.Group.Revision = 2 }, ErrConflict},
		{"unknown member", func(p *GroupPublication, _ *int64) {
			p.Group.CandidateIDs = []string{"foreign"}
			p.Group.SelectedNodeID = "foreign"
		}, ErrInvalidRevision},
		{"removed selection", func(p *GroupPublication, _ *int64) { p.Group.SelectedNodeID = "b" }, ErrSelection},
	} {
		t.Run(test.name, func(t *testing.T) {
			publication, generation := base.clone(), before.Generation
			test.mutate(&publication, &generation)
			if _, err := e.PublishGroup(ctx, publication, generation); !errors.Is(err, test.cause) {
				t.Fatalf("got %v, want %v", err, test.cause)
			}
			got, _ := e.Inventory(ctx)
			if !reflect.DeepEqual(got, before) {
				t.Fatal("rejected group publication mutated inventory")
			}
		})
	}
}
