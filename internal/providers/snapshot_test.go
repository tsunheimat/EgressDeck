package providers

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
)

func TestPrivateRegistrySnapshotPreservesCredentialsIDsAndLifecycle(t *testing.T) {
	r := NewRegistry(DefaultLimits(), nil)
	n, err := nodes.New("p", "first", nodes.Definition{Protocol: nodes.ProtocolTrojan, Host: "example.org", Port: 443, Username: "user", Password: "password", UUID: "credential-uuid", ALPN: []string{"h2", "http/1.1"}, Headers: map[string]string{"Authorization": "secret-header"}, Extra: map[string]string{"private-token": "secret-extra"}}, "trusted-provider-id")
	if err != nil {
		t.Fatal(err)
	}
	s := r.state("p")
	first, _, err := stageParsed(s, Parsed{ProviderID: "p", ContentHash: "first-hash", Nodes: []nodes.Node{n}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Publish("p", first.Number, 0); err != nil {
		t.Fatal(err)
	}
	next, err := nodes.New("p", "second", nodes.Definition{Protocol: nodes.ProtocolTrojan, Host: "example.org", Port: 443, Password: "rotated"}, "trusted-provider-id")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := stageParsed(s, Parsed{ProviderID: "p", ContentHash: "second-hash", Nodes: []nodes.Node{next}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Nodes[0].ID != first.Nodes[0].ID || second.Nodes[0].Revision != 2 {
		t.Fatal("trusted stable identity was not reconciled")
	}
	raw, err := r.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	fetchCalls := 0
	restored := NewRegistry(DefaultLimits(), func(context.Context, domain.Provider) ([]byte, error) {
		fetchCalls++
		return []byte("trojan://fresh@example.net:443#fresh"), nil
	})
	if err := restored.ImportState(raw); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.List("p"), restored.List("p")) || !reflect.DeepEqual(r.Status("p"), restored.Status("p")) {
		t.Fatal("private snapshot roundtrip lost revision state, node credentials, or public IDs")
	}
	active, err := restored.Active("p")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(active.Nodes[0].Definition, n.Definition) {
		t.Fatal("private connection definition was not restored")
	}
	if _, err := restored.Publish("p", second.Number, first.Number); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restored.Refresh(context.Background(), domain.Provider{ID: "p"}, FormatLinks); err != nil || fetchCalls != 1 {
		t.Fatal("restore replaced configured provider fetcher")
	}
}

func TestPrivateRegistrySnapshotInvalidImportIsAtomic(t *testing.T) {
	r := NewRegistry(DefaultLimits(), nil)
	first, _, err := r.Stage("p", []byte("trojan://secret@example.org:443#one"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Publish("p", first.Number, 0); err != nil {
		t.Fatal(err)
	}
	original, err := r.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*registrySnapshot){
		"invalid pointer":     func(in *registrySnapshot) { p := in.Providers["p"]; p.Status.Active = 900; in.Providers["p"] = p },
		"unreferenced active": func(in *registrySnapshot) { p := in.Providers["p"]; p.Status.Active = 0; in.Providers["p"] = p },
		"missing private credential": func(in *registrySnapshot) {
			p := in.Providers["p"]
			p.Revisions[0].Nodes = []byte(`{"version":1,"nodes":[]}`)
			in.Providers["p"] = p
		},
		"mismatched provider": func(in *registrySnapshot) {
			p := in.Providers["p"]
			p.Revisions[0].ProviderID = "elsewhere"
			in.Providers["p"] = p
		},
		"duplicate revision": func(in *registrySnapshot) {
			p := in.Providers["p"]
			p.Revisions = append(p.Revisions, p.Revisions[0])
			in.Providers["p"] = p
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var in registrySnapshot
			if err := json.Unmarshal(original, &in); err != nil {
				t.Fatal(err)
			}
			mutate(&in)
			bad, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.ImportState(bad); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
			after, err := r.ExportState()
			if err != nil || string(after) != string(original) {
				t.Fatal("rejected import changed live inventory")
			}
		})
	}
}
