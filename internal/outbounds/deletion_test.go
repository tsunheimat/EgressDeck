package outbounds

import (
	"errors"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

func TestDeleteRequiresCASNoReferencesAndNoRuntimeIntent(t *testing.T) {
	s := NewService()
	g, err := s.Create(Group{Name: "group", GatewayID: "gateway", NodeIDs: []string{"node"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, revision := range []int64{0, g.Revision + 1} {
		if err := s.Delete(g.ID, revision, nil); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("revision %d accepted: %v", revision, err)
		}
	}
	if err := s.Delete(g.ID, g.Revision, []string{"policy-one"}); !errors.Is(err, ErrGroupReferenced) {
		t.Fatalf("referenced deletion: %v", err)
	}
	if _, err := s.Get(g.ID); err != nil {
		t.Fatal("rejected deletion mutated group")
	}
	if _, err := s.SetDesired(g.ID, Scope{}, "node", 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(g.ID, g.Revision, nil); !errors.Is(err, ErrGroupInUse) {
		t.Fatalf("intent deletion: %v", err)
	}
	other, err := s.Create(Group{Name: "unused", GatewayID: "gateway"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(other.ID, other.Revision, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(other.ID); !errors.Is(err, ErrGroupNotFound) {
		t.Fatalf("deleted group returned: %v", err)
	}
}
