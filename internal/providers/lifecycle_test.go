package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistryPreservesActiveOnBadStageAndPublishesExplicitly(t *testing.T) {
	r := NewRegistry(DefaultLimits(), nil)
	first, _, err := r.Stage("p", []byte("trojan://secret@example.org:443#one"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Publish("p", first.Number, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Stage("p", []byte("not-a-node"), FormatLinks); err == nil {
		t.Fatal("bad stage accepted")
	}
	active, err := r.Active("p")
	if err != nil || active.Number != first.Number {
		t.Fatalf("active lost after bad stage: %#v %v", active, err)
	}
	second, _, err := r.Stage("p", []byte("trojan://secret@example.org:443#two\nss://aes-128-gcm:pass@example.net:8388#three"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Publish("p", second.Number, first.Number+1); err == nil {
		t.Fatal("stale expected generation accepted")
	}
	if _, err := r.Publish("p", second.Number, first.Number); err != nil {
		t.Fatal(err)
	}
	third, _, err := r.Stage("p", []byte("trojan://other@example.org:443#three"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	fourth, _, err := r.Stage("p", []byte("trojan://fourth@example.org:443#four"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Publish("p", third.Number, second.Number); err == nil {
		t.Fatal("superseded staged revision published")
	}
	if _, err := r.Publish("p", fourth.Number, second.Number); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshSerializesAndUsesFetcher(t *testing.T) {
	calls := 0
	r := NewRegistry(DefaultLimits(), func(_ context.Context, p domain.Provider) ([]byte, error) {
		calls++
		return []byte("vless://u@example.com:443#n"), nil
	})
	p := domain.Provider{ID: "p", Name: "p", Source: "https://example.invalid"}
	if _, _, err := r.Refresh(context.Background(), p, FormatAuto); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("fetch calls=%d", calls)
	}
}

func TestRegistryReconcilesRandomIDsAndKeepsRenamedInventory(t *testing.T) {
	r := NewRegistry(DefaultLimits(), nil)
	first, changes, err := r.Stage("p", []byte("trojan://secret@example.org:443#one"), FormatLinks)
	if err != nil || len(changes.Added) != 1 {
		t.Fatalf("first: %+v %v", changes, err)
	}
	if _, err := r.Publish("p", first.Number, 0); err != nil {
		t.Fatal(err)
	}
	renamed, changes, err := r.Stage("p", []byte("trojan://secret@example.org:443#renamed"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if !changes.Noop || len(changes.Renamed) != 1 || renamed.Number != first.Number || renamed.Nodes[0].ID != first.Nodes[0].ID || renamed.Nodes[0].Revision != first.Nodes[0].Revision {
		t.Fatalf("rename created new runtime identity: %+v %+v", renamed, changes)
	}
	active, _ := r.Active("p")
	if active.Nodes[0].Name != "renamed" || r.Status("p").Staged != 0 {
		t.Fatal("renamed inventory was not retained")
	}
	changed, changes, err := r.Stage("p", []byte("trojan://secret@example.org:443#again\ntrojan://other@example.net:443#two"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Nodes[0].ID != first.Nodes[0].ID || len(changes.Added) != 1 {
		t.Fatal("unchanged node lost its identity")
	}
}

func TestRegistryRotationRequiresApprovalAndDoesNotClaimContinuity(t *testing.T) {
	r := NewRegistry(DefaultLimits(), nil)
	first, _, err := r.Stage("p", []byte("trojan://secret@example.org:443#one"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Publish("p", first.Number, 0); err != nil {
		t.Fatal(err)
	}
	rotated, changes, err := r.Stage("p", []byte("trojan://replacement@example.org:443#one"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Ambiguous) != 1 || len(changes.Added) != 1 || len(changes.Removed) != 1 || len(changes.Changed) != 0 || rotated.Nodes[0].ID == first.Nodes[0].ID || !rotated.RequiresApproval() {
		t.Fatalf("rotation silently claimed continuity: %+v", changes)
	}
	repeated, noop, err := r.Stage("p", []byte("trojan://replacement@example.org:443#renamed"), FormatLinks)
	if err != nil || !noop.Noop || !repeated.RequiresApproval() {
		t.Fatal("repeated stage lost the ambiguity protection")
	}
	changes.Ambiguous[0].PreviousNodeIDs[0] = "mutated"
	stored, _ := r.Get("p", rotated.Number)
	if stored.Changes.Ambiguous[0].PreviousNodeIDs[0] != first.Nodes[0].ID {
		t.Fatal("caller mutated retained ambiguity")
	}
	public, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{stored.Hash, stored.Nodes[0].Identity, stored.Nodes[0].ContentHash, "replacement"} {
		if strings.Contains(string(public), secret) {
			t.Fatalf("public revision exposes private credential material: %s", secret)
		}
	}
}

func TestRegistryExactCASIncludesZeroAndIdempotentPublish(t *testing.T) {
	r := NewRegistry(DefaultLimits(), nil)
	first, _, _ := r.Stage("p", []byte("trojan://secret@example.org:443#one"), FormatLinks)
	if _, err := r.Publish("p", first.Number, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Publish("p", first.Number, 0); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale retry accepted: %v", err)
	}
	if _, err := r.Publish("p", first.Number, first.Number); err != nil {
		t.Fatal(err)
	}
	next, _, _ := r.Stage("p", []byte("trojan://secret@example.net:443#two"), FormatLinks)
	if _, err := r.Publish("p", next.Number, 0); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("zero bypassed CAS: %v", err)
	}
	active, _ := r.Active("p")
	if active.Number != first.Number {
		t.Fatal("stale publish changed active revision")
	}
}

func TestRegistryReadAndWriteBoundariesDeepClone(t *testing.T) {
	r := NewRegistry(DefaultLimits(), nil)
	n, err := nodes.New("p", "one", nodes.Definition{Protocol: nodes.ProtocolTrojan, Host: "example.org", Port: 443, Password: "secret", ALPN: []string{"h2"}, Headers: map[string]string{"Auth": "secret"}, Extra: map[string]string{"opaque": "secret"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	parsed := Parsed{ProviderID: "p", ContentHash: "hash", Nodes: []nodes.Node{n}}
	s := r.state("p")
	first, _, err := stageParsed(s, parsed, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Nodes[0].Definition.Headers["Auth"] = "input mutation"
	first.Nodes[0].Definition.ALPN[0] = "mutated"
	first.Nodes[0].Definition.Headers["Auth"] = "mutated"
	first.Nodes[0].Definition.Extra["opaque"] = "mutated"
	stored, _ := r.Get("p", first.Number)
	if !reflect.DeepEqual(stored.Nodes[0].Definition.ALPN, []string{"h2"}) || stored.Nodes[0].Definition.Headers["Auth"] != "secret" || stored.Nodes[0].Definition.Extra["opaque"] != "secret" {
		t.Fatal("mutable node data crossed registry boundary")
	}
	active, err := r.Publish("p", first.Number, 0)
	if err != nil {
		t.Fatal(err)
	}
	original := *active.PublishedAt
	*active.PublishedAt = time.Time{}
	reread, _ := r.Active("p")
	if !reread.PublishedAt.Equal(original) {
		t.Fatal("timestamp pointer leaked")
	}
}

// observedContext makes the duplicate caller's arrival at the singleflight
// wait observable without a timing sleep or a production-only testing hook.
type observedContext struct {
	context.Context
	waiting chan struct{}
}

func (c observedContext) Done() <-chan struct{} { close(c.waiting); return c.Context.Done() }

func TestRefreshCoalescesInFlightRequestsAndUpdatesNoopSuccess(t *testing.T) {
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	r := NewRegistry(DefaultLimits(), func(context.Context, domain.Provider) ([]byte, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return []byte("trojan://secret@example.org:443#one"), nil
	})
	provider := domain.Provider{ID: "p"}
	type result struct {
		revision Revision
		changes  ChangeReport
		err      error
	}
	results := make(chan result, 2)
	go func() {
		rev, changes, err := r.Refresh(context.Background(), provider, FormatLinks)
		results <- result{rev, changes, err}
	}()
	<-started
	waiting := make(chan struct{})
	go func() {
		rev, changes, err := r.Refresh(observedContext{context.Background(), waiting}, provider, FormatLinks)
		results <- result{rev, changes, err}
	}()
	<-waiting
	if status := r.Status("p"); status.LastAttemptAt == nil || status.LastSuccessAt != nil {
		t.Fatal("fetch status does not distinguish in-flight attempt")
	}
	close(release)
	one, two := <-results, <-results
	if one.err != nil || two.err != nil || calls.Load() != 1 || !reflect.DeepEqual(one, two) {
		t.Fatalf("duplicate fetch was not coalesced: calls=%d errors=%v,%v", calls.Load(), one.err, two.err)
	}
	old := time.Unix(1, 0)
	state := r.state("p")
	state.status.LastSuccessAt = &old
	_, changes, err := r.Refresh(context.Background(), provider, FormatLinks)
	if err != nil || !changes.Noop || calls.Load() != 2 {
		t.Fatalf("sequential refresh unexpectedly reused old request: %+v %v", changes, err)
	}
	if status := r.Status("p"); status.LastSuccessAt == nil || !status.LastSuccessAt.After(old) {
		t.Fatal("successful no-op did not advance success timestamp")
	}
}

func TestRefreshRedactsFetchErrorsAndKeepsLastSuccess(t *testing.T) {
	fail := false
	r := NewRegistry(DefaultLimits(), func(context.Context, domain.Provider) ([]byte, error) {
		if fail {
			return nil, errors.New("https://user:password@example.org/?token=private")
		}
		return []byte("trojan://secret@example.org:443#one"), nil
	})
	provider := domain.Provider{ID: "p"}
	first, _, err := r.Refresh(context.Background(), provider, FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Publish("p", first.Number, 0); err != nil {
		t.Fatal(err)
	}
	previous := r.Status("p")
	fail = true
	_, _, err = r.Refresh(context.Background(), provider, FormatLinks)
	if !errors.Is(err, ErrFetch) || strings.Contains(err.Error(), "password") {
		t.Fatalf("fetch error leaked credentials: %v", err)
	}
	status := r.Status("p")
	if status.LastError != ErrFetch.Error() || !status.LastSuccessAt.Equal(*previous.LastSuccessAt) || !status.LastAttemptAt.After(*previous.LastAttemptAt) {
		t.Fatalf("failed refresh damaged status: %+v", status)
	}
	active, _ := r.Active("p")
	if active.Number != first.Number {
		t.Fatal("failed refresh replaced active")
	}
}

func TestRegistryBoundsRetentionWithoutDeletingReferencedHistory(t *testing.T) {
	r := NewRegistry(DefaultLimits(), nil)
	first, _, err := r.Stage("p", []byte("trojan://secret@example.org:443#one"), FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Publish("p", first.Number, 0); err != nil {
		t.Fatal(err)
	}
	var newest Revision
	for i := 1; i < RetainedRevisionLimit; i++ {
		newest, _, err = r.Stage("p", []byte(fmt.Sprintf("trojan://secret@example-%d.org:443#node", i)), FormatLinks)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := r.Stage("p", []byte("trojan://secret@overflow.org:443#overflow"), FormatLinks); !errors.Is(err, ErrRevisionCapacity) {
		t.Fatalf("retention limit bypassed: %v", err)
	}
	status := r.Status("p")
	if len(r.List("p")) != RetainedRevisionLimit || status.Active != first.Number || status.Staged != newest.Number {
		t.Fatal("capacity failure deleted referenced history or changed lifecycle state")
	}
	if _, changes, err := r.Stage("p", []byte("trojan://secret@example.org:443#rename"), FormatLinks); err != nil || !changes.Noop {
		t.Fatalf("capacity blocked safe metadata no-op: %v", err)
	}
}
