package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func testMutationIdentity() MutationIdentity {
	return MutationIdentity{ID: "operation-1", RequestHash: strings.Repeat("a", 64), TargetKind: "outbound_group", TargetID: "group-1", FenceToken: 7}
}

func TestMutationIdentityValidationAndContext(t *testing.T) {
	valid := testMutationIdentity()
	if !valid.Valid() {
		t.Fatal(valid.Validate())
	}
	ctx := WithMutationIdentity(context.Background(), valid)
	if actual, ok := MutationIdentityFromContext(ctx); !ok || actual != valid {
		t.Fatalf("identity not retained: %+v, %v", actual, ok)
	}
	for _, change := range []func(*MutationIdentity){
		func(i *MutationIdentity) { i.ID = "bad/id" },
		func(i *MutationIdentity) { i.ID = "." },
		func(i *MutationIdentity) { i.ID = ".." },
		func(i *MutationIdentity) { i.ID = "bad\r\nheader" },
		func(i *MutationIdentity) { i.ID = strings.Repeat("a", 257) },
		func(i *MutationIdentity) { i.TargetID = "" },
		func(i *MutationIdentity) { i.TargetKind = " " },
		func(i *MutationIdentity) { i.RequestHash = "hash" },
		func(i *MutationIdentity) { i.RequestHash = strings.Repeat("A", 64) },
		func(i *MutationIdentity) { i.RequestHash = strings.Repeat("g", 64) },
		func(i *MutationIdentity) { i.FenceToken = 0 },
	} {
		invalid := valid
		change(&invalid)
		if invalid.Valid() {
			t.Fatalf("invalid identity accepted: %+v", invalid)
		}
	}
}

func assertMutationHeaders(t *testing.T, r *http.Request, identity MutationIdentity) {
	t.Helper()
	want := map[string]string{
		"X-EgressDeck-Mutation-ID":          identity.ID,
		"X-EgressDeck-Mutation-Hash":        identity.RequestHash,
		"X-EgressDeck-Mutation-Target-Kind": identity.TargetKind,
		"X-EgressDeck-Mutation-Target-ID":   identity.TargetID,
		"X-EgressDeck-Mutation-Fence":       "7",
	}
	for key, value := range want {
		if r.Header.Get(key) != value || len(r.Header.Values(key)) != 1 {
			t.Errorf("%s = %v, want one %q", key, r.Header.Values(key), value)
		}
	}
}

func TestClientMutationIdentitySurvivesAuthenticatedSelectionTransport(t *testing.T) {
	identity := testMutationIdentity()
	scope := SelectionScope{GroupID: "group-1", Transport: "tcp"}
	_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertMutationHeaders(t, r, identity)
		clientTestJSON(t, w, http.StatusOK, Selection{Scope: scope, DesiredNodeID: "node-1", ObservedNodeID: "node-1", Revision: 2})
	}))
	client := clientTestClient(t, options)
	if _, err := client.SetRuntimeSelection(WithMutationIdentity(context.Background(), identity), scope, "node-1", 1); err != nil {
		t.Fatal(err)
	}
}

func TestClientMutationStatusAndResolveUseExactIdentity(t *testing.T) {
	identity := testMutationIdentity()
	var count atomic.Int64
	_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		assertMutationHeaders(t, r, identity)
		state := MutationUnknown
		if r.URL.Path == "/v1/mutations/operation-1/resolve" {
			if r.Method != http.MethodPost {
				t.Error("resolution must use POST")
			}
			state = MutationRejected
		} else if r.URL.Path != "/v1/mutations/operation-1" || r.Method != http.MethodGet {
			t.Errorf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		clientTestJSON(t, w, http.StatusOK, MutationReceipt{Identity: identity, State: state, Generation: 4})
	}))
	client := clientTestClient(t, options)
	status, err := client.MutationStatus(context.Background(), identity)
	if err != nil || status.State != MutationUnknown {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	status, err = client.ResolveMutation(context.Background(), identity)
	if err != nil || status.State != MutationRejected {
		t.Fatalf("resolve=%+v err=%v", status, err)
	}
	if count.Load() != 2 {
		t.Fatalf("requests=%d", count.Load())
	}
}

func TestClientMutationReceiptMismatchRemainsUncertain(t *testing.T) {
	identity := testMutationIdentity()
	for _, test := range []struct {
		name   string
		change func(*MutationReceipt)
	}{
		{"different identity", func(r *MutationReceipt) { r.Identity.ID = "other" }},
		{"different fence", func(r *MutationReceipt) { r.Identity.FenceToken++ }},
		{"different request", func(r *MutationReceipt) { r.Identity.RequestHash = strings.Repeat("b", 64) }},
		{"invalid state", func(r *MutationReceipt) { r.State = "not_started" }},
		{"invalid generation", func(r *MutationReceipt) { r.Generation = -1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receipt := MutationReceipt{Identity: identity, State: MutationRejected}
				test.change(&receipt)
				clientTestJSON(t, w, http.StatusOK, receipt)
			}))
			client := clientTestClient(t, options)
			if _, err := client.MutationStatus(context.Background(), identity); !errors.Is(err, ErrProtocol) {
				t.Fatalf("status err=%v", err)
			}
			if _, err := client.ResolveMutation(context.Background(), identity); !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("resolve err=%v", err)
			}
		})
	}
}

func TestClientRejectsInvalidMutationBeforeTransmission(t *testing.T) {
	var count atomic.Int64
	_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); w.WriteHeader(http.StatusNoContent) }))
	client := clientTestClient(t, options)
	invalid := testMutationIdentity()
	invalid.ID = "bad\r\nheader"
	if _, err := client.MutationStatus(context.Background(), invalid); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if _, err := client.ResolveMutation(context.Background(), invalid); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if _, err := client.SetRuntimeSelection(WithMutationIdentity(context.Background(), invalid), SelectionScope{GroupID: "g", Transport: "tcp"}, "n", 0); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if count.Load() != 0 {
		t.Fatalf("invalid identity reached server: %d", count.Load())
	}
}

func TestClientDefiniteRejectionRequiresMatchingAuthenticatedProof(t *testing.T) {
	identity := testMutationIdentity()
	for _, test := range []struct {
		name     string
		proof    bool
		mutate   func(*MutationIdentity)
		definite bool
	}{
		{"exact proof", true, nil, true},
		{"generic conflict", false, nil, false},
		{"other id", true, func(i *MutationIdentity) { i.ID = "other" }, false},
		{"other hash", true, func(i *MutationIdentity) { i.RequestHash = strings.Repeat("b", 64) }, false},
		{"other target", true, func(i *MutationIdentity) { i.TargetID = "other" }, false},
		{"other fence", true, func(i *MutationIdentity) { i.FenceToken++ }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proofIdentity := identity
				if test.mutate != nil {
					test.mutate(&proofIdentity)
				}
				clientTestJSON(t, w, http.StatusConflict, map[string]any{"rejected_before_mutation": test.proof, "mutation_identity": proofIdentity})
			}))
			client := clientTestClient(t, options)
			_, err := client.SetRuntimeSelection(WithMutationIdentity(context.Background(), identity), SelectionScope{GroupID: "g", Transport: "tcp"}, "n", 0)
			if !errors.Is(err, ErrConflict) || IsDefiniteRejection(err) != test.definite {
				t.Fatalf("err=%v definitive=%v", err, IsDefiniteRejection(err))
			}
		})
	}
}
