package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

type mutationAgentEngine struct {
	gateway.Engine
	seen  gateway.MutationIdentity
	calls int
	state gateway.MutationState
	err   error
}

func (e *mutationAgentEngine) MutationStatus(ctx context.Context, identity gateway.MutationIdentity) (gateway.MutationReceipt, error) {
	e.calls++
	e.seen, _ = gateway.MutationIdentityFromContext(ctx)
	return gateway.MutationReceipt{Identity: identity, State: e.state, Generation: 4}, e.err
}

func (e *mutationAgentEngine) ResolveMutation(ctx context.Context, identity gateway.MutationIdentity) (gateway.MutationReceipt, error) {
	return e.MutationStatus(ctx, identity)
}

func (e *mutationAgentEngine) SetRuntimeSelection(ctx context.Context, scope gateway.SelectionScope, node string, expected int64) (gateway.Selection, error) {
	e.calls++
	e.seen, _ = gateway.MutationIdentityFromContext(ctx)
	return gateway.Selection{}, e.err
}

func agentMutationIdentity() gateway.MutationIdentity {
	return gateway.MutationIdentity{ID: "operation-1", RequestHash: strings.Repeat("a", 64), TargetKind: "outbound_group", TargetID: "group-1", FenceToken: 7}
}

func addAgentMutationHeaders(r *http.Request) {
	identity := agentMutationIdentity()
	r.Header.Set("X-EgressDeck-Mutation-ID", identity.ID)
	r.Header.Set("X-EgressDeck-Mutation-Hash", identity.RequestHash)
	r.Header.Set("X-EgressDeck-Mutation-Target-Kind", identity.TargetKind)
	r.Header.Set("X-EgressDeck-Mutation-Target-ID", identity.TargetID)
	r.Header.Set("X-EgressDeck-Mutation-Fence", "7")
}

func TestAgentMutationRoutesRequireMatchingAuthenticatedIdentity(t *testing.T) {
	for _, test := range []struct {
		name, method, path string
		auth, headers      bool
		change             func(*http.Request)
		want               int
	}{
		{"status", http.MethodGet, "/v1/mutations/operation-1", true, true, nil, 200},
		{"resolve", http.MethodPost, "/v1/mutations/operation-1/resolve", true, true, nil, 200},
		{"unauthenticated", http.MethodGet, "/v1/mutations/operation-1", false, true, nil, 401},
		{"missing identity", http.MethodGet, "/v1/mutations/operation-1", true, false, nil, 400},
		{"wrong path identity", http.MethodGet, "/v1/mutations/operation-2", true, true, nil, 400},
		{"partial identity", http.MethodGet, "/v1/mutations/operation-1", true, true, func(r *http.Request) { r.Header.Del("X-EgressDeck-Mutation-Hash") }, 400},
		{"duplicate identity", http.MethodGet, "/v1/mutations/operation-1", true, true, func(r *http.Request) { r.Header.Add("X-EgressDeck-Mutation-ID", "operation-1") }, 400},
		{"zero fence", http.MethodGet, "/v1/mutations/operation-1", true, true, func(r *http.Request) { r.Header.Set("X-EgressDeck-Mutation-Fence", "0") }, 400},
		{"noncanonical fence", http.MethodGet, "/v1/mutations/operation-1", true, true, func(r *http.Request) { r.Header.Set("X-EgressDeck-Mutation-Fence", "07") }, 400},
		{"unsupported method", http.MethodPost, "/v1/mutations/operation-1", true, true, nil, 405},
		{"resolve read", http.MethodGet, "/v1/mutations/operation-1/resolve", true, true, nil, 405},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := &mutationAgentEngine{Engine: gateway.NewFakeEngine(), state: gateway.MutationUnknown}
			a := &agent{engine: engine, token: "secret"}
			r := httptest.NewRequest(test.method, test.path, nil)
			if test.auth {
				r.Header.Set("Authorization", "Bearer secret")
			}
			if test.headers {
				addAgentMutationHeaders(r)
			}
			if test.change != nil {
				test.change(r)
			}
			w := httptest.NewRecorder()
			a.routes().ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if test.want == 200 {
				var receipt gateway.MutationReceipt
				if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
					t.Fatal(err)
				}
				if engine.calls != 1 || engine.seen != agentMutationIdentity() || receipt.ValidateFor(agentMutationIdentity()) != nil {
					t.Fatalf("identity/receipt mismatch: %+v %+v", engine, receipt)
				}
			} else if engine.calls != 0 {
				t.Fatalf("invalid request reached engine: %d", engine.calls)
			}
		})
	}
}

func TestAgentMutationRoutesRefuseUnsupportedEngine(t *testing.T) {
	a := &agent{engine: gateway.NewFakeEngine(), token: "secret"}
	for _, path := range []string{"/v1/mutations/operation-1", "/v1/mutations/operation-1/resolve"} {
		method := http.MethodGet
		if strings.HasSuffix(path, "/resolve") {
			method = http.MethodPost
		}
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer secret")
		addAgentMutationHeaders(r)
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, r)
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
	}
}

func TestAgentSelectionPropagatesIdentityAndExplicitPreflightProof(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		definite bool
	}{
		{"preflight", gateway.RejectBeforeMutation("group_not_applied", "internal-private-diagnostic", gateway.ErrConflict), true},
		{"generic conflict", gateway.ErrConflict, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := &mutationAgentEngine{Engine: gateway.NewFakeEngine(), err: test.err}
			a := &agent{engine: engine, token: "secret"}
			r := httptest.NewRequest(http.MethodPut, "/v1/selections", strings.NewReader(`{"scope":{"group_id":"group-1","transport":"tcp"},"desired_node_id":"node-1","expected_revision":0,"persist_restart":false}`))
			r.Header.Set("Authorization", "Bearer secret")
			addAgentMutationHeaders(r)
			w := httptest.NewRecorder()
			a.routes().ServeHTTP(w, r)
			if w.Code != http.StatusConflict || engine.seen != agentMutationIdentity() {
				t.Fatalf("status=%d body=%s seen=%+v", w.Code, w.Body.String(), engine.seen)
			}
			var proof struct {
				Rejected bool                     `json:"rejected_before_mutation"`
				Identity gateway.MutationIdentity `json:"mutation_identity"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &proof); err != nil {
				t.Fatal(err)
			}
			if proof.Rejected != test.definite || (test.definite && proof.Identity != agentMutationIdentity()) {
				t.Fatalf("proof=%+v", proof)
			}
			if strings.Contains(w.Body.String(), "internal-private-diagnostic") {
				t.Fatal("private error escaped")
			}
		})
	}
}

func TestAgentStatusNeverUpgradesUnknownFromGeneration(t *testing.T) {
	engine := &mutationAgentEngine{Engine: gateway.NewFakeEngine(), state: gateway.MutationUnknown}
	a := &agent{engine: engine, token: "secret"}
	r := httptest.NewRequest(http.MethodGet, "/v1/mutations/operation-1", nil)
	r.Header.Set("Authorization", "Bearer secret")
	addAgentMutationHeaders(r)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	var receipt gateway.MutationReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.State != gateway.MutationUnknown || receipt.Generation != 4 {
		t.Fatalf("status was inferred from generation: %+v", receipt)
	}
	engine.err = errors.New("status unavailable")
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", w.Code)
	}
}
