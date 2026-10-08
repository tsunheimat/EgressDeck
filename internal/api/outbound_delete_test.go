package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/policy"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func outboundDeleteFixture(t *testing.T) *Server {
	t.Helper()
	server := NewServer(store.NewMemoryStore(), nil)
	if _, err := server.Services.Outbounds.Create(outbounds.Group{ID: "exit", Name: "Exit", GatewayID: "gateway", NodeIDs: []string{"node"}}); err != nil {
		t.Fatal(err)
	}
	return server
}

func requestOutboundDelete(handler http.Handler, target, revision string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodDelete, target, nil)
	if revision != "" {
		request.Header.Set("If-Match", revision)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestOutboundDeleteRequiresHeaderCASAndRemovesOnlyTarget(t *testing.T) {
	server := outboundDeleteFixture(t)
	if _, err := server.Services.Outbounds.Create(outbounds.Group{ID: "keep", Name: "Keep", GatewayID: "gateway"}); err != nil {
		t.Fatal(err)
	}
	before := server.Services.Outbounds.List()
	handler := server.Handler()
	for _, test := range []struct {
		name, target, revision string
		status                 int
	}{
		{"missing", "/api/v1/outbound-groups/exit", "", http.StatusPreconditionRequired},
		{"query only", "/api/v1/outbound-groups/exit?revision=1", "", http.StatusPreconditionRequired},
		{"zero", "/api/v1/outbound-groups/exit", "0", http.StatusPreconditionRequired},
		{"negative", "/api/v1/outbound-groups/exit", "-1", http.StatusPreconditionRequired},
		{"wildcard", "/api/v1/outbound-groups/exit", "*", http.StatusPreconditionRequired},
		{"invalid", "/api/v1/outbound-groups/exit", "abc", http.StatusPreconditionRequired},
		{"stale", "/api/v1/outbound-groups/exit", "2", http.StatusPreconditionFailed},
		{"unknown", "/api/v1/outbound-groups/absent", "1", http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := requestOutboundDelete(handler, test.target, test.revision)
			if response.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
			if !reflect.DeepEqual(before, server.Services.Outbounds.List()) {
				t.Fatal("rejected deletion changed group state")
			}
		})
	}
	response := requestOutboundDelete(handler, "/api/v1/outbound-groups/exit", `"1"`)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := server.Services.Outbounds.Get("exit"); !errors.Is(err, outbounds.ErrGroupNotFound) {
		t.Fatalf("deleted group remains: %v", err)
	}
	if groups := server.Services.Outbounds.List(); len(groups) != 1 || groups[0].ID != "keep" {
		t.Fatalf("unrelated group changed: %+v", groups)
	}
}

func TestOutboundDeleteRejectsEveryStoredReferenceIncludingDisabledRules(t *testing.T) {
	rule := policy.Rule{ID: "rule", Enabled: false, Action: policy.Action{Kind: " OUTBOUND_GROUP ", OutboundGroupID: " exit "}}
	for _, test := range []struct {
		name string
		item policy.Policy
	}{
		{"default", policy.Policy{DefaultAction: policy.Outbound("exit")}},
		{"unknown domain", policy.Policy{UnknownDomainAction: policy.Outbound("exit")}},
		{"proxy failure", policy.Policy{ProxyFailureAction: policy.Outbound("exit")}},
		{"mandatory rules", policy.Policy{MandatoryRules: []policy.Rule{rule}}},
		{"mandatory alias", policy.Policy{Mandatory: []policy.Rule{rule}}},
		{"exceptions", policy.Policy{Exceptions: []policy.Rule{rule}}},
		{"rules", policy.Policy{Rules: []policy.Rule{rule}}},
		{"entries", policy.Policy{Entries: []policy.PolicyEntry{{Rule: &rule}}}},
		{"rule set", policy.Policy{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := outboundDeleteFixture(t)
			if test.name == "rule set" {
				server.Services.ruleSets["reusable"] = policy.RuleSet{ID: "reusable", Revision: 1, Rules: []policy.Rule{rule}}
			} else {
				test.item.ID = "policy"
				server.Services.policies["policy"] = test.item
			}
			before := server.Services.Outbounds.List()
			response := requestOutboundDelete(server.Handler(), "/api/v1/outbound-groups/exit", "1")
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "resource_referenced") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if !reflect.DeepEqual(before, server.Services.Outbounds.List()) {
				t.Fatal("reference rejection changed group state")
			}
		})
	}
}

func TestOutboundDeleteRejectsDesiredAppliedAndObservedSelections(t *testing.T) {
	for _, phase := range []string{"desired", "applied", "observed"} {
		t.Run(phase, func(t *testing.T) {
			server := outboundDeleteFixture(t)
			scope := outbounds.Scope{GatewayID: "gateway", Transport: "udp"}
			var err error
			switch phase {
			case "desired":
				_, err = server.Services.Outbounds.SetDesired("exit", scope, "node", 0)
			case "applied":
				_, err = server.Services.Outbounds.MarkApplied("exit", scope, "node", 3)
			case "observed":
				_, err = server.Services.Outbounds.Observe("exit", scope, "node", 3)
			}
			if err != nil {
				t.Fatal(err)
			}
			beforeGroups, beforeSelections := server.Services.Outbounds.List(), server.Services.Outbounds.Selections("exit")
			response := requestOutboundDelete(server.Handler(), "/api/v1/outbound-groups/exit", "1")
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "resource_in_use") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if !reflect.DeepEqual(beforeGroups, server.Services.Outbounds.List()) || !reflect.DeepEqual(beforeSelections, server.Services.Outbounds.Selections("exit")) {
				t.Fatal("runtime rejection changed group or selection state")
			}
		})
	}
}

func TestOutboundDeletePersistsSuccessAndPreservesDurableStateOnSaveFailure(t *testing.T) {
	for _, failSave := range []bool{false, true} {
		name := "success"
		if failSave {
			name = "save failure"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			documents := store.NewMemoryStore()
			vault := lifecycleTestVault(t, 1)
			server := outboundDeleteFixture(t)
			if err := server.Services.Load(ctx, documents, vault); err != nil {
				t.Fatal(err)
			}
			if err := server.Services.Persist(ctx); err != nil {
				t.Fatal(err)
			}
			if failSave {
				server.Services.persistence.documents = failingLifecycleDocuments{DocumentStore: documents, failure: errors.New("disk unavailable")}
			}
			response := requestOutboundDelete(server.Handler(), "/api/v1/outbound-groups/exit", "1")
			want := http.StatusNoContent
			if failSave {
				want = http.StatusServiceUnavailable
			}
			if response.Code != want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, want, response.Body.String())
			}
			restored := NewServices()
			if err := restored.Load(ctx, documents, vault); err != nil {
				t.Fatal(err)
			}
			_, err := restored.Outbounds.Get("exit")
			if failSave && err != nil {
				t.Fatalf("failed save lost durable group: %v", err)
			}
			if !failSave && !errors.Is(err, outbounds.ErrGroupNotFound) {
				t.Fatalf("successful deletion was not durable: %v", err)
			}
			if failSave && !server.Services.mutationBlocked {
				t.Fatal("save failure did not freeze subsequent writes")
			}
		})
	}
}
