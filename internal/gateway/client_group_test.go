package gateway

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestClientGroupPublicationChecksExactRevisionReadback(t *testing.T) {
	publication := GroupPublication{ProviderID: "p", ProviderRevision: 7, Group: PublicationGroup{ID: "g", Name: "managed", Revision: 3, CandidateIDs: []string{"a"}, SelectedNodeID: "a"}}
	for _, mismatch := range []bool{false, true} {
		t.Run(map[bool]string{false: "exact", true: "wrong group revision"}[mismatch], func(t *testing.T) {
			_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				clientTestRequest(t, r, http.MethodPost, "/v1/groups/publish", GroupPublishRequest{Publication: publication, ExpectedGeneration: 4})
				revision := int64(3)
				if mismatch {
					revision = 2
				}
				clientTestJSON(t, w, http.StatusOK, map[string]any{"status": "published", "snapshot": Snapshot{Generation: 5, Providers: map[string]ProviderRevision{"p": {ProviderID: "p", Revision: 7}}, Groups: map[string]OutboundGroup{"g": {ID: "g", Name: "managed", ProviderIDs: []string{"p"}, NodeIDs: []string{"a"}, Revision: revision}}}})
			}))
			client := clientTestClient(t, options)
			_, err := client.PublishGroup(context.Background(), publication, 4)
			if !mismatch && err != nil {
				t.Fatal(err)
			}
			if mismatch && !errors.Is(err, ErrOutcomeUnknown) {
				t.Fatalf("mismatching acknowledgement: %v", err)
			}
		})
	}
}

func TestClientGroupPublicationAcceptsExactGenerationNoop(t *testing.T) {
	publication := GroupPublication{ProviderID: "p", ProviderRevision: 7, Group: PublicationGroup{ID: "g", Name: "managed", Revision: 3, CandidateIDs: []string{"a"}, SelectedNodeID: "a"}}
	_, options := newClientTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientTestRequest(t, r, http.MethodPost, "/v1/groups/publish", GroupPublishRequest{Publication: publication, ExpectedGeneration: 4})
		clientTestJSON(t, w, http.StatusOK, map[string]any{"status": "published", "snapshot": Snapshot{Generation: 4, Providers: map[string]ProviderRevision{"p": {ProviderID: "p", Revision: 7}}, Groups: map[string]OutboundGroup{"g": {ID: "g", Name: "managed", ProviderIDs: []string{"p"}, NodeIDs: []string{"a"}, Revision: 3}}}})
	}))
	client := clientTestClient(t, options)
	if _, err := client.PublishGroup(context.Background(), publication, 4); err != nil {
		t.Fatalf("exact-generation no-op: %v", err)
	}
}
