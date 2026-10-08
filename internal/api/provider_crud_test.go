package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func providerCRUDRequest(handler http.Handler, method, id string, revision int64, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "/api/v1/providers/"+id, strings.NewReader(body))
	if revision >= 0 {
		request.Header.Set("If-Match", strconv.FormatInt(revision, 10))
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func providerCRUDServer(t *testing.T) (*Server, *store.FileStore, domain.Provider) {
	t.Helper()
	inventory, err := store.NewFileStore(filepath.Join(t.TempDir(), "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(inventory, nil)
	if err := server.Services.Load(context.Background(), inventory, lifecycleTestVault(t, 41)); err != nil {
		t.Fatal(err)
	}
	provider, err := server.createProvider(context.Background(), domain.Provider{ID: "subscription", Name: "Original", Source: "https://old.example/sub?token=private-old", Format: "links"})
	if err != nil {
		t.Fatal(err)
	}
	return server, inventory, provider
}

// Failed management requests may append an audit event. Compare the exact
// credential envelopes and provider inventory independently of that expected
// audit write; neither may change when the provider mutation is rejected.
func providerDurableBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		Providers json.RawMessage            `json:"providers"`
		Documents map[string]json.RawMessage `json:"documents"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	for key := range state.Documents {
		if !strings.HasPrefix(key, providerSourceDocumentPrefix) {
			delete(state.Documents, key)
		}
	}
	canonical, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestProviderEditPreservesSourceAndWorkingRevisions(t *testing.T) {
	server, inventory, original := providerCRUDServer(t)
	ctx := context.Background()
	active, _, err := server.Services.Providers.Stage(original.ID, []byte("socks5://old.example:1080#old"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Services.Providers.Publish(original.ID, active.Number, 0); err != nil {
		t.Fatal(err)
	}
	staged, _, err := server.Services.Providers.Stage(original.ID, []byte("socks5://new.example:1080#new"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	privateBefore, _ := server.Services.Providers.ExportState()
	sourceBefore, _ := inventory.LoadDocument(ctx, providerSourceDocumentKey(original.Source))
	fetches := 0
	// Keeping the existing registry retains revision identities; no edit path
	// has access to a fetch adapter or publication callback.
	server.Services.ProviderPublisher = func(context.Context, domain.Provider, providers.Revision) error { fetches++; return nil }
	response := providerCRUDRequest(server.Handler(), http.MethodPatch, original.ID, original.Revision, `{"name":" Edited ","format":" LINKS ","fetch_route":" DIRECT "}`)
	if response.Code != http.StatusOK {
		t.Fatalf("edit status=%d body=%s", response.Code, response.Body)
	}
	stored, _ := inventory.GetProvider(ctx, original.ID)
	if stored.Source != original.Source || stored.Name != "Edited" || stored.Format != "links" || stored.FetchRoute != "direct" || stored.Revision != 2 {
		t.Fatalf("unexpected saved settings: %+v", publicProvider(stored))
	}
	sourceAfter, _ := inventory.LoadDocument(ctx, providerSourceDocumentKey(original.Source))
	privateAfter, _ := server.Services.Providers.ExportState()
	if !bytes.Equal(sourceBefore, sourceAfter) || !bytes.Equal(privateBefore, privateAfter) || fetches != 0 {
		t.Fatal("settings edit changed credentials or working revisions")
	}
	status := server.Services.Providers.Status(original.ID)
	if status.Active != active.Number || status.Staged != staged.Number {
		t.Fatal("edit changed active/staged pointers")
	}
	if strings.Contains(response.Body.String(), original.Source) || strings.Contains(response.Body.String(), "private-old") {
		t.Fatal("edit response exposed source")
	}
}

func TestProviderSourceEditRotatesAtomicallyAndRestoresAfterRestart(t *testing.T) {
	server, inventory, original := providerCRUDServer(t)
	ctx := context.Background()
	fetchCalls := 0
	server.Services.Providers = providers.NewRegistry(providers.DefaultLimits(), func(context.Context, domain.Provider) ([]byte, error) {
		fetchCalls++
		return nil, errors.New("edit must not fetch")
	})
	staged, _, err := server.Services.Providers.Stage(original.ID, []byte("socks5://staged.example:1080#staged"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	privateBefore, _ := server.Services.Providers.ExportState()
	response := providerCRUDRequest(server.Handler(), http.MethodPut, original.ID, original.Revision, `{"source":"https://replacement.example/sub?token=private-new"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("edit status=%d body=%s", response.Code, response.Body)
	}
	stored, _ := inventory.GetProvider(ctx, original.ID)
	if stored.Source == original.Source || !isProviderSourceRef(stored.Source) || stored.Name != original.Name {
		t.Fatal("source rotation did not retain settings with a fresh reference")
	}
	privateAfter, _ := server.Services.Providers.ExportState()
	if !bytes.Equal(privateBefore, privateAfter) || server.Services.Providers.Status(original.ID).Staged != staged.Number || fetchCalls != 0 {
		t.Fatal("source edit fetched or changed the staged revision")
	}
	retired, _ := inventory.LoadDocument(ctx, providerSourceDocumentKey(original.Source))
	if !bytes.Contains(retired, []byte(`"deleted":true`)) || bytes.Contains(retired, []byte("ciphertext")) {
		t.Fatalf("old ciphertext was not retired: %s", retired)
	}
	reopened, err := store.NewFileStore(inventory.Path())
	if err != nil {
		t.Fatal(err)
	}
	restored := NewServer(reopened, nil)
	if err := restored.Services.Load(ctx, reopened, lifecycleTestVault(t, 41)); err != nil {
		t.Fatal(err)
	}
	resolved, err := restored.Services.resolveProviderSource(ctx, stored)
	if err != nil || resolved.Source != "https://replacement.example/sub?token=private-new" {
		t.Fatalf("restored source mismatch: %v", err)
	}
	raw, _ := os.ReadFile(inventory.Path())
	for _, secret := range []string{"private-old", "private-new", "replacement.example", "old.example"} {
		if bytes.Contains(raw, []byte(secret)) || strings.Contains(response.Body.String(), secret) {
			t.Fatalf("secret %q exposed", secret)
		}
	}
}

func TestProviderEditConflictEncryptionAndValidationLeaveDurableBytesUntouched(t *testing.T) {
	for _, scenario := range []struct {
		name, body string
		revision   int64
		status     int
		noKey      bool
	}{
		{"missing CAS", `{"source":"https://new.example"}`, -1, http.StatusPreconditionRequired, false},
		{"zero CAS", `{"source":"https://new.example"}`, 0, http.StatusPreconditionRequired, false},
		{"stale CAS", `{"source":"https://new.example"}`, 9, http.StatusPreconditionFailed, false},
		{"encryption unavailable", `{"source":"https://new.example"}`, 1, http.StatusServiceUnavailable, true},
		{"unsupported format", `{"format":"unknown"}`, 1, http.StatusUnprocessableEntity, false},
		{"route injection", `{"fetch_route":"direct\nproxy"}`, 1, http.StatusUnprocessableEntity, false},
		{"bad URL", `{"source":"https://"}`, 1, http.StatusUnprocessableEntity, false},
		{"opaque URL", `{"source":"https:private"}`, 1, http.StatusUnprocessableEntity, false},
		{"redacted input", `{"source":"[redacted]"}`, 1, http.StatusUnprocessableEntity, false},
		{"derived state", `{"active_revision":90}`, 1, http.StatusBadRequest, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server, inventory, provider := providerCRUDServer(t)
			before := providerDurableBytes(t, inventory.Path())
			if scenario.noKey {
				server.Services.persistence.vault = &secrets.Vault{}
			}
			response := providerCRUDRequest(server.Handler(), http.MethodPatch, provider.ID, scenario.revision, scenario.body)
			if response.Code != scenario.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, scenario.status, response.Body)
			}
			after := providerDurableBytes(t, inventory.Path())
			if !bytes.Equal(before, after) {
				t.Fatal("failed settings update changed durable inventory or encrypted source")
			}
		})
	}
}

type failingProviderEditStore struct{ *store.FileStore }

func (s *failingProviderEditStore) UpdateProviderSource(context.Context, domain.Provider, int64, string, json.RawMessage, string) (domain.Provider, error) {
	return domain.Provider{}, errors.New("database rejected row containing private-new")
}

func TestProviderSourceEditDatabaseFailureDoesNotTouchDurableStateOrExposeError(t *testing.T) {
	server, inventory, provider := providerCRUDServer(t)
	failing := &failingProviderEditStore{inventory}
	server.Store = failing
	server.Services.persistence.documents = failing
	before := providerDurableBytes(t, inventory.Path())
	response := providerCRUDRequest(server.Handler(), http.MethodPatch, provider.ID, provider.Revision, `{"source":"https://new.example?token=private-new"}`)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "private-new") {
		t.Fatalf("unexpected failure: %d %s", response.Code, response.Body)
	}
	after := providerDurableBytes(t, inventory.Path())
	if !bytes.Equal(before, after) {
		t.Fatal("database failure changed durable bytes")
	}
	resolved, err := server.Services.resolveProviderSource(context.Background(), provider)
	if err != nil || !strings.Contains(resolved.Source, "private-old") {
		t.Fatal("database failure damaged prior source")
	}
}

func TestProviderDeleteUnpublishedRetiresSourceAndForgetsStaging(t *testing.T) {
	server, inventory, provider := providerCRUDServer(t)
	if _, _, err := server.Services.Providers.Stage(provider.ID, []byte("socks5://node.example:1080#unpublished"), providers.FormatLinks); err != nil {
		t.Fatal(err)
	}
	response := providerCRUDRequest(server.Handler(), http.MethodDelete, provider.ID, provider.Revision, "")
	if response.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", response.Code, response.Body)
	}
	if _, err := inventory.GetProvider(context.Background(), provider.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted provider remains: %v", err)
	}
	if len(server.Services.Providers.List(provider.ID)) != 0 {
		t.Fatal("unpublished node credentials retained after deletion")
	}
	retired, _ := inventory.LoadDocument(context.Background(), providerSourceDocumentKey(provider.Source))
	if !bytes.Contains(retired, []byte(`"deleted":true`)) || bytes.Contains(retired, []byte("ciphertext")) {
		t.Fatal("deleted provider source was not retired")
	}
}

func TestProviderDeleteRejectsReferencesWithoutChangingDurableBytes(t *testing.T) {
	for _, scenario := range []string{"active", "group", "selection", "pending provider operation", "pending gateway operation"} {
		t.Run(scenario, func(t *testing.T) {
			server, inventory, provider := providerCRUDServer(t)
			ctx := context.Background()
			revision, _, err := server.Services.Providers.Stage(provider.ID, []byte("socks5://node.example:1080#node"), providers.FormatLinks)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "active":
				_, err = server.Services.Providers.Publish(provider.ID, revision.Number, 0)
			case "group", "selection":
				var group outbounds.Group
				group, err = server.Services.Outbounds.Create(outbounds.Group{ID: "group", Name: "group", GatewayID: "gateway", NodeIDs: []string{revision.Nodes[0].ID}, Mode: outbounds.SelectionManual, Replacement: outbounds.ReplacementBlock})
				if err == nil && scenario == "selection" {
					_, err = server.Services.Outbounds.SetDesired(group.ID, outbounds.Scope{GatewayID: "gateway", Transport: "tcp"}, revision.Nodes[0].ID, 0)
					if err == nil {
						group.NodeIDs = []string{"unrelated-node"}
						_, err = server.Services.Outbounds.Update(group, group.Revision)
					}
				}
			case "pending provider operation":
				_, err = server.Services.Journal.Create(ctx, deployment.Operation{Target: deployment.Target{Kind: "provider", ID: provider.ID}, Action: "publish", Status: deployment.StatusOutcomeUnknown})
			case "pending gateway operation":
				data, _ := json.Marshal(map[string]any{"node_ids": []string{revision.Nodes[0].ID}})
				_, err = server.Services.Journal.Create(ctx, deployment.Operation{Target: deployment.Target{Kind: "gateway", ID: "gateway"}, Action: "apply", Status: deployment.StatusApplying, Views: deployment.StateViews{Desired: &deployment.StateRecord{Data: data}}})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := server.Services.Persist(ctx); err != nil {
				t.Fatal(err)
			}
			before := providerDurableBytes(t, inventory.Path())
			response := providerCRUDRequest(server.Handler(), http.MethodDelete, provider.ID, provider.Revision, "")
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "provider_in_use") {
				t.Fatalf("delete status=%d body=%s", response.Code, response.Body)
			}
			after := providerDurableBytes(t, inventory.Path())
			if !bytes.Equal(before, after) {
				t.Fatal("reference rejection changed durable bytes")
			}
		})
	}
}
