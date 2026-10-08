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
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func TestProviderSourceIsEncryptedRedactedAndFetchedAfterRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "providers.json")
	inventory, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	vault := lifecycleTestVault(t, 3)
	server := NewServer(inventory, nil)
	if err := server.Services.Load(ctx, inventory, vault); err != nil {
		t.Fatal(err)
	}
	source := "https://secret-user:secret-pass@subscription.example/token-path?token=private-token#private-fragment"
	body, _ := json.Marshal(domain.Provider{ID: "private-provider", Name: "subscription", Source: source, Format: "links"})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/providers", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create status=%d: %s", recorder.Code, recorder.Body)
	}
	assertProviderSourcePrivate(t, recorder.Body.Bytes())
	stored, err := inventory.GetProvider(ctx, "private-provider")
	if err != nil || !isProviderSourceRef(stored.Source) {
		t.Fatalf("inventory does not hold a private source ref: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertProviderSourcePrivate(t, raw)

	reopened, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewServer(reopened, nil)
	fetchCalls := 0
	restored.Services.Providers = providers.NewRegistry(providers.DefaultLimits(), func(_ context.Context, provider domain.Provider) ([]byte, error) {
		fetchCalls++
		if provider.Source != source {
			t.Error("fetch adapter did not receive the original private source")
		}
		return []byte("socks5://test.example:1080#exit"), nil
	})
	restored.Services.ProviderStageEnabled = true
	if err := restored.Services.Load(ctx, reopened, vault); err != nil {
		t.Fatal(err)
	}
	handler := restored.Handler()
	for _, path := range []string{"/api/v1/providers", "/api/v1/providers/private-provider", "/api/v1/overview"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d: %s", path, recorder.Code, recorder.Body)
		}
		assertProviderSourcePrivate(t, recorder.Body.Bytes())
		if strings.Contains(recorder.Body.String(), stored.Source) || !strings.Contains(recorder.Body.String(), redactedProviderSource) {
			t.Fatalf("GET %s leaked a source ref or omitted redaction", path)
		}
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/providers/private-provider/refresh", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusAccepted || fetchCalls != 1 {
		t.Fatalf("refresh status=%d fetch calls=%d body=%s", recorder.Code, fetchCalls, recorder.Body)
	}
	assertProviderSourcePrivate(t, recorder.Body.Bytes())
}

func assertProviderSourcePrivate(t *testing.T, raw []byte) {
	t.Helper()
	for _, secret := range []string{"secret-user", "secret-pass", "subscription.example", "token-path", "private-token", "private-fragment"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("provider source secret %q was exposed", secret)
		}
	}
}

func TestProviderSourceDuplicateIDCannotReplaceOriginalSource(t *testing.T) {
	ctx := context.Background()
	inventory := store.NewMemoryStore()
	server := NewServer(inventory, nil)
	if err := server.Services.Load(ctx, inventory, lifecycleTestVault(t, 4)); err != nil {
		t.Fatal(err)
	}
	provider := domain.Provider{ID: "one", Name: "one", Source: "https://original.example?token=original"}
	original, err := server.createProvider(ctx, provider)
	if err != nil {
		t.Fatal(err)
	}
	provider.Source = "https://replacement.example?token=replacement"
	if _, err := server.createProvider(ctx, provider); err == nil {
		t.Fatal("duplicate provider ID accepted")
	}
	resolved, err := server.Services.resolveProviderSource(ctx, original)
	if err != nil || resolved.Source != "https://original.example?token=original" {
		t.Fatalf("failed duplicate creation damaged original source: %v", err)
	}
}

func TestProviderSourceCannotBeSwappedAcrossProvidersOrRefs(t *testing.T) {
	ctx := context.Background()
	inventory := store.NewMemoryStore()
	server := NewServer(inventory, nil)
	if err := server.Services.Load(ctx, inventory, lifecycleTestVault(t, 5)); err != nil {
		t.Fatal(err)
	}
	first, err := server.createProvider(ctx, domain.Provider{ID: "one", Name: "one", Source: "https://one.example"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := server.createProvider(ctx, domain.Provider{ID: "two", Name: "two", Source: "https://two.example"})
	if err != nil {
		t.Fatal(err)
	}
	firstDoc, err := inventory.LoadDocument(ctx, providerSourceDocumentKey(first.Source))
	if err != nil {
		t.Fatal(err)
	}
	var swapped providerSourceDocument
	if err := json.Unmarshal(firstDoc, &swapped); err != nil {
		t.Fatal(err)
	}
	// Even a modified plaintext provider_id cannot change authenticated owner.
	swapped.ProviderID = second.ID
	swappedBytes, _ := json.Marshal(swapped)
	if err := inventory.SaveDocument(ctx, providerSourceDocumentKey(second.Source), swappedBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Services.resolveProviderSource(ctx, second); !errors.Is(err, secrets.ErrAuthentication) {
		t.Fatalf("swapped ciphertext error=%v", err)
	}
	if _, err := server.createProvider(ctx, domain.Provider{Name: "spoof", Source: first.Source}); err == nil {
		t.Fatal("caller-provided secret reference was accepted")
	}
}

func TestDurableProviderSourceRequiresConfiguredVault(t *testing.T) {
	ctx := context.Background()
	inventory, err := store.NewFileStore(filepath.Join(t.TempDir(), "providers.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(inventory, nil)
	if _, err := server.createProvider(ctx, domain.Provider{ID: "one", Name: "one", Source: "https://private.example?token=private"}); !errors.Is(err, secrets.ErrKeyUnavailable) {
		t.Fatalf("unencrypted durable provider accepted: %v", err)
	}
	if _, err := inventory.GetProvider(ctx, "one"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("inventory mutated without encryption: %v", err)
	}
}

type failingSourceDocuments struct{ store.DocumentStore }

func (f failingSourceDocuments) SaveDocument(context.Context, string, json.RawMessage) error {
	return errors.New("source storage unavailable")
}

func TestProviderSourcePersistenceFailureDoesNotCreateInventory(t *testing.T) {
	ctx := context.Background()
	inventory := store.NewMemoryStore()
	server := NewServer(inventory, nil)
	if err := server.Services.Load(ctx, failingSourceDocuments{inventory}, lifecycleTestVault(t, 6)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.createProvider(ctx, domain.Provider{ID: "one", Name: "one", Source: "https://private.example?token=private"}); err == nil {
		t.Fatal("source persistence failure was ignored")
	}
	if _, err := inventory.GetProvider(ctx, "one"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("inventory mutated before source was durably saved: %v", err)
	}
}

type ambiguousProviderCreateStore struct{ store.Store }

func (s ambiguousProviderCreateStore) CreateProvider(ctx context.Context, provider domain.Provider) (domain.Provider, error) {
	if _, err := s.Store.CreateProvider(ctx, provider); err != nil {
		return domain.Provider{}, err
	}
	return domain.Provider{}, errors.New("database connection lost after commit")
}

func TestProviderSourceSurvivesAmbiguousInventoryCommit(t *testing.T) {
	ctx := context.Background()
	inventory := store.NewMemoryStore()
	server := NewServer(ambiguousProviderCreateStore{inventory}, nil)
	if err := server.Services.Load(ctx, inventory, lifecycleTestVault(t, 7)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.createProvider(ctx, domain.Provider{ID: "committed", Name: "committed", Source: "https://committed.example?token=private"}); err == nil {
		t.Fatal("ambiguous inventory failure was ignored")
	}
	stored, err := inventory.GetProvider(ctx, "committed")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := server.Services.resolveProviderSource(ctx, stored)
	if err != nil || resolved.Source != "https://committed.example?token=private" {
		t.Fatalf("cleanup destroyed credentials for a committed inventory row: %v", err)
	}
}
