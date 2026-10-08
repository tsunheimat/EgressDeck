package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/opnsense"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/policy"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func lifecycleTestVault(t *testing.T, keyByte byte) *secrets.Vault {
	t.Helper()
	vault, err := secrets.New("test-key", bytes.Repeat([]byte{keyByte}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return vault
}

func populateLifecycle(t *testing.T, services *Services) {
	t.Helper()
	first, _, err := services.Providers.Stage("provider-1", []byte("trojan://restart-secret@example.org:443#primary"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services.Providers.Publish("provider-1", first.Number, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := services.Providers.Stage("provider-1", []byte("trojan://next-restart-secret@example.org:443#primary"), providers.FormatLinks); err != nil {
		t.Fatal(err)
	}
	group, err := services.Outbounds.Create(outbounds.Group{ID: "outbound-1", Name: "Primary", GatewayID: "gateway-1", NodeIDs: []string{first.Nodes[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	scope := outbounds.Scope{GatewayID: group.GatewayID, Transport: "tcp"}
	if _, err := services.Outbounds.SetDesired(group.ID, scope, first.Nodes[0].ID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := services.Outbounds.MarkApplied(group.ID, scope, first.Nodes[0].ID, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := services.Outbounds.Observe(group.ID, scope, first.Nodes[0].ID, 3); err != nil {
		t.Fatal(err)
	}
	services.policies["policy-1"] = policy.Policy{ID: "policy-1", DefaultAction: policy.Block(), RuleSetIDs: []string{"rules-1"}, Revision: 2}
	services.ruleSets["rules-1"] = policy.RuleSet{ID: "rules-1", Revision: 3, Rules: []policy.Rule{{ID: "rule-1", Enabled: true, Action: policy.Direct()}}}
	services.bindings["binding-1"] = opnsense.Binding{ID: "binding-1", GatewayID: "gateway-1", Alias: opnsense.AliasShape{Name: "managed", Type: opnsense.HostAlias}, Family: opnsense.IPv4Family, ManagedAddresses: []string{"192.0.2.10"}, Revision: 4}
	services.record("test", "provider", "provider-1", "publish", "applied")
}

func TestLifecyclePersistsEncryptedStateAcrossFileStoreRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.json")
	documents, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	vault := lifecycleTestVault(t, 1)
	original := NewServices()
	if err := original.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	populateLifecycle(t, original)
	if err := original.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"restart-secret", "next-restart-secret", "example.org", "policy-1", "192.0.2.10"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("plaintext lifecycle value %q leaked into persisted storage", secret)
		}
	}
	reopened, err := store.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restored := NewServices()
	fetchCalls := 0
	restored.Providers = providers.NewRegistry(providers.DefaultLimits(), func(context.Context, domain.Provider) ([]byte, error) {
		fetchCalls++
		return []byte("trojan://next-restart-secret@example.org:443#primary"), nil
	})
	providerAdapter, outboundAdapter := restored.Providers, restored.Outbounds
	if err := restored.Load(ctx, reopened, vault); err != nil {
		t.Fatal(err)
	}
	if restored.Providers != providerAdapter || restored.Outbounds != outboundAdapter {
		t.Fatal("load replaced configured adapters")
	}
	for _, number := range []int64{1, 2} {
		before, err := original.Providers.Get("provider-1", number)
		if err != nil {
			t.Fatal(err)
		}
		after, err := restored.Providers.Get("provider-1", number)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) || after.Nodes[0].Definition.Password == "" {
			t.Fatal("private provider state, including credentials, changed across restart")
		}
	}
	if !reflect.DeepEqual(original.Outbounds.List(), restored.Outbounds.List()) || !reflect.DeepEqual(original.Outbounds.Selections("outbound-1"), restored.Outbounds.Selections("outbound-1")) {
		t.Fatal("outbound membership or scoped selection changed across restart")
	}
	if !reflect.DeepEqual(original.policies, restored.policies) || !reflect.DeepEqual(original.ruleSets, restored.ruleSets) || !reflect.DeepEqual(original.bindings, restored.bindings) || !reflect.DeepEqual(original.audit, restored.audit) {
		t.Fatal("policy, rule set, binding, or audit state changed across restart")
	}
	if _, _, err := restored.Providers.Refresh(ctx, domain.Provider{ID: "provider-1"}, providers.FormatLinks); err != nil || fetchCalls != 1 {
		t.Fatalf("configured fetcher was not preserved: calls=%d err=%v", fetchCalls, err)
	}
}

func TestLifecycleLoadRejectsMissingOrWrongKeysWithoutReplacingState(t *testing.T) {
	ctx := context.Background()
	documents := store.NewMemoryStore()
	goodKey := lifecycleTestVault(t, 1)
	original := NewServices()
	if err := original.Load(ctx, documents, goodKey); err != nil {
		t.Fatal(err)
	}
	populateLifecycle(t, original)
	if err := original.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	for name, vault := range map[string]*secrets.Vault{"missing": nil, "wrong": lifecycleTestVault(t, 2)} {
		t.Run(name, func(t *testing.T) {
			restored := NewServices()
			restored.policies["preserve"] = policy.Policy{ID: "preserve"}
			if err := restored.Load(ctx, documents, vault); err == nil {
				t.Fatal("encrypted state loaded without its key")
			}
			if len(restored.policies) != 1 || restored.policies["preserve"].ID != "preserve" || len(restored.Outbounds.List()) != 0 {
				t.Fatal("failed load mutated existing service state")
			}
			if restored.persistence.documents != nil {
				t.Fatal("failed load enabled persistence over unreadable state")
			}
		})
	}
}

func TestLifecycleLoadValidatesWholeSnapshotBeforeRestoringProviders(t *testing.T) {
	ctx := context.Background()
	documents := store.NewMemoryStore()
	vault := lifecycleTestVault(t, 1)
	original := NewServices()
	if err := original.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	populateLifecycle(t, original)
	if err := original.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := documents.LoadDocument(ctx, lifecycleDocumentKey)
	if err != nil {
		t.Fatal(err)
	}
	var document lifecycleDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	var snapshot lifecycleSnapshot
	if err := vault.OpenJSON(lifecycleDocumentKey, document.Envelope, &snapshot); err != nil {
		t.Fatal(err)
	}
	snapshot.Outbounds = json.RawMessage(`{"version":999}`)
	document.Envelope, err = vault.SealJSON(lifecycleDocumentKey, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := documents.SaveDocument(ctx, lifecycleDocumentKey, raw); err != nil {
		t.Fatal(err)
	}
	restored := NewServices()
	if _, _, err := restored.Providers.Stage("existing-provider", []byte("trojan://existing@example.net:443#preserve"), providers.FormatLinks); err != nil {
		t.Fatal(err)
	}
	if err := restored.Load(ctx, documents, vault); err == nil {
		t.Fatal("corrupt outbound snapshot accepted")
	}
	if len(restored.Providers.List("existing-provider")) != 1 || len(restored.Providers.List("provider-1")) != 0 {
		t.Fatal("valid provider snapshot applied before corrupt outbound snapshot was rejected")
	}
}

type failingLifecycleDocuments struct {
	store.DocumentStore
	failure error
}

func (s failingLifecycleDocuments) SaveDocument(context.Context, string, json.RawMessage) error {
	return s.failure
}

func TestLifecyclePersistPropagatesDurabilityAndContextFailures(t *testing.T) {
	ctx := context.Background()
	failure := errors.New("disk unavailable")
	documents := store.NewMemoryStore()
	vault := lifecycleTestVault(t, 1)
	baseline := NewServices()
	if err := baseline.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	baseline.policies["durable"] = policy.Policy{ID: "durable", Revision: 1}
	if err := baseline.Persist(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := documents.LoadDocument(ctx, lifecycleDocumentKey)
	if err != nil {
		t.Fatal(err)
	}
	services := NewServices()
	if err := services.Load(ctx, failingLifecycleDocuments{DocumentStore: documents, failure: failure}, vault); err != nil {
		t.Fatal(err)
	}
	services.policies["durable"] = policy.Policy{ID: "durable", Revision: 2}
	if err := services.Persist(ctx); !errors.Is(err, failure) {
		t.Fatalf("save failure lost: %v", err)
	}
	after, err := documents.LoadDocument(ctx, lifecycleDocumentKey)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed save changed the previous durable document: %v", err)
	}
	restarted := NewServices()
	if err := restarted.Load(ctx, documents, vault); err != nil {
		t.Fatal(err)
	}
	if restarted.policies["durable"].Revision != 1 {
		t.Fatal("restart recovered an unacknowledged policy mutation")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := services.Persist(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled persist = %v", err)
	}
	if err := NewServices().Load(ctx, documents, nil); !errors.Is(err, secrets.ErrKeyUnavailable) {
		t.Fatalf("empty durable store accepted missing key: %v", err)
	}
	if err := NewServices().Load(ctx, nil, lifecycleTestVault(t, 1)); err == nil {
		t.Fatal("explicit persistence setup accepted nil store")
	}
	if err := NewServices().Persist(ctx); err != nil {
		t.Fatalf("unconfigured memory services should not persist: %v", err)
	}
}
