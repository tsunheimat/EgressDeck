package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/opnsense"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/policy"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

const lifecycleDocumentKey = "lifecycle/v1"

// servicePersistence serializes complete lifecycle snapshots so an older save
// cannot overtake a newer one. The inventory and operation journal retain their
// own persistence boundaries; this document does not claim a transaction with
// either of them or with a remote gateway.
type servicePersistence struct {
	mu        sync.Mutex
	documents store.DocumentStore
	vault     *secrets.Vault
}

type lifecycleDocument struct {
	Version  int              `json:"version"`
	Envelope secrets.Envelope `json:"envelope"`
}

// Only this encrypted private representation includes node credentials. Public
// provider and node JSON intentionally omit them and cannot restore a registry.
type lifecycleSnapshot struct {
	Version   int                         `json:"version"`
	Providers json.RawMessage             `json:"providers"`
	Outbounds json.RawMessage             `json:"outbounds"`
	Policies  map[string]policy.Policy    `json:"policies"`
	RuleSets  map[string]policy.RuleSet   `json:"rule_sets"`
	Bindings  map[string]opnsense.Binding `json:"bindings"`
	Audit     []AuditEvent                `json:"audit"`
}

// Load configures persistence and restores a complete authenticated snapshot.
// Call it once during startup, after wiring adapters and before serving requests.
// Existing adapters are restored in place so configured provider fetchers remain
// attached. Missing keys and corrupt state fail startup instead of opening an
// empty controller that could overwrite existing configuration.
func (s *Services) Load(ctx context.Context, documents store.DocumentStore, vault *secrets.Vault) error {
	if s == nil {
		return errors.New("lifecycle services are required")
	}
	if documents == nil {
		return errors.New("lifecycle document store is required")
	}
	if vault == nil || vault.ActiveKeyID() == "" {
		return secrets.ErrKeyUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.persistence.mu.Lock()
	defer s.persistence.mu.Unlock()
	raw, err := documents.LoadDocument(ctx, lifecycleDocumentKey)
	if errors.Is(err, domain.ErrNotFound) {
		s.persistence.documents, s.persistence.vault = documents, vault
		return nil
	}
	if err != nil {
		return fmt.Errorf("load lifecycle state: %w", err)
	}
	var document lifecycleDocument
	if err := decodeLifecycleJSON(raw, &document); err != nil || document.Version != 1 {
		return errors.New("invalid or unsupported lifecycle document")
	}
	plaintext, err := vault.Open(lifecycleDocumentKey, document.Envelope)
	if err != nil {
		return fmt.Errorf("decrypt lifecycle state: %w", err)
	}
	defer clear(plaintext)
	var snapshot lifecycleSnapshot
	if err := decodeLifecycleJSON(plaintext, &snapshot); err != nil || snapshot.Version != 1 {
		return errors.New("invalid or unsupported lifecycle snapshot")
	}
	defer clear(snapshot.Providers)
	defer clear(snapshot.Outbounds)
	if err := validateLifecycleSnapshot(snapshot); err != nil {
		return err
	}
	// Validate both private adapter formats before touching any live state. A
	// valid provider snapshot followed by a corrupt outbound snapshot must not
	// partially replace an otherwise usable controller.
	providerCheck := providers.NewRegistry(providers.DefaultLimits(), nil)
	if err := providerCheck.ImportState(snapshot.Providers); err != nil {
		return errors.New("invalid provider lifecycle snapshot")
	}
	outboundCheck := outbounds.NewService()
	if err := outboundCheck.ImportState(snapshot.Outbounds); err != nil {
		return errors.New("invalid outbound lifecycle snapshot")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.Providers == nil {
		s.Providers = providerCheck
	} else if err := s.Providers.ImportState(snapshot.Providers); err != nil {
		return errors.New("restore provider lifecycle snapshot failed")
	}
	if s.Outbounds == nil {
		s.Outbounds = outboundCheck
	} else if err := s.Outbounds.ImportState(snapshot.Outbounds); err != nil {
		return errors.New("restore outbound lifecycle snapshot failed")
	}
	s.mu.Lock()
	s.policies, s.ruleSets, s.bindings, s.audit = snapshot.Policies, snapshot.RuleSets, snapshot.Bindings, snapshot.Audit
	s.mu.Unlock()
	s.persistence.documents, s.persistence.vault = documents, vault
	return nil
}

// Persist must complete before acknowledging a lifecycle mutation. It is a
// no-op for explicitly in-memory Services that were never configured with Load.
// Any configured storage or encryption failure is returned to the caller.
func (s *Services) Persist(ctx context.Context) error {
	if s == nil {
		return errors.New("lifecycle services are required")
	}
	s.persistence.mu.Lock()
	defer s.persistence.mu.Unlock()
	if s.persistence.documents == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.Providers == nil || s.Outbounds == nil {
		return errors.New("lifecycle provider and outbound services are required")
	}
	providerState, err := s.Providers.ExportState()
	if err != nil {
		return errors.New("encode provider lifecycle state failed")
	}
	defer clear(providerState)
	outboundState, err := s.Outbounds.ExportState()
	if err != nil {
		return errors.New("encode outbound lifecycle state failed")
	}
	defer clear(outboundState)
	s.mu.RLock()
	plaintext, err := json.Marshal(lifecycleSnapshot{
		Version: 1, Providers: providerState, Outbounds: outboundState,
		Policies: s.policies, RuleSets: s.ruleSets, Bindings: s.bindings, Audit: s.audit,
	})
	s.mu.RUnlock()
	if err != nil {
		return errors.New("encode lifecycle state failed")
	}
	defer clear(plaintext)
	envelope, err := s.persistence.vault.Seal(lifecycleDocumentKey, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt lifecycle state: %w", err)
	}
	document, err := json.Marshal(lifecycleDocument{Version: 1, Envelope: envelope})
	if err != nil {
		return errors.New("encode lifecycle document failed")
	}
	if err := s.persistence.documents.SaveDocument(ctx, lifecycleDocumentKey, document); err != nil {
		return fmt.Errorf("persist lifecycle state: %w", err)
	}
	return nil
}

func decodeLifecycleJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected trailing lifecycle data")
	}
	return nil
}

func validateLifecycleSnapshot(snapshot lifecycleSnapshot) error {
	if snapshot.Policies == nil || snapshot.RuleSets == nil || snapshot.Bindings == nil {
		return errors.New("incomplete lifecycle snapshot")
	}
	for id, item := range snapshot.Policies {
		if id == "" || item.ID != id {
			return errors.New("invalid lifecycle policy identity")
		}
	}
	for id, item := range snapshot.RuleSets {
		if id == "" || item.ID != id {
			return errors.New("invalid lifecycle rule set identity")
		}
	}
	for id, item := range snapshot.Bindings {
		if id == "" || item.ID != id || item.Validate() != nil {
			return errors.New("invalid lifecycle binding")
		}
	}
	if len(snapshot.Audit) > 5000 {
		return errors.New("lifecycle audit exceeds retention limit")
	}
	return nil
}
