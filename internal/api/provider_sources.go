package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

const (
	providerSourceDocumentPrefix = "provider-source/v1/"
	redactedProviderSource       = "[redacted]"
)

// providerSourceDocument is the private persistence record for a provider's
// source. The source itself is authenticated to the provider identity by the
// vault object ID and is never written to a public provider response.
type providerSourceDocument struct {
	Version    int              `json:"version"`
	ProviderID string           `json:"provider_id"`
	Envelope   secrets.Envelope `json:"envelope"`
}

func providerSourceDocumentKey(ref string) string {
	return providerSourceDocumentPrefix + ref
}

func providerSourceObjectID(provider domain.Provider) string {
	return fmt.Sprintf("provider/%d:%s/source/%s", len(provider.ID), provider.ID, provider.Source)
}

func isProviderSourceRef(source string) bool {
	if !strings.HasPrefix(source, "secret_") || len(source) != len("secret_")+32 {
		return false
	}
	for _, c := range source[len("secret_"):] {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// createProvider validates the caller's source before replacing it with a
// private reference. Durable inventory creation always requires configured
// encryption; only the explicit MemoryStore contract-test path stays transient.
func (s *Server) createProvider(ctx context.Context, provider domain.Provider) (domain.Provider, error) {
	if isProviderSourceRef(provider.Source) {
		return domain.Provider{}, &domain.ValidationError{Problems: []string{"source must be a provider URL or local content, not a secret reference"}}
	}
	if err := provider.Validate(); err != nil {
		return domain.Provider{}, err
	}
	if provider.ID == "" {
		provider.ID = domain.NewID()
	}
	services := s.servicesOrDefault()
	services.persistence.mu.Lock()
	documents, vault := services.persistence.documents, services.persistence.vault
	services.persistence.mu.Unlock()
	if documents == nil && vault == nil {
		if _, ok := s.Store.(*store.MemoryStore); ok {
			return s.Store.CreateProvider(ctx, provider)
		}
		return domain.Provider{}, secrets.ErrKeyUnavailable
	}
	if documents == nil || vault == nil {
		return domain.Provider{}, secrets.ErrKeyUnavailable
	}
	if err := ctx.Err(); err != nil {
		return domain.Provider{}, err
	}
	ref, err := secrets.NewSecretRef()
	if err != nil {
		return domain.Provider{}, err
	}
	plaintext := []byte(provider.Source)
	defer clear(plaintext)
	provider.Source = string(ref)
	envelope, err := vault.Seal(providerSourceObjectID(provider), plaintext)
	if err != nil {
		return domain.Provider{}, fmt.Errorf("encrypt provider source: %w", err)
	}
	document, err := json.Marshal(providerSourceDocument{Version: 1, ProviderID: provider.ID, Envelope: envelope})
	if err != nil {
		return domain.Provider{}, errors.New("encode provider source document")
	}
	key := providerSourceDocumentKey(provider.Source)
	if err := documents.SaveDocument(ctx, key, document); err != nil {
		return domain.Provider{}, fmt.Errorf("persist provider source: %w", err)
	}
	created, err := s.Store.CreateProvider(ctx, provider)
	if err != nil {
		// The random ref makes this document private to this attempt. Inventory
		// rejects cannot overwrite an existing provider's source. DocumentStore
		// has no delete operation, so clear this unused ciphertext to a tombstone.
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		current, lookupErr := s.Store.GetProvider(cleanupContext, provider.ID)
		if (lookupErr == nil && current.Source == provider.Source) || (lookupErr != nil && !errors.Is(lookupErr, domain.ErrNotFound)) {
			// A transport error can arrive after inventory committed. Retain the
			// encrypted source when readback cannot prove it is unreferenced.
			return domain.Provider{}, err
		}
		if cleanupErr := documents.SaveDocument(cleanupContext, key, json.RawMessage(`{"version":1,"deleted":true}`)); cleanupErr != nil {
			return domain.Provider{}, errors.Join(err, errors.New("unused encrypted provider source cleanup failed"))
		}
		return domain.Provider{}, err
	}
	return created, nil
}

// resolveProviderSource returns a private provider copy for internal fetch and
// publication paths. Public handlers must use publicProvider instead.
func (s *Services) resolveProviderSource(ctx context.Context, provider domain.Provider) (domain.Provider, error) {
	if !isProviderSourceRef(provider.Source) {
		return provider, nil
	}
	if s == nil {
		return domain.Provider{}, secrets.ErrKeyUnavailable
	}
	s.persistence.mu.Lock()
	documents, vault := s.persistence.documents, s.persistence.vault
	s.persistence.mu.Unlock()
	if documents == nil || vault == nil {
		return domain.Provider{}, secrets.ErrKeyUnavailable
	}
	key := providerSourceDocumentKey(provider.Source)
	raw, err := documents.LoadDocument(ctx, key)
	if err != nil {
		return domain.Provider{}, fmt.Errorf("load provider source: %w", err)
	}
	var document providerSourceDocument
	if err := decodeLifecycleJSON(raw, &document); err != nil || document.Version != 1 || document.ProviderID != provider.ID {
		return domain.Provider{}, errors.New("invalid provider source document")
	}
	plaintext, err := vault.Open(providerSourceObjectID(provider), document.Envelope)
	if err != nil {
		return domain.Provider{}, fmt.Errorf("decrypt provider source: %w", err)
	}
	defer clear(plaintext)
	provider.Source = string(plaintext)
	return provider, nil
}

// publicProvider creates the only provider representation allowed on API
// responses. Source is always redacted, including opaque SecretRefs, because a
// ref is an implementation detail and must not become a retrieval handle.
func publicProvider(provider domain.Provider) domain.Provider {
	provider.Source = redactedProviderSource
	return provider
}

func publicProviders(providers []domain.Provider) []domain.Provider {
	out := make([]domain.Provider, len(providers))
	for i, provider := range providers {
		out[i] = publicProvider(provider)
	}
	return out
}

// ProviderView adds safe source metadata and live lifecycle pointers. The
// inventory row's active revision is not runtime readback and must not hide the
// registry's restored staged/active state.
type ProviderView struct {
	domain.Provider
	SourceKind     string     `json:"source_kind"`
	Refreshable    bool       `json:"refreshable"`
	ActiveRevision int64      `json:"active_revision"`
	StagedRevision int64      `json:"staged_revision"`
	LastAttemptAt  *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt  *time.Time `json:"last_success_at,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
}

func (s *Server) providerView(ctx context.Context, provider domain.Provider) ProviderView {
	services := s.servicesOrDefault()
	status := services.Providers.Status(provider.ID)
	view := ProviderView{Provider: publicProvider(provider), SourceKind: "manual", ActiveRevision: status.Active, StagedRevision: status.Staged, LastAttemptAt: status.LastAttemptAt, LastSuccessAt: status.LastSuccessAt, LastError: status.LastError}
	private, err := services.resolveProviderSource(ctx, provider)
	if err != nil {
		view.SourceKind = "unknown"
	} else if remoteProvider(private) {
		view.SourceKind, view.Refreshable = "url", true
	}
	return view
}

func (s *Server) providerViews(ctx context.Context, providers []domain.Provider) []ProviderView {
	views := make([]ProviderView, len(providers))
	for i, provider := range providers {
		views[i] = s.providerView(ctx, provider)
	}
	return views
}
