package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

// Provider edits describe future fetches. They neither fetch nor change any
// staged, published or observed runtime revision.
type providerEdit struct {
	Name       *string `json:"name"`
	Source     *string `json:"source"`
	Format     *string `json:"format"`
	FetchRoute *string `json:"fetch_route"`
}

var providerRoutePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

func normalizeProviderEdit(provider *domain.Provider) error {
	provider.Name = strings.TrimSpace(provider.Name)
	provider.Format = strings.ToLower(strings.TrimSpace(provider.Format))
	provider.FetchRoute = strings.TrimSpace(provider.FetchRoute)
	if provider.Format == "" {
		provider.Format = "auto"
	}
	if provider.FetchRoute == "" || strings.EqualFold(provider.FetchRoute, "direct") {
		provider.FetchRoute = "direct"
	}
	problems := []string{}
	switch provider.Format {
	case "auto", "native", "base64", "links", "sip008", "clash", "json", "local":
	default:
		problems = append(problems, "format is not supported")
	}
	if !providerRoutePattern.MatchString(provider.FetchRoute) {
		problems = append(problems, "fetch_route must be direct or a configured route identifier")
	}
	if provider.Format != "local" && !isProviderSourceRef(provider.Source) {
		source, err := url.Parse(provider.Source)
		if err != nil || source.Hostname() == "" || (source.Scheme != "https" && source.Scheme != "http") || source.Opaque != "" {
			problems = append(problems, "source must be a valid http(s) URL")
		}
	}
	if len(problems) > 0 {
		return &domain.ValidationError{Problems: problems}
	}
	return provider.Validate()
}

func (s *Server) updateProvider(w http.ResponseWriter, r *http.Request, id string) {
	expected, ok := expectedRevision(r)
	if !ok {
		writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match or revision query is required")
		return
	}
	var edit providerEdit
	if !decodeJSON(w, r, &edit) {
		return
	}
	old, err := s.Store.GetProvider(r.Context(), id)
	if err != nil {
		writeProviderMutationError(w, err)
		return
	}
	if old.Revision != expected {
		writeStoreError(w, domain.ErrConflict)
		return
	}
	provider := old
	if edit.Name != nil {
		provider.Name = *edit.Name
	}
	if edit.Source != nil {
		if isProviderSourceRef(*edit.Source) || *edit.Source == redactedProviderSource {
			writeError(w, http.StatusUnprocessableEntity, "validation_error", "source must contain a new provider URL or local content")
			return
		}
		provider.Source = strings.TrimSpace(*edit.Source)
	}
	if edit.Format != nil {
		provider.Format = *edit.Format
	}
	if edit.FetchRoute != nil {
		provider.FetchRoute = *edit.FetchRoute
	}
	// Resolve only for validation when changing format with a retained source;
	// the durable provider continues to hold the same opaque reference.
	validation := provider
	if edit.Source == nil && edit.Format != nil && isProviderSourceRef(provider.Source) {
		validation, err = s.servicesOrDefault().resolveProviderSource(r.Context(), validation)
		if err != nil {
			writeProviderMutationError(w, err)
			return
		}
	}
	if err := normalizeProviderEdit(&validation); err != nil {
		writeProviderMutationError(w, err)
		return
	}
	provider.Name, provider.Format, provider.FetchRoute = validation.Name, validation.Format, validation.FetchRoute
	updated, err := s.saveProviderEdit(r.Context(), old, provider, expected, edit.Source != nil)
	if err != nil {
		writeProviderMutationError(w, err)
		return
	}
	s.servicesOrDefault().record(requestActor(r), "provider", id, "update", "saved")
	writeJSON(w, http.StatusOK, s.providerView(r.Context(), updated))
}

func (s *Server) saveProviderEdit(ctx context.Context, old, provider domain.Provider, expected int64, sourceChanged bool) (domain.Provider, error) {
	mutator, ok := s.Store.(store.ProviderMutator)
	if !ok {
		return domain.Provider{}, errors.New("provider mutations are unavailable")
	}
	if !sourceChanged {
		return mutator.UpdateProvider(ctx, provider, expected)
	}
	services := s.servicesOrDefault()
	services.persistence.mu.Lock()
	documents, vault := services.persistence.documents, services.persistence.vault
	services.persistence.mu.Unlock()
	if documents == nil && vault == nil {
		if _, ok := s.Store.(*store.MemoryStore); ok && !isProviderSourceRef(old.Source) {
			return mutator.UpdateProvider(ctx, provider, expected)
		}
		return domain.Provider{}, secrets.ErrKeyUnavailable
	}
	atomic, ok := s.Store.(store.ProviderSourceMutator)
	if !ok || vault == nil || !sameProviderStorage(documents, s.Store) {
		return domain.Provider{}, errors.New("atomic encrypted provider storage is unavailable")
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
		return domain.Provider{}, err
	}
	document, err := json.Marshal(providerSourceDocument{Version: 1, ProviderID: provider.ID, Envelope: envelope})
	if err != nil {
		return domain.Provider{}, errors.New("encode provider source failed")
	}
	retiredKey := ""
	if isProviderSourceRef(old.Source) {
		retiredKey = providerSourceDocumentKey(old.Source)
	}
	return atomic.UpdateProviderSource(ctx, provider, expected, providerSourceDocumentKey(provider.Source), document, retiredKey)
}

// The atomic provider/document extension is valid only when inventory and
// lifecycle documents share one backend. Split stores cannot safely retire a
// source across two independent commits.
func sameProviderStorage(documents store.DocumentStore, inventory store.Store) bool {
	if documents == nil || inventory == nil {
		return false
	}
	t := reflect.TypeOf(documents)
	return t == reflect.TypeOf(inventory) && t.Comparable() && any(documents) == any(inventory)
}

func (s *Server) deleteProvider(w http.ResponseWriter, r *http.Request, id string) {
	expected, ok := expectedRevision(r)
	if !ok {
		writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match or revision query is required")
		return
	}
	provider, err := s.Store.GetProvider(r.Context(), id)
	if err != nil {
		writeProviderMutationError(w, err)
		return
	}
	if provider.Revision != expected {
		writeStoreError(w, domain.ErrConflict)
		return
	}
	if err := s.providerDeletionAllowed(r.Context(), provider); err != nil {
		writeError(w, http.StatusConflict, "provider_in_use", err.Error())
		return
	}
	mutator, ok := s.Store.(store.ProviderMutator)
	if !ok {
		writeProviderMutationError(w, errors.New("provider mutations are unavailable"))
		return
	}
	if isProviderSourceRef(provider.Source) {
		services := s.servicesOrDefault()
		services.persistence.mu.Lock()
		documents := services.persistence.documents
		services.persistence.mu.Unlock()
		atomic, ok := s.Store.(store.ProviderSourceMutator)
		if !ok || !sameProviderStorage(documents, s.Store) {
			writeProviderMutationError(w, errors.New("atomic encrypted provider storage is unavailable"))
			return
		}
		err = atomic.DeleteProviderSource(r.Context(), id, expected, providerSourceDocumentKey(provider.Source))
	} else {
		err = mutator.DeleteProvider(r.Context(), id, expected)
	}
	if err != nil {
		writeProviderMutationError(w, err)
		return
	}
	services := s.servicesOrDefault()
	if err := services.Providers.ForgetUnpublished(id); err != nil {
		writeProviderMutationError(w, err)
		return
	}
	if err := s.RemoveProviderSchedule(r.Context(), id); err != nil {
		writeProviderMutationError(w, err)
		return
	}
	services.record(requestActor(r), "provider", id, "delete", "deleted")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) providerDeletionAllowed(ctx context.Context, provider domain.Provider) error {
	services := s.servicesOrDefault()
	if provider.ActiveRevision != 0 || services.Providers.Status(provider.ID).Active != 0 {
		return errors.New("an active provider cannot be deleted; deploy and verify an explicit replacement first")
	}
	references := map[string]bool{provider.ID: true}
	for _, revision := range services.Providers.List(provider.ID) {
		if revision.PublishedAt != nil {
			return errors.New("published provider revisions may still be used by gateway sessions or rollback")
		}
		for _, node := range revision.Nodes {
			references[node.ID] = true
		}
	}
	for _, group := range services.Outbounds.List() {
		for _, nodeID := range group.NodeIDs {
			if references[nodeID] {
				return errors.New("provider nodes are referenced by an outbound group")
			}
		}
		for _, selection := range services.Outbounds.Selections(group.ID) {
			if references[selection.DesiredNodeID] || references[selection.AppliedNodeID] || references[selection.ObservedNodeID] {
				return errors.New("provider nodes are referenced by an outbound selection")
			}
		}
	}
	operations, err := services.Journal.List(ctx)
	if err != nil {
		return errors.New("provider operation references could not be checked")
	}
	for _, operation := range operations {
		if operation.Status == deployment.StatusApplied || (operation.Status == deployment.StatusFailed && operation.Rollback != deployment.RollbackPending && operation.Rollback != deployment.RollbackRunning && operation.Rollback != deployment.RollbackFailed) {
			continue
		}
		if operation.Target.Kind == "provider" && operation.Target.ID == provider.ID {
			return errors.New("provider is referenced by an unfinished operation")
		}
		for _, view := range []*deployment.StateRecord{operation.Views.Desired, operation.Views.Applied, operation.Views.Observed, operation.Views.Verified} {
			if view == nil || len(view.Data) == 0 {
				continue
			}
			var data any
			if json.Unmarshal(view.Data, &data) != nil || providerReferenceInJSON(data, references) {
				return errors.New("provider may be referenced by an unfinished operation")
			}
		}
		if operation.Target.Kind == "gateway" && (operation.Views.Desired == nil || len(operation.Views.Desired.Data) == 0) {
			return errors.New("an unfinished gateway operation has no safe provider reference readback")
		}
	}
	return nil
}

func providerReferenceInJSON(value any, references map[string]bool) bool {
	switch value := value.(type) {
	case string:
		return references[value]
	case []any:
		for _, child := range value {
			if providerReferenceInJSON(child, references) {
				return true
			}
		}
	case map[string]any:
		for key, child := range value {
			if references[key] || providerReferenceInJSON(child, references) {
				return true
			}
		}
	}
	return false
}

func writeProviderMutationError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrProviderReferenced) {
		writeError(w, http.StatusConflict, "provider_in_use", "provider has active or retained runtime references")
		return
	}
	var validation *domain.ValidationError
	if errors.Is(err, domain.ErrConflict) || errors.Is(err, domain.ErrNotFound) || errors.As(err, &validation) {
		writeStoreError(w, err)
		return
	}
	// Database errors may contain input values; never return their detail from
	// a credential mutation endpoint.
	writeError(w, http.StatusServiceUnavailable, "provider_storage_unavailable", "provider settings could not be saved")
}
