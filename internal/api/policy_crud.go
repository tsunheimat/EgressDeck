package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/policy"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

// Policy writes use the same compiler as deployment preview. Validating while
// holding the service mutex keeps referenced rule sets stable until the new
// revision is installed. Runtime capability checks remain deployment checks.
func (s *Server) policiesCRUD(w http.ResponseWriter, r *http.Request) {
	services := s.servicesOrDefault()
	switch r.Method {
	case http.MethodGet:
		services.mu.RLock()
		items := make([]policy.Policy, 0, len(services.policies))
		for _, item := range services.policies {
			items = append(items, clonePolicyResource(item))
		}
		services.mu.RUnlock()
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		writeCollection(w, r, items, nil)
	case http.MethodPost:
		var item policy.Policy
		if !decodeJSON(w, r, &item) {
			return
		}
		item.ID = strings.TrimSpace(item.ID)
		if item.ID == "" {
			item.ID = domain.NewID()
		}
		item.Revision = 1
		services.mu.Lock()
		if _, exists := services.policies[item.ID]; exists {
			services.mu.Unlock()
			writeError(w, http.StatusConflict, "already_exists", "policy already exists")
			return
		}
		if err := validatePolicyResourceLocked(services, item); err != nil {
			services.mu.Unlock()
			writeServiceError(w, err)
			return
		}
		if refs, ok := s.Store.(store.PolicyReferenceStore); ok {
			if err := refs.SavePolicyReference(r.Context(), policyReference(item)); err != nil {
				services.mu.Unlock()
				writeStoreError(w, err)
				return
			}
		}
		services.policies[item.ID] = clonePolicyResource(item)
		services.mu.Unlock()
		services.record(requestActor(r), "policy", item.ID, "create", "accepted")
		writePolicyRevision(w, item.Revision)
		writeJSON(w, http.StatusCreated, item)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (s *Server) policyCRUD(w http.ResponseWriter, r *http.Request) {
	services := s.servicesOrDefault()
	id := r.PathValue("id")
	if r.Method == http.MethodGet {
		services.mu.RLock()
		item, exists := services.policies[id]
		item = clonePolicyResource(item)
		services.mu.RUnlock()
		if !exists {
			writeError(w, http.StatusNotFound, "not_found", "policy not found")
			return
		}
		writePolicyRevision(w, item.Revision)
		writeJSON(w, http.StatusOK, item)
		return
	}
	if r.Method != http.MethodPatch && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		methodNotAllowed(w, "GET, PATCH, PUT, DELETE")
		return
	}
	expected, ok := expectedRevision(r)
	if !ok {
		writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match or revision query is required")
		return
	}
	var item policy.Policy
	if r.Method != http.MethodDelete && !decodeJSON(w, r, &item) {
		return
	}
	item.ID = id
	services.mu.Lock()
	old, exists := services.policies[id]
	if !exists {
		services.mu.Unlock()
		writeError(w, http.StatusNotFound, "not_found", "policy not found")
		return
	}
	if old.Revision != expected {
		services.mu.Unlock()
		writeStoreError(w, domain.ErrConflict)
		return
	}
	if r.Method == http.MethodDelete {
		// Disabled device groups still retain an explicit policy reference.
		// Requiring reassignment prevents enabling a dangling group later.
		if s.Store == nil {
			services.mu.Unlock()
			writeError(w, http.StatusServiceUnavailable, "not_ready", "inventory store is unavailable")
			return
		}
		groups, err := s.Store.ListDeviceGroups(r.Context())
		if err != nil {
			services.mu.Unlock()
			writeStoreError(w, err)
			return
		}
		for _, group := range groups {
			if group.PolicyID == id {
				services.mu.Unlock()
				writeError(w, http.StatusConflict, "resource_referenced", "policy is referenced by device group "+group.ID)
				return
			}
		}
		if refs, ok := s.Store.(store.PolicyReferenceStore); ok {
			if err := refs.DeletePolicyReference(r.Context(), id); err != nil {
				services.mu.Unlock()
				writeStoreError(w, err)
				return
			}
		}
		delete(services.policies, id)
		services.mu.Unlock()
		services.record(requestActor(r), "policy", id, "delete", "accepted")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	item.Revision = old.Revision + 1
	if err := validatePolicyResourceLocked(services, item); err != nil {
		services.mu.Unlock()
		writeServiceError(w, err)
		return
	}
	if refs, ok := s.Store.(store.PolicyReferenceStore); ok {
		if err := refs.SavePolicyReference(r.Context(), policyReference(item)); err != nil {
			services.mu.Unlock()
			writeStoreError(w, err)
			return
		}
	}
	services.policies[id] = clonePolicyResource(item)
	services.mu.Unlock()
	services.record(requestActor(r), "policy", id, "update", "accepted")
	writePolicyRevision(w, item.Revision)
	writeJSON(w, http.StatusOK, item)
}

func policyReference(item policy.Policy) domain.Policy {
	return domain.Policy{ID: item.ID, Name: item.Name, Revision: item.Revision, DefaultAction: domain.Action(item.DefaultAction.Kind), UnknownDomainAction: domain.Action(item.UnknownDomainAction.Kind), ProxyFailureAction: domain.Action(item.ProxyFailureAction.Kind)}
}

func (s *Server) ruleSetsCRUD(w http.ResponseWriter, r *http.Request) {
	services := s.servicesOrDefault()
	switch r.Method {
	case http.MethodGet:
		services.mu.RLock()
		items := make([]policy.RuleSet, 0, len(services.ruleSets))
		for _, item := range services.ruleSets {
			items = append(items, clonePolicyResource(item))
		}
		services.mu.RUnlock()
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		writeCollection(w, r, items, nil)
	case http.MethodPost:
		var item policy.RuleSet
		if !decodeJSON(w, r, &item) {
			return
		}
		item.ID = strings.TrimSpace(item.ID)
		if item.ID == "" {
			item.ID = domain.NewID()
		}
		item.Revision = 1
		services.mu.Lock()
		if _, exists := services.ruleSets[item.ID]; exists {
			services.mu.Unlock()
			writeError(w, http.StatusConflict, "already_exists", "rule set already exists")
			return
		}
		if err := validateRuleSetResourceLocked(services, item); err != nil {
			services.mu.Unlock()
			writeServiceError(w, err)
			return
		}
		services.ruleSets[item.ID] = clonePolicyResource(item)
		services.mu.Unlock()
		services.record(requestActor(r), "rule_set", item.ID, "create", "accepted")
		writePolicyRevision(w, item.Revision)
		writeJSON(w, http.StatusCreated, item)
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (s *Server) ruleSetCRUD(w http.ResponseWriter, r *http.Request) {
	services := s.servicesOrDefault()
	id := r.PathValue("id")
	if r.Method == http.MethodGet {
		services.mu.RLock()
		item, exists := services.ruleSets[id]
		item = clonePolicyResource(item)
		services.mu.RUnlock()
		if !exists {
			writeError(w, http.StatusNotFound, "not_found", "rule set not found")
			return
		}
		writePolicyRevision(w, item.Revision)
		writeJSON(w, http.StatusOK, item)
		return
	}
	if r.Method != http.MethodPatch && r.Method != http.MethodPut && r.Method != http.MethodDelete {
		methodNotAllowed(w, "GET, PATCH, PUT, DELETE")
		return
	}
	expected, ok := expectedRevision(r)
	if !ok {
		writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match or revision query is required")
		return
	}
	var item policy.RuleSet
	if r.Method != http.MethodDelete && !decodeJSON(w, r, &item) {
		return
	}
	item.ID = id
	services.mu.Lock()
	old, exists := services.ruleSets[id]
	if !exists {
		services.mu.Unlock()
		writeError(w, http.StatusNotFound, "not_found", "rule set not found")
		return
	}
	if old.Revision != expected {
		services.mu.Unlock()
		writeStoreError(w, domain.ErrConflict)
		return
	}
	if r.Method == http.MethodDelete {
		for _, existing := range services.policies {
			if policyReferencesRuleSet(existing, id) {
				services.mu.Unlock()
				writeError(w, http.StatusConflict, "resource_referenced", "rule set is referenced by policy "+existing.ID)
				return
			}
		}
		delete(services.ruleSets, id)
		services.mu.Unlock()
		services.record(requestActor(r), "rule_set", id, "delete", "accepted")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	item.Revision = old.Revision + 1
	if err := validateRuleSetResourceLocked(services, item); err != nil {
		services.mu.Unlock()
		writeServiceError(w, err)
		return
	}
	services.ruleSets[id] = clonePolicyResource(item)
	services.mu.Unlock()
	services.record(requestActor(r), "rule_set", id, "update", "accepted")
	writePolicyRevision(w, item.Revision)
	writeJSON(w, http.StatusOK, item)
}

func writePolicyRevision(w http.ResponseWriter, revision int64) {
	w.Header().Set("ETag", `"`+strconv.FormatInt(revision, 10)+`"`)
}

// These schemas contain only JSON-compatible typed fields. Round-tripping
// also detaches pointer-based policy entries and all nested match slices.
func clonePolicyResource[T policy.Policy | policy.RuleSet](item T) T {
	data, _ := json.Marshal(item)
	var copy T
	_ = json.Unmarshal(data, &copy)
	return copy
}

func policyReferencesRuleSet(item policy.Policy, id string) bool {
	for _, reference := range item.RuleSetIDs {
		if strings.TrimSpace(reference) == id {
			return true
		}
	}
	for _, entry := range item.Entries {
		if strings.TrimSpace(entry.RuleSetID) == id {
			return true
		}
	}
	return false
}

func policyResourceInputLocked(services *Services) policy.CompileInput {
	// Policy and rule-set CRUD validates typed syntax while the resource is
	// still independent of any selected gateway. Deployment preview performs
	// the real capability check against the target gateway. Advertise every
	// transport understood by the policy model here so valid UDP/QUIC rules do
	// not fail merely because this synthetic validation context has no adapter.
	input := policy.CompileInput{Gateway: policy.Gateway{
		ID:                  "policy-validation",
		SupportedTransports: []policy.Transport{policy.TransportTCP, policy.TransportUDP, policy.TransportQUIC},
	}}
	for _, item := range services.ruleSets {
		input.RuleSets = append(input.RuleSets, clonePolicyResource(item))
	}
	for _, group := range services.Outbounds.List() {
		input.OutboundGroups = append(input.OutboundGroups, policy.OutboundGroup{ID: group.ID, Name: group.Name, NodeIDs: append([]string(nil), group.NodeIDs...)})
	}
	return input
}

func validatePolicyResourceLocked(services *Services, item policy.Policy) error {
	input := policyResourceInputLocked(services)
	input.Policies = []policy.Policy{clonePolicyResource(item)}
	_, err := policy.Compile(input)
	return err
}

func validateRuleSetResourceLocked(services *Services, item policy.RuleSet) error {
	input := policyResourceInputLocked(services)
	found := false
	for i := range input.RuleSets {
		if input.RuleSets[i].ID == item.ID {
			input.RuleSets[i] = clonePolicyResource(item)
			found = true
			break
		}
	}
	if !found {
		input.RuleSets = append(input.RuleSets, clonePolicyResource(item))
	}
	for _, existing := range services.policies {
		if policyReferencesRuleSet(existing, item.ID) {
			input.Policies = append(input.Policies, clonePolicyResource(existing))
		}
	}
	_, err := policy.Compile(input)
	return err
}
