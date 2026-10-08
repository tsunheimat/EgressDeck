package api

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/policy"
)

func (s *Server) deleteOutboundGroup(w http.ResponseWriter, r *http.Request) {
	expected, ok := expectedRevision(r)
	if r.Header.Get("If-Match") == "" || !ok {
		writeError(w, http.StatusPreconditionRequired, "revision_required", "a positive If-Match revision is required")
		return
	}
	services := s.servicesOrDefault()
	id := r.PathValue("id")
	if err := services.rejectUnknownTarget(r.Context(), deployment.Target{Kind: "outbound_group", ID: id}); err != nil {
		writeError(w, http.StatusConflict, "outcome_unknown", err.Error())
		return
	}
	// Keep policy and rule-set writes blocked until the library has checked
	// the group revision and runtime selections and completed the deletion.
	services.mu.RLock()
	references := outboundGroupReferencesLocked(services, id)
	err := services.Outbounds.Delete(id, expected, references)
	services.mu.RUnlock()
	if errors.Is(err, outbounds.ErrGroupReferenced) {
		writeError(w, http.StatusConflict, "resource_referenced", "outbound group is referenced by "+strings.Join(references, ", "))
		return
	}
	if errors.Is(err, outbounds.ErrGroupInUse) {
		writeError(w, http.StatusConflict, "resource_in_use", err.Error())
		return
	}
	if err != nil {
		writeServiceError(w, err)
		return
	}
	services.record(requestActor(r), "outbound_group", id, "delete", "accepted")
	w.WriteHeader(http.StatusNoContent)
}

// Disabled rules remain references: deleting their target would leave an
// invalid resource that could not safely be enabled again.
func outboundGroupReferencesLocked(services *Services, id string) []string {
	references := []string{}
	for _, item := range services.policies {
		if policyReferencesOutboundGroup(item, id) {
			references = append(references, "policy "+item.ID)
		}
	}
	for _, item := range services.ruleSets {
		if rulesReferenceOutboundGroup(item.Rules, id) {
			references = append(references, "rule set "+item.ID)
		}
	}
	sort.Strings(references)
	return references
}

func actionReferencesOutboundGroup(action policy.Action, id string) bool {
	return strings.EqualFold(strings.TrimSpace(string(action.Kind)), string(policy.ActionOutboundGroup)) && strings.TrimSpace(action.OutboundGroupID) == id
}

func rulesReferenceOutboundGroup(rules []policy.Rule, id string) bool {
	for _, rule := range rules {
		if actionReferencesOutboundGroup(rule.Action, id) {
			return true
		}
	}
	return false
}

func policyReferencesOutboundGroup(item policy.Policy, id string) bool {
	for _, action := range []policy.Action{item.DefaultAction, item.UnknownDomainAction, item.ProxyFailureAction} {
		if actionReferencesOutboundGroup(action, id) {
			return true
		}
	}
	for _, rules := range [][]policy.Rule{item.MandatoryRules, item.Mandatory, item.Exceptions, item.Rules} {
		if rulesReferenceOutboundGroup(rules, id) {
			return true
		}
	}
	for _, entry := range item.Entries {
		if entry.Rule != nil && actionReferencesOutboundGroup(entry.Rule.Action, id) {
			return true
		}
	}
	return false
}
