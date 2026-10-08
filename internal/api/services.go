package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/auth"
	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
	"github.com/egressdeck/homelab-proxy-controller/internal/opnsense"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/policy"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
)

// Services are optional adapter boundaries behind the management API. A nil
// mutating adapter is an explicit unsupported operation; handlers never claim
// a provider publication or runtime selection succeeded merely because the
// controller accepted a request.
type Services struct {
	mutationMu      sync.Mutex
	mutationBlocked bool
	refreshFlights  providerRefreshFlights
	Providers       *providers.Registry
	Outbounds       *outbounds.Service
	Journal         deployment.Journal
	Runner          *deployment.Runner
	Firewall        *opnsense.Adapter

	// ProviderPublisher and SelectionApplier are supplied by a gateway adapter
	// only after it has proved the corresponding runtime capability.
	ProviderStageEnabled bool
	SelectionPersistence bool
	ProviderPublisher    func(context.Context, domain.Provider, providers.Revision) error
	ProviderReadback     func(context.Context, domain.Provider) (int64, error)
	SelectionApplier     func(context.Context, outbounds.Group, outbounds.Selection) (outbounds.Selection, error)
	SelectionScopeMode   func(outbounds.Group) string
	ProviderTargetIDs    func(context.Context, domain.Provider) ([]string, error)
	ExecutorFactory      func(deployment.Target) deployment.Executor
	PolicyApplyEnabled   bool
	EnrollmentEnabled    bool
	GatewayObserver      func(context.Context, domain.Gateway) (gateway.Capabilities, gateway.Health, error)
	GatewayDiagnostics   func(context.Context, domain.Gateway) (GatewayDiagnostics, error)

	mu                   sync.RWMutex
	policies             map[string]policy.Policy
	ruleSets             map[string]policy.RuleSet
	bindings             map[string]opnsense.Binding
	firewallObservations map[string]firewallObservation
	audit                []AuditEvent
	persistence          servicePersistence
	eventFeed            eventFeedState
}

type AuditEvent struct {
	ID         string    `json:"id"`
	Actor      string    `json:"actor"`
	ObjectType string    `json:"object_type"`
	ObjectID   string    `json:"object_id"`
	Action     string    `json:"action"`
	Outcome    string    `json:"outcome"`
	CreatedAt  time.Time `json:"created_at"`
}

func NewServices() *Services {
	journal := deployment.NewMemoryJournal()
	services := &Services{
		Providers: providers.NewRegistry(providers.DefaultLimits(), nil),
		Outbounds: outbounds.NewService(),
		Journal:   journal,
		Runner:    deployment.NewRunner(journal),
		policies:  map[string]policy.Policy{},
		ruleSets:  map[string]policy.RuleSet{},
		bindings:  map[string]opnsense.Binding{},
	}
	services.Providers.SetMetadataImpactEvaluator(services.Outbounds.ProviderMetadataImpact)
	return services
}

func (s *Services) record(actor, objectType, objectID, action, outcome string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = append(s.audit, AuditEvent{ID: domain.NewID(), Actor: actor, ObjectType: objectType, ObjectID: objectID, Action: action, Outcome: outcome, CreatedAt: time.Now().UTC()})
	if len(s.audit) > 5000 {
		s.audit = append([]AuditEvent(nil), s.audit[len(s.audit)-5000:]...)
	}
}

func requestActor(r *http.Request) string {
	if session, ok := auth.SessionFromContext(r.Context()); ok {
		return session.Subject
	}
	return "development"
}

func (s *Server) servicesOrDefault() *Services {
	if s.Services != nil {
		if s.Services.Providers == nil {
			s.Services.Providers = providers.NewRegistry(providers.DefaultLimits(), nil)
		}
		if s.Services.Outbounds == nil {
			s.Services.Outbounds = outbounds.NewService()
		}
		if s.Services.Journal == nil {
			s.Services.Journal = deployment.NewMemoryJournal()
		}
		if s.Services.Runner == nil {
			s.Services.Runner = deployment.NewRunner(s.Services.Journal)
		}
		if s.Services.policies == nil {
			s.Services.policies = map[string]policy.Policy{}
		}
		if s.Services.ruleSets == nil {
			s.Services.ruleSets = map[string]policy.RuleSet{}
		}
		if s.Services.bindings == nil {
			s.Services.bindings = map[string]opnsense.Binding{}
		}
		return s.Services
	}
	s.Services = NewServices()
	return s.Services
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	services := s.servicesOrDefault()
	gateways, err := s.Store.ListGateways(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	gatewayViews := make([]GatewayView, 0, len(gateways))
	for _, item := range gateways {
		gatewayViews = append(gatewayViews, s.gatewayView(r.Context(), item))
	}
	providersList, err := s.Store.ListProviders(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	groups, err := s.Store.ListDeviceGroups(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	ops, err := services.Runner.List(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"gateways": gatewayViews, "bindings": services.firewallBindingViews(time.Now().UTC()), "providers": s.providerViews(r.Context(), providersList), "device_groups": groups, "operations": publicOperations(ops), "coverage": nil, "coverage_status": "unavailable"})
}

func (s *Server) nodes(w http.ResponseWriter, r *http.Request) {
	services := s.servicesOrDefault()
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	items := []nodes.Node{}
	for _, provider := range mustProviders(s.Store, r.Context()) {
		status := services.Providers.Status(provider.ID)
		revisionNumber := status.Staged
		if revisionNumber == 0 {
			revisionNumber = status.Active
		}
		if revisionNumber == 0 {
			continue
		}
		revision, err := services.Providers.Get(provider.ID, revisionNumber)
		if err != nil {
			continue
		}
		items = append(items, revision.Nodes...)
	}
	writeCollection(w, r, items, nil)
}

func mustProviders(s storeProviderList, ctx context.Context) []domain.Provider {
	list, _ := s.ListProviders(ctx)
	return list
}

type storeProviderList interface {
	ListProviders(context.Context) ([]domain.Provider, error)
}

func (s *Server) outboundGroups(w http.ResponseWriter, r *http.Request) {
	services := s.servicesOrDefault()
	if r.Method == http.MethodGet {
		writeCollection(w, r, services.Outbounds.List(), nil)
		return
	}
	if r.Method == http.MethodPost {
		var group outbounds.Group
		if !decodeJSON(w, r, &group) {
			return
		}
		if !s.checkOutboundInventory(w, r, &group) {
			return
		}
		created, err := services.Outbounds.Create(group)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		services.record(requestActor(r), "outbound_group", created.ID, "create", "accepted")
		writeJSON(w, http.StatusCreated, created)
		return
	}
	methodNotAllowed(w, "GET, POST")
}

func (s *Server) outboundGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		s.deleteOutboundGroup(w, r)
		return
	}
	services := s.servicesOrDefault()
	id := r.PathValue("id")
	if r.Method == http.MethodGet {
		group, err := services.Outbounds.Get(id)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, group)
		return
	}
	if r.Method == http.MethodPatch || r.Method == http.MethodPut {
		expected, ok := expectedRevision(r)
		if !ok {
			writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match or revision query is required")
			return
		}
		var group outbounds.Group
		if !decodeJSON(w, r, &group) {
			return
		}
		group.ID = id
		if !s.checkOutboundInventory(w, r, &group) {
			return
		}
		updated, err := services.Outbounds.Update(group, expected)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		services.record(requestActor(r), "outbound_group", id, "update", "accepted")
		writeJSON(w, http.StatusOK, updated)
		return
	}
	methodNotAllowed(w, "GET, PATCH, PUT")
}

type selectionRequest struct {
	NodeID           string   `json:"node_id"`
	GatewayID        string   `json:"gateway_id"`
	Transport        string   `json:"transport,omitempty"`
	TransportScopes  []string `json:"transport_scopes,omitempty"`
	ExpectedRevision int64    `json:"expected_revision,omitempty"`
}

func (s *Server) selection(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"items": s.servicesOrDefault().Outbounds.Selections(r.PathValue("id"))})
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		methodNotAllowed(w, "PUT, POST")
		return
	}
	services := s.servicesOrDefault()
	groupID := r.PathValue("id")
	var req selectionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	scopes := req.TransportScopes
	if len(scopes) == 0 {
		scopes = []string{req.Transport}
		if scopes[0] == "" {
			scopes[0] = "tcp"
		}
	}
	seenScopes := map[string]bool{}
	for _, scope := range scopes {
		if (scope != "tcp" && scope != "udp") || seenScopes[scope] {
			writeError(w, 422, "invalid_transport_scope", "transport scopes must be unique TCP or UDP entries")
			return
		}
		seenScopes[scope] = true
	}
	expected, hasExpected := expectedRuntimeRevision(r)
	group, err := services.Outbounds.Get(groupID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if req.GatewayID == "" {
		req.GatewayID = group.GatewayID
	}
	sharedSelection := services.SelectionScopeMode != nil && services.SelectionScopeMode(group) == "shared"
	if sharedSelection {
		if len(scopes) != 2 || !((scopes[0] == "tcp" && scopes[1] == "udp") || (scopes[0] == "udp" && scopes[1] == "tcp")) {
			writeError(w, 422, "shared_transport_required", "this gateway requires an explicit shared TCP and UDP selection")
			return
		}
		scopes = []string{"tcp", "udp"}
	}
	if services.SelectionApplier == nil {
		writeUnsupported(w, "selection.set_runtime", "gateway selection adapter is unavailable")
		return
	}
	if !hasExpected {
		writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match is required; use 0 for a new selection")
		return
	}
	req.TransportScopes = scopes
	req.Transport = ""
	req.ExpectedRevision = expected
	if err := services.rejectUnknownTarget(r.Context(), deployment.Target{Kind: "outbound_group", ID: groupID}); err != nil {
		writeError(w, http.StatusConflict, "outcome_unknown", err.Error())
		return
	}
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		if old, lookupErr := services.Journal.FindByIdempotency(r.Context(), deployment.Target{Kind: "outbound_group", ID: groupID}, key); lookupErr == nil {
			encoded, _ := json.Marshal(req)
			if old.Action != "selection" || old.Views.Desired == nil || string(old.Views.Desired.Data) != string(encoded) {
				writeError(w, http.StatusConflict, "idempotency_conflict", "idempotency key is bound to another selection request")
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": old.ID, "status": old.Status})
			return
		}
	}
	for _, transport := range scopes {
		scope := outbounds.Scope{GatewayID: req.GatewayID, Transport: transport}
		current, getErr := services.Outbounds.GetSelection(groupID, scope)
		if getErr == nil && current.Revision != expected {
			writeStoreError(w, domain.ErrConflict)
			return
		}
		if errors.Is(getErr, domain.ErrNotFound) && expected != 0 {
			writeStoreError(w, domain.ErrConflict)
			return
		}
		if getErr != nil && !errors.Is(getErr, domain.ErrNotFound) {
			writeServiceError(w, getErr)
			return
		}
		member := false
		for _, id := range group.NodeIDs {
			if id == req.NodeID {
				member = true
			}
		}
		if !member {
			writeServiceError(w, outbounds.ErrNodeNotMember)
			return
		}
	}
	intentBytes, _ := json.Marshal(req)
	selectionTarget := deployment.Target{Kind: "outbound_group", ID: groupID}
	fence, err := services.Journal.NextFence(r.Context(), selectionTarget)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	intent, err := services.Journal.Create(r.Context(), deployment.Operation{Target: selectionTarget, FenceToken: fence.Token, Action: "selection", IdempotencyKey: r.Header.Get("Idempotency-Key"), Status: deployment.StatusApplying, Views: deployment.StateViews{Desired: &deployment.StateRecord{Data: intentBytes, Status: "requested", At: time.Now().UTC()}}})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	selectedIntents := make([]outbounds.Selection, 0, len(scopes))
	priorSelections := map[string]*outbounds.Selection{}
	for _, transport := range scopes {
		scope := outbounds.Scope{GatewayID: req.GatewayID, Transport: transport}
		var prior *outbounds.Selection
		if previous, getErr := services.Outbounds.GetSelection(groupID, scope); getErr == nil {
			prior = &previous
		}
		priorSelections[transport] = prior
		selected, err := services.Outbounds.SetDesired(groupID, scope, req.NodeID, expected)
		if err != nil {
			intent.Status = deployment.StatusFailed
			intent.Error = "selection intent validation failed"
			_ = services.Journal.Save(context.WithoutCancel(r.Context()), intent)
			writeServiceError(w, err)
			return
		}
		selectedIntents = append(selectedIntents, selected)
	}
	if err := services.Persist(r.Context()); err != nil {
		for _, selected := range selectedIntents {
			_ = services.Outbounds.RestoreDesired(groupID, selected.Scope, priorSelections[selected.Scope.Transport])
		}
		intent.Status = deployment.StatusFailed
		intent.Error = "selection intent persistence failed"
		_ = services.Journal.Save(context.WithoutCancel(r.Context()), intent)
		writeServiceError(w, err)
		return
	}
	results := make([]outbounds.Selection, 0, len(scopes))
	verified := true
	var sharedResult outbounds.Selection
	for index, selected := range selectedIntents {
		scope := selected.Scope
		applied := sharedResult
		var err error
		if !sharedSelection || index == 0 {
			applied, err = services.SelectionApplier(r.Context(), group, selected)
			sharedResult = applied
		}
		if err != nil {
			intent.Status = deployment.StatusOutcomeUnknown
			intent.Error = "selection result is unknown; gateway readback is required"
			_ = services.Journal.Save(context.WithoutCancel(r.Context()), intent)
			writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": intent.ID, "status": intent.Status})
			return
		}
		if applied.ObservedNodeID == req.NodeID {
			if _, markErr := services.Outbounds.MarkApplied(groupID, scope, req.NodeID, applied.Generation); markErr != nil {
				writeServiceError(w, markErr)
				return
			}
			if observed, observeErr := services.Outbounds.Observe(groupID, scope, applied.ObservedNodeID, applied.Generation); observeErr == nil {
				applied = observed
			}
		}
		if applied.ObservedNodeID != req.NodeID {
			verified = false
		}
		results = append(results, applied)
	}
	status := "pending"
	if verified {
		status = "verified"
		services.record(requestActor(r), "outbound_group", groupID, "selection", "verified")
	} else {
		services.record(requestActor(r), "outbound_group", groupID, "selection", "pending")
	}
	opStatus := deployment.StatusPartiallyApplied
	if verified {
		opStatus = deployment.StatusApplied
	}
	resultBytes, _ := json.Marshal(results)
	intent.Status = opStatus
	intent.Views.Observed = &deployment.StateRecord{Status: status, Data: resultBytes, At: time.Now().UTC()}
	if err := services.Journal.Save(context.WithoutCancel(r.Context()), intent); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": intent.ID, "items": results, "status": opStatus})
}

func (s *Server) providerRevisions(w http.ResponseWriter, r *http.Request) {
	services := s.servicesOrDefault()
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	writeCollection(w, r, services.Providers.List(r.PathValue("id")), nil)
}

func (s *Server) providerRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	services := s.servicesOrDefault()
	provider, err := s.Store.GetProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if services.Providers == nil || !services.ProviderStageEnabled {
		writeUnsupported(w, "provider.stage", "provider registry is unavailable")
		return
	}
	requestHash := privateRequestHash(provider)
	provider, err = services.resolveProviderSource(r.Context(), provider)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		if old, lookupErr := services.Journal.FindByIdempotency(r.Context(), deployment.Target{Kind: "provider", ID: provider.ID}, key); lookupErr == nil {
			if old.Action != "refresh" || old.RequestHash != requestHash {
				writeError(w, http.StatusConflict, "idempotency_conflict", "idempotency key is bound to another action")
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": old.ID, "status": old.Status})
			return
		}
	}
	revision, changes, err := services.Providers.Refresh(r.Context(), provider, providers.Format(provider.Format))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	services.record(requestActor(r), "provider", provider.ID, "refresh", "staged")
	desiredBytes, _ := json.Marshal(map[string]any{"revision": revision, "changes": changes})
	op, err := services.Journal.Create(r.Context(), deployment.Operation{Target: deployment.Target{Kind: "provider", ID: provider.ID}, Action: "refresh", RequestHash: requestHash, IdempotencyKey: r.Header.Get("Idempotency-Key"), Status: deployment.StatusStaged, Views: deployment.StateViews{Desired: &deployment.StateRecord{Revision: strconv.FormatInt(revision.Number, 10), Status: "staged", Data: desiredBytes, At: time.Now().UTC()}}})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": op.ID, "revision": revision, "changes": changes, "status": "staged"})
}

func (s *Server) providerApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	services := s.servicesOrDefault()
	provider, err := s.Store.GetProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	provider, err = services.resolveProviderSource(r.Context(), provider)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	number, err := strconv.ParseInt(r.PathValue("revision"), 10, 64)
	if err != nil || number < 1 {
		writeError(w, http.StatusBadRequest, "invalid_revision", "revision must be a positive integer")
		return
	}
	revision, err := services.Providers.Get(provider.ID, number)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if services.ProviderPublisher == nil || services.ProviderReadback == nil {
		writeUnsupported(w, "provider.publish_hot", "gateway provider publication adapter is unavailable")
		return
	}
	if err := services.rejectUnknownTarget(r.Context(), deployment.Target{Kind: "provider", ID: provider.ID}); err != nil {
		writeError(w, http.StatusConflict, "outcome_unknown", err.Error())
		return
	}
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		if old, lookupErr := services.Journal.FindByIdempotency(r.Context(), deployment.Target{Kind: "provider", ID: provider.ID}, key); lookupErr == nil {
			if old.Action != "publish" {
				writeError(w, http.StatusConflict, "idempotency_conflict", "idempotency key is bound to another provider action")
				return
			}
			if old.Views.Desired == nil || old.Views.Desired.Revision != strconv.FormatInt(number, 10) {
				writeError(w, http.StatusConflict, "idempotency_conflict", "idempotency key is bound to another provider revision")
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": old.ID, "status": old.Status})
			return
		}
	}
	status := services.Providers.Status(provider.ID)
	expected, hasExpected := expectedRuntimeRevision(r)
	if !hasExpected {
		writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match is required; use 0 for first publication")
		return
	}
	if revision.State != providers.RevisionStaged || status.Active != expected {
		writeStoreError(w, domain.ErrConflict)
		return
	}
	available := map[string]bool{}
	for _, node := range revision.Nodes {
		available[node.ID] = true
	}
	for _, group := range services.Outbounds.List() {
		for _, selection := range services.Outbounds.Selections(group.ID) {
			if selection.DesiredNodeID == "" {
				continue
			}
			active, activeErr := services.Providers.Active(provider.ID)
			if activeErr != nil {
				continue
			}
			for _, node := range active.Nodes {
				if node.ID == selection.DesiredNodeID && !available[node.ID] {
					writeError(w, http.StatusConflict, "pinned_node_removed", "staged revision removes a selected node")
					return
				}
			}
		}
	}
	providerTarget := deployment.Target{Kind: "provider", ID: provider.ID}
	targetIDs := []string{}
	if services.ProviderTargetIDs != nil {
		targetIDs, err = services.ProviderTargetIDs(r.Context(), provider)
		if err != nil {
			writeServiceError(w, err)
			return
		}
	}
	fence, err := services.Journal.NextFence(r.Context(), providerTarget)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	providerIntent, _ := json.Marshal(map[string]any{"provider_id": provider.ID, "revision": number, "expected_active_revision": expected, "content_hash": revision.Hash, "gateway_ids": targetIDs})
	intent, err := services.Journal.Create(r.Context(), deployment.Operation{Target: providerTarget, FenceToken: fence.Token, Action: "publish", IdempotencyKey: r.Header.Get("Idempotency-Key"), Status: deployment.StatusApplying, Views: deployment.StateViews{Desired: &deployment.StateRecord{Revision: strconv.FormatInt(number, 10), Data: providerIntent, Status: "requested", At: time.Now().UTC()}}})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	publishErr := services.ProviderPublisher(r.Context(), provider, revision)
	observed, readErr := services.ProviderReadback(r.Context(), provider)
	if readErr != nil || observed != number {
		intent.Status = deployment.StatusOutcomeUnknown
		intent.Error = "provider publication was not confirmed by gateway readback"
		if publishErr != nil {
			intent.OriginalError = "provider publication acknowledgement failed"
		}
		_ = services.Journal.Save(context.WithoutCancel(r.Context()), intent)
		writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": intent.ID, "status": intent.Status})
		return
	}
	active, err := services.Providers.Publish(provider.ID, number, expected)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	services.record(requestActor(r), "provider", provider.ID, "publish", "applied")
	resultBytes, _ := json.Marshal(active)
	intent.Status = deployment.StatusApplied
	intent.Views.Observed = &deployment.StateRecord{Revision: strconv.FormatInt(number, 10), Status: "applied", Data: resultBytes, At: time.Now().UTC()}
	if err := services.Journal.Save(context.WithoutCancel(r.Context()), intent); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": intent.ID, "revision": active, "status": "applied"})
}

func parseExpected(r *http.Request) int64 { n, _ := expectedRevision(r); return n }

func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-EgressDeck-Preview-Scope", "caller-supplied-draft")
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var input policy.CompileInput
	if !decodeJSON(w, r, &input) {
		return
	}
	result, err := policy.Compile(input)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (s *Server) explain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var request struct {
		Manifest policy.Manifest `json:"manifest"`
		Packet   policy.Packet   `json:"packet"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	writeJSON(w, http.StatusOK, policy.Explain(request.Manifest, request.Packet))
}

func (s *Server) operations(w http.ResponseWriter, r *http.Request) {
	services := s.servicesOrDefault()
	if r.Method == http.MethodGet {
		list, err := services.Runner.List(r.Context())
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeCollection(w, r, publicOperations(list), nil)
		return
	}
	if r.Method == http.MethodPost {
		var request deployment.Request
		if !decodeJSON(w, r, &request) {
			return
		}
		if request.IdempotencyKey == "" {
			request.IdempotencyKey = r.Header.Get("Idempotency-Key")
		}
		if request.Target.Kind != "gateway" || !services.PolicyApplyEnabled {
			writeUnsupported(w, "policy.apply_generation", "use the typed lifecycle endpoint for the configured mutation")
			return
		}
		if services.ExecutorFactory == nil {
			writeUnsupported(w, "policy.apply_generation", "no remote deployment executor is configured")
			return
		}
		executor := services.ExecutorFactory(request.Target)
		if executor == nil {
			writeUnsupported(w, "policy.apply_generation", "remote deployment target is unavailable")
			return
		}
		op, err := services.Runner.Submit(r.Context(), request, executor)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, publicOperation(op))
		return
	}
	methodNotAllowed(w, "GET, POST")
}
func (s *Server) operation(w http.ResponseWriter, r *http.Request) {
	services := s.servicesOrDefault()
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	op, err := services.Runner.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, publicOperation(op))
}
func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	services := s.servicesOrDefault()
	services.mu.RLock()
	events := append([]AuditEvent(nil), services.audit...)
	services.mu.RUnlock()
	writeCollection(w, r, events, nil)
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	s.eventsFeed(w, r)
}

func writeUnsupported(w http.ResponseWriter, capability, message string) {
	writeJSON(w, http.StatusNotImplemented, map[string]any{"error": map[string]string{"code": "unsupported_capability", "capability": capability, "message": message}})
}
func writeServiceError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, domain.ErrNotFound) || errors.Is(err, deployment.ErrNotFound) || errors.Is(err, outbounds.ErrGroupNotFound) {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	if errors.Is(err, domain.ErrConflict) || errors.Is(err, deployment.ErrConflict) {
		writeError(w, http.StatusPreconditionFailed, "revision_conflict", err.Error())
		return
	}
	var validation *domain.ValidationError
	if errors.As(err, &validation) {
		writeError(w, http.StatusUnprocessableEntity, "validation_error", validation.Error())
		return
	}
	var policyValidation *policy.ValidationError
	if errors.As(err, &policyValidation) {
		writeError(w, http.StatusUnprocessableEntity, "validation_error", policyValidation.Error())
		return
	}
	writeError(w, http.StatusBadRequest, "request_error", err.Error())
}
