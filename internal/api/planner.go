package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/policy"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

// PlanRequest deliberately accepts no policy, source addresses, capability
// claims, or partial membership. The complete gateway scope comes from storage.
type PlanRequest struct {
	GatewayID           string `json:"gateway_id"`
	PreviousOperationID string `json:"previous_operation_id,omitempty"`
}

type ResourceRevision struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	SHA256   string `json:"sha256"`
}

type PlanPrevious struct {
	Status       string `json:"status"`
	OperationID  string `json:"operation_id,omitempty"`
	ManifestHash string `json:"manifest_hash,omitempty"`
}

type PlanTarget struct {
	GatewayID         string               `json:"gateway_id"`
	ObservationStatus string               `json:"observation_status"`
	Capabilities      gateway.Capabilities `json:"capabilities"`
}

// InventoryPlan is an immutable local snapshot, not authorization to enroll
// clients or evidence of observed/verified runtime state. Checksum covers every
// field except itself and CreatedAt; a repeat with identical inputs reuses it.
type InventoryPlan struct {
	Version           int                   `json:"version"`
	Checksum          string                `json:"checksum"`
	CreatedAt         time.Time             `json:"created_at"`
	Scope             string                `json:"scope"`
	Consistency       string                `json:"consistency"`
	ResourceRevisions []ResourceRevision    `json:"resource_revisions"`
	Input             policy.CompileInput   `json:"input"`
	Compilation       *policy.CompileResult `json:"compilation,omitempty"`
	NativeArtifact    *policy.DAEArtifact   `json:"native_artifact,omitempty"`
	Valid             bool                  `json:"valid"`
	Deployable        bool                  `json:"deployable"`
	Diagnostics       []policy.Diagnostic   `json:"diagnostics,omitempty"`
	Blockers          []policy.Diagnostic   `json:"blockers"`
	Target            PlanTarget            `json:"target"`
	Previous          PlanPrevious          `json:"previous"`
}

func (s *Server) plan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var request PlanRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.GatewayID == "" || strings.TrimSpace(request.GatewayID) != request.GatewayID {
		writeError(w, http.StatusUnprocessableEntity, "gateway_required", "gateway_id must identify a stored gateway")
		return
	}
	documents, ok := s.Store.(store.DocumentStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "plan_storage_unavailable", "immutable plan storage is unavailable")
		return
	}
	immutable, ok := s.Store.(store.ImmutableDocumentStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "plan_storage_unavailable", "atomic immutable plan storage is unavailable")
		return
	}
	input, revisions, err := s.capturePlanResources(r.Context(), request.GatewayID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	previous, previousInfo, err := s.previousPlanManifest(r.Context(), request)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	input.Previous = previous
	plan := InventoryPlan{Version: 1, Scope: "gateway", Consistency: "revision_rechecked", Input: input,
		ResourceRevisions: revisions, Previous: previousInfo,
		Target: PlanTarget{GatewayID: request.GatewayID, ObservationStatus: "unavailable"},
		Blockers: []policy.Diagnostic{planBlocker("native_artifact_incomplete", "A routing artifact requires gateway globals, outbound credentials, DNS and native validation before application."),
			planBlocker("enrollment_unqualified", "Client enrollment requires independently verified gateway and firewall guards, address coverage and packet-path checks.")}}
	value, _ := s.Store.GetGateway(r.Context(), request.GatewayID)
	if observer := s.servicesOrDefault().GatewayObserver; observer != nil {
		capabilities, _, observationErr := observer(r.Context(), value)
		if observationErr != nil {
			plan.Target.ObservationStatus = "failed"
		} else {
			plan.Target.ObservationStatus = "observed"
			plan.Target.Capabilities = capabilities
		}
	}
	for _, required := range []gateway.CapabilityName{gateway.CapabilityPolicyValidate, gateway.CapabilityPolicyApply} {
		if !plan.Target.Capabilities.Has(required) {
			plan.Blockers = append(plan.Blockers, planBlocker("capability_unavailable", "Target has not advertised "+string(required)+"."))
		}
	}
	// Syntax compilation uses the model's matcher set. Capability observation
	// is separate: no current adapter exposes qualified IPv6/transport coverage.
	// Strict compilation remains fail-closed while that proof is unavailable.
	compiled, compileErr := policy.Compile(input)
	if compileErr != nil {
		var validation *policy.ValidationError
		if !errors.As(compileErr, &validation) {
			writeServiceError(w, compileErr)
			return
		}
		plan.Diagnostics = validation.Problems
	} else {
		plan.Valid, plan.Compilation = true, &compiled
		artifact, renderErr := policy.RenderDAE(input)
		if renderErr == nil {
			plan.NativeArtifact = &artifact
		} else {
			plan.Blockers = append(plan.Blockers, planBlocker("native_render_unsupported", renderErr.Error()))
		}
	}
	plan.Blockers = append(plan.Blockers, planBlocker("coverage_unqualified", "Runtime transport and IPv6 enforcement coverage has not been qualified for this target."))
	_, check, err := s.capturePlanResources(r.Context(), request.GatewayID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if privateRequestHash(revisions) != privateRequestHash(check) {
		writeError(w, http.StatusConflict, "snapshot_changed", "inventory changed while planning; create a new plan")
		return
	}
	plan.Checksum = inventoryPlanChecksum(plan)
	key := "plans/v1/" + plan.Checksum
	stored, err := documents.LoadDocument(r.Context(), key)
	if err == nil {
		var existing InventoryPlan
		if json.Unmarshal(stored, &existing) != nil || existing.Checksum != plan.Checksum || inventoryPlanChecksum(existing) != plan.Checksum {
			writeError(w, http.StatusServiceUnavailable, "plan_corrupt", "stored plan checksum does not match its contents")
			return
		}
		plan = existing
	} else if !errors.Is(err, domain.ErrNotFound) {
		writeError(w, http.StatusServiceUnavailable, "plan_storage_unavailable", "immutable plan storage is unavailable")
		return
	} else {
		plan.CreatedAt = time.Now().UTC()
		data, _ := json.Marshal(plan)
		if err := immutable.CreateDocument(r.Context(), key, data); errors.Is(err, domain.ErrConflict) {
			stored, loadErr := documents.LoadDocument(r.Context(), key)
			var existing InventoryPlan
			if loadErr != nil || json.Unmarshal(stored, &existing) != nil || existing.Checksum != plan.Checksum || inventoryPlanChecksum(existing) != plan.Checksum {
				writeError(w, http.StatusServiceUnavailable, "plan_corrupt", "concurrently stored plan checksum does not match its contents")
				return
			}
			plan = existing
		} else if err != nil {
			writeError(w, http.StatusServiceUnavailable, "plan_persistence_failed", "immutable plan could not be persisted")
			return
		}
	}
	w.Header().Set("ETag", `"`+plan.Checksum+`"`)
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) getPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	id := r.PathValue("id")
	if decoded, err := hex.DecodeString(id); err != nil || len(decoded) != 32 || strings.ToLower(id) != id {
		writeError(w, http.StatusBadRequest, "invalid_plan_id", "plan id must be its lowercase SHA-256 checksum")
		return
	}
	documents, ok := s.Store.(store.DocumentStore)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "plan_storage_unavailable", "immutable plan storage is unavailable")
		return
	}
	data, err := documents.LoadDocument(r.Context(), "plans/v1/"+id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	var plan InventoryPlan
	if json.Unmarshal(data, &plan) != nil || plan.Checksum != id || inventoryPlanChecksum(plan) != id {
		writeError(w, http.StatusServiceUnavailable, "plan_corrupt", "stored plan checksum does not match its contents")
		return
	}
	w.Header().Set("ETag", `"`+id+`"`)
	writeJSON(w, http.StatusOK, plan)
}

func inventoryPlanChecksum(plan InventoryPlan) string {
	plan.Checksum, plan.CreatedAt = "", time.Time{}
	return privateRequestHash(plan)
}

func planBlocker(code, message string) policy.Diagnostic {
	return policy.Diagnostic{Severity: policy.SeverityError, Code: code, Message: message}
}

func (s *Server) capturePlanResources(ctx context.Context, gatewayID string) (policy.CompileInput, []ResourceRevision, error) {
	input := policy.CompileInput{Gateway: policy.Gateway{ID: gatewayID, SupportsIPv6: true,
		SupportedTransports: []policy.Transport{policy.TransportTCP, policy.TransportUDP, policy.TransportQUIC}},
		Options: policy.CompileOptions{UncontrolledIPv6: true}}
	var revisions []ResourceRevision
	bind := func(kind, id string, revision int64, value any) {
		revisions = append(revisions, ResourceRevision{Kind: kind, ID: id, Revision: revision, SHA256: privateRequestHash(value)})
	}
	target, err := s.Store.GetGateway(ctx, gatewayID)
	if err != nil {
		return input, nil, err
	}
	input.Gateway.Name = target.Name
	bind("gateway", target.ID, target.Revision, target)
	groups, err := s.Store.ListDeviceGroups(ctx)
	if err != nil {
		return input, nil, err
	}
	devices, err := s.Store.ListDevices(ctx)
	if err != nil {
		return input, nil, err
	}
	groupIDs, policyIDs, ruleSetIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, group := range groups {
		if group.GatewayID != gatewayID {
			continue
		}
		groupIDs[group.ID], policyIDs[group.PolicyID] = true, true
		bind("device_group", group.ID, group.Revision, group)
		input.DeviceGroups = append(input.DeviceGroups, policy.DeviceGroup{ID: group.ID, Name: group.Name, GatewayID: gatewayID, PolicyID: group.PolicyID, Enabled: group.Enabled})
	}
	for _, device := range devices {
		if !groupIDs[device.PrimaryGroupID] {
			continue
		}
		exceptions, err := decodeDeviceExceptions(device.Exceptions)
		if err != nil {
			return input, nil, err
		}
		item := policy.Device{ID: device.ID, Name: device.Name, GroupID: device.PrimaryGroupID, Enabled: true, Exceptions: exceptions}
		for _, address := range device.Addresses {
			item.Addresses = append(item.Addresses, policy.DeviceAddress{Address: address.Address, Family: policy.AddressFamily(address.Family), Provenance: address.Provenance})
		}
		input.Devices = append(input.Devices, item)
		bind("device", device.ID, device.Revision, device)
	}
	services := s.servicesOrDefault()
	services.mu.RLock()
	for id := range policyIDs {
		if item, ok := services.policies[id]; ok {
			input.Policies = append(input.Policies, clonePolicyResource(item))
			bind("policy", id, item.Revision, item)
			for _, id := range item.RuleSetIDs {
				ruleSetIDs[strings.TrimSpace(id)] = true
			}
			for _, entry := range item.Entries {
				if entry.RuleSetID != "" {
					ruleSetIDs[strings.TrimSpace(entry.RuleSetID)] = true
				}
			}
		}
	}
	for id := range ruleSetIDs {
		if item, ok := services.ruleSets[id]; ok {
			input.RuleSets = append(input.RuleSets, clonePolicyResource(item))
			bind("rule_set", id, item.Revision, item)
		}
	}
	services.mu.RUnlock()
	for _, group := range services.Outbounds.List() {
		if group.GatewayID != gatewayID {
			continue
		}
		input.OutboundGroups = append(input.OutboundGroups, policy.OutboundGroup{ID: group.ID, Name: group.Name, NodeIDs: group.NodeIDs})
		bind("outbound_group", group.ID, group.Revision, group)
		for _, selection := range services.Outbounds.Selections(group.ID) {
			bind("outbound_selection", group.ID+"/"+selection.Scope.Transport, selection.Revision, selection)
		}
	}
	sort.Slice(input.Policies, func(i, j int) bool { return input.Policies[i].ID < input.Policies[j].ID })
	sort.Slice(input.RuleSets, func(i, j int) bool { return input.RuleSets[i].ID < input.RuleSets[j].ID })
	sort.Slice(revisions, func(i, j int) bool {
		if revisions[i].Kind != revisions[j].Kind {
			return revisions[i].Kind < revisions[j].Kind
		}
		return revisions[i].ID < revisions[j].ID
	})
	return input, revisions, nil
}

// Only an acknowledged applied record containing a hash-checked normalized
// manifest is eligible. A desired snapshot or a native-config-only operation
// cannot be promoted into a previous applied compiler manifest.
func (s *Server) previousPlanManifest(ctx context.Context, request PlanRequest) (*policy.Manifest, PlanPrevious, error) {
	info := PlanPrevious{Status: "unavailable"}
	operations, err := s.servicesOrDefault().Journal.List(ctx)
	if err != nil {
		return nil, info, err
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i].UpdatedAt.After(operations[j].UpdatedAt) })
	found := request.PreviousOperationID == ""
	for _, operation := range operations {
		if request.PreviousOperationID != "" && operation.ID != request.PreviousOperationID {
			continue
		}
		found = true
		if operation.Target != (deployment.Target{Kind: "gateway", ID: request.GatewayID}) || operation.Status != deployment.StatusApplied {
			if request.PreviousOperationID != "" {
				return nil, info, &domain.ValidationError{Problems: []string{"previous operation is not an applied operation for this gateway"}}
			}
			continue
		}
		if operation.Views.Applied == nil {
			return nil, PlanPrevious{Status: "manifest_unavailable", OperationID: operation.ID}, nil
		}
		var manifest policy.Manifest
		if json.Unmarshal(operation.Views.Applied.Data, &manifest) != nil || manifest.Version != 1 || manifest.GatewayID != request.GatewayID || manifest.ContentHash == "" {
			// The latest applied operation has no normalized compiler snapshot.
			// Never silently compare against an older generation instead.
			return nil, PlanPrevious{Status: "manifest_unavailable", OperationID: operation.ID}, nil
		}
		hash := manifest.ContentHash
		manifest.ContentHash = ""
		if privateRequestHash(manifest) != hash {
			return nil, info, errors.New("previous applied manifest checksum is invalid")
		}
		manifest.ContentHash = hash
		return &manifest, PlanPrevious{Status: "applied", OperationID: operation.ID, ManifestHash: hash}, nil
	}
	if !found {
		return nil, info, domain.ErrNotFound
	}
	return nil, info, nil
}

func decodeDeviceExceptions(raw []json.RawMessage) ([]policy.Rule, error) {
	rules := make([]policy.Rule, 0, len(raw))
	for i, encoded := range raw {
		var rule policy.Rule
		if err := decodeLifecycleJSON(encoded, &rule); err != nil || len(encoded) == 0 || strings.TrimSpace(string(encoded))[0] != '{' {
			return nil, &domain.ValidationError{Problems: []string{fmt.Sprintf("exceptions[%d] must be a typed policy rule with known fields", i)}}
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (s *Server) validateDeviceExceptions(w http.ResponseWriter, d domain.Device) bool {
	rules, err := decodeDeviceExceptions(d.Exceptions)
	if err == nil && len(rules) > 0 {
		services := s.servicesOrDefault()
		services.mu.RLock()
		input := policyResourceInputLocked(services)
		services.mu.RUnlock()
		input.Devices = []policy.Device{{ID: "device-validation", Exceptions: rules}}
		_, err = policy.Compile(input)
	}
	if err != nil {
		writeServiceError(w, err)
		return false
	}
	return true
}
