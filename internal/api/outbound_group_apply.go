package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
)

type GroupApplyIntent struct {
	Group outbounds.Group `json:"group"`
}
type GroupApplyReadback struct {
	GroupID    string   `json:"group_id"`
	Revision   int64    `json:"revision"`
	NodeIDs    []string `json:"node_ids"`
	Generation int64    `json:"generation"`
}

func groupApplyIntent(group outbounds.Group) GroupApplyIntent {
	group.AppliedRevision, group.ObservedRevision, group.AppliedGeneration, group.ObservedGeneration = 0, 0, 0, 0
	group.AppliedNodeIDs, group.ObservedNodeIDs = nil, nil
	group.CreatedAt, group.UpdatedAt = time.Time{}, time.Time{}
	return GroupApplyIntent{Group: group}
}

// outboundGroupApply is a separate runtime lifecycle from provider
// publication. It allows candidate membership to be deployed while provider
// content and its immutable revision remain unchanged.
func (s *Server) outboundGroupApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var request struct{}
	if !decodeJSON(w, r, &request) {
		return
	}
	services := s.servicesOrDefault()
	id := r.PathValue("id")
	group, err := services.Outbounds.Get(id)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if services.GroupPublisher == nil || services.GroupReadback == nil {
		writeUnsupported(w, "group.publish_hot", "gateway outbound-group publication adapter is unavailable")
		return
	}
	expected, ok := expectedRuntimeRevision(r)
	if !ok {
		writeError(w, http.StatusPreconditionRequired, "revision_required", "If-Match is required and must equal the desired group revision")
		return
	}
	if expected != group.Revision {
		writeStoreError(w, domain.ErrConflict)
		return
	}
	if len(group.NodeIDs) == 0 {
		writeServiceError(w, outbounds.ErrNoCandidates)
		return
	}
	intentData, _ := json.Marshal(groupApplyIntent(group))
	requestHash := privateRequestHash(json.RawMessage(intentData))
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		if old, lookupErr := services.Journal.FindByIdempotency(r.Context(), deployment.Target{Kind: "outbound_group", ID: id}, key); lookupErr == nil {
			if old.Action != "group_apply" || old.RequestHash != requestHash {
				writeError(w, http.StatusConflict, "idempotency_conflict", "idempotency key is bound to another group configuration")
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": old.ID, "status": old.Status})
			return
		}
	}
	if err := services.rejectUnknownTarget(r.Context(), deployment.Target{Kind: "outbound_group", ID: id}); err != nil {
		writeError(w, http.StatusConflict, "outcome_unknown", err.Error())
		return
	}
	target := deployment.Target{Kind: "outbound_group", ID: id}
	fence, err := services.Journal.NextFence(r.Context(), target)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	intent, err := services.Journal.Create(r.Context(), deployment.Operation{Target: target, FenceToken: fence.Token, Action: "group_apply", RequestHash: requestHash, IdempotencyKey: r.Header.Get("Idempotency-Key"), Status: deployment.StatusApplying, Views: deployment.StateViews{Desired: &deployment.StateRecord{Revision: strconv.FormatInt(group.Revision, 10), Status: "requested", Data: intentData, At: time.Now().UTC()}}})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	snapshot, pubErr := services.GroupPublisher(operationMutationContext(r.Context(), intent), group)
	if pubErr != nil {
		if gateway.IsDefiniteRejection(pubErr) {
			intent.Status = deployment.StatusFailed
			intent.Error = pubErr.Error()
			if err := services.Journal.Save(context.WithoutCancel(r.Context()), intent); err != nil {
				writeServiceError(w, err)
				return
			}
			writeServiceError(w, pubErr)
			return
		}
		intent.Status = deployment.StatusOutcomeUnknown
		intent.Error = "group publication result is unknown; gateway readback is required"
		_ = services.Journal.Save(context.WithoutCancel(r.Context()), intent)
		writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": intent.ID, "status": intent.Status})
		return
	}
	observed, exists := snapshot.Groups[id]
	if !exists || observed.Revision != group.Revision || !sameStringSet(observed.NodeIDs, group.NodeIDs) {
		intent.Status = deployment.StatusOutcomeUnknown
		intent.Error = "group publication readback differs from desired configuration"
		_ = services.Journal.Save(context.WithoutCancel(r.Context()), intent)
		writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": intent.ID, "status": intent.Status})
		return
	}
	if _, err := services.Outbounds.ObserveConfiguration(id, group.Revision, observed.NodeIDs, snapshot.Generation); err != nil {
		intent.Status = deployment.StatusOutcomeUnknown
		intent.Error = "group publication readback could not be committed"
		_ = services.Journal.Save(context.WithoutCancel(r.Context()), intent)
		writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": intent.ID, "status": intent.Status})
		return
	}
	if err := services.Persist(r.Context()); err != nil {
		intent.Status = deployment.StatusOutcomeUnknown
		intent.Error = "group lifecycle persistence failed"
		_ = services.Journal.Save(context.WithoutCancel(r.Context()), intent)
		writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": intent.ID, "status": intent.Status})
		return
	}
	resultData, _ := json.Marshal(GroupApplyReadback{GroupID: id, Revision: group.Revision, NodeIDs: append([]string(nil), observed.NodeIDs...), Generation: snapshot.Generation})
	intent.Status = deployment.StatusApplied
	intent.Views.Applied = &deployment.StateRecord{Revision: strconv.FormatInt(group.Revision, 10), Status: "applied", Data: resultData, At: time.Now().UTC()}
	intent.Views.Observed = &deployment.StateRecord{Revision: strconv.FormatInt(group.Revision, 10), Status: "verified", Data: resultData, At: time.Now().UTC()}
	if err := services.Journal.Save(context.WithoutCancel(r.Context()), intent); err != nil {
		writeServiceError(w, err)
		return
	}
	services.record(requestActor(r), "outbound_group", id, "apply", "verified")
	group, _ = services.Outbounds.Get(id)
	writeJSON(w, http.StatusAccepted, map[string]any{"operation_id": intent.ID, "status": intent.Status, "group": services.outboundGroupView(group)})
}
