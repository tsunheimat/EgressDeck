package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

const eventDocumentKey = "management-events/v1"

var eventIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,200}$`)

type eventFeedState struct {
	mu    sync.Mutex
	state *eventHistory
}
type eventHistory struct {
	Version  int               `json:"version"`
	Stream   string            `json:"stream"`
	Sequence uint64            `json:"sequence"`
	Events   []ManagementEvent `json:"events"`
	Seen     map[string]string `json:"seen"`
}
type eventDocument struct {
	Version  int              `json:"version"`
	Envelope secrets.Envelope `json:"envelope"`
}
type eventCandidate struct {
	key   string
	event ManagementEvent
}

// projectEvents serializes projection and persistence. GET materializes only
// this management feed; it never invokes an external adapter. Source records
// are read from their acknowledged persistence boundary when configured.
func (s *Services) projectEvents(ctx context.Context) (eventHistory, bool, error) {
	s.eventFeed.mu.Lock()
	defer s.eventFeed.mu.Unlock()
	s.persistence.mu.Lock()
	documents, vault := s.persistence.documents, s.persistence.vault
	s.persistence.mu.Unlock()
	durable := documents != nil
	var current eventHistory
	if s.eventFeed.state != nil {
		current = *s.eventFeed.state
		current.Events = append([]ManagementEvent(nil), current.Events...)
	} else {
		current = eventHistory{Version: 1, Stream: domain.NewID(), Events: []ManagementEvent{}, Seen: map[string]string{}}
		if durable {
			raw, err := documents.LoadDocument(ctx, eventDocumentKey)
			if err != nil && !errors.Is(err, domain.ErrNotFound) {
				return eventHistory{}, durable, err
			}
			if err == nil {
				var doc eventDocument
				if decodeLifecycleJSON(raw, &doc) != nil || doc.Version != 1 {
					return eventHistory{}, durable, errors.New("invalid event document")
				}
				plain, err := vault.Open(eventDocumentKey, doc.Envelope)
				if err != nil {
					return eventHistory{}, durable, err
				}
				decodeErr := decodeLifecycleJSON(plain, &current)
				clear(plain)
				if decodeErr != nil || !validEventHistory(current) {
					return eventHistory{}, durable, errors.New("invalid event history")
				}
			}
		}
	}
	candidates, err := s.eventCandidates(ctx, documents, vault)
	if err != nil {
		return eventHistory{}, durable, err
	}
	seen := make(map[string]string, len(candidates))
	changed := s.eventFeed.state == nil
	for _, candidate := range candidates {
		encoded, _ := json.Marshal(candidate.event)
		digest := sha256.Sum256(encoded)
		fingerprint := hex.EncodeToString(digest[:])
		seen[candidate.key] = fingerprint
		if current.Seen[candidate.key] == fingerprint {
			continue
		}
		if current.Sequence == ^uint64(0) {
			return eventHistory{}, durable, errors.New("event sequence exhausted")
		}
		current.Sequence++
		candidate.event.Sequence = current.Sequence
		candidate.event.ID = encodeEventCursor(current.Stream, current.Sequence)
		current.Events = append(current.Events, candidate.event)
		changed = true
	}
	if len(seen) != len(current.Seen) {
		changed = true
	}
	current.Seen = seen
	if len(current.Events) > eventRetention {
		current.Events = append([]ManagementEvent(nil), current.Events[len(current.Events)-eventRetention:]...)
	}
	if durable && changed {
		plain, err := json.Marshal(current)
		if err != nil {
			return eventHistory{}, durable, err
		}
		envelope, err := vault.Seal(eventDocumentKey, plain)
		clear(plain)
		if err != nil {
			return eventHistory{}, durable, err
		}
		raw, err := json.Marshal(eventDocument{Version: 1, Envelope: envelope})
		if err != nil {
			return eventHistory{}, durable, err
		}
		if err := documents.SaveDocument(ctx, eventDocumentKey, raw); err != nil {
			return eventHistory{}, durable, err
		}
	}
	if err := ctx.Err(); err != nil {
		return eventHistory{}, durable, err
	}
	s.eventFeed.state = &current
	return current, durable, nil
}

func validEventHistory(h eventHistory) bool {
	if h.Version != 1 || !eventIdentifierPattern.MatchString(h.Stream) || h.Seen == nil || len(h.Seen) > 2*eventRetention || len(h.Events) > eventRetention {
		return false
	}
	for i, event := range h.Events {
		if event.Sequence == 0 || event.Sequence > h.Sequence || event.ID != encodeEventCursor(h.Stream, event.Sequence) {
			return false
		}
		if i > 0 && h.Events[i-1].Sequence+1 != event.Sequence {
			return false
		}
	}
	return len(h.Events) == 0 && h.Sequence == 0 || len(h.Events) > 0 && h.Events[len(h.Events)-1].Sequence == h.Sequence
}

func (s *Services) eventCandidates(ctx context.Context, documents store.DocumentStore, vault *secrets.Vault) ([]eventCandidate, error) {
	if s.Journal == nil {
		return nil, errors.New("missing operation journal")
	}
	operations, err := s.Journal.List(ctx)
	if err != nil {
		return nil, err
	}
	audit, err := s.eventAudit(ctx, documents, vault)
	if err != nil {
		return nil, err
	}
	sort.Slice(operations, func(i, j int) bool {
		a, b := operations[i].UpdatedAt, operations[j].UpdatedAt
		if a.Equal(b) {
			return operations[i].ID < operations[j].ID
		}
		return a.Before(b)
	})
	if len(operations) > eventRetention {
		operations = operations[len(operations)-eventRetention:]
	}
	if len(audit) > eventRetention {
		audit = audit[len(audit)-eventRetention:]
	}
	candidates := make([]eventCandidate, 0, len(operations)+len(audit))
	for _, op := range operations {
		at := op.UpdatedAt
		if at.IsZero() {
			at = op.CreatedAt
		}
		candidates = append(candidates, eventCandidate{key: "operation:" + op.ID, event: ManagementEvent{Type: "operation.changed", ResourceType: eventLabel(op.Target.Kind, "provider", "gateway", "opnsense", "outbound_group", "guard", "firewall", "device"), ResourceID: eventID(op.Target.ID), Action: eventLabel(op.Action, "refresh", "stage", "publish", "selection", "apply", "enroll", "enable", "move_group", "bypass", "deploy", "policy.apply_generation", "provider.publish_hot", "selection.set_runtime"), Status: eventLabel(string(op.Status), "draft", "validated", "staged", "applying", "verifying", "applied", "partially_applied", "failed", "outcome_unknown"), OperationID: eventID(op.ID), OccurredAt: at}})
	}
	for _, record := range audit {
		event := ManagementEvent{Type: "audit.recorded", ResourceType: eventLabel(record.ObjectType, "provider", "outbound_group", "policy", "rule_set", "firewall_binding", "device", "device_group", "gateway"), ResourceID: eventID(record.ObjectID), Action: eventLabel(record.Action, "create", "update", "delete", "refresh", "stage", "publish", "selection", "attach", "apply", "enroll", "bypass"), Status: eventLabel(record.Outcome, "accepted", "observed", "verified", "applied", "pending", "staged", "failed", "error"), OccurredAt: record.CreatedAt}
		if record.ObjectType == "management_request" {
			event.ResourceType = "management_request"
			event.ResourceID = ""
			event.Action = safeManagementAction(record.Action)
			event.Status = "unknown"
			if code, err := strconv.Atoi(record.Outcome); err == nil && code >= 100 && code <= 599 {
				event.Status = "http_" + strconv.Itoa(code)
			}
		}
		candidates = append(candidates, eventCandidate{key: "audit:" + record.ID, event: event})
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.event.OccurredAt.Equal(b.event.OccurredAt) {
			return a.key < b.key
		}
		return a.event.OccurredAt.Before(b.event.OccurredAt)
	})
	return candidates, nil
}

func safeManagementAction(action string) string {
	parts := strings.SplitN(action, " ", 2)
	if len(parts) != 2 || eventLabel(parts[0], "POST", "PUT", "PATCH", "DELETE") == "unknown" {
		return "unknown"
	}
	for _, route := range []string{"/api/v1/devices", "/api/v1/devices/{id}", "/api/v1/device-groups", "/api/v1/device-groups/{id}", "/api/v1/providers", "/api/v1/providers/{id}", "/api/v1/providers/{id}/stage", "/api/v1/providers/{id}/refresh", "/api/v1/providers/{id}/schedule", "/api/v1/providers/{id}/revisions/{revision}/apply", "/api/v1/gateways", "/api/v1/gateways/{id}", "/api/v1/outbound-groups", "/api/v1/outbound-groups/{id}", "/api/v1/outbound-groups/{id}/selection", "/api/v1/policies", "/api/v1/policies/{id}", "/api/v1/policies/explain", "/api/v1/rule-sets", "/api/v1/rule-sets/{id}", "/api/v1/deployments/preview", "/api/v1/deployments/plan", "/api/v1/deployments/enrollment", "/api/v1/firewall-bindings", "/api/v1/firewall-bindings/{id}/readback", "/api/v1/operations"} {
		if route == parts[1] {
			return action
		}
	}
	return "unknown"
}

func (s *Services) eventAudit(ctx context.Context, documents store.DocumentStore, vault *secrets.Vault) ([]AuditEvent, error) {
	if documents == nil {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return append([]AuditEvent(nil), s.audit...), nil
	}
	raw, err := documents.LoadDocument(ctx, lifecycleDocumentKey)
	if errors.Is(err, domain.ErrNotFound) {
		return []AuditEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	var doc lifecycleDocument
	if decodeLifecycleJSON(raw, &doc) != nil || doc.Version != 1 {
		return nil, errors.New("invalid lifecycle document")
	}
	plain, err := vault.Open(lifecycleDocumentKey, doc.Envelope)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var snapshot struct {
		Version int          `json:"version"`
		Audit   []AuditEvent `json:"audit"`
	}
	if json.Unmarshal(plain, &snapshot) != nil || snapshot.Version != 1 || len(snapshot.Audit) > eventRetention {
		return nil, errors.New("invalid durable audit")
	}
	return snapshot.Audit, nil
}

func eventID(value string) string {
	if eventIdentifierPattern.MatchString(value) {
		return value
	}
	return "redacted"
}
func eventLabel(value string, allowed ...string) string {
	for _, label := range allowed {
		if value == label {
			return value
		}
	}
	return "unknown"
}
