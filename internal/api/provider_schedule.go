package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/deployment"
	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/secrets"
)

const providerScheduleDocumentKey = "provider-schedules/v1"
const minProviderInterval = 300
const maxProviderInterval = 604800

// ProviderSchedule is a controller schedule, not a publication policy. Revision
// changes only when the administrator changes settings; timer progress does not
// invalidate an administrator's settings edit.
type ProviderSchedule struct {
	ProviderID      string     `json:"provider_id"`
	Revision        int64      `json:"revision"`
	Enabled         bool       `json:"enabled"`
	IntervalSeconds int        `json:"interval_seconds"`
	AutoApply       bool       `json:"auto_apply"`
	Eligible        bool       `json:"eligible"`
	NextDueAt       *time.Time `json:"next_due_at,omitempty"`
	LastAttemptAt   *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt   *time.Time `json:"last_success_at,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	LastOperationID string     `json:"last_operation_id,omitempty"`
	Running         bool       `json:"running"`
}

type providerScheduler struct {
	mu        sync.Mutex
	schedules map[string]ProviderSchedule
	started   bool
	cancel    context.CancelFunc
	done      chan struct{}
}

type scheduleSnapshot struct {
	Version   int                         `json:"version"`
	Schedules map[string]ProviderSchedule `json:"schedules"`
}

func (s *Server) providerSchedules(ctx context.Context) (*providerScheduler, error) {
	s.schedulerMu.Lock()
	defer s.schedulerMu.Unlock()
	if s.scheduler != nil {
		return s.scheduler, nil
	}
	manager := &providerScheduler{schedules: map[string]ProviderSchedule{}}
	services := s.servicesOrDefault()
	services.persistence.mu.Lock()
	documents, vault := services.persistence.documents, services.persistence.vault
	services.persistence.mu.Unlock()
	if documents != nil {
		raw, err := documents.LoadDocument(ctx, providerScheduleDocumentKey)
		if err != nil && !errors.Is(err, domain.ErrNotFound) {
			return nil, errors.New("load provider schedules failed")
		}
		if err == nil {
			var document lifecycleDocument
			if decodeLifecycleJSON(raw, &document) != nil || document.Version != 1 {
				return nil, errors.New("invalid provider schedule document")
			}
			if vault == nil {
				return nil, secrets.ErrKeyUnavailable
			}
			plain, err := vault.Open(providerScheduleDocumentKey, document.Envelope)
			if err != nil {
				return nil, errors.New("decrypt provider schedules failed")
			}
			defer clear(plain)
			var snapshot scheduleSnapshot
			if decodeLifecycleJSON(plain, &snapshot) != nil || snapshot.Version != 1 || snapshot.Schedules == nil {
				return nil, errors.New("invalid provider schedule snapshot")
			}
			for id, item := range snapshot.Schedules {
				if item.ProviderID != id || id == "" || item.Revision < 1 || item.IntervalSeconds < minProviderInterval || item.IntervalSeconds > maxProviderInterval || item.AutoApply || (item.Enabled && item.NextDueAt == nil) || (!item.Enabled && item.NextDueAt != nil) {
					return nil, errors.New("invalid persisted provider schedule")
				}
				if item.Running {
					item.Running = false
					item.LastError = "scheduled refresh interrupted before completion; next due attempt retained"
				}
				snapshot.Schedules[id] = item
			}
			manager.schedules = snapshot.Schedules
		}
	}
	s.scheduler = manager
	return manager, nil
}

// saveProviderSchedules is called under the shared management mutation lock.
// A failed schedule save freezes all writes; restart reloads committed state.
func (s *Server) saveProviderSchedules(ctx context.Context, manager *providerScheduler) error {
	services := s.servicesOrDefault()
	services.persistence.mu.Lock()
	documents, vault := services.persistence.documents, services.persistence.vault
	services.persistence.mu.Unlock()
	if documents == nil {
		return nil
	}
	manager.mu.Lock()
	plain, err := json.Marshal(scheduleSnapshot{Version: 1, Schedules: manager.schedules})
	manager.mu.Unlock()
	if err != nil {
		return err
	}
	defer clear(plain)
	if vault == nil {
		return secrets.ErrKeyUnavailable
	}
	envelope, err := vault.Seal(providerScheduleDocumentKey, plain)
	if err != nil {
		return err
	}
	document, err := json.Marshal(lifecycleDocument{Version: 1, Envelope: envelope})
	if err == nil {
		err = documents.SaveDocument(ctx, providerScheduleDocumentKey, document)
	}
	if err != nil {
		services.mutationBlocked = true
		return errors.New("persist provider schedules failed; controller writes are paused")
	}
	return nil
}

func remoteProvider(provider domain.Provider) bool {
	u, err := url.Parse(provider.Source)
	return err == nil && u.Host != "" && (u.Scheme == "https" || u.Scheme == "http")
}

func defaultProviderSchedule(id string) ProviderSchedule {
	return ProviderSchedule{ProviderID: id, IntervalSeconds: 3600}
}

func (s *Server) providerSchedule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		methodNotAllowed(w, "GET, PUT")
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
	manager, err := s.providerSchedules(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	manager.mu.Lock()
	current, ok := manager.schedules[provider.ID]
	manager.mu.Unlock()
	if !ok {
		current = defaultProviderSchedule(provider.ID)
	}
	current.Eligible = remoteProvider(provider)
	if r.Method == http.MethodGet {
		writeJSON(w, 200, current)
		return
	}
	expected, ok := expectedRuntimeRevision(r)
	if !ok {
		writeError(w, 428, "revision_required", "If-Match is required; use 0 for a new schedule")
		return
	}
	if expected != current.Revision {
		writeStoreError(w, domain.ErrConflict)
		return
	}
	var request struct {
		Enabled         bool `json:"enabled"`
		IntervalSeconds int  `json:"interval_seconds"`
		AutoApply       bool `json:"auto_apply"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.IntervalSeconds < minProviderInterval || request.IntervalSeconds > maxProviderInterval {
		writeError(w, 400, "invalid_interval", "interval_seconds must be between 300 and 604800")
		return
	}
	if request.AutoApply {
		writeUnsupported(w, "provider.schedule_auto_apply", "scheduled refresh stages revisions for review; automatic publication is unavailable")
		return
	}
	if request.Enabled && (!current.Eligible || !services.ProviderStageEnabled) {
		writeError(w, 409, "schedule_unavailable", "scheduled refresh requires a remote subscription and enabled provider staging")
		return
	}
	current.Enabled, current.IntervalSeconds = request.Enabled, request.IntervalSeconds
	current.Revision++
	if current.Enabled {
		next := time.Now().UTC().Add(time.Duration(current.IntervalSeconds) * time.Second)
		current.NextDueAt = &next
	} else {
		current.NextDueAt = nil
	}
	manager.mu.Lock()
	manager.schedules[provider.ID] = current
	manager.mu.Unlock()
	if err := s.saveProviderSchedules(r.Context(), manager); err != nil {
		writeError(w, 503, "persistence_failed", err.Error())
		return
	}
	services.record(requestActor(r), "provider", provider.ID, "schedule_update", "saved")
	writeJSON(w, 200, current)
}

// StartProviderScheduler validates and loads durable schedules after Services.Load.
// The passed context owns its lifetime. Missed intervals are coalesced into one
// attempt and next_due is committed before any fetch, including after restart.
func (s *Server) StartProviderScheduler(ctx context.Context) error {
	services := s.servicesOrDefault()
	services.mutationMu.Lock()
	manager, err := s.providerSchedules(ctx)
	if err == nil {
		err = s.saveProviderSchedules(ctx, manager)
	}
	services.mutationMu.Unlock()
	if err != nil {
		return err
	}
	manager.mu.Lock()
	if manager.started {
		manager.mu.Unlock()
		return errors.New("provider scheduler already started")
	}
	manager.started = true
	ctx, manager.cancel = context.WithCancel(ctx)
	done := make(chan struct{})
	manager.done = done
	manager.mu.Unlock()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		defer close(done)
		defer func() { manager.mu.Lock(); manager.started = false; manager.mu.Unlock() }()
		for {
			if ctx.Err() != nil {
				return
			}
			if err := s.runProviderSchedules(ctx, time.Now().UTC()); err != nil && s.Logger != nil {
				s.Logger.Printf("provider scheduler paused: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}

// StopProviderScheduler cancels a bounded in-flight fetch and waits until final
// lifecycle/schedule persistence has completed before storage may be closed.
func (s *Server) StopProviderScheduler() {
	s.schedulerMu.Lock()
	manager := s.scheduler
	s.schedulerMu.Unlock()
	if manager == nil {
		return
	}
	manager.mu.Lock()
	cancel, done := manager.cancel, manager.done
	manager.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (s *Server) runProviderSchedules(ctx context.Context, now time.Time) error {
	manager, err := s.providerSchedules(ctx)
	if err != nil {
		return err
	}
	manager.mu.Lock()
	ids := make([]string, 0, len(manager.schedules))
	for id, item := range manager.schedules {
		if item.Enabled && !item.Running && item.NextDueAt != nil && !item.NextDueAt.After(now) {
			ids = append(ids, id)
		}
	}
	manager.mu.Unlock()
	sort.Strings(ids)
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.runProviderSchedule(ctx, manager, id, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) runProviderSchedule(ctx context.Context, manager *providerScheduler, id string, now time.Time) error {
	services := s.servicesOrDefault()
	services.mutationMu.Lock()
	defer services.mutationMu.Unlock()
	if services.mutationBlocked {
		return errors.New("controller writes are paused after a persistence failure")
	}
	manager.mu.Lock()
	item := manager.schedules[id]
	if !item.Enabled || item.Running || item.NextDueAt == nil || item.NextDueAt.After(now) {
		manager.mu.Unlock()
		return nil
	}
	// Providers run sequentially. A delayed attempt starts its interval from
	// its actual admission time, not the timestamp of an earlier provider.
	if actual := time.Now().UTC(); actual.After(now) {
		now = actual
	}
	item.LastAttemptAt, item.Running = &now, true
	next := now.Add(time.Duration(item.IntervalSeconds) * time.Second)
	item.NextDueAt = &next
	manager.schedules[id] = item
	manager.mu.Unlock()
	if err := s.saveProviderSchedules(ctx, manager); err != nil {
		return err
	}
	// This path deliberately shares the protected source resolver and Registry
	// fetch/parse/stage boundary with manual refresh; it cannot publish a revision.
	fetchCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	provider, fetchErr := s.Store.GetProvider(fetchCtx, id)
	if fetchErr == nil {
		provider, fetchErr = services.resolveProviderSource(fetchCtx, provider)
	}
	var revision providers.Revision
	var changes providers.ChangeReport
	if fetchErr == nil && (!remoteProvider(provider) || !services.ProviderStageEnabled) {
		fetchErr = errors.New("provider staging unavailable")
	}
	if fetchErr == nil {
		revision, changes, fetchErr = services.Providers.Refresh(fetchCtx, provider, providers.Format(provider.Format))
	}
	cancel()
	completed := time.Now().UTC()
	item.Running = false
	outcome := "staged"
	operation := deployment.Operation{Target: deployment.Target{Kind: "provider", ID: id}, Action: "scheduled_refresh", Status: deployment.StatusStaged}
	if fetchErr != nil {
		item.LastError = "scheduled provider refresh failed; existing inventory retained"
		operation.Status, operation.Error, outcome = deployment.StatusFailed, item.LastError, "failed"
	} else {
		item.LastSuccessAt, item.LastError = &completed, ""
		data, _ := json.Marshal(map[string]any{"revision": revision, "changes": changes})
		operation.Views.Desired = &deployment.StateRecord{Revision: strconv.FormatInt(revision.Number, 10), Status: "staged", Data: data, At: completed}
	}
	persistCtx, persistCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer persistCancel()
	services.record("scheduler", "provider", id, "scheduled_refresh", outcome)
	// The lifecycle document must contain the revision before the operation
	// journal may claim it was durably staged. A crash between these commits
	// leaves conservative interrupted schedule state, never a missing revision
	// advertised as a completed stage.
	if err := services.Persist(persistCtx); err != nil {
		services.mutationBlocked = true
		return errors.New("persist scheduled refresh lifecycle failed")
	}
	op, err := services.Journal.Create(persistCtx, operation)
	if err != nil {
		services.mutationBlocked = true
		return errors.New("persist scheduled refresh operation failed")
	}
	item.LastOperationID = op.ID
	manager.mu.Lock()
	manager.schedules[id] = item
	manager.mu.Unlock()
	return s.saveProviderSchedules(persistCtx, manager)
}

// RemoveProviderSchedule is called after inventory deletion under the API write
// lock. A retained schedule cannot fetch a deleted provider: each attempt reads
// inventory again before resolving or downloading its source.
func (s *Server) RemoveProviderSchedule(ctx context.Context, id string) error {
	manager, err := s.providerSchedules(ctx)
	if err != nil {
		return err
	}
	manager.mu.Lock()
	delete(manager.schedules, id)
	manager.mu.Unlock()
	return s.saveProviderSchedules(ctx, manager)
}
