package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/nodes"
)

// snapshotRevision deliberately stores nodes as the private node codec bytes.
// The outer document is metadata only; callers that persist it must encrypt
// the returned bytes with the application key before writing them to disk.
type snapshotRevision struct {
	ProviderID  string        `json:"provider_id"`
	Number      int64         `json:"number"`
	Hash        string        `json:"hash"`
	Nodes       []byte        `json:"nodes"`
	Report      ParseReport   `json:"parse_report"`
	Changes     ChangeReport  `json:"changes"`
	State       RevisionState `json:"state"`
	CreatedAt   time.Time     `json:"created_at"`
	PublishedAt *time.Time    `json:"published_at,omitempty"`
}

type snapshotProvider struct {
	Next      int64              `json:"next"`
	Status    ProviderStatus     `json:"status"`
	Revisions []snapshotRevision `json:"revisions"`
}

type registrySnapshot struct {
	Version   int                         `json:"version"`
	Providers map[string]snapshotProvider `json:"providers"`
}

// ExportState returns an authenticated-encryption-ready snapshot of all
// provider revisions. It never uses public Node JSON, so credentials,
// private identity fingerprints, and content hashes remain inside the private
// node payload. Encrypt the returned bytes before persistence.
func (r *Registry) ExportState() ([]byte, error) {
	r.boundary.Lock()
	defer r.boundary.Unlock()
	r.mu.RLock()
	ids := make([]string, 0, len(r.providers))
	for id := range r.providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := registrySnapshot{Version: 1, Providers: make(map[string]snapshotProvider, len(ids))}
	for _, id := range ids {
		s := r.providers[id]
		s.mutation.Lock()
		s.mu.Lock()
		sp := snapshotProvider{Next: s.next, Status: cloneStatus(s.status), Revisions: make([]snapshotRevision, 0, len(s.revisions))}
		numbers := make([]int64, 0, len(s.revisions))
		for number := range s.revisions {
			numbers = append(numbers, number)
		}
		sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
		for _, number := range numbers {
			rev := s.revisions[number]
			privateNodes, err := nodes.MarshalPrivate(rev.Nodes)
			if err != nil {
				s.mu.Unlock()
				s.mutation.Unlock()
				r.mu.RUnlock()
				return nil, fmt.Errorf("export provider %q revision %d: %w", id, number, err)
			}
			sp.Revisions = append(sp.Revisions, snapshotRevision{ProviderID: rev.ProviderID, Number: rev.Number, Hash: rev.Hash, Nodes: privateNodes, Report: rev.Report, Changes: cloneChanges(rev.Changes), State: rev.State, CreatedAt: rev.CreatedAt, PublishedAt: cloneTime(rev.PublishedAt)})
		}
		s.mu.Unlock()
		s.mutation.Unlock()
		out.Providers[id] = sp
	}
	r.mu.RUnlock()
	return json.Marshal(out)
}

// ImportState atomically replaces the in-memory revision inventory after
// validating every private node payload and lifecycle pointer. It is intended
// for startup/recovery; callers must decrypt and authenticate bytes first.
func (r *Registry) ImportState(raw []byte) error {
	r.boundary.Lock()
	defer r.boundary.Unlock()
	var in registrySnapshot
	if err := json.Unmarshal(raw, &in); err != nil {
		return errors.New("invalid provider registry snapshot")
	}
	if in.Version != 1 {
		return errors.New("unsupported provider registry snapshot version")
	}
	if in.Providers == nil {
		return errors.New("provider registry snapshot has no providers")
	}
	validated := make(map[string]*providerState, len(in.Providers))
	for providerID, sp := range in.Providers {
		if providerID == "" {
			return errors.New("provider registry snapshot has an empty provider id")
		}
		if len(sp.Revisions) > RetainedRevisionLimit {
			return fmt.Errorf("provider %q: %w", providerID, ErrRevisionCapacity)
		}
		s := &providerState{revisions: make(map[int64]Revision), next: sp.Next, status: cloneStatus(sp.Status)}
		if s.status.ProviderID != "" && s.status.ProviderID != providerID {
			return fmt.Errorf("provider %q has mismatched status identity", providerID)
		}
		s.status.ProviderID = providerID
		seen := make(map[int64]bool, len(sp.Revisions))
		for _, stored := range sp.Revisions {
			if stored.Number < 1 || seen[stored.Number] {
				return fmt.Errorf("provider %q has invalid revision number", providerID)
			}
			seen[stored.Number] = true
			if stored.Hash == "" {
				return fmt.Errorf("provider %q revision %d has no content hash", providerID, stored.Number)
			}
			if stored.ProviderID != providerID {
				return fmt.Errorf("provider %q has mismatched revision identity", providerID)
			}
			ns, err := nodes.UnmarshalPrivate(stored.Nodes)
			if err != nil {
				return fmt.Errorf("provider %q revision %d: %w", providerID, stored.Number, err)
			}
			if len(ns) == 0 {
				return fmt.Errorf("provider %q revision %d has no nodes", providerID, stored.Number)
			}
			nodeIDs, identities := map[string]bool{}, map[string]bool{}
			for _, n := range ns {
				if n.ProviderID != providerID {
					return fmt.Errorf("provider %q revision %d contains a node for another provider", providerID, stored.Number)
				}
				if nodeIDs[n.ID] || identities[n.Identity] {
					return fmt.Errorf("provider %q revision %d contains duplicate nodes", providerID, stored.Number)
				}
				nodeIDs[n.ID], identities[n.Identity] = true, true
			}
			s.revisions[stored.Number] = Revision{ProviderID: stored.ProviderID, Number: stored.Number, Hash: stored.Hash, Nodes: ns, Report: stored.Report, Changes: cloneChanges(stored.Changes), State: stored.State, CreatedAt: stored.CreatedAt, PublishedAt: cloneTime(stored.PublishedAt)}
			if stored.Number > s.next {
				s.next = stored.Number
			}
		}
		if err := validatePointers(s); err != nil {
			return fmt.Errorf("provider %q: %w", providerID, err)
		}
		validated[providerID] = s
	}
	r.mu.Lock()
	r.providers = validated
	r.mu.Unlock()
	return nil
}

func validatePointers(s *providerState) error {
	if s.status.Active < 0 || s.status.Staged < 0 || s.next < 0 {
		return errors.New("negative revision pointer")
	}
	if s.status.Active != 0 {
		rev, ok := s.revisions[s.status.Active]
		if !ok || rev.State != RevisionActive {
			return errors.New("active revision pointer is invalid")
		}
	}
	if s.status.Staged != 0 {
		rev, ok := s.revisions[s.status.Staged]
		if !ok || rev.State != RevisionStaged {
			return errors.New("staged revision pointer is invalid")
		}
	}
	for number, rev := range s.revisions {
		if rev.State == RevisionActive && number != s.status.Active {
			return fmt.Errorf("revision %d is an unreferenced active revision", number)
		}
		if rev.State == RevisionStaged && number != s.status.Staged {
			return fmt.Errorf("revision %d is an unreferenced staged revision", number)
		}
		switch rev.State {
		case RevisionActive, RevisionStaged, RevisionSuperseded, RevisionFailed:
		default:
			return fmt.Errorf("revision %d has invalid state", number)
		}
	}
	return nil
}
