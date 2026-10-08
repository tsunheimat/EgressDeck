package gateway

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// CapabilityGroupPublish identifies the independent hot publication of one
// outbound group's membership. It deliberately does not imply that provider
// connections or other groups are rebuilt.
const CapabilityGroupPublish CapabilityName = "group.publish_hot"

// GroupPublication is the controller-to-gateway contract for changing the
// eligible members of an already published group. ProviderRevision is the
// immutable provider connection revision the group is based on; Group.Revision
// advances independently when membership changes.
type GroupPublication struct {
	Group            PublicationGroup `json:"group"`
	ProviderID       string           `json:"provider_id"`
	ProviderRevision int64            `json:"provider_revision"`
}

func (p GroupPublication) normalized() (GroupPublication, error) {
	if strings.TrimSpace(p.ProviderID) == "" || p.ProviderRevision < 0 {
		return GroupPublication{}, fmt.Errorf("%w: provider and nonnegative provider revision are required", ErrInvalidRevision)
	}
	g := p.Group
	if strings.TrimSpace(g.ID) == "" || strings.TrimSpace(g.Name) == "" || g.Revision < 0 || len(g.CandidateIDs) == 0 {
		return GroupPublication{}, fmt.Errorf("%w: group id, name, revision, and candidates are required", ErrInvalidRevision)
	}
	seen := map[string]bool{}
	for _, id := range g.CandidateIDs {
		if strings.TrimSpace(id) == "" || seen[id] {
			return GroupPublication{}, fmt.Errorf("%w: group candidates must be unique and non-empty", ErrInvalidRevision)
		}
		seen[id] = true
	}
	if strings.TrimSpace(g.SelectedNodeID) == "" || !seen[g.SelectedNodeID] {
		return GroupPublication{}, fmt.Errorf("%w: selected node must remain an eligible candidate", ErrSelection)
	}
	p.Group.CandidateIDs = append([]string(nil), g.CandidateIDs...)
	return p, nil
}

func (p GroupPublication) clone() GroupPublication {
	p.Group.CandidateIDs = append([]string(nil), p.Group.CandidateIDs...)
	return p
}

// PublishGroup updates one group's candidate set against the exact active
// provider revision and expected gateway generation.
type GroupPublisher interface {
	PublishGroup(context.Context, GroupPublication, int64) (Snapshot, error)
}

func (e *FakeEngine) PublishGroup(ctx context.Context, publication GroupPublication, expectedGeneration int64) (Snapshot, error) {
	if !e.supports(CapabilityGroupPublish) {
		return Snapshot{}, unsupported(string(CapabilityGroupPublish))
	}
	p, err := publication.normalized()
	if err != nil {
		return Snapshot{}, err
	}
	started := time.Now().UTC()
	e.mu.Lock()
	defer e.mu.Unlock()
	if expectedGeneration != e.generation {
		return Snapshot{}, conflict(string(CapabilityGroupPublish), "expected generation does not match gateway inventory")
	}
	provider, ok := e.providers[p.ProviderID]
	if !ok || provider.Revision != p.ProviderRevision {
		return Snapshot{}, conflict(string(CapabilityGroupPublish), "provider revision is not the active revision")
	}
	nodes := map[string]bool{}
	for _, n := range provider.Nodes {
		nodes[n.ID] = true
	}
	for _, id := range p.Group.CandidateIDs {
		if !nodes[id] {
			return Snapshot{}, fmt.Errorf("%w: group candidate %s is outside active provider", ErrInvalidRevision, id)
		}
	}
	old, exists := providerGroup(provider, p.Group.ID)
	if exists && old.Name != p.Group.Name {
		return Snapshot{}, conflict(string(CapabilityGroupPublish), "group identity does not match active provider")
	}
	if exists && p.Group.Revision <= old.Revision {
		return Snapshot{}, conflict(string(CapabilityGroupPublish), "group revision must advance")
	}
	if existing, ok := e.groups[p.Group.ID]; ok && existing.ProviderIDs != nil && len(existing.ProviderIDs) > 0 && (len(existing.ProviderIDs) != 1 || existing.ProviderIDs[0] != p.ProviderID) {
		return Snapshot{}, conflict(string(CapabilityGroupPublish), "group is owned by another provider")
	}
	// Build all state before mutating so an invalid/journal-failed operation
	// leaves provider connections, selections, and unrelated groups intact.
	nextProvider := cloneRevision(provider)
	replaced := false
	for i := range nextProvider.Groups {
		if nextProvider.Groups[i].ID == p.Group.ID {
			nextProvider.Groups[i] = p.Group
			replaced = true
			break
		}
	}
	if !replaced {
		nextProvider.Groups = append(nextProvider.Groups, p.Group)
	}
	nextGroup := OutboundGroup{ID: p.Group.ID, Name: p.Group.Name, ProviderIDs: []string{p.ProviderID}, NodeIDs: append([]string(nil), p.Group.CandidateIDs...), SelectionMode: "manual", Revision: p.Group.Revision}
	previousProvider := e.providers[p.ProviderID]
	previousGroup, hadGroup := e.groups[p.Group.ID]
	previousGeneration := e.generation
	previousEvents := len(e.events)
	previousSelections := copySelections(e.selections)
	e.providers[p.ProviderID] = nextProvider
	e.groups[p.Group.ID] = nextGroup
	for key, selection := range e.selections {
		if selection.Scope.GroupID != p.Group.ID {
			continue
		}
		if selection.DesiredNodeID != p.Group.SelectedNodeID {
			selection.DesiredNodeID = p.Group.SelectedNodeID
			selection.ObservedNodeID = p.Group.SelectedNodeID
			selection.Revision++
			selection.UpdatedAt = time.Now().UTC()
			e.selections[key] = selection
		}
	}
	e.generation++
	e.eventLocked("group.published", p.Group.ID, fmt.Sprintf("provider=%s revision=%d", p.ProviderID, p.Group.Revision))
	if err := e.appendStateJournal(ctx, string(CapabilityGroupPublish), p.Group.ID, "published", e.generation, started, nil); err != nil {
		e.providers[p.ProviderID] = previousProvider
		if hadGroup {
			e.groups[p.Group.ID] = previousGroup
		} else {
			delete(e.groups, p.Group.ID)
		}
		e.generation = previousGeneration
		e.selections = previousSelections
		e.events = e.events[:previousEvents]
		return Snapshot{}, err
	}
	return e.snapshotLocked(), nil
}

func providerGroup(provider ProviderRevision, id string) (PublicationGroup, bool) {
	for _, g := range provider.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return PublicationGroup{}, false
}
