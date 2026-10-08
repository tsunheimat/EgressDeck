// Package outbounds models candidate groups and runtime selection. A group is
// deliberately independent from a device group: several device policies may
// share a selection, while independent choices use separate groups that reuse
// the same node inventory.
package outbounds

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

type SelectionMode string

const (
	SelectionManual    SelectionMode = "manual"
	SelectionAutomatic SelectionMode = "automatic"
)

type ReplacementPolicy string

const (
	ReplacementBlock ReplacementPolicy = "block"
	ReplacementNone  ReplacementPolicy = "none"
)

type Group struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	GatewayID string   `json:"gateway_id"`
	NodeIDs   []string `json:"node_ids"`
	// SourceFilters preserves the membership rule across provider refreshes.
	// When present, NodeIDs is the last resolved candidate snapshot.
	SourceFilters *SourceFilters    `json:"source_filters,omitempty"`
	Mode          SelectionMode     `json:"mode"`
	Replacement   ReplacementPolicy `json:"replacement_policy"`
	Revision      int64             `json:"revision"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type Scope struct {
	GatewayID string `json:"gateway_id"`
	Transport string `json:"transport"`
}

func (s Scope) Key() string {
	transport := strings.ToLower(strings.TrimSpace(s.Transport))
	if transport == "" {
		transport = "tcp"
	}
	return s.GatewayID + "\x00" + transport
}

type Selection struct {
	GroupID            string `json:"group_id"`
	Scope              Scope  `json:"scope"`
	DesiredNodeID      string `json:"desired_node_id,omitempty"`
	AppliedNodeID      string `json:"applied_node_id,omitempty"`
	ObservedNodeID     string `json:"observed_node_id,omitempty"`
	Generation         int64  `json:"generation"`
	AppliedGeneration  int64  `json:"applied_generation"`
	ObservedGeneration int64  `json:"observed_generation"`
	// Unavailable means the intended node is missing from the candidate group.
	// It requests blocking behavior; it does not assert the engine has blocked.
	Unavailable bool      `json:"unavailable"`
	Revision    int64     `json:"revision"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var (
	ErrGroupNotFound   = errors.New("outbound group not found")
	ErrNodeNotMember   = errors.New("node is not a member of outbound group")
	ErrGatewayMismatch = errors.New("selection gateway does not match outbound group")
	// ErrSelectionConflict aliases the shared revision conflict so callers can
	// map group and selection CAS failures consistently at the API boundary.
	ErrSelectionConflict = domain.ErrConflict
	ErrNoCandidates      = errors.New("outbound group has no candidates")
)

func ValidateGroup(g Group) error {
	problems := []string{}
	if g.ID != "" && !validID(g.ID) {
		problems = append(problems, "id is invalid")
	}
	if strings.TrimSpace(g.Name) == "" {
		problems = append(problems, "name is required")
	}
	if !validID(g.GatewayID) {
		problems = append(problems, "gateway_id is required and must be a valid identifier")
	}
	if g.Mode == "" {
		g.Mode = SelectionManual
	}
	if g.Mode != SelectionManual && g.Mode != SelectionAutomatic {
		problems = append(problems, "mode must be manual or automatic")
	}
	if g.Replacement == "" {
		g.Replacement = ReplacementBlock
	}
	if g.Replacement != ReplacementBlock && g.Replacement != ReplacementNone {
		problems = append(problems, "invalid replacement_policy")
	}
	seen := map[string]bool{}
	for _, id := range g.NodeIDs {
		id = strings.TrimSpace(id)
		if !validID(id) {
			problems = append(problems, "node_ids must contain valid identifiers")
		}
		if seen[id] {
			problems = append(problems, "duplicate node id")
		}
		seen[id] = true
	}
	if g.SourceFilters != nil {
		problems = append(problems, validateSourceFilters(*g.SourceFilters)...)
	}
	if len(problems) > 0 {
		return &domain.ValidationError{Problems: problems}
	}
	return nil
}

func normalizeGroup(g Group) Group {
	g = cloneGroup(g)
	g.Name = strings.TrimSpace(g.Name)
	if g.Mode == "" {
		g.Mode = SelectionManual
	}
	if g.Replacement == "" {
		g.Replacement = ReplacementBlock
	}
	for i, id := range g.NodeIDs {
		g.NodeIDs[i] = strings.TrimSpace(id)
	}
	if g.SourceFilters != nil {
		filters := normalizeSourceFilters(*g.SourceFilters)
		g.SourceFilters = &filters
	}
	return g
}

func validID(id string) bool {
	return id != "" && id == strings.TrimSpace(id) && len(id) <= 256 && strings.IndexFunc(id, unicode.IsControl) < 0
}

func normalizeScope(g Group, scope Scope) (Scope, error) {
	if scope.GatewayID == "" {
		scope.GatewayID = g.GatewayID
	}
	if scope.GatewayID != g.GatewayID {
		return Scope{}, ErrGatewayMismatch
	}
	scope.Transport = strings.ToLower(strings.TrimSpace(scope.Transport))
	if scope.Transport == "" {
		scope.Transport = "tcp"
	}
	if scope.Transport != "tcp" && scope.Transport != "udp" {
		return Scope{}, &domain.ValidationError{Problems: []string{"transport must be tcp or udp"}}
	}
	return scope, nil
}

type Service struct {
	mu         sync.RWMutex
	groups     map[string]Group
	selections map[string]Selection
}

func NewService() *Service {
	return &Service{groups: map[string]Group{}, selections: map[string]Selection{}}
}

func cloneGroup(g Group) Group {
	g.NodeIDs = append([]string(nil), g.NodeIDs...)
	if g.SourceFilters != nil {
		filters := cloneSourceFilters(*g.SourceFilters)
		g.SourceFilters = &filters
	}
	return g
}
func cloneSelection(s Selection) Selection { return s }

func (s *Service) Create(g Group) (Group, error) {
	g = normalizeGroup(g)
	if err := ValidateGroup(g); err != nil {
		return Group{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if g.ID == "" {
		g.ID = domain.NewID()
	}
	if _, ok := s.groups[g.ID]; ok {
		return Group{}, fmt.Errorf("%w: group already exists", domain.ErrConflict)
	}
	now := time.Now().UTC()
	g.Revision, g.CreatedAt, g.UpdatedAt = 1, now, now
	s.groups[g.ID] = cloneGroup(g)
	return cloneGroup(g), nil
}

func (s *Service) Get(id string) (Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[id]
	if !ok {
		return Group{}, ErrGroupNotFound
	}
	return cloneGroup(g), nil
}
func (s *Service) List() []Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Group, 0, len(s.groups))
	for _, g := range s.groups {
		out = append(out, cloneGroup(g))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Service) Update(g Group, expectedRevision int64) (Group, error) {
	g = normalizeGroup(g)
	if err := ValidateGroup(g); err != nil {
		return Group{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.groups[g.ID]
	if !ok {
		return Group{}, ErrGroupNotFound
	}
	if expectedRevision <= 0 || old.Revision != expectedRevision {
		return Group{}, ErrSelectionConflict
	}
	for _, selected := range s.selections {
		if selected.GroupID != g.ID {
			continue
		}
		if g.GatewayID != old.GatewayID {
			return Group{}, &domain.ValidationError{Problems: []string{"cannot change gateway while selections exist"}}
		}
		if g.Replacement == ReplacementNone && referencesMissingNode(g, selected) {
			return Group{}, &domain.ValidationError{Problems: []string{"replacement_policy none prevents removal of selected nodes"}}
		}
	}
	g.CreatedAt, g.UpdatedAt, g.Revision = old.CreatedAt, time.Now().UTC(), old.Revision+1
	s.groups[g.ID] = cloneGroup(g)
	for key, selected := range s.selections {
		if selected.GroupID == g.ID {
			selected.Unavailable = selectionUnavailable(g, selected)
			selected.Revision++
			selected.UpdatedAt = g.UpdatedAt
			s.selections[key] = selected
		}
	}
	return cloneGroup(g), nil
}

func hasNode(g Group, nodeID string) bool {
	for _, id := range g.NodeIDs {
		if id == nodeID {
			return true
		}
	}
	return false
}

func referencesMissingNode(g Group, sel Selection) bool {
	for _, id := range []string{sel.DesiredNodeID, sel.AppliedNodeID, sel.ObservedNodeID} {
		if id != "" && !hasNode(g, id) {
			return true
		}
	}
	return false
}

func selectionUnavailable(g Group, sel Selection) bool {
	if sel.DesiredNodeID != "" {
		return !hasNode(g, sel.DesiredNodeID)
	}
	return referencesMissingNode(g, sel)
}

// SetDesired validates membership and records intent. It does not claim that
// the engine has switched: callers must Apply/Observe the returned selection.
func (s *Service) SetDesired(groupID string, scope Scope, nodeID string, expectedRevision int64) (Selection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[groupID]
	if !ok {
		return Selection{}, ErrGroupNotFound
	}
	var err error
	if scope, err = normalizeScope(g, scope); err != nil {
		return Selection{}, err
	}
	if nodeID == "" {
		return Selection{}, ErrNodeNotMember
	}
	if !hasNode(g, nodeID) {
		return Selection{}, ErrNodeNotMember
	}
	key := groupID + "\x00" + scope.Key()
	old, exists := s.selections[key]
	if expectedRevision < 0 || (exists && (expectedRevision == 0 || old.Revision != expectedRevision)) || (!exists && expectedRevision != 0) {
		return Selection{}, ErrSelectionConflict
	}
	old.GroupID, old.Scope, old.DesiredNodeID, old.Revision, old.UpdatedAt = groupID, scope, nodeID, old.Revision+1, time.Now().UTC()
	old.Unavailable = false
	s.selections[key] = old
	return cloneSelection(old), nil
}

// RestoreDesired compensates a desired-selection mutation when the remote
// adapter rejected publication. It is used by the controller so an API error
// cannot leave an intent that was never applied remotely.
func (s *Service) RestoreDesired(groupID string, scope Scope, prior *Selection) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[groupID]
	if !ok {
		return ErrGroupNotFound
	}
	var err error
	if scope, err = normalizeScope(g, scope); err != nil {
		return err
	}
	key := groupID + "\x00" + scope.Key()
	current, exists := s.selections[key]
	if !exists {
		return ErrSelectionConflict
	}
	expected := int64(1)
	if prior != nil {
		priorScope, scopeErr := normalizeScope(g, prior.Scope)
		if scopeErr != nil || prior.GroupID != groupID || priorScope != scope || prior.Revision <= 0 {
			return ErrSelectionConflict
		}
		if prior.DesiredNodeID != "" && (!validID(prior.DesiredNodeID) || (!hasNode(g, prior.DesiredNodeID) && (g.Replacement != ReplacementBlock || !prior.Unavailable))) {
			return ErrNodeNotMember
		}
		expected = prior.Revision + 1
	}
	if current.Revision != expected {
		return ErrSelectionConflict
	}
	current.DesiredNodeID = ""
	if prior != nil {
		current.DesiredNodeID = prior.DesiredNodeID
	}
	current.Unavailable = selectionUnavailable(g, current)
	current.Revision++
	current.UpdatedAt = time.Now().UTC()
	s.selections[key] = current
	return nil
}

func (s *Service) Observe(groupID string, scope Scope, nodeID string, generation int64) (Selection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[groupID]
	if !ok {
		return Selection{}, ErrGroupNotFound
	}
	var err error
	if scope, err = normalizeScope(g, scope); err != nil {
		return Selection{}, err
	}
	if nodeID != "" && !hasNode(g, nodeID) {
		return Selection{}, ErrNodeNotMember
	}
	key := groupID + "\x00" + scope.Key()
	old := s.selections[key]
	if generation < 0 || generation < old.ObservedGeneration {
		return Selection{}, ErrSelectionConflict
	}
	old.GroupID, old.Scope, old.ObservedNodeID, old.ObservedGeneration, old.UpdatedAt = groupID, scope, nodeID, generation, time.Now().UTC()
	old.Generation = max(old.AppliedGeneration, old.ObservedGeneration)
	if old.Revision == 0 {
		old.Revision = 1
	}
	old.Unavailable = selectionUnavailable(g, old)
	s.selections[key] = old
	return cloneSelection(old), nil
}

func (s *Service) MarkApplied(groupID string, scope Scope, nodeID string, generation int64) (Selection, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[groupID]
	if !ok {
		return Selection{}, ErrGroupNotFound
	}
	var err error
	if scope, err = normalizeScope(g, scope); err != nil {
		return Selection{}, err
	}
	if nodeID != "" && !hasNode(g, nodeID) {
		return Selection{}, ErrNodeNotMember
	}
	key := groupID + "\x00" + scope.Key()
	old := s.selections[key]
	if generation < 0 || generation < old.AppliedGeneration {
		return Selection{}, ErrSelectionConflict
	}
	old.GroupID, old.Scope, old.AppliedNodeID, old.AppliedGeneration, old.UpdatedAt = groupID, scope, nodeID, generation, time.Now().UTC()
	old.Generation = max(old.AppliedGeneration, old.ObservedGeneration)
	if old.Revision == 0 {
		old.Revision = 1
	}
	old.Unavailable = selectionUnavailable(g, old)
	s.selections[key] = old
	return cloneSelection(old), nil
}

func (s *Service) GetSelection(groupID string, scope Scope) (Selection, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[groupID]
	if !ok {
		return Selection{}, ErrGroupNotFound
	}
	var err error
	if scope, err = normalizeScope(g, scope); err != nil {
		return Selection{}, err
	}
	sel, ok := s.selections[groupID+"\x00"+scope.Key()]
	if !ok {
		return Selection{}, domain.ErrNotFound
	}
	return cloneSelection(sel), nil
}

func (s *Service) Selections(groupID string) []Selection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Selection{}
	for _, sel := range s.selections {
		if sel.GroupID == groupID {
			out = append(out, cloneSelection(sel))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope.Key() < out[j].Scope.Key() })
	return out
}

// Candidates returns a stable copy suitable for runtime publication. It never
// inserts Direct or another implicit fallback when a node is unavailable.
func (s *Service) Candidates(groupID string) ([]string, error) {
	g, err := s.Get(groupID)
	if err != nil {
		return nil, err
	}
	if len(g.NodeIDs) == 0 {
		return nil, ErrNoCandidates
	}
	return append([]string(nil), g.NodeIDs...), nil
}

// stateSnapshot is a private, versioned persistence format, not an API response.
// Callers must encrypt it before writing it to durable storage.
type stateSnapshot struct {
	Version    int         `json:"version"`
	Groups     []Group     `json:"groups"`
	Selections []Selection `json:"selections"`
}

func (s *Service) ExportState() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot := stateSnapshot{Version: 1, Groups: []Group{}, Selections: []Selection{}}
	for _, group := range s.groups {
		snapshot.Groups = append(snapshot.Groups, cloneGroup(group))
	}
	for _, selection := range s.selections {
		snapshot.Selections = append(snapshot.Selections, selection)
	}
	sort.Slice(snapshot.Groups, func(i, j int) bool { return snapshot.Groups[i].ID < snapshot.Groups[j].ID })
	sort.Slice(snapshot.Selections, func(i, j int) bool {
		a, b := snapshot.Selections[i], snapshot.Selections[j]
		return a.GroupID+"\x00"+a.Scope.Key() < b.GroupID+"\x00"+b.Scope.Key()
	})
	return json.Marshal(snapshot)
}

// ImportState validates the whole snapshot before replacing any live state.
func (s *Service) ImportState(data []byte) error {
	var snapshot stateSnapshot
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("invalid outbound snapshot: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("invalid outbound snapshot trailing data")
	}
	if snapshot.Version != 1 {
		return errors.New("unsupported outbound snapshot version")
	}
	groups := make(map[string]Group, len(snapshot.Groups))
	selections := make(map[string]Selection, len(snapshot.Selections))
	for _, group := range snapshot.Groups {
		if err := ValidateGroup(group); err != nil {
			return fmt.Errorf("invalid outbound snapshot group: %w", err)
		}
		if !validID(group.ID) || group.Revision <= 0 || group.CreatedAt.IsZero() || group.UpdatedAt.Before(group.CreatedAt) || group.Mode == "" || group.Replacement == "" {
			return errors.New("invalid outbound snapshot group metadata")
		}
		for _, id := range group.NodeIDs {
			if !validID(id) {
				return errors.New("invalid outbound snapshot member")
			}
		}
		if _, exists := groups[group.ID]; exists {
			return errors.New("duplicate outbound snapshot group")
		}
		groups[group.ID] = cloneGroup(group)
	}
	for _, selection := range snapshot.Selections {
		group, exists := groups[selection.GroupID]
		if !exists {
			return errors.New("outbound snapshot selection references missing group")
		}
		scope, err := normalizeScope(group, selection.Scope)
		if err != nil || scope != selection.Scope || selection.Revision <= 0 || selection.UpdatedAt.IsZero() {
			return errors.New("invalid outbound snapshot selection metadata")
		}
		if selection.AppliedGeneration < 0 || selection.ObservedGeneration < 0 || selection.Generation != max(selection.AppliedGeneration, selection.ObservedGeneration) {
			return errors.New("invalid outbound snapshot selection generation")
		}
		for _, id := range []string{selection.DesiredNodeID, selection.AppliedNodeID, selection.ObservedNodeID} {
			if id != "" && !validID(id) {
				return errors.New("invalid outbound snapshot selected node")
			}
		}
		if selection.Unavailable != selectionUnavailable(group, selection) || (group.Replacement == ReplacementNone && referencesMissingNode(group, selection)) {
			return errors.New("outbound snapshot selection violates replacement policy")
		}
		key := selection.GroupID + "\x00" + scope.Key()
		if _, exists := selections[key]; exists {
			return errors.New("duplicate outbound snapshot selection")
		}
		selections[key] = selection
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups, s.selections = groups, selections
	return nil
}
