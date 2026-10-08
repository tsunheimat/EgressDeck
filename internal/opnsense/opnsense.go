// Package opnsense contains the controller's narrow OPNsense integration
// boundary.  It deliberately models an alias as a complete, owned set of
// addresses and makes persisted and active readback separate observations.
// A successful HTTP response from OPNsense is therefore not treated as proof
// that an alias is active.
package opnsense

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// AddressFamily is the address coverage of a firewall binding.
type AddressFamily string

const (
	IPv4Family AddressFamily = "ipv4"
	IPv6Family AddressFamily = "ipv6"
	DualFamily AddressFamily = "dual"
	// FamilyIPv4, FamilyIPv6, and FamilyDual are descriptive aliases kept for
	// callers that prefer the family-first naming used by the API model.
	FamilyIPv4 = IPv4Family
	FamilyIPv6 = IPv6Family
	FamilyDual = DualFamily
)

// AliasType is the OPNsense alias object type understood by this adapter.
// Host and network aliases are the only types for which address ownership is
// safe to manage. Other alias types must be handled by a separate adapter.
type AliasType string

const (
	HostAlias    AliasType = "host"
	NetworkAlias AliasType = "network"
)

var (
	ErrNotFound       = errors.New("opnsense object not found")
	ErrInvalidBinding = errors.New("invalid opnsense binding")
	ErrShapeChanged   = errors.New("opnsense alias shape changed")
	ErrDrift          = errors.New("opnsense binding drift detected")
	ErrPartialUpdate  = errors.New("opnsense alias update partially applied")
	ErrUnsupported    = errors.New("opnsense operation unsupported")
)

// AliasRecord is the readback-independent representation returned by the
// client. Revision is the OPNsense object revision observed by the client,
// when the installed OPNsense version exposes one.
type AliasRecord struct {
	Name        string    `json:"name"`
	UUID        string    `json:"uuid,omitempty"`
	Type        AliasType `json:"type"`
	Description string    `json:"description,omitempty"`
	OwnerTag    string    `json:"owner_tag,omitempty"`
	Disabled    bool      `json:"disabled,omitempty"`
	Addresses   []string  `json:"addresses"`
	Revision    int64     `json:"revision,omitempty"`
	ObservedAt  time.Time `json:"observed_at,omitempty"`
	// Native spellings are needed for exact persisted deletion: the upstream
	// controller compares strings, so equivalent IPv6/CIDR forms may differ.
	nativeAddresses map[string]string
}

// AliasShape identifies the object that an attached binding is allowed to
// mutate. Shape is checked before every write so an administrator changing an
// alias to another object cannot cause a destructive update.
type AliasShape struct {
	Name        string    `json:"name"`
	UUID        string    `json:"uuid,omitempty"`
	Type        AliasType `json:"type"`
	Description string    `json:"description,omitempty"`
	OwnerTag    string    `json:"owner_tag,omitempty"`
	Disabled    bool      `json:"disabled,omitempty"`
}

// Binding is a typed registration of an existing OPNsense steering alias.
// ManagedAddresses is the complete set the controller owns for this binding;
// addresses outside that set are never silently preserved or overwritten.
type Binding struct {
	ID               string        `json:"id"`
	GatewayID        string        `json:"gateway_id"`
	Alias            AliasShape    `json:"alias"`
	Family           AddressFamily `json:"family"`
	InterfaceScope   string        `json:"interface_scope"`
	RuleIDs          []string      `json:"rule_ids,omitempty"`
	Enforcement      string        `json:"enforcement,omitempty"`
	ManagedAddresses []string      `json:"managed_addresses"`
	Revision         int64         `json:"revision,omitempty"`
}

// AttachRequest registers an existing alias. ExpectedAddresses and the
// Expected* alias fields are optional for discovery, but when supplied they
// must match readback exactly (after canonicalization).
type AttachRequest struct {
	ID                string        `json:"id,omitempty"`
	GatewayID         string        `json:"gateway_id"`
	Alias             string        `json:"alias"`
	AliasUUID         string        `json:"alias_uuid,omitempty"`
	AliasType         AliasType     `json:"alias_type,omitempty"`
	AliasDescription  string        `json:"alias_description,omitempty"`
	OwnerTag          string        `json:"owner_tag,omitempty"`
	Family            AddressFamily `json:"family"`
	InterfaceScope    string        `json:"interface_scope"`
	RuleIDs           []string      `json:"rule_ids,omitempty"`
	Enforcement       string        `json:"enforcement,omitempty"`
	ExpectedAddresses []string      `json:"expected_addresses,omitempty"`
}

// Readback keeps each state source separate. Persisted is configuration
// readback and Active is the currently loaded firewall table. A table can be
// active while persistence is stale, or vice versa; callers must inspect both.
type Readback struct {
	Persisted AliasRecord `json:"persisted"`
	Active    AliasRecord `json:"active"`
	Drift     DriftReport `json:"drift"`
	ReadAt    time.Time   `json:"read_at"`
}

// DriftKind describes why persisted/active state does not match binding
// intent.
type DriftKind string

const (
	DriftPersistedAddresses DriftKind = "persisted_addresses"
	DriftActiveAddresses    DriftKind = "active_addresses"
	DriftPersistedActive    DriftKind = "persisted_active"
	DriftShape              DriftKind = "shape"
)

type DriftItem struct {
	Kind     DriftKind `json:"kind"`
	Expected []string  `json:"expected,omitempty"`
	Observed []string  `json:"observed,omitempty"`
	Message  string    `json:"message"`
}

type DriftReport struct {
	Drifted bool        `json:"drifted"`
	Items   []DriftItem `json:"items,omitempty"`
}

// AddressDelta is a canonical set difference. Add and Remove are sorted and
// contain no duplicates, making requests deterministic and idempotent.
type AddressDelta struct {
	Add    []string `json:"add,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// SyncResult reports both the requested delta and the post-mutation state.
// Complete is true only when persisted and active readback both equal the
// requested set and the binding shape still matches.
type SyncResult struct {
	Binding  Binding      `json:"binding"`
	Delta    AddressDelta `json:"delta"`
	Before   Readback     `json:"before"`
	After    Readback     `json:"after"`
	Complete bool         `json:"complete"`
}

// Client is the smallest version-tested OPNsense surface used by Adapter.
// Implementations must not treat a mutation response as active-table
// confirmation; Adapter always invokes both read methods after writes.
type Client interface {
	ReadPersistedAlias(context.Context, string) (AliasRecord, error)
	ReadActiveAlias(context.Context, string) (AliasRecord, error)
	AddAliasAddresses(context.Context, string, []string) error
	DeleteAliasAddresses(context.Context, string, []string) error
}

// Adapter serializes writes per OPNsense target. A caller can create one
// Adapter for each configured OPNsense installation, or use the Target field
// in a higher-level operation journal to serialize across processes.
type Adapter struct {
	client Client
	mu     sync.Mutex
}

// FirewallBinding is the adapter spelling of Binding. The domain package has
// a persistence-facing summary with the same concept; keeping this alias here
// avoids exposing OPNsense-specific alias shape fields in that model.
type FirewallBinding = Binding

func NewAdapter(client Client) (*Adapter, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: nil client", ErrUnsupported)
	}
	return &Adapter{client: client}, nil
}

// New is a concise constructor for dependency-injection sites.
func New(client Client) (*Adapter, error) { return NewAdapter(client) }

func (a *Adapter) Client() Client { return a.client }

// Attach validates and registers an existing alias without changing it.
func (a *Adapter) Attach(ctx context.Context, req AttachRequest) (Binding, Readback, error) {
	if err := req.validate(); err != nil {
		return Binding{}, Readback{}, err
	}
	persisted, err := a.client.ReadPersistedAlias(ctx, req.Alias)
	if err != nil {
		return Binding{}, Readback{}, err
	}
	active, err := a.client.ReadActiveAlias(ctx, req.Alias)
	if err != nil {
		return Binding{}, Readback{}, err
	}
	persisted, err = canonicalRecord(persisted)
	if err != nil {
		return Binding{}, Readback{}, fmt.Errorf("persisted alias: %w", err)
	}
	active, err = canonicalRecord(active)
	if err != nil {
		return Binding{}, Readback{}, fmt.Errorf("active alias: %w", err)
	}
	if err := validateShape(persisted, req); err != nil {
		return Binding{}, Readback{}, err
	}
	if err := validateShape(active, req); err != nil {
		return Binding{}, Readback{}, err
	}
	managed := persisted.Addresses
	if req.ExpectedAddresses != nil {
		managed, err = CanonicalAddresses(req.ExpectedAddresses)
		if err != nil {
			return Binding{}, Readback{}, fmt.Errorf("expected addresses: %w", err)
		}
		if !equalStrings(managed, persisted.Addresses) {
			return Binding{}, Readback{}, fmt.Errorf("%w: persisted alias addresses differ from expected addresses", ErrShapeChanged)
		}
	}
	if err := validateFamily(req.Family, managed); err != nil {
		return Binding{}, Readback{}, err
	}
	binding := Binding{
		ID: req.ID, GatewayID: req.GatewayID,
		Alias: shapeFromRecord(persisted), Family: req.Family,
		InterfaceScope: req.InterfaceScope, RuleIDs: append([]string(nil), req.RuleIDs...),
		Enforcement: req.Enforcement, ManagedAddresses: append([]string(nil), managed...),
		Revision: persisted.Revision,
	}
	rb := Readback{Persisted: persisted, Active: active, ReadAt: time.Now().UTC()}
	rb.Drift = DetectDrift(binding, rb)
	return binding, rb, nil
}

// AttachBinding is a convenience alias for callers that use binding as the
// operation name in their controller code.
func (a *Adapter) AttachBinding(ctx context.Context, req AttachRequest) (Binding, Readback, error) {
	return a.Attach(ctx, req)
}

// Readback reads both persisted configuration and active table and computes
// drift against the binding's owned set.
func (a *Adapter) Readback(ctx context.Context, binding Binding) (Readback, error) {
	if err := binding.Validate(); err != nil {
		return Readback{}, err
	}
	persisted, err := a.client.ReadPersistedAlias(ctx, binding.Alias.Name)
	if err != nil {
		return Readback{}, err
	}
	active, err := a.client.ReadActiveAlias(ctx, binding.Alias.Name)
	if err != nil {
		return Readback{}, err
	}
	persisted, err = canonicalRecord(persisted)
	if err != nil {
		return Readback{}, fmt.Errorf("persisted alias: %w", err)
	}
	active, err = canonicalRecord(active)
	if err != nil {
		return Readback{}, fmt.Errorf("active alias: %w", err)
	}
	rb := Readback{Persisted: persisted, Active: active, ReadAt: time.Now().UTC()}
	rb.Drift = DetectDrift(binding, rb)
	return rb, nil
}

// ReadAlias is a short alias for Readback.
func (a *Adapter) ReadAlias(ctx context.Context, binding Binding) (Readback, error) {
	return a.Readback(ctx, binding)
}

// Sync computes and applies an address delta. It refuses to write if the
// current alias shape or owned contents have drifted. Additions are sent before
// removals so an enrollment cannot briefly lose all coverage. Every write is
// followed by persisted and active readback.
func (a *Adapter) Sync(ctx context.Context, binding Binding, desired []string) (SyncResult, error) {
	if err := binding.Validate(); err != nil {
		return SyncResult{}, err
	}
	canonicalDesired, err := CanonicalAddresses(desired)
	if err != nil {
		return SyncResult{}, err
	}
	if err := validateFamily(binding.Family, canonicalDesired); err != nil {
		return SyncResult{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if validator, ok := a.client.(interface {
		ValidateBinding(context.Context, Binding) error
	}); ok {
		if err := validator.ValidateBinding(ctx, binding); err != nil {
			return SyncResult{}, err
		}
	}
	before, err := a.Readback(ctx, binding)
	if err != nil {
		return SyncResult{}, err
	}
	if before.Drift.Drifted {
		return SyncResult{Binding: binding, Before: before, After: before}, fmt.Errorf("%w: %s", ErrDrift, before.Drift.Items[0].Message)
	}
	delta, err := ComputeAddressDelta(binding.ManagedAddresses, canonicalDesired)
	if err != nil {
		return SyncResult{}, err
	}
	result := SyncResult{Binding: binding, Delta: delta, Before: before}
	if len(delta.Add) > 0 {
		if err := a.client.AddAliasAddresses(ctx, binding.Alias.Name, delta.Add); err != nil {
			// An error or lost acknowledgement cannot prove that no addresses
			// were added. Preserve the observed side effects for reconciliation.
			after, readErr := a.Readback(ctx, binding)
			result.After = after
			if readErr != nil {
				return result, fmt.Errorf("%w: add: %v; readback: %v", ErrPartialUpdate, err, readErr)
			}
			return result, fmt.Errorf("%w: add: %v", ErrPartialUpdate, err)
		}
		if len(delta.Remove) > 0 {
			// Check the intermediate set before the destructive half of a
			// replacement. OPNsense has no assumed object-level compare-and-swap.
			intermediate := binding
			intermediate.ManagedAddresses, _ = CanonicalAddresses(append(append([]string(nil), binding.ManagedAddresses...), delta.Add...))
			observed, readErr := a.Readback(ctx, intermediate)
			result.After = observed
			if readErr != nil {
				return result, fmt.Errorf("%w: add readback: %v", ErrPartialUpdate, readErr)
			}
			if observed.Drift.Drifted {
				return result, fmt.Errorf("%w: %w after add; deletion halted", ErrPartialUpdate, ErrDrift)
			}
		}
	}
	if len(delta.Remove) > 0 {
		if err := a.client.DeleteAliasAddresses(ctx, binding.Alias.Name, delta.Remove); err != nil {
			// The add operation may have succeeded; readback lets the caller
			// reconcile without assuming a rollback was safe.
			after, readErr := a.Readback(ctx, binding)
			result.After = after
			if readErr != nil {
				return result, fmt.Errorf("%w: delete: %v; readback: %v", ErrPartialUpdate, err, readErr)
			}
			return result, fmt.Errorf("%w: delete: %v", ErrPartialUpdate, err)
		}
	}
	updated := binding
	updated.ManagedAddresses = append([]string(nil), canonicalDesired...)
	updated.Revision = before.Persisted.Revision
	result.Binding = updated
	after, readErr := a.Readback(ctx, updated)
	result.After = after
	if readErr != nil {
		return result, fmt.Errorf("%w: final readback: %v", ErrPartialUpdate, readErr)
	}
	result.Binding.Revision = after.Persisted.Revision
	result.Complete = !after.Drift.Drifted && equalStrings(after.Persisted.Addresses, canonicalDesired) && equalStrings(after.Active.Addresses, canonicalDesired)
	if !result.Complete {
		return result, fmt.Errorf("%w: post-update readback does not match requested addresses", ErrDrift)
	}
	return result, nil
}

// ApplyAddresses is a descriptive alias for Sync.
func (a *Adapter) ApplyAddresses(ctx context.Context, binding Binding, desired []string) (SyncResult, error) {
	return a.Sync(ctx, binding, desired)
}

// DetectDrift compares a binding's owned set and shape against both readback
// sources. It is pure and safe to call from status/reconciliation paths.
func DetectDrift(binding Binding, rb Readback) DriftReport {
	report := DriftReport{}
	managed, err := CanonicalAddresses(binding.ManagedAddresses)
	if err != nil {
		report.Drifted = true
		report.Items = append(report.Items, DriftItem{Kind: DriftPersistedAddresses, Expected: nil, Observed: append([]string(nil), binding.ManagedAddresses...), Message: err.Error()})
		return report
	}
	if !shapeMatches(binding.Alias, rb.Persisted) || !shapeMatches(binding.Alias, rb.Active) {
		report.Drifted = true
		report.Items = append(report.Items, DriftItem{Kind: DriftShape, Message: "alias identity or type differs from attached shape"})
	}
	if !equalStrings(managed, rb.Persisted.Addresses) {
		report.Drifted = true
		report.Items = append(report.Items, DriftItem{Kind: DriftPersistedAddresses, Expected: managed, Observed: append([]string(nil), rb.Persisted.Addresses...), Message: "persisted alias addresses differ from owned addresses"})
	}
	if !equalStrings(managed, rb.Active.Addresses) {
		report.Drifted = true
		report.Items = append(report.Items, DriftItem{Kind: DriftActiveAddresses, Expected: managed, Observed: append([]string(nil), rb.Active.Addresses...), Message: "active alias addresses differ from owned addresses"})
	}
	if !equalStrings(rb.Persisted.Addresses, rb.Active.Addresses) {
		report.Drifted = true
		report.Items = append(report.Items, DriftItem{Kind: DriftPersistedActive, Expected: append([]string(nil), rb.Persisted.Addresses...), Observed: append([]string(nil), rb.Active.Addresses...), Message: "persisted alias and active table differ"})
	}
	return report
}

// ComputeAddressDelta canonicalizes both inputs and computes a sorted set
// difference. It never returns an operation that flushes the entire alias.
func ComputeAddressDelta(current, desired []string) (AddressDelta, error) {
	current, err := CanonicalAddresses(current)
	if err != nil {
		return AddressDelta{}, fmt.Errorf("current addresses: %w", err)
	}
	desired, err = CanonicalAddresses(desired)
	if err != nil {
		return AddressDelta{}, fmt.Errorf("desired addresses: %w", err)
	}
	have := make(map[string]struct{}, len(current))
	want := make(map[string]struct{}, len(desired))
	for _, address := range current {
		have[address] = struct{}{}
	}
	for _, address := range desired {
		want[address] = struct{}{}
	}
	delta := AddressDelta{}
	for address := range want {
		if _, ok := have[address]; !ok {
			delta.Add = append(delta.Add, address)
		}
	}
	for address := range have {
		if _, ok := want[address]; !ok {
			delta.Remove = append(delta.Remove, address)
		}
	}
	sort.Strings(delta.Add)
	sort.Strings(delta.Remove)
	return delta, nil
}

// AddressDeltaFor is retained as a concise spelling for callers that prefer
// a noun-first helper name.
func AddressDeltaFor(current, desired []string) (AddressDelta, error) {
	return ComputeAddressDelta(current, desired)
}

// CanonicalAddress accepts an IP or CIDR and returns its stable textual form.
// Host prefixes (/32 and /128) collapse to their IP; network prefixes retain
// the canonical network address. IPv4-mapped IPv6 values normalize to IPv4.
func CanonicalAddress(raw string) (string, AddressFamily, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("address is empty")
	}
	if strings.Contains(raw, "%") {
		return "", "", fmt.Errorf("address zones are not supported: %q", raw)
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			return ip.String(), IPv4Family, nil
		}
		return ip.String(), IPv6Family, nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid address %q", raw)
	}
	// Only a mapped prefix contained in ::ffff:0:0/96 is an IPv4 network.
	// Shorter prefixes include ordinary IPv6 addresses and stay IPv6.
	if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	prefix = prefix.Masked()
	family := IPv6Family
	if prefix.Addr().Is4() {
		family = IPv4Family
	}
	if prefix.Bits() == prefix.Addr().BitLen() {
		return prefix.Addr().String(), family, nil
	}
	return prefix.String(), family, nil
}

// NormalizeAddress is a compatibility alias used by adapters that call the
// operation normalization rather than canonicalization.
func NormalizeAddress(raw string) (string, AddressFamily, error) {
	return CanonicalAddress(raw)
}

// CanonicalAddresses canonicalizes, deduplicates, and sorts addresses.
func CanonicalAddresses(addresses []string) ([]string, error) {
	seen := make(map[string]struct{}, len(addresses))
	for _, raw := range addresses {
		address, _, err := CanonicalAddress(raw)
		if err != nil {
			return nil, err
		}
		seen[address] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for address := range seen {
		out = append(out, address)
	}
	sort.Strings(out)
	return out, nil
}

// CanonicalizeAddresses is a compatibility alias.
func CanonicalizeAddresses(addresses []string) ([]string, error) {
	return CanonicalAddresses(addresses)
}

// FlattenAddressUnion canonicalizes and unions addresses from all active
// members of a binding. It is intentionally a set operation: repeated device
// membership cannot result in repeated OPNsense requests.
func FlattenAddressUnion(addressSets ...[]string) ([]string, error) {
	var all []string
	for _, addresses := range addressSets {
		all = append(all, addresses...)
	}
	return CanonicalAddresses(all)
}

func (r AttachRequest) validate() error {
	if strings.TrimSpace(r.GatewayID) == "" {
		return fmt.Errorf("%w: gateway id is required", ErrInvalidBinding)
	}
	if strings.TrimSpace(r.Alias) == "" {
		return fmt.Errorf("%w: alias is required", ErrInvalidBinding)
	}
	if strings.TrimSpace(r.InterfaceScope) == "" {
		return fmt.Errorf("%w: client interface scope is required", ErrInvalidBinding)
	}
	if r.Family != IPv4Family && r.Family != IPv6Family && r.Family != DualFamily {
		return fmt.Errorf("%w: invalid address family %q", ErrInvalidBinding, r.Family)
	}
	if r.AliasType != "" && r.AliasType != HostAlias && r.AliasType != NetworkAlias {
		return fmt.Errorf("%w: unsupported alias type %q", ErrInvalidBinding, r.AliasType)
	}
	if r.ExpectedAddresses != nil {
		if _, err := CanonicalAddresses(r.ExpectedAddresses); err != nil {
			return fmt.Errorf("%w: expected addresses: %v", ErrInvalidBinding, err)
		}
	}
	return nil
}

func (b Binding) Validate() error {
	if strings.TrimSpace(b.GatewayID) == "" || strings.TrimSpace(b.Alias.Name) == "" {
		return fmt.Errorf("%w: gateway and alias are required", ErrInvalidBinding)
	}
	if b.Family != IPv4Family && b.Family != IPv6Family && b.Family != DualFamily {
		return fmt.Errorf("%w: invalid address family %q", ErrInvalidBinding, b.Family)
	}
	if b.Alias.Type != HostAlias && b.Alias.Type != NetworkAlias {
		return fmt.Errorf("%w: unsupported alias type %q", ErrInvalidBinding, b.Alias.Type)
	}
	addresses, err := CanonicalAddresses(b.ManagedAddresses)
	if err != nil {
		return fmt.Errorf("%w: managed addresses: %v", ErrInvalidBinding, err)
	}
	return validateFamily(b.Family, addresses)
}

func validateFamily(family AddressFamily, addresses []string) error {
	for _, address := range addresses {
		_, actual, err := CanonicalAddress(address)
		if err != nil {
			return err
		}
		if family == IPv4Family && actual != IPv4Family {
			return fmt.Errorf("%w: IPv6 address %q is outside an IPv4 binding", ErrInvalidBinding, address)
		}
		if family == IPv6Family && actual != IPv6Family {
			return fmt.Errorf("%w: IPv4 address %q is outside an IPv6 binding", ErrInvalidBinding, address)
		}
	}
	return nil
}

func canonicalRecord(record AliasRecord) (AliasRecord, error) {
	if record.Disabled {
		return AliasRecord{}, fmt.Errorf("%w: alias is disabled", ErrShapeChanged)
	}
	if strings.TrimSpace(record.Name) == "" {
		return AliasRecord{}, fmt.Errorf("%w: alias name is empty", ErrShapeChanged)
	}
	if record.Type != HostAlias && record.Type != NetworkAlias {
		return AliasRecord{}, fmt.Errorf("%w: unsupported alias type %q", ErrShapeChanged, record.Type)
	}
	addresses, err := CanonicalAddresses(record.Addresses)
	if err != nil {
		return AliasRecord{}, err
	}
	record.Name = strings.TrimSpace(record.Name)
	record.UUID = strings.TrimSpace(record.UUID)
	record.Description = strings.TrimSpace(record.Description)
	record.OwnerTag = strings.TrimSpace(record.OwnerTag)
	record.Addresses = addresses
	return record, nil
}

func validateShape(record AliasRecord, req AttachRequest) error {
	if record.Name != strings.TrimSpace(req.Alias) {
		return fmt.Errorf("%w: expected alias %q, observed %q", ErrShapeChanged, req.Alias, record.Name)
	}
	if req.AliasUUID != "" && record.UUID != strings.TrimSpace(req.AliasUUID) {
		return fmt.Errorf("%w: alias UUID changed", ErrShapeChanged)
	}
	if req.AliasType != "" && record.Type != req.AliasType {
		return fmt.Errorf("%w: alias type changed", ErrShapeChanged)
	}
	if req.AliasDescription != "" && record.Description != strings.TrimSpace(req.AliasDescription) {
		return fmt.Errorf("%w: alias description changed", ErrShapeChanged)
	}
	if req.OwnerTag != "" && record.OwnerTag != strings.TrimSpace(req.OwnerTag) {
		return fmt.Errorf("%w: alias ownership tag changed", ErrShapeChanged)
	}
	return nil
}

func shapeFromRecord(record AliasRecord) AliasShape {
	return AliasShape{Name: record.Name, UUID: record.UUID, Type: record.Type, Description: record.Description, OwnerTag: record.OwnerTag, Disabled: record.Disabled}
}

func shapeMatches(shape AliasShape, record AliasRecord) bool {
	return shape.Name == record.Name && shape.UUID == record.UUID && shape.Type == record.Type && shape.Description == record.Description && shape.OwnerTag == record.OwnerTag && shape.Disabled == record.Disabled
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
