package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

type EnrollmentMode string

const (
	EnableEnrollment EnrollmentMode = "enable"
	MoveDeviceGroup  EnrollmentMode = "move_group"
	BypassEnrollment EnrollmentMode = "bypass"
)

type SessionDisposition string

const (
	PreserveSessions SessionDisposition = "preserve"
	CleanupSessions  SessionDisposition = "cleanup"
)

// EnrollmentManifest is an approved, immutable snapshot. Addresses and
// PreviousAddresses are complete controller-owned alias contents; Sources
// identifies just the clients affected by this operation. Policy is a typed
// adapter payload, never a shell command or filesystem path.
type EnrollmentManifest struct {
	Mode                      EnrollmentMode     `json:"mode"`
	GatewayID                 string             `json:"gateway_id"`
	PreviousGatewayID         string             `json:"previous_gateway_id,omitempty"`
	FirewallID                string             `json:"firewall_id"`
	BindingID                 string             `json:"binding_id"`
	ExpectedFirewallShapeHash string             `json:"expected_firewall_shape_hash"`
	ExpectedGeneration        uint64             `json:"expected_generation"`
	ExpectedPolicyHash        string             `json:"expected_policy_hash"`
	Generation                uint64             `json:"generation"`
	PolicyHash                string             `json:"policy_hash"`
	Policy                    json.RawMessage    `json:"policy,omitempty"`
	Sources                   []string           `json:"sources"`
	PreviousAddresses         []string           `json:"previous_addresses"`
	Addresses                 []string           `json:"addresses"`
	Strict                    bool               `json:"strict"`
	Disposition               string             `json:"disposition,omitempty"`
	Sessions                  SessionDisposition `json:"sessions"`
	ProbeRequired             bool               `json:"probe_required"`
}

// GuardState describes independent enforcement on the gateway and firewall
// fallback paths. IPv6Protected includes an independently blocked IPv6 segment.
// Ready must mean the guard is installed, not merely that a process is alive.
type GuardState struct {
	Generation        uint64   `json:"generation"`
	PolicyHash        string   `json:"policy_hash"`
	Ready             bool     `json:"ready"`
	FailClosed        bool     `json:"fail_closed"`
	Quarantined       bool     `json:"quarantined"`
	Sources           []string `json:"sources"`
	FallbackProtected bool     `json:"fallback_protected"`
	IPv6Protected     bool     `json:"ipv6_protected"`
}

type GatewayState struct {
	Generation    uint64 `json:"generation"`
	PolicyHash    string `json:"policy_hash"`
	PolicyRetired bool   `json:"policy_retired"`
}

type FirewallState struct {
	BindingID string   `json:"binding_id"`
	ShapeHash string   `json:"shape_hash"`
	Persisted []string `json:"persisted"`
	Active    []string `json:"active"`
}

type FirewallDelta struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

// SessionCleanupResult covers only the sources and generation in the manifest.
// Complete is false if any relevant enforcement layer could not retire its
// old sessions. Implementations must never substitute a global state flush.
type SessionCleanupResult struct {
	Requested bool   `json:"requested"`
	Complete  bool   `json:"complete"`
	Removed   int    `json:"removed"`
	Message   string `json:"message,omitempty"`
}

type ClientProbeResult struct {
	Available     bool   `json:"available"`
	Passed        bool   `json:"passed"`
	SourceAddress string `json:"source_address"`
	GatewayID     string `json:"gateway_id"`
	Generation    uint64 `json:"generation"`
	Kind          string `json:"kind"`
	Message       string `json:"message,omitempty"`
}

type Guard interface {
	// Prepare cannot clear an existing quarantine. Release is the only
	// loosening operation; every method must reject stale guard-target fences.
	Prepare(context.Context, EnrollmentManifest, Fence) error
	Observe(context.Context, EnrollmentManifest) (GuardState, error)
	Quarantine(context.Context, EnrollmentManifest, Fence) error
	Release(context.Context, EnrollmentManifest, Fence) error
}

type Gateway interface {
	Validate(context.Context, EnrollmentManifest) error
	Apply(context.Context, EnrollmentManifest, Fence) error
	// RetirePolicy retires only the affected sources' unused policy. With
	// PreserveSessions it retains live session references until they drain.
	RetirePolicy(context.Context, EnrollmentManifest, Fence) error
	Observe(context.Context, EnrollmentManifest) (GatewayState, error)
	CleanupSessions(context.Context, EnrollmentManifest, Fence) (SessionCleanupResult, error)
}

type Firewall interface {
	ApplyDelta(context.Context, EnrollmentManifest, FirewallDelta, Fence) error
	Observe(context.Context, EnrollmentManifest) (FirewallState, error)
	CleanupSessions(context.Context, EnrollmentManifest, Fence) (SessionCleanupResult, error)
}

type TrafficProbe interface {
	ProbeClient(context.Context, EnrollmentManifest) (ClientProbeResult, error)
}

// BoundaryReceipt is saved before each mutation and after its independent
// readback. An interrupted running receipt is resolved by observation, not by
// replaying the call. Receipt errors are retained even if quarantine succeeds.
type BoundaryReceipt struct {
	Name   string     `json:"name"`
	Status StepStatus `json:"status"`
	Error  string     `json:"error,omitempty"`
}

type CrossSystemState struct {
	Guard                GuardState           `json:"guard"`
	Gateway              GatewayState         `json:"gateway"`
	Firewall             FirewallState        `json:"firewall"`
	PreviousGuard        GuardState           `json:"previous_guard"`
	PreviousGateway      GatewayState         `json:"previous_gateway"`
	PreviousFirewall     FirewallState        `json:"previous_firewall"`
	FirewallFence        Fence                `json:"firewall_fence"`
	GuardFence           Fence                `json:"guard_fence"`
	GatewaySessions      SessionCleanupResult `json:"gateway_sessions"`
	FirewallSessions     SessionCleanupResult `json:"firewall_sessions"`
	Probe                *ClientProbeResult   `json:"probe,omitempty"`
	ConfigurationApplied bool                 `json:"configuration_applied"`
	TrafficVerified      bool                 `json:"traffic_verified"`
	VerifiedSources      []string             `json:"verified_sources,omitempty"`
	Receipts             []BoundaryReceipt    `json:"receipts"`
	Failure              string               `json:"failure,omitempty"`
	QuarantineError      string               `json:"quarantine_error,omitempty"`
}

var (
	ErrUnsafeRollback           = errors.New("strict deployment cannot roll back to a permissive policy")
	ErrExplicitRecoveryRequired = errors.New("rollback requires a new explicitly approved recovery manifest")
	crossSystemLocks            = NewTargetLocker()
)

// CrossSystemExecutor coordinates guard -> engine/readback -> alias/readback
// -> targeted sessions -> client probe. Instances share target locks, including
// a firewall shared by multiple gateways. Remote adapters must also enforce
// Fence tokens; the controller lock alone cannot fence a delayed remote call.
// No failure causes automatic rollback to an older, potentially permissive
// policy. In strict mode an independent quarantine is applied and read back.
// Locks must be distinct from Runner.Locks because Runner owns its operation
// lock throughout the call. TrafficVerified is scoped to VerifiedSources.
type CrossSystemExecutor struct {
	Journal  Journal
	Guard    Guard
	Gateway  Gateway
	Firewall Firewall
	Probe    TrafficProbe
	Locks    *TargetLocker
}

func NewCrossSystemExecutor(j Journal, guard Guard, gateway Gateway, firewall Firewall, probe TrafficProbe) *CrossSystemExecutor {
	return &CrossSystemExecutor{Journal: j, Guard: guard, Gateway: gateway, Firewall: firewall, Probe: probe, Locks: crossSystemLocks}
}

var _ Executor = (*CrossSystemExecutor)(nil)
var _ ReadbackExecutor = (*CrossSystemExecutor)(nil)

func EnrollmentRequest(key string, manifest EnrollmentManifest) (Request, error) {
	data, err := json.Marshal(manifest)
	if err != nil {
		return Request{}, err
	}
	return Request{IdempotencyKey: key, Target: Target{Kind: "gateway", ID: manifest.GatewayID}, Action: string(manifest.Mode), RequestedGeneration: manifest.Generation, Desired: &StateRecord{Generation: manifest.Generation, Revision: manifest.PolicyHash, Data: data}}, nil
}

func enrollmentManifest(op Operation) (EnrollmentManifest, error) {
	var m EnrollmentManifest
	if op.Views.Desired == nil || len(op.Views.Desired.Data) == 0 {
		return m, fmt.Errorf("%w: enrollment manifest is required", ErrInvalidRequest)
	}
	if err := json.Unmarshal(op.Views.Desired.Data, &m); err != nil {
		return m, fmt.Errorf("%w: malformed enrollment manifest", ErrInvalidRequest)
	}
	if m.GatewayID == "" || m.FirewallID == "" || m.BindingID == "" || m.ExpectedFirewallShapeHash == "" || len(m.Sources) == 0 {
		return m, fmt.Errorf("%w: gateway, firewall, binding, expected shape and sources are required", ErrInvalidRequest)
	}
	if op.Target != (Target{Kind: "gateway", ID: m.GatewayID}) || op.Action != string(m.Mode) || op.RequestedGeneration != m.Generation {
		return m, fmt.Errorf("%w: operation identity does not match its manifest", ErrInvalidRequest)
	}
	for _, set := range [][]string{m.Sources, m.PreviousAddresses, m.Addresses} {
		seen := map[string]bool{}
		for _, raw := range set {
			ip, err := netip.ParseAddr(raw)
			if err != nil || ip.Is4In6() || ip.Zone() != "" || ip.String() != raw || seen[raw] {
				return m, fmt.Errorf("%w: addresses must be unique canonical host IPs", ErrInvalidRequest)
			}
			seen[raw] = true
		}
	}
	if m.Sessions != PreserveSessions && m.Sessions != CleanupSessions {
		return m, fmt.Errorf("%w: explicit session disposition is required", ErrInvalidRequest)
	}
	delta := addressDelta(m.PreviousAddresses, m.Addresses)
	switch m.Mode {
	case EnableEnrollment:
		if len(delta.Remove) > 0 || !containsAll(m.Sources, delta.Add) || !containsAll(m.Addresses, m.Sources) {
			return m, fmt.Errorf("%w: enrollment delta exceeds affected sources", ErrInvalidRequest)
		}
	case MoveDeviceGroup:
		if m.PreviousGatewayID != m.GatewayID || !sameAddresses(m.PreviousAddresses, m.Addresses) || !containsAll(m.Addresses, m.Sources) {
			return m, fmt.Errorf("%w: same-gateway group move must retain enrollment", ErrInvalidRequest)
		}
	case BypassEnrollment:
		if m.Disposition != "bypass" || len(delta.Add) > 0 || !containsAll(m.Sources, delta.Remove) || !containsAll(m.PreviousAddresses, m.Sources) || intersects(m.Addresses, m.Sources) {
			return m, fmt.Errorf("%w: bypass requires explicit disposition and removal of affected sources", ErrInvalidRequest)
		}
	default:
		return m, fmt.Errorf("%w: unsupported enrollment mode", ErrInvalidRequest)
	}
	if m.Mode != BypassEnrollment && (m.Generation <= m.ExpectedGeneration || m.PolicyHash == "" || len(m.Policy) == 0 || !json.Valid(m.Policy)) {
		return m, fmt.Errorf("%w: a newer policy generation and valid policy payload are required", ErrInvalidRequest)
	}
	if m.ExpectedGeneration > 0 && m.ExpectedPolicyHash == "" {
		return m, fmt.Errorf("%w: expected policy content hash is required", ErrInvalidRequest)
	}
	if m.Strict && m.Mode != BypassEnrollment && m.Sessions != CleanupSessions {
		return m, fmt.Errorf("%w: strict transition requires targeted session cleanup", ErrInvalidRequest)
	}
	return m, nil
}

func (e *CrossSystemExecutor) Validate(ctx context.Context, op Operation) error {
	m, err := enrollmentManifest(op)
	if err != nil {
		return err
	}
	if e.Journal == nil || e.Guard == nil || e.Gateway == nil || e.Firewall == nil {
		return fmt.Errorf("%w: cross-system adapters and journal are required", ErrInvalidRequest)
	}
	if m.ProbeRequired && e.Probe == nil {
		return fmt.Errorf("%w: required enrolled-client probe is unavailable", ErrInvalidRequest)
	}
	if m.ProbeRequired && len(m.Sources) != 1 {
		return fmt.Errorf("%w: required client verification needs one source per deployment", ErrInvalidRequest)
	}
	if m.Mode != BypassEnrollment {
		return e.Gateway.Validate(ctx, m)
	}
	return nil
}

func (e *CrossSystemExecutor) Stage(ctx context.Context, op Operation, f Fence) error {
	_, err := enrollmentManifest(op)
	if err != nil {
		return err
	}
	return e.current(ctx, f)
}

func (e *CrossSystemExecutor) lock(m EnrollmentManifest) func() {
	locks := e.Locks
	if locks == nil {
		locks = crossSystemLocks
	}
	targets := []Target{{Kind: "gateway", ID: m.GatewayID}, {Kind: "opnsense", ID: m.FirewallID}}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Key() < targets[j].Key() })
	a := locks.lock(targets[0])
	b := locks.lock(targets[1])
	return func() { b(); a() }
}

func (e *CrossSystemExecutor) current(ctx context.Context, f Fence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := e.Journal.FenceCurrent(ctx, f.Target, f.Token)
	if err != nil {
		return err
	}
	if !current {
		return ErrFenceLost
	}
	return nil
}

func crossRecord(m EnrollmentManifest, s CrossSystemState) *StateRecord {
	data, _ := json.Marshal(s)
	status := "partially_applied"
	if s.ConfigurationApplied {
		status = "configuration_applied"
	}
	if s.TrafficVerified {
		status = "traffic_verified"
	}
	return &StateRecord{Generation: m.Generation, Revision: m.PolicyHash, Status: status, Data: data, At: time.Now().UTC()}
}

func (e *CrossSystemExecutor) checkpoint(ctx context.Context, op Operation, m EnrollmentManifest, s CrossSystemState) error {
	ctx, cancel := recoveryContext(ctx)
	defer cancel()
	latest, err := e.Journal.Get(ctx, op.ID)
	if err != nil {
		return err
	}
	latest.Views.Applied = crossRecord(m, s)
	latest.UpdatedAt = time.Now().UTC()
	return e.Journal.Save(ctx, latest)
}

func recoveryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
}

func (e *CrossSystemExecutor) observeGuardAfterMutation(ctx context.Context, m EnrollmentManifest) (GuardState, error) {
	ctx, cancel := recoveryContext(ctx)
	defer cancel()
	return e.Guard.Observe(ctx, m)
}
func (e *CrossSystemExecutor) observeGatewayAfterMutation(ctx context.Context, m EnrollmentManifest) (GatewayState, error) {
	ctx, cancel := recoveryContext(ctx)
	defer cancel()
	return e.Gateway.Observe(ctx, m)
}
func (e *CrossSystemExecutor) observeFirewallAfterMutation(ctx context.Context, m EnrollmentManifest) (FirewallState, error) {
	ctx, cancel := recoveryContext(ctx)
	defer cancel()
	return e.Firewall.Observe(ctx, m)
}

func (e *CrossSystemExecutor) begin(ctx context.Context, op Operation, m EnrollmentManifest, s *CrossSystemState, name string, f Fence) error {
	if err := e.current(ctx, f); err != nil {
		return err
	}
	if err := e.current(ctx, Fence{Target: op.Target, Token: op.FenceToken}); err != nil {
		return err
	}
	s.Receipts = append(s.Receipts, BoundaryReceipt{Name: name, Status: StepRunning})
	return e.checkpoint(ctx, op, m, *s)
}

func (e *CrossSystemExecutor) nextGuardFence(ctx context.Context, m EnrollmentManifest, s *CrossSystemState) (Fence, error) {
	f, err := e.Journal.NextFence(ctx, Target{Kind: "guard", ID: m.GatewayID})
	if err == nil {
		s.GuardFence = f
	}
	return f, err
}

func (e *CrossSystemExecutor) ensureFirewallTargetAvailable(ctx context.Context, op Operation, m EnrollmentManifest) error {
	ops, err := e.Journal.List(ctx)
	if err != nil {
		return err
	}
	for _, other := range ops {
		if other.ID == op.ID || terminal(other.Status) {
			continue
		}
		prior, decodeErr := enrollmentManifest(other)
		if decodeErr == nil && prior.FirewallID == m.FirewallID && !terminal(other.Status) {
			return fmt.Errorf("%w: firewall target has unresolved operation %s", ErrAlreadyRunning, other.ID)
		}
	}
	return nil
}

func (e *CrossSystemExecutor) end(ctx context.Context, op Operation, m EnrollmentManifest, s *CrossSystemState, err error) error {
	i := len(s.Receipts) - 1
	if i >= 0 {
		s.Receipts[i].Status = StepSucceeded
		if err != nil {
			s.Receipts[i].Status = StepFailed
			s.Receipts[i].Error = err.Error()
			if isUnknown(err) {
				s.Receipts[i].Status = StepUnknown
			}
		}
	}
	if saveErr := e.checkpoint(ctx, op, m, *s); saveErr != nil {
		return errors.Join(err, saveErr)
	}
	return err
}

func (e *CrossSystemExecutor) observe(ctx context.Context, m EnrollmentManifest, s *CrossSystemState) error {
	var err error
	s.Guard, err = e.Guard.Observe(ctx, m)
	if err != nil {
		return fmt.Errorf("guard readback: %w", err)
	}
	s.Gateway, err = e.Gateway.Observe(ctx, m)
	if err != nil {
		return fmt.Errorf("gateway readback: %w", err)
	}
	s.Firewall, err = e.Firewall.Observe(ctx, m)
	if err != nil {
		return fmt.Errorf("firewall readback: %w", err)
	}
	return nil
}

func (e *CrossSystemExecutor) Apply(ctx context.Context, op Operation, f Fence) (ApplyResult, error) {
	m, err := enrollmentManifest(op)
	if err != nil {
		return ApplyResult{}, err
	}
	unlock := e.lock(m)
	defer unlock()
	latest, getErr := e.Journal.Get(ctx, op.ID)
	if getErr != nil {
		return ApplyResult{}, getErr
	}
	if latest.Views.Applied != nil {
		readback, readErr := e.readbackLocked(ctx, latest, m, f)
		result := ApplyResult{Applied: readback.Observed}
		if readErr != nil {
			return result, readErr
		}
		if !readback.VerifiedOK {
			return result, &PartialError{Err: errors.New("interrupted composite operation requires a new recovery manifest")}
		}
		return result, nil
	}
	var s CrossSystemState
	if err = e.current(ctx, f); err != nil {
		return ApplyResult{}, err
	}
	if err = e.observe(ctx, m, &s); err != nil {
		return e.failed(ctx, op, m, s, f, err)
	}
	s.PreviousGuard, s.PreviousGateway, s.PreviousFirewall = s.Guard, s.Gateway, s.Firewall
	s.PreviousGuard.Sources = append([]string(nil), s.Guard.Sources...)
	s.PreviousFirewall.Persisted = append([]string(nil), s.Firewall.Persisted...)
	s.PreviousFirewall.Active = append([]string(nil), s.Firewall.Active...)
	if !firewallShapeMatches(m, s.Firewall) || (!firewallAddressesMatch(s.Firewall, m.PreviousAddresses) && !firewallAddressesMatch(s.Firewall, m.Addresses)) {
		return e.failed(ctx, op, m, s, f, &DriftError{Err: errors.New("owned firewall shape or membership changed")})
	}
	baseMatches := s.Gateway.Generation == m.ExpectedGeneration && s.Gateway.PolicyHash == m.ExpectedPolicyHash
	if !baseMatches && !gatewayMatches(m, s.Gateway) && !(m.Mode == BypassEnrollment && gatewayRetired(s.Gateway)) {
		return e.failed(ctx, op, m, s, f, &DriftError{Err: errors.New("gateway generation changed")})
	}
	if err = e.ensureFirewallTargetAvailable(ctx, op, m); err != nil {
		return e.failed(ctx, op, m, s, f, err)
	}
	s.FirewallFence, err = e.Journal.NextFence(ctx, Target{Kind: "opnsense", ID: m.FirewallID})
	if err != nil {
		return ApplyResult{}, err
	}
	if err = e.checkpoint(ctx, op, m, s); err != nil {
		return ApplyResult{}, err
	}
	if m.Mode != BypassEnrollment {
		if !guardMatches(m, s.Guard) {
			guardFence, fenceErr := e.nextGuardFence(ctx, m, &s)
			if fenceErr != nil {
				return e.failed(ctx, op, m, s, f, fenceErr)
			}
			if err = e.begin(ctx, op, m, &s, "guard.prepare", guardFence); err != nil {
				return e.failed(ctx, op, m, s, f, err)
			}
			callErr := e.Guard.Prepare(ctx, m, guardFence)
			readErr := error(nil)
			s.Guard, readErr = e.observeGuardAfterMutation(ctx, m)
			err = boundaryError(callErr, readErr, guardMatches(m, s.Guard), "guard readiness")
			if err = e.end(ctx, op, m, &s, err); err != nil {
				return e.failed(ctx, op, m, s, f, err)
			}
		}
		if !gatewayMatches(m, s.Gateway) {
			if err = e.begin(ctx, op, m, &s, "gateway.apply", f); err != nil {
				return e.failed(ctx, op, m, s, f, err)
			}
			callErr := e.Gateway.Apply(ctx, m, f)
			readErr := error(nil)
			s.Gateway, readErr = e.observeGatewayAfterMutation(ctx, m)
			err = boundaryError(callErr, readErr, gatewayMatches(m, s.Gateway), "gateway generation")
			if err = e.end(ctx, op, m, &s, err); err != nil {
				return e.failed(ctx, op, m, s, f, err)
			}
		}
	}
	if !firewallAddressesMatch(s.Firewall, m.Addresses) {
		// Group moves have equal before/after sets and never enter this branch.
		if err = e.begin(ctx, op, m, &s, "firewall.delta", s.FirewallFence); err != nil {
			return e.failed(ctx, op, m, s, f, err)
		}
		callErr := e.Firewall.ApplyDelta(ctx, m, addressDelta(s.Firewall.Persisted, m.Addresses), s.FirewallFence)
		readErr := error(nil)
		s.Firewall, readErr = e.observeFirewallAfterMutation(ctx, m)
		err = boundaryError(callErr, readErr, firewallShapeMatches(m, s.Firewall) && firewallAddressesMatch(s.Firewall, m.Addresses), "persisted and active enrollment")
		if err = e.end(ctx, op, m, &s, err); err != nil {
			return e.failed(ctx, op, m, s, f, err)
		}
	}
	if m.Sessions == CleanupSessions {
		if err = e.begin(ctx, op, m, &s, "gateway.sessions", f); err != nil {
			return e.failed(ctx, op, m, s, f, err)
		}
		s.GatewaySessions, err = e.Gateway.CleanupSessions(ctx, m, f)
		s.GatewaySessions.Requested = true
		if err == nil && !s.GatewaySessions.Complete {
			err = errors.New("gateway session cleanup incomplete")
		}
		if err = e.end(ctx, op, m, &s, err); err != nil {
			return e.failed(ctx, op, m, s, f, err)
		}
		if err = e.begin(ctx, op, m, &s, "firewall.sessions", s.FirewallFence); err != nil {
			return e.failed(ctx, op, m, s, f, err)
		}
		s.FirewallSessions, err = e.Firewall.CleanupSessions(ctx, m, s.FirewallFence)
		s.FirewallSessions.Requested = true
		if err == nil && !s.FirewallSessions.Complete {
			err = errors.New("firewall session cleanup incomplete")
		}
		if err = e.end(ctx, op, m, &s, err); err != nil {
			return e.failed(ctx, op, m, s, f, err)
		}
	}
	if m.Mode == BypassEnrollment && intersects(s.Guard.Sources, m.Sources) {
		guardFence, fenceErr := e.nextGuardFence(ctx, m, &s)
		if fenceErr != nil {
			return e.failed(ctx, op, m, s, f, fenceErr)
		}
		if err = e.begin(ctx, op, m, &s, "guard.release", guardFence); err != nil {
			return e.failed(ctx, op, m, s, f, err)
		}
		callErr := e.Guard.Release(ctx, m, guardFence)
		readErr := error(nil)
		s.Guard, readErr = e.observeGuardAfterMutation(ctx, m)
		err = boundaryError(callErr, readErr, !intersects(s.Guard.Sources, m.Sources), "guard release")
		if err = e.end(ctx, op, m, &s, err); err != nil {
			return e.failed(ctx, op, m, s, f, err)
		}
	}
	if m.Mode == BypassEnrollment && !gatewayRetired(s.Gateway) {
		if err = e.begin(ctx, op, m, &s, "gateway.retire_policy", f); err != nil {
			return e.failed(ctx, op, m, s, f, err)
		}
		callErr := e.Gateway.RetirePolicy(ctx, m, f)
		readErr := error(nil)
		s.Gateway, readErr = e.observeGatewayAfterMutation(ctx, m)
		err = boundaryError(callErr, readErr, gatewayRetired(s.Gateway), "gateway policy retirement")
		if err = e.end(ctx, op, m, &s, err); err != nil {
			return e.failed(ctx, op, m, s, f, err)
		}
	}
	s.ConfigurationApplied = configurationMatches(m, s)
	if e.Probe != nil {
		if err = e.begin(ctx, op, m, &s, "traffic.probe", f); err != nil {
			return e.failed(ctx, op, m, s, f, err)
		}
		probe, probeErr := e.Probe.ProbeClient(ctx, m)
		s.Probe = &probe
		s.TrafficVerified = probeErr == nil && probeMatches(m, probe)
		if m.ProbeRequired && !s.TrafficVerified {
			if probeErr == nil {
				probeErr = errors.New("required enrolled-client traffic probe did not verify this generation")
			}
			err = probeErr
		}
		i := len(s.Receipts) - 1
		s.Receipts[i].Status = StepSucceeded
		if probeErr != nil || !s.TrafficVerified {
			s.Receipts[i].Status = StepFailed
			if probeErr != nil {
				s.Receipts[i].Error = probeErr.Error()
			}
		}
		if saveErr := e.checkpoint(ctx, op, m, s); saveErr != nil {
			return e.failed(ctx, op, m, s, f, saveErr)
		}
		if err != nil && m.ProbeRequired {
			return e.failed(ctx, op, m, s, f, err)
		}
		if s.TrafficVerified {
			s.VerifiedSources = []string{probe.SourceAddress}
		}
	}
	if err = e.checkpoint(ctx, op, m, s); err != nil {
		return ApplyResult{Applied: crossRecord(m, s)}, err
	}
	return ApplyResult{Applied: crossRecord(m, s)}, nil
}

func (e *CrossSystemExecutor) failed(ctx context.Context, op Operation, m EnrollmentManifest, s CrossSystemState, f Fence, cause error) (ApplyResult, error) {
	ctx, cancel := recoveryContext(ctx)
	defer cancel()
	s.Failure = cause.Error()
	s.ConfigurationApplied = false
	s.TrafficVerified = false
	if m.Strict {
		// A quarantine may only tighten access. Even a failed bypass stays
		// blocked until its operator-requested transition is complete.
		guardFence, fenceErr := e.nextGuardFence(ctx, m, &s)
		if fenceErr != nil {
			s.QuarantineError = fenceErr.Error()
			cause = errors.Join(cause, fenceErr)
		} else if err := e.begin(ctx, op, m, &s, "guard.quarantine", guardFence); err != nil {
			s.QuarantineError = err.Error()
			cause = errors.Join(cause, err)
		} else {
			callErr := e.Guard.Quarantine(ctx, m, guardFence)
			observed, readErr := e.Guard.Observe(ctx, m)
			s.Guard = observed
			qerr := boundaryError(callErr, readErr, quarantineMatches(m, observed), "quarantine")
			if err := e.end(ctx, op, m, &s, qerr); err != nil {
				s.QuarantineError = err.Error()
				cause = errors.Join(cause, err)
			} else if qerr != nil {
				s.QuarantineError = qerr.Error()
				cause = errors.Join(cause, qerr)
			}
		}
	}
	if saveErr := e.checkpoint(ctx, op, m, s); saveErr != nil {
		cause = errors.Join(cause, saveErr)
	}
	if isUnknown(cause) {
		return ApplyResult{Applied: crossRecord(m, s)}, &OutcomeUnknownError{Err: cause}
	}
	return ApplyResult{Applied: crossRecord(m, s)}, &PartialError{Err: cause}
}

func (e *CrossSystemExecutor) Verify(ctx context.Context, op Operation, f Fence) (VerifyResult, error) {
	return e.Readback(ctx, op, f)
}

// Readback performs no mutation and never replays a missing component. A
// partial operation requires a new approved manifest based on observed state.
// Durable cleanup/probe receipts are needed before claiming those boundaries.
func (e *CrossSystemExecutor) Readback(ctx context.Context, op Operation, f Fence) (VerifyResult, error) {
	m, err := enrollmentManifest(op)
	if err != nil {
		return VerifyResult{}, err
	}
	unlock := e.lock(m)
	defer unlock()
	return e.readbackLocked(ctx, op, m, f)
}

func (e *CrossSystemExecutor) readbackLocked(ctx context.Context, op Operation, m EnrollmentManifest, f Fence) (VerifyResult, error) {
	var err error
	if err = e.current(ctx, f); err != nil {
		return VerifyResult{}, err
	}
	var s CrossSystemState
	if op.Views.Applied != nil {
		if err = json.Unmarshal(op.Views.Applied.Data, &s); err != nil {
			return VerifyResult{}, fmt.Errorf("invalid composite receipt: %w", err)
		}
	}
	if s.FirewallFence.Token != 0 {
		current, fenceErr := e.Journal.FenceCurrent(ctx, s.FirewallFence.Target, s.FirewallFence.Token)
		if fenceErr != nil {
			return VerifyResult{}, fenceErr
		}
		if !current {
			return VerifyResult{}, ErrFenceLost
		}
	}
	if s.GuardFence.Token != 0 {
		if err = e.current(ctx, s.GuardFence); err != nil {
			return VerifyResult{}, err
		}
	}
	if err = e.observe(ctx, m, &s); err != nil {
		return VerifyResult{Observed: crossRecord(m, s)}, &OutcomeUnknownError{Err: err}
	}
	s.ConfigurationApplied = configurationMatches(m, s)
	s.TrafficVerified = s.ConfigurationApplied && s.Probe != nil && probeMatches(m, *s.Probe) && receiptSucceeded(s, "traffic.probe")
	if s.TrafficVerified {
		s.VerifiedSources = []string{s.Probe.SourceAddress}
	} else {
		s.VerifiedSources = nil
	}
	record := crossRecord(m, s)
	result := VerifyResult{Observed: record, VerifiedOK: s.ConfigurationApplied && (!m.ProbeRequired || s.TrafficVerified)}
	if s.TrafficVerified {
		result.Verified = record
	}
	if !result.VerifiedOK {
		result.Message = "cross-system readback or required session/traffic verification is incomplete"
	}
	return result, nil
}

// Rollback never changes enforcement. Failure handling already quarantines
// strict intent; restoring or loosening it requires an approved new manifest.
// Refusing here also preserves the existing fence for outcome readback.
func (e *CrossSystemExecutor) Rollback(_ context.Context, op Operation, _ Fence) error {
	m, err := enrollmentManifest(op)
	if err != nil {
		return err
	}
	if !m.Strict {
		return ErrExplicitRecoveryRequired
	}
	return ErrUnsafeRollback
}

func boundaryError(callErr, readErr error, matches bool, label string) error {
	if readErr == nil && matches {
		return nil
	}
	if readErr != nil {
		return &OutcomeUnknownError{Err: fmt.Errorf("%s readback failed: %w", label, errors.Join(callErr, readErr))}
	}
	if callErr != nil {
		return callErr
	}
	return fmt.Errorf("%s readback does not match manifest", label)
}
func guardMatches(m EnrollmentManifest, s GuardState) bool {
	return s.Ready && !s.Quarantined && s.Generation == m.Generation && s.PolicyHash == m.PolicyHash && containsAll(s.Sources, m.Sources) && (!m.Strict || (s.FailClosed && s.FallbackProtected && s.IPv6Protected))
}
func quarantineMatches(m EnrollmentManifest, s GuardState) bool {
	return s.Ready && s.Quarantined && s.FailClosed && s.FallbackProtected && s.IPv6Protected && containsAll(s.Sources, m.Sources)
}
func gatewayMatches(m EnrollmentManifest, s GatewayState) bool {
	return s.Generation == m.Generation && s.PolicyHash == m.PolicyHash
}
func firewallShapeMatches(m EnrollmentManifest, s FirewallState) bool {
	return s.BindingID == m.BindingID && s.ShapeHash == m.ExpectedFirewallShapeHash
}
func firewallAddressesMatch(s FirewallState, addresses []string) bool {
	return sameAddresses(s.Persisted, addresses) && sameAddresses(s.Active, addresses)
}
func configurationMatches(m EnrollmentManifest, s CrossSystemState) bool {
	if !firewallShapeMatches(m, s.Firewall) || !firewallAddressesMatch(s.Firewall, m.Addresses) {
		return false
	}
	if m.Sessions == CleanupSessions && (!s.GatewaySessions.Complete || !s.FirewallSessions.Complete || !receiptSucceeded(s, "gateway.sessions") || !receiptSucceeded(s, "firewall.sessions")) {
		return false
	}
	if m.Mode == BypassEnrollment {
		return !intersects(s.Guard.Sources, m.Sources) && gatewayRetired(s.Gateway)
	}
	return guardMatches(m, s.Guard) && gatewayMatches(m, s.Gateway)
}
func probeMatches(m EnrollmentManifest, p ClientProbeResult) bool {
	return p.Available && p.Passed && p.Kind == "enrolled_client" && p.GatewayID == m.GatewayID && p.Generation == m.Generation && containsAll(m.Sources, []string{p.SourceAddress})
}
func gatewayRetired(s GatewayState) bool { return s.PolicyRetired }
func receiptSucceeded(s CrossSystemState, name string) bool {
	for i := len(s.Receipts) - 1; i >= 0; i-- {
		if s.Receipts[i].Name == name {
			return s.Receipts[i].Status == StepSucceeded
		}
	}
	return false
}
func containsAll(set, subset []string) bool {
	values := map[string]bool{}
	for _, v := range set {
		values[v] = true
	}
	for _, v := range subset {
		if !values[v] {
			return false
		}
	}
	return true
}
func sameAddresses(a, b []string) bool {
	return len(a) == len(b) && containsAll(a, b) && containsAll(b, a)
}
func intersects(a, b []string) bool {
	for _, v := range a {
		if containsAll(b, []string{v}) {
			return true
		}
	}
	return false
}
func addressDelta(old, next []string) FirewallDelta {
	d := FirewallDelta{Add: []string{}, Remove: []string{}}
	for _, v := range next {
		if !containsAll(old, []string{v}) {
			d.Add = append(d.Add, v)
		}
	}
	for _, v := range old {
		if !containsAll(next, []string{v}) {
			d.Remove = append(d.Remove, v)
		}
	}
	sort.Strings(d.Add)
	sort.Strings(d.Remove)
	return d
}
