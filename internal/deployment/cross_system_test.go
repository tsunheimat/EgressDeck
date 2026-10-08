package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
)

type enrollmentLab struct {
	j                Journal
	opID             string
	calls            []string
	counts           map[string]int
	guardFence       uint64
	fail             string
	lost             string
	guard            GuardState
	gateway          GatewayState
	firewall         FirewallState
	gatewaySessions  []string
	firewallSessions []string
}

type labGuard struct{ lab *enrollmentLab }
type labGateway struct{ lab *enrollmentLab }
type labFirewall struct{ lab *enrollmentLab }
type labProbe struct{ lab *enrollmentLab }

type cancelGateway struct {
	labGateway
	cancel context.CancelFunc
}

func (g cancelGateway) Apply(ctx context.Context, m EnrollmentManifest, f Fence) error {
	if err := g.labGateway.Apply(ctx, m, f); err != nil {
		return err
	}
	g.cancel()
	return ctx.Err()
}
func (g cancelGateway) Observe(ctx context.Context, m EnrollmentManifest) (GatewayState, error) {
	if err := ctx.Err(); err != nil {
		return GatewayState{}, err
	}
	return g.labGateway.Observe(ctx, m)
}

type liveContextGuard struct{ labGuard }

func (g liveContextGuard) Quarantine(ctx context.Context, m EnrollmentManifest, f Fence) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return g.labGuard.Quarantine(ctx, m, f)
}
func (g liveContextGuard) Observe(ctx context.Context, m EnrollmentManifest) (GuardState, error) {
	if err := ctx.Err(); err != nil {
		return GuardState{}, err
	}
	return g.labGuard.Observe(ctx, m)
}

type probeWithError struct{ labProbe }

func (p probeWithError) ProbeClient(ctx context.Context, m EnrollmentManifest) (ClientProbeResult, error) {
	result, err := p.labProbe.ProbeClient(ctx, m)
	if err != nil {
		return result, err
	}
	return result, errors.New("probe connection lost")
}

func (l *enrollmentLab) hit(name string) error {
	l.calls = append(l.calls, name)
	l.counts[name]++
	if l.fail == name || (l.fail == name+".readback" && l.counts[name] > 1) {
		return errors.New("injected " + name + " failure")
	}
	return nil
}
func (l *enrollmentLab) mutation(name string) error {
	op, err := l.j.Get(context.Background(), l.opID)
	if err != nil {
		return err
	}
	var s CrossSystemState
	if op.Views.Applied == nil {
		return errors.New("mutation missing durable intent")
	}
	if err = json.Unmarshal(op.Views.Applied.Data, &s); err != nil {
		return err
	}
	if len(s.Receipts) == 0 || s.Receipts[len(s.Receipts)-1].Name != name || s.Receipts[len(s.Receipts)-1].Status != StepRunning {
		return errors.New("mutation missing running receipt")
	}
	return l.hit(name)
}
func (l *enrollmentLab) ack(name string) error {
	if l.lost == name {
		return &OutcomeUnknownError{Err: errors.New("acknowledgement lost")}
	}
	return nil
}
func (g labGuard) Observe(context.Context, EnrollmentManifest) (GuardState, error) {
	err := g.lab.hit("guard.observe")
	return g.lab.guard, err
}
func (g labGuard) Prepare(_ context.Context, m EnrollmentManifest, f Fence) error {
	if f.Token < g.lab.guardFence {
		return ErrFenceLost
	}
	g.lab.guardFence = f.Token
	if err := g.lab.mutation("guard.prepare"); err != nil {
		return err
	}
	g.lab.guard = GuardState{Ready: true, Generation: m.Generation, PolicyHash: m.PolicyHash, FailClosed: m.Strict, FallbackProtected: m.Strict, IPv6Protected: m.Strict, Sources: append([]string(nil), m.Sources...)}
	return g.lab.ack("guard.prepare")
}
func (g labGuard) Quarantine(_ context.Context, m EnrollmentManifest, f Fence) error {
	if f.Token < g.lab.guardFence {
		return ErrFenceLost
	}
	g.lab.guardFence = f.Token
	if err := g.lab.hit("guard.quarantine"); err != nil {
		return err
	}
	g.lab.guard = GuardState{Ready: true, FailClosed: true, Quarantined: true, FallbackProtected: true, IPv6Protected: true, Sources: append([]string(nil), m.Sources...)}
	return g.lab.ack("guard.quarantine")
}
func (g labGuard) Release(_ context.Context, _ EnrollmentManifest, f Fence) error {
	if f.Token < g.lab.guardFence {
		return ErrFenceLost
	}
	g.lab.guardFence = f.Token
	if err := g.lab.mutation("guard.release"); err != nil {
		return err
	}
	g.lab.guard = GuardState{}
	return g.lab.ack("guard.release")
}
func (g labGateway) Validate(context.Context, EnrollmentManifest) error {
	return g.lab.hit("gateway.validate")
}
func (g labGateway) Observe(context.Context, EnrollmentManifest) (GatewayState, error) {
	err := g.lab.hit("gateway.observe")
	return g.lab.gateway, err
}
func (g labGateway) Apply(_ context.Context, m EnrollmentManifest, _ Fence) error {
	if err := g.lab.mutation("gateway.apply"); err != nil {
		return err
	}
	g.lab.gateway = GatewayState{Generation: m.Generation, PolicyHash: m.PolicyHash}
	return g.lab.ack("gateway.apply")
}
func (g labGateway) RetirePolicy(_ context.Context, _ EnrollmentManifest, _ Fence) error {
	if err := g.lab.mutation("gateway.retire_policy"); err != nil {
		return err
	}
	g.lab.gateway.PolicyHash = ""
	g.lab.gateway.PolicyRetired = true
	return g.lab.ack("gateway.retire_policy")
}
func (g labGateway) CleanupSessions(_ context.Context, m EnrollmentManifest, _ Fence) (SessionCleanupResult, error) {
	if err := g.lab.mutation("gateway.sessions"); err != nil {
		return SessionCleanupResult{}, err
	}
	g.lab.gatewaySessions = []string{"unrelated"}
	return SessionCleanupResult{Complete: true, Removed: 1}, g.lab.ack("gateway.sessions")
}
func (f labFirewall) Observe(context.Context, EnrollmentManifest) (FirewallState, error) {
	err := f.lab.hit("firewall.observe")
	return f.lab.firewall, err
}
func (f labFirewall) ApplyDelta(_ context.Context, m EnrollmentManifest, d FirewallDelta, _ Fence) error {
	if err := f.lab.mutation("firewall.delta"); err != nil {
		return err
	}
	next := append([]string(nil), f.lab.firewall.Persisted...)
	for _, v := range d.Remove {
		for i := len(next) - 1; i >= 0; i-- {
			if next[i] == v {
				next = append(next[:i], next[i+1:]...)
			}
		}
	}
	next = append(next, d.Add...)
	f.lab.firewall.Persisted = next
	f.lab.firewall.Active = append([]string(nil), next...)
	return f.lab.ack("firewall.delta")
}
func (f labFirewall) CleanupSessions(context.Context, EnrollmentManifest, Fence) (SessionCleanupResult, error) {
	if err := f.lab.mutation("firewall.sessions"); err != nil {
		return SessionCleanupResult{}, err
	}
	f.lab.firewallSessions = []string{"unrelated"}
	return SessionCleanupResult{Complete: true, Removed: 1}, f.lab.ack("firewall.sessions")
}
func (p labProbe) ProbeClient(_ context.Context, m EnrollmentManifest) (ClientProbeResult, error) {
	if err := p.lab.mutation("traffic.probe"); err != nil {
		return ClientProbeResult{}, err
	}
	return ClientProbeResult{Available: true, Passed: true, SourceAddress: m.Sources[0], GatewayID: m.GatewayID, Generation: m.Generation, Kind: "enrolled_client"}, nil
}

func enrollmentFixture(t *testing.T) (*enrollmentLab, *Runner, *CrossSystemExecutor, EnrollmentManifest) {
	t.Helper()
	j := NewMemoryJournal()
	m := EnrollmentManifest{Mode: EnableEnrollment, GatewayID: "g1", FirewallID: "f1", BindingID: "b1", ExpectedFirewallShapeHash: "shape", ExpectedGeneration: 1, ExpectedPolicyHash: "old", Generation: 2, PolicyHash: "new", Policy: json.RawMessage(`{"rules":[]}`), Sources: []string{"192.0.2.10"}, PreviousAddresses: []string{"192.0.2.20"}, Addresses: []string{"192.0.2.20", "192.0.2.10"}, Sessions: CleanupSessions, Strict: true, ProbeRequired: true}
	l := &enrollmentLab{j: j, opID: "op", counts: map[string]int{}, gateway: GatewayState{Generation: 1, PolicyHash: "old"}, firewall: FirewallState{BindingID: "b1", ShapeHash: "shape", Persisted: []string{"192.0.2.20"}, Active: []string{"192.0.2.20"}}, gatewaySessions: []string{"affected", "unrelated"}, firewallSessions: []string{"affected", "unrelated"}}
	ex := NewCrossSystemExecutor(j, labGuard{l}, labGateway{l}, labFirewall{l}, labProbe{l})
	return l, NewRunner(j), ex, m
}

func submitEnrollment(t *testing.T, r *Runner, e *CrossSystemExecutor, m EnrollmentManifest) (Operation, error) {
	t.Helper()
	req, err := EnrollmentRequest("key", m)
	if err != nil {
		t.Fatal(err)
	}
	req.ID = "op"
	return r.Submit(context.Background(), req, e)
}
func enrollmentState(t *testing.T, op Operation) CrossSystemState {
	t.Helper()
	var s CrossSystemState
	if op.Views.Applied == nil {
		t.Fatal("no durable component state")
	}
	if err := json.Unmarshal(op.Views.Applied.Data, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCrossSystemEnableOrderAndIndependentReadback(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	op, err := submitEnrollment(t, r, e, m)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gateway.validate", "guard.observe", "gateway.observe", "firewall.observe", "guard.prepare", "guard.observe", "gateway.apply", "gateway.observe", "firewall.delta", "firewall.observe", "gateway.sessions", "firewall.sessions", "traffic.probe", "guard.observe", "gateway.observe", "firewall.observe"}
	if !reflect.DeepEqual(l.calls, want) {
		t.Fatalf("calls\n got %v\nwant %v", l.calls, want)
	}
	s := enrollmentState(t, op)
	if op.Status != StatusApplied || !s.ConfigurationApplied || !s.TrafficVerified || op.Views.Verified == nil {
		t.Fatalf("status=%s state=%+v", op.Status, s)
	}
	if !sameAddresses(l.firewall.Active, m.Addresses) || !sameAddresses(l.firewall.Persisted, m.Addresses) || !reflect.DeepEqual(l.gatewaySessions, []string{"unrelated"}) || !reflect.DeepEqual(l.firewallSessions, []string{"unrelated"}) {
		t.Fatalf("unexpected final remote state: %+v", l)
	}
}

func TestCrossSystemWithoutClientProbeDoesNotClaimTrafficVerification(t *testing.T) {
	_, r, e, m := enrollmentFixture(t)
	m.ProbeRequired = false
	e.Probe = nil
	op, err := submitEnrollment(t, r, e, m)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != StatusApplied || op.Views.Verified != nil || enrollmentState(t, op).TrafficVerified {
		t.Fatalf("claimed traffic verification without client probe: %+v", op)
	}
}

func TestCrossSystemSameGatewayMoveDoesNotChurnAliases(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	m.Mode = MoveDeviceGroup
	m.PreviousGatewayID = m.GatewayID
	m.PreviousAddresses = m.Addresses
	l.firewall.Persisted = append([]string(nil), m.Addresses...)
	l.firewall.Active = append([]string(nil), m.Addresses...)
	op, err := submitEnrollment(t, r, e, m)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != StatusApplied || l.counts["firewall.delta"] != 0 || !sameAddresses(l.firewall.Persisted, m.Addresses) {
		t.Fatalf("group move changed enrollment: %+v", l)
	}
}

func TestCrossSystemLostAcknowledgementReadsBeforeContinuing(t *testing.T) {
	for _, boundary := range []string{"guard.prepare", "gateway.apply", "firewall.delta"} {
		t.Run(boundary, func(t *testing.T) {
			l, r, e, m := enrollmentFixture(t)
			l.lost = boundary
			op, err := submitEnrollment(t, r, e, m)
			if err != nil {
				t.Fatal(err)
			}
			if op.Status != StatusApplied || l.counts[boundary] != 1 {
				t.Fatalf("operation=%s boundary calls=%d", op.Status, l.counts[boundary])
			}
		})
	}
}

func TestCrossSystemFailureBoundariesPreserveExactSafeState(t *testing.T) {
	for _, tc := range []struct {
		name                                             string
		newPolicy, enrolled, gatewayClean, firewallClean bool
	}{
		{"guard.prepare", false, false, false, false},
		{"gateway.apply", false, false, false, false},
		{"gateway.observe.readback", true, false, false, false},
		{"firewall.delta", true, false, false, false},
		{"firewall.observe.readback", true, true, false, false},
		{"gateway.sessions", true, true, false, false},
		{"firewall.sessions", true, true, true, false},
		{"traffic.probe", true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, r, e, m := enrollmentFixture(t)
			l.fail = tc.name
			op, err := submitEnrollment(t, r, e, m)
			if err == nil {
				t.Fatal("expected injected failure")
			}
			if op.Status != StatusPartiallyApplied && op.Status != StatusOutcomeUnknown {
				t.Fatalf("status=%s", op.Status)
			}
			wantGateway := GatewayState{Generation: 1, PolicyHash: "old"}
			if tc.newPolicy {
				wantGateway = GatewayState{Generation: 2, PolicyHash: "new"}
			}
			wantAddresses := m.PreviousAddresses
			if tc.enrolled {
				wantAddresses = m.Addresses
			}
			wantGatewaySessions := []string{"affected", "unrelated"}
			if tc.gatewayClean {
				wantGatewaySessions = []string{"unrelated"}
			}
			wantFirewallSessions := []string{"affected", "unrelated"}
			if tc.firewallClean {
				wantFirewallSessions = []string{"unrelated"}
			}
			if l.gateway != wantGateway || !sameAddresses(l.firewall.Persisted, wantAddresses) || !sameAddresses(l.firewall.Active, wantAddresses) || !reflect.DeepEqual(l.gatewaySessions, wantGatewaySessions) || !reflect.DeepEqual(l.firewallSessions, wantFirewallSessions) {
				t.Fatalf("unexpected remote effects: gateway=%+v aliases=%+v gateway sessions=%v firewall sessions=%v", l.gateway, l.firewall, l.gatewaySessions, l.firewallSessions)
			}
			if !l.guard.Quarantined || !l.guard.FailClosed || !l.guard.Ready || !sameAddresses(l.guard.Sources, m.Sources) {
				t.Fatalf("strict failure not quarantined: %+v", l.guard)
			}
			stored, getErr := l.j.Get(context.Background(), op.ID)
			if getErr != nil {
				t.Fatal(getErr)
			}
			s := enrollmentState(t, stored)
			if s.Failure == "" || s.ConfigurationApplied || s.TrafficVerified || !s.Guard.Quarantined {
				t.Fatalf("incorrect durable state: %+v", s)
			}
			if stored.OriginalError == "" {
				t.Fatal("original boundary error lost")
			}
		})
	}
}

func TestCrossSystemBypassRequiresIntentAndHandlesSessionsBeforeRelease(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	m.Mode = BypassEnrollment
	m.PreviousAddresses = m.Addresses
	m.Addresses = []string{"192.0.2.20"}
	m.ProbeRequired = false
	e.Probe = nil
	l.firewall.Persisted = append([]string(nil), m.PreviousAddresses...)
	l.firewall.Active = append([]string(nil), m.PreviousAddresses...)
	l.guard = GuardState{Ready: true, FailClosed: true, Sources: m.Sources}
	if _, err := submitEnrollment(t, r, e, m); err == nil {
		t.Fatal("bypass without explicit intent accepted")
	}
	if len(l.calls) != 0 {
		t.Fatal("missing bypass intent caused remote calls")
	}
	// Validation failure is durable. Use a new id/key for the corrected intent.
	m.Disposition = "bypass"
	req, _ := EnrollmentRequest("bypass", m)
	req.ID = "bypass"
	l.opID = req.ID
	op, err := r.Submit(context.Background(), req, e)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"guard.observe", "gateway.observe", "firewall.observe", "firewall.delta", "firewall.observe", "gateway.sessions", "firewall.sessions", "guard.release", "guard.observe", "gateway.retire_policy", "gateway.observe", "guard.observe", "gateway.observe", "firewall.observe"}
	if !reflect.DeepEqual(l.calls, want) {
		t.Fatalf("bypass order: got=%v want=%v", l.calls, want)
	}
	if op.Status != StatusApplied || intersects(l.guard.Sources, m.Sources) || !sameAddresses(l.firewall.Active, m.Addresses) || l.gateway.Generation != 1 {
		t.Fatalf("bypass effects: op=%s world=%+v", op.Status, l)
	}
}

func TestCrossSystemStrictRollbackNeverRestoresPermissivePolicy(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	l.fail = "firewall.delta"
	op, err := submitEnrollment(t, r, e, m)
	if err == nil {
		t.Fatal("expected partial deployment")
	}
	beforeGateway := l.gateway
	beforeFirewall := l.firewall
	_, err = r.Rollback(context.Background(), op.ID, e)
	if !errors.Is(err, ErrUnsafeRollback) {
		t.Fatalf("rollback error=%v", err)
	}
	if l.gateway != beforeGateway || !reflect.DeepEqual(l.firewall, beforeFirewall) || !l.guard.Quarantined {
		t.Fatalf("rollback weakened state: %+v", l)
	}
}

func TestCrossSystemUnresolvedReadbackCannotBeOverwrittenOrRetried(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	l.fail = "gateway.observe.readback"
	op, err := submitEnrollment(t, r, e, m)
	if err == nil || op.Status != StatusOutcomeUnknown {
		t.Fatalf("op=%s err=%v", op.Status, err)
	}
	req, _ := EnrollmentRequest("new", m)
	if _, err = r.Submit(context.Background(), req, e); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("new mutation accepted while old result unknown: %v", err)
	}
	delete(l.counts, "gateway.observe")
	l.fail = ""
	callsBefore := l.counts["gateway.apply"]
	op, err = r.Resume(context.Background(), op.ID, e)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != StatusPartiallyApplied || l.counts["gateway.apply"] != callsBefore || l.counts["firewall.delta"] != 0 {
		t.Fatalf("readback retried mutation: op=%s calls=%v", op.Status, l.calls)
	}
}

func TestCrossSystemCancellationStillReadsBackAndQuarantines(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Gateway = cancelGateway{labGateway{l}, cancel}
	e.Guard = liveContextGuard{labGuard{l}}
	req, _ := EnrollmentRequest("key", m)
	req.ID = "op"
	op, err := r.Submit(ctx, req, e)
	if !errors.Is(err, context.Canceled) || op.Status != StatusOutcomeUnknown {
		t.Fatalf("status=%s error=%v", op.Status, err)
	}
	if l.gateway.Generation != m.Generation || l.counts["gateway.observe"] != 2 || l.counts["firewall.delta"] != 0 || !quarantineMatches(m, l.guard) {
		t.Fatalf("cancellation effects: %+v", l)
	}
	stored, getErr := l.j.Get(context.Background(), op.ID)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if stored.Status != StatusOutcomeUnknown || !enrollmentState(t, stored).Guard.Quarantined {
		t.Fatalf("cancellation outcome not durable: %+v", stored)
	}
}

func TestCrossSystemErroredProbeCannotBecomeVerifiedOnReadback(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	m.ProbeRequired = false
	e.Probe = probeWithError{labProbe{l}}
	op, err := submitEnrollment(t, r, e, m)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != StatusApplied || op.Views.Verified != nil || enrollmentState(t, op).TrafficVerified {
		t.Fatalf("errored probe promoted to verified: %+v", op)
	}
}

func TestCrossSystemUnknownCleanupReceiptBlocksActivation(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	m.Strict = false
	l.lost = "gateway.sessions"
	op, err := submitEnrollment(t, r, e, m)
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("error=%v", err)
	}
	if !enrollmentState(t, op).GatewaySessions.Complete {
		t.Fatal("fixture must return complete plus timeout")
	}
	op, err = r.Resume(context.Background(), op.ID, e)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != StatusPartiallyApplied || l.counts["gateway.sessions"] != 1 || l.counts["firewall.sessions"] != 0 || op.Views.Verified != nil {
		t.Fatalf("unknown cleanup treated as success: %+v", op)
	}
}

func TestCrossSystemSharedFirewallUnknownOperationBlocksOtherGateway(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	prior := m
	prior.GatewayID = "g0"
	req, _ := EnrollmentRequest("prior", prior)
	f, err := l.j.NextFence(context.Background(), req.Target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.j.Create(context.Background(), Operation{ID: "prior", IdempotencyKey: req.IdempotencyKey, Target: req.Target, Action: req.Action, RequestedGeneration: req.RequestedGeneration, FenceToken: f.Token, Status: StatusOutcomeUnknown, Views: StateViews{Desired: req.Desired}}); err != nil {
		t.Fatal(err)
	}
	op, err := submitEnrollment(t, r, e, m)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("shared firewall unresolved operation bypassed: %v", err)
	}
	if l.counts["gateway.apply"] != 0 || l.counts["firewall.delta"] != 0 || op.Status != StatusPartiallyApplied {
		t.Fatalf("unexpected side effect: %+v", l)
	}
	if current, _ := l.j.FenceCurrent(context.Background(), Target{Kind: "opnsense", ID: m.FirewallID}, 1); current {
		t.Fatal("unresolved firewall was refenced")
	}
}

func TestCrossSystemBypassCleanupFailureKeepsFallbackGuard(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	m.Mode = BypassEnrollment
	m.Disposition = "bypass"
	m.PreviousAddresses = m.Addresses
	m.Addresses = []string{"192.0.2.20"}
	m.ProbeRequired = false
	e.Probe = nil
	l.firewall.Persisted = append([]string(nil), m.PreviousAddresses...)
	l.firewall.Active = append([]string(nil), m.PreviousAddresses...)
	l.guard = GuardState{Ready: true, FailClosed: true, Sources: m.Sources}
	l.fail = "gateway.sessions"
	op, err := submitEnrollment(t, r, e, m)
	if err == nil || op.Status != StatusPartiallyApplied {
		t.Fatalf("op=%s err=%v", op.Status, err)
	}
	if !sameAddresses(l.firewall.Active, m.Addresses) || !quarantineMatches(m, l.guard) || l.counts["guard.release"] != 0 || l.counts["gateway.retire_policy"] != 0 {
		t.Fatalf("failed bypass state=%+v", l)
	}
}

func TestCrossSystemLateGuardMutationCannotUndoQuarantine(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	l.fail = "gateway.apply"
	op, err := submitEnrollment(t, r, e, m)
	if err == nil {
		t.Fatal("expected failure")
	}
	s := enrollmentState(t, op)
	if s.GuardFence.Token != 2 {
		t.Fatalf("quarantine fence=%d", s.GuardFence.Token)
	}
	before := l.guard
	if err := (labGuard{l}).Prepare(context.Background(), m, Fence{Target: s.GuardFence.Target, Token: 1}); !errors.Is(err, ErrFenceLost) {
		t.Fatalf("late preparation accepted: %v", err)
	}
	if !reflect.DeepEqual(before, l.guard) {
		t.Fatal("late preparation changed quarantined guard")
	}
}

func TestCrossSystemPolicyContentDriftDoesNotOverwriteRemote(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	l.gateway.PolicyHash = "administrator-change"
	op, err := submitEnrollment(t, r, e, m)
	var drift *DriftError
	if !errors.As(err, &drift) || op.Status != StatusPartiallyApplied {
		t.Fatalf("status=%s error=%v", op.Status, err)
	}
	if l.gateway.PolicyHash != "administrator-change" || l.counts["gateway.apply"] != 0 || l.counts["firewall.delta"] != 0 || !quarantineMatches(m, l.guard) {
		t.Fatalf("drift overwritten: %+v", l)
	}
}

func TestCrossSystemConcurrentApplyReplaysReadbackOnly(t *testing.T) {
	l, _, e, m := enrollmentFixture(t)
	req, _ := EnrollmentRequest("key", m)
	f, err := l.j.NextFence(context.Background(), req.Target)
	if err != nil {
		t.Fatal(err)
	}
	op, err := l.j.Create(context.Background(), Operation{ID: "op", Target: req.Target, Action: req.Action, RequestedGeneration: req.RequestedGeneration, FenceToken: f.Token, Status: StatusApplying, Views: StateViews{Desired: req.Desired}})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errorsCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := e.Apply(context.Background(), op, f); errorsCh <- err }()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"gateway.apply", "firewall.delta", "gateway.sessions", "firewall.sessions", "traffic.probe"} {
		if l.counts[name] != 1 {
			t.Fatalf("duplicate %s count=%d", name, l.counts[name])
		}
	}
}

func TestCrossSystemRejectedRollbackKeepsUnknownReadbackRecoverable(t *testing.T) {
	l, r, e, m := enrollmentFixture(t)
	l.fail = "gateway.observe.readback"
	op, err := submitEnrollment(t, r, e, m)
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("error=%v", err)
	}
	before := enrollmentState(t, op).GuardFence
	_, err = r.Rollback(context.Background(), op.ID, e)
	if !errors.Is(err, ErrUnsafeRollback) {
		t.Fatalf("rollback error=%v", err)
	}
	if current, err := l.j.FenceCurrent(context.Background(), before.Target, before.Token); err != nil || !current {
		t.Fatalf("rollback invalidated readback fence: %v %v", current, err)
	}
	l.fail = ""
	op, err = r.Resume(context.Background(), op.ID, e)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != StatusPartiallyApplied {
		t.Fatalf("unknown recovery stuck: %s", op.Status)
	}
}
