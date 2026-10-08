package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

// The fixture engine stores immutable policy bytes and exercises the real
// gateway interface; it is not evidence of dae packet-path behavior.
type policyFixture struct {
	engine      *gateway.FakeEngine
	calls       []string
	applyErr    error
	unsupported bool
}

func (f *policyFixture) Capabilities(ctx context.Context) (gateway.Capabilities, error) {
	f.calls = append(f.calls, "capabilities")
	caps, _ := f.engine.Capabilities(ctx)
	caps.Implementation = "qualified-protocol-fixture"
	if f.unsupported {
		for i := range caps.Items {
			if caps.Items[i].Name == gateway.CapabilityPolicyApply {
				caps.Items[i].Supported = false
			}
		}
	}
	return caps, nil
}
func (f *policyFixture) Inventory(ctx context.Context) (gateway.Snapshot, error) {
	f.calls = append(f.calls, "inventory")
	return f.engine.Inventory(ctx)
}
func (f *policyFixture) ValidatePolicy(ctx context.Context, p gateway.Policy) error {
	f.calls = append(f.calls, "validate")
	return f.engine.ValidatePolicy(ctx, p)
}
func (f *policyFixture) ApplyPolicyGeneration(ctx context.Context, p gateway.Policy, g int64) (gateway.Snapshot, error) {
	f.calls = append(f.calls, "apply")
	snapshot, err := f.engine.ApplyPolicyGeneration(ctx, p, g)
	if f.applyErr != nil {
		return snapshot, f.applyErr
	}
	return snapshot, err
}

func policyManifest() GatewayPolicyManifest {
	return GatewayPolicyManifest{GatewayID: "g1", Format: NativeDAEPolicyFormat, Policy: gateway.Policy{ID: "policy-1", Generation: 7, Payload: json.RawMessage(`{"native_config":"routing { fallback: block }"}`)}}
}

func TestGatewayPolicyExecutorPreservesArtifactAndSeparatesTrafficProof(t *testing.T) {
	j := NewMemoryJournal()
	fixture := &policyFixture{engine: gateway.NewFakeEngine()}
	e := NewGatewayPolicyExecutor(j, fixture, "g1", GatewayPolicyOptions{EnableApply: true, Format: NativeDAEPolicyFormat})
	req, err := GatewayPolicyRequest("key", policyManifest())
	if err != nil {
		t.Fatal(err)
	}
	op, err := NewRunner(j).Submit(context.Background(), req, e)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"capabilities", "validate", "capabilities", "inventory", "apply", "inventory", "inventory"}
	if !reflect.DeepEqual(fixture.calls, want) {
		t.Fatalf("calls=%v want=%v", fixture.calls, want)
	}
	observed, _ := fixture.engine.Inventory(context.Background())
	if string(observed.Policy.Payload) != string(policyManifest().Policy.Payload) || op.Status != StatusApplied || op.Views.Applied == nil || op.Views.Observed == nil || op.Views.Verified != nil {
		t.Fatalf("artifact or state incorrect: op=%+v policy=%+v", op, observed.Policy)
	}
}

func TestGatewayPolicyExecutorLostAckUsesReadbackWithoutRetry(t *testing.T) {
	j := NewMemoryJournal()
	fixture := &policyFixture{engine: gateway.NewFakeEngine(), applyErr: gateway.ErrOutcomeUnknown}
	e := NewGatewayPolicyExecutor(j, fixture, "g1", GatewayPolicyOptions{EnableApply: true, Format: NativeDAEPolicyFormat})
	req, _ := GatewayPolicyRequest("key", policyManifest())
	op, err := NewRunner(j).Submit(context.Background(), req, e)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range fixture.calls {
		if name == "apply" {
			count++
		}
	}
	if op.Status != StatusApplied || count != 1 {
		t.Fatalf("status=%s apply count=%d", op.Status, count)
	}
}

func TestGatewayPolicyExecutorRefusesUnsupportedOrMismatchedArtifact(t *testing.T) {
	for _, tc := range []struct {
		name        string
		options     GatewayPolicyOptions
		unsupported bool
		change      func(*GatewayPolicyManifest)
	}{
		{"not opted in", GatewayPolicyOptions{Format: NativeDAEPolicyFormat}, false, nil},
		{"stock capability absent", GatewayPolicyOptions{EnableApply: true, Format: NativeDAEPolicyFormat}, true, nil},
		{"unqualified format", GatewayPolicyOptions{EnableApply: true, Format: "compiler_manifest"}, false, nil},
		{"routing fragment", GatewayPolicyOptions{EnableApply: true, Format: NativeDAEPolicyFormat}, false, func(m *GatewayPolicyManifest) {
			m.Policy.Payload = json.RawMessage(`{"routing_config":"routing { fallback: block }"}`)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := NewMemoryJournal()
			fixture := &policyFixture{engine: gateway.NewFakeEngine(), unsupported: tc.unsupported}
			e := NewGatewayPolicyExecutor(j, fixture, "g1", tc.options)
			m := policyManifest()
			if tc.change != nil {
				tc.change(&m)
			}
			req, _ := GatewayPolicyRequest("key", m)
			op, err := NewRunner(j).Submit(context.Background(), req, e)
			if err == nil || op.Status != StatusFailed {
				t.Fatalf("status=%s err=%v", op.Status, err)
			}
			for _, name := range fixture.calls {
				if name == "apply" {
					t.Fatal("unsupported input reached mutation")
				}
			}
		})
	}
}

func TestGatewayPolicyExecutorBaseContentDriftPreservesActivePolicy(t *testing.T) {
	j := NewMemoryJournal()
	engine := gateway.NewFakeEngine()
	old := gateway.Policy{ID: "administrator-policy", Generation: 1, Payload: json.RawMessage(`{"native_config":"routing { fallback: direct }"}`)}
	if _, err := engine.ApplyPolicyGeneration(context.Background(), old, 0); err != nil {
		t.Fatal(err)
	}
	fixture := &policyFixture{engine: engine}
	e := NewGatewayPolicyExecutor(j, fixture, "g1", GatewayPolicyOptions{EnableApply: true, Format: NativeDAEPolicyFormat})
	m := policyManifest()
	m.ExpectedGeneration = 1
	m.ExpectedPolicyHash = GatewayPolicyHash(gateway.Policy{ID: "expected-other-policy"})
	req, _ := GatewayPolicyRequest("key", m)
	_, err := NewRunner(j).Submit(context.Background(), req, e)
	var drift *DriftError
	if !errors.As(err, &drift) {
		t.Fatalf("error=%v", err)
	}
	observed, _ := engine.Inventory(context.Background())
	if observed.Generation != 1 || GatewayPolicyHash(observed.Policy) != GatewayPolicyHash(old) {
		t.Fatal("manual policy drift was overwritten")
	}
}

func TestGatewayPolicyExecutorRecoveryRemainsReadOnlyWhenApplyDisabled(t *testing.T) {
	j := NewMemoryJournal()
	m := policyManifest()
	fixture := &policyFixture{engine: gateway.NewFakeEngine()}
	if _, err := fixture.engine.ApplyPolicyGeneration(context.Background(), m.Policy, 0); err != nil {
		t.Fatal(err)
	}
	req, _ := GatewayPolicyRequest("key", m)
	f, _ := j.NextFence(context.Background(), req.Target)
	op, err := j.Create(context.Background(), Operation{ID: "recover", Target: req.Target, Action: req.Action, RequestedGeneration: req.RequestedGeneration, FenceToken: f.Token, Status: StatusApplying, Views: StateViews{Desired: req.Desired}})
	if err != nil {
		t.Fatal(err)
	}
	e := NewGatewayPolicyExecutor(j, fixture, "g1", GatewayPolicyOptions{Format: NativeDAEPolicyFormat})
	op, err = NewRunner(j).InspectOutcome(context.Background(), op.ID, e)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != StatusApplied || op.Views.Verified != nil || !reflect.DeepEqual(fixture.calls, []string{"inventory"}) {
		t.Fatalf("readback=%+v calls=%v", op, fixture.calls)
	}
}

func TestGatewayPolicyExecutorCannotOptInSimulation(t *testing.T) {
	j := NewMemoryJournal()
	engine := gateway.NewFakeEngine()
	e := NewGatewayPolicyExecutor(j, engine, "g1", GatewayPolicyOptions{EnableApply: true, Format: NativeDAEPolicyFormat})
	req, _ := GatewayPolicyRequest("simulation", policyManifest())
	_, err := NewRunner(j).Submit(context.Background(), req, e)
	if !errors.Is(err, gateway.ErrUnsupported) {
		t.Fatalf("simulated engine accepted as native backend: %v", err)
	}
	snapshot, err := engine.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Generation != 0 {
		t.Fatal("simulation was mutated")
	}
}
