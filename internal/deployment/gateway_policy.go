package deployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

const GatewayPolicyAction = "policy.apply_generation"
const NativeDAEPolicyFormat = "native_dae"

// GatewayPolicyManifest carries an existing native engine artifact unchanged.
// This bridge does not render controller rules into dae syntax, manage client
// enrollment, or establish fail-closed guards. ExpectedGeneration fences the
// engine's global mutation stream; Policy.Generation identifies this artifact.
type GatewayPolicyManifest struct {
	GatewayID          string         `json:"gateway_id"`
	Format             string         `json:"format"`
	ExpectedGeneration int64          `json:"expected_generation"`
	ExpectedPolicyHash string         `json:"expected_policy_hash"`
	Policy             gateway.Policy `json:"policy"`
}

type GatewayPolicyEngine interface {
	Capabilities(context.Context) (gateway.Capabilities, error)
	Inventory(context.Context) (gateway.Snapshot, error)
	ValidatePolicy(context.Context, gateway.Policy) error
	ApplyPolicyGeneration(context.Context, gateway.Policy, int64) (gateway.Snapshot, error)
}

type GatewayPolicyOptions struct {
	EnableApply bool
	Format      string
	// BeforeRequest rechecks operator-bound endpoint identity before sending
	// a credential-bearing request. It must not mutate remote state.
	BeforeRequest func(context.Context) error
}

type GatewayPolicyExecutor struct {
	Journal   Journal
	Engine    GatewayPolicyEngine
	GatewayID string
	Options   GatewayPolicyOptions
}

func NewGatewayPolicyExecutor(j Journal, engine GatewayPolicyEngine, gatewayID string, options GatewayPolicyOptions) *GatewayPolicyExecutor {
	return &GatewayPolicyExecutor{Journal: j, Engine: engine, GatewayID: gatewayID, Options: options}
}

func GatewayPolicyRequest(key string, m GatewayPolicyManifest) (Request, error) {
	if m.Policy.Generation < 0 {
		return Request{}, fmt.Errorf("%w: policy generation must be nonnegative", ErrInvalidRequest)
	}
	data, err := json.Marshal(m)
	if err != nil {
		return Request{}, err
	}
	return Request{IdempotencyKey: key, Target: Target{Kind: "gateway", ID: m.GatewayID}, Action: GatewayPolicyAction, RequestedGeneration: uint64(m.Policy.Generation), Desired: &StateRecord{Generation: uint64(m.Policy.Generation), Revision: m.Policy.ID, Hash: GatewayPolicyHash(m.Policy), Data: data}}, nil
}

func GatewayPolicyHash(policy gateway.Policy) string {
	encoded, err := json.Marshal(policy)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:])
}

func (e *GatewayPolicyExecutor) manifest(op Operation) (GatewayPolicyManifest, error) {
	var m GatewayPolicyManifest
	if op.Action != GatewayPolicyAction {
		return m, fmt.Errorf("%w: native policy executor cannot perform enrollment or other actions", gateway.ErrUnsupported)
	}
	if op.Views.Desired == nil || len(op.Views.Desired.Data) == 0 {
		return m, fmt.Errorf("%w: typed native policy manifest is required", ErrInvalidRequest)
	}
	dec := json.NewDecoder(bytes.NewReader(op.Views.Desired.Data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("%w: invalid native policy manifest", ErrInvalidRequest)
	}
	if dec.Decode(new(any)) != io.EOF {
		return m, fmt.Errorf("%w: policy manifest must contain one object", ErrInvalidRequest)
	}
	if m.GatewayID == "" || m.GatewayID != e.GatewayID || op.Target != (Target{Kind: "gateway", ID: m.GatewayID}) || m.Policy.ID == "" || m.Policy.Generation < 1 || op.RequestedGeneration != uint64(m.Policy.Generation) || m.ExpectedGeneration < 0 || m.ExpectedGeneration == math.MaxInt64 {
		return m, fmt.Errorf("%w: policy identity or generation mismatch", ErrInvalidRequest)
	}
	if m.Format != NativeDAEPolicyFormat || e.Options.Format != m.Format {
		return m, fmt.Errorf("%w: native policy artifact format is not explicitly configured", gateway.ErrUnsupported)
	}
	var payload struct {
		NativeConfig string `json:"native_config"`
	}
	payloadDecoder := json.NewDecoder(bytes.NewReader(m.Policy.Payload))
	payloadDecoder.DisallowUnknownFields()
	if err := payloadDecoder.Decode(&payload); err != nil || payloadDecoder.Decode(new(any)) != io.EOF || strings.TrimSpace(payload.NativeConfig) == "" || len(payload.NativeConfig) > 1<<20 {
		return m, fmt.Errorf("%w: standalone payload.native_config artifact is required", ErrInvalidRequest)
	}
	if m.ExpectedPolicyHash != "" {
		decoded, err := hex.DecodeString(m.ExpectedPolicyHash)
		if err != nil || len(decoded) != sha256.Size {
			return m, fmt.Errorf("%w: expected policy hash must be SHA-256", ErrInvalidRequest)
		}
	}
	return m, nil
}

func (e *GatewayPolicyExecutor) before(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.Engine == nil || e.Journal == nil {
		return fmt.Errorf("%w: policy engine and journal are required", gateway.ErrUnsupported)
	}
	if e.Options.BeforeRequest != nil {
		return e.Options.BeforeRequest(ctx)
	}
	return nil
}

func (e *GatewayPolicyExecutor) current(ctx context.Context, f Fence) error {
	current, err := e.Journal.FenceCurrent(ctx, f.Target, f.Token)
	if err != nil {
		return err
	}
	if !current || f.Target != (Target{Kind: "gateway", ID: e.GatewayID}) {
		return ErrFenceLost
	}
	return nil
}

func (e *GatewayPolicyExecutor) capabilities(ctx context.Context) error {
	if !e.Options.EnableApply {
		return fmt.Errorf("%w: native policy application is not enabled by operator configuration", gateway.ErrUnsupported)
	}
	if err := e.before(ctx); err != nil {
		return err
	}
	caps, err := e.Engine.Capabilities(ctx)
	if err != nil {
		return err
	}
	implementation := strings.ToLower(caps.Implementation)
	if implementation == "" || strings.Contains(implementation, "fake") || strings.Contains(implementation, "simulation") || implementation == "dae-stock" {
		return fmt.Errorf("%w: configured engine is not a native policy application backend", gateway.ErrUnsupported)
	}
	for _, required := range []gateway.CapabilityName{gateway.CapabilityInventoryRead, gateway.CapabilityPolicyValidate, gateway.CapabilityPolicyApply} {
		if !caps.Has(required) {
			return fmt.Errorf("%w: gateway has not advertised %s", gateway.ErrUnsupported, required)
		}
	}
	return nil
}

func (e *GatewayPolicyExecutor) Validate(ctx context.Context, op Operation) error {
	m, err := e.manifest(op)
	if err != nil {
		return err
	}
	if err = e.capabilities(ctx); err != nil {
		return err
	}
	if err = e.before(ctx); err != nil {
		return err
	}
	return e.Engine.ValidatePolicy(ctx, m.Policy)
}

func (e *GatewayPolicyExecutor) Stage(ctx context.Context, op Operation, f Fence) error {
	if _, err := e.manifest(op); err != nil {
		return err
	}
	return e.current(ctx, f)
}

func (e *GatewayPolicyExecutor) Apply(ctx context.Context, op Operation, f Fence) (ApplyResult, error) {
	m, err := e.manifest(op)
	if err != nil {
		return ApplyResult{}, err
	}
	if err = e.current(ctx, f); err != nil {
		return ApplyResult{}, err
	}
	if err = e.capabilities(ctx); err != nil {
		return ApplyResult{}, err
	}
	if err = e.before(ctx); err != nil {
		return ApplyResult{}, err
	}
	base, err := e.Engine.Inventory(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	if gatewayPolicyMatches(m, base) {
		return ApplyResult{Applied: gatewayPolicyRecord(base)}, nil
	}
	if base.Generation != m.ExpectedGeneration || !basePolicyMatches(m, base.Policy) {
		return ApplyResult{}, &DriftError{Err: errors.New("gateway policy or base generation changed")}
	}
	if err = e.current(ctx, f); err != nil {
		return ApplyResult{}, err
	}
	if err = e.before(ctx); err != nil {
		return ApplyResult{}, err
	}
	_, applyErr := e.Engine.ApplyPolicyGeneration(ctx, m.Policy, m.ExpectedGeneration)
	// HTTP acceptance alone is never applied state, including a timed-out
	// request that changed the engine. Inspect through an independent read.
	readCtx, cancel := recoveryContext(ctx)
	defer cancel()
	if err = e.before(readCtx); err != nil {
		return ApplyResult{}, &OutcomeUnknownError{Err: err}
	}
	observed, readErr := e.Engine.Inventory(readCtx)
	if readErr != nil {
		return ApplyResult{}, &OutcomeUnknownError{Err: readErr}
	}
	if err = e.current(readCtx, f); err != nil {
		return ApplyResult{}, &OutcomeUnknownError{Err: err}
	}
	if gatewayPolicyMatches(m, observed) {
		return ApplyResult{Applied: gatewayPolicyRecord(observed)}, nil
	}
	if applyErr != nil {
		if errors.Is(applyErr, gateway.ErrOutcomeUnknown) || isUnknown(applyErr) {
			return ApplyResult{}, &OutcomeUnknownError{Err: applyErr}
		}
		return ApplyResult{}, applyErr
	}
	return ApplyResult{}, &OutcomeUnknownError{Err: errors.New("policy acknowledgement was not confirmed by generation and artifact readback")}
}

func (e *GatewayPolicyExecutor) Verify(ctx context.Context, op Operation, f Fence) (VerifyResult, error) {
	return e.Readback(ctx, op, f)
}

func (e *GatewayPolicyExecutor) Readback(ctx context.Context, op Operation, f Fence) (VerifyResult, error) {
	m, err := e.manifest(op)
	if err != nil {
		return VerifyResult{}, err
	}
	if err = e.current(ctx, f); err != nil {
		return VerifyResult{}, err
	}
	if err = e.before(ctx); err != nil {
		return VerifyResult{}, err
	}
	observed, err := e.Engine.Inventory(ctx)
	if err != nil {
		return VerifyResult{}, err
	}
	if err = e.current(ctx, f); err != nil {
		return VerifyResult{}, err
	}
	result := VerifyResult{Observed: gatewayPolicyRecord(observed), VerifiedOK: gatewayPolicyMatches(m, observed)}
	if !result.VerifiedOK {
		result.Message = "gateway generation or native policy artifact differs from requested intent"
	}
	// Deliberately leave Verified nil: engine configuration is not a real
	// enrolled-client traffic measurement.
	return result, nil
}

func (*GatewayPolicyExecutor) Rollback(context.Context, Operation, Fence) error {
	return ErrExplicitRecoveryRequired
}

func basePolicyMatches(m GatewayPolicyManifest, p gateway.Policy) bool {
	if m.ExpectedPolicyHash == "" {
		return p.ID == "" && p.Generation == 0 && len(p.Payload) == 0
	}
	return GatewayPolicyHash(p) == m.ExpectedPolicyHash
}
func gatewayPolicyMatches(m GatewayPolicyManifest, s gateway.Snapshot) bool {
	return s.Generation == m.ExpectedGeneration+1 && s.Policy.Generation == m.Policy.Generation && s.Policy.ID == m.Policy.ID && GatewayPolicyHash(s.Policy) == GatewayPolicyHash(m.Policy)
}
func gatewayPolicyRecord(s gateway.Snapshot) *StateRecord {
	// Provider/node/connection inventory may contain unrelated private state.
	// Persist only the policy and observed global generation for this action.
	data, _ := json.Marshal(struct {
		Generation int64          `json:"generation"`
		Policy     gateway.Policy `json:"policy"`
	}{s.Generation, s.Policy})
	generation := uint64(0)
	if s.Generation > 0 {
		generation = uint64(s.Generation)
	}
	return &StateRecord{Generation: generation, Revision: s.Policy.ID, Hash: GatewayPolicyHash(s.Policy), Status: "configuration_observed", Data: data, At: time.Now().UTC()}
}

var _ Executor = (*GatewayPolicyExecutor)(nil)
var _ ReadbackExecutor = (*GatewayPolicyExecutor)(nil)
