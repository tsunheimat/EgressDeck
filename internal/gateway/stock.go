package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// These are inspected source revisions, not a claim that an installed binary
// was built from either source tree. ExecutableSHA256 identifies actual bytes.
const DaeInspectedRevision = "e3fee8fbc68a65167af13b685ab0b958757e20ee"
const ZashboardInspectedRevision = "9b867b76a8cbca014423e93af59f7ce0996bc4f4"

var ErrUnavailable = errors.New("gateway engine unavailable")
var ErrValidation = errors.New("native dae validation failed")

type Health struct {
	Status              string    `json:"status"`
	Implementation      string    `json:"implementation"`
	ExecutableAvailable bool      `json:"executable_available"`
	ExecutableSHA256    string    `json:"executable_sha256,omitempty"`
	EngineVersion       string    `json:"engine_version,omitempty"`
	EnginePID           int       `json:"engine_pid,omitempty"`
	ProcessObserved     bool      `json:"process_observed"`
	ObservedAt          time.Time `json:"observed_at"`
	Details             []string  `json:"details,omitempty"`
}

type HealthReader interface {
	Health(context.Context) (Health, error)
}

// StockOptions is operator configuration. No path or executable comes from an
// HTTP request. StockEngine never signals or starts the packet-processing daemon.
type StockOptions struct {
	Executable     string
	ExpectedSHA256 string
	PIDFile        string
	ValidationRoot string
	Timeout        time.Duration
}

type StockEngine struct{ options StockOptions }

func NewStockEngine(options StockOptions) *StockEngine {
	if options.Executable == "" {
		options.Executable = "dae"
	}
	if options.PIDFile == "" {
		options.PIDFile = "/var/run/dae.pid"
	}
	if options.Timeout <= 0 {
		options.Timeout = 15 * time.Second
	}
	return &StockEngine{options: options}
}

func (e *StockEngine) executable() (string, string, error) {
	p, err := exec.LookPath(e.options.Executable)
	if err != nil {
		return "", "", &Error{Code: "unavailable", Detail: "configured dae executable is unavailable", Cause: ErrUnavailable}
	}
	p, err = filepath.Abs(p)
	if err != nil {
		return "", "", err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", "", &Error{Code: "unavailable", Detail: "configured dae executable cannot be read", Cause: ErrUnavailable}
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", "", err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if e.options.ExpectedSHA256 != "" && !strings.EqualFold(e.options.ExpectedSHA256, digest) {
		return "", digest, &Error{Code: "unavailable", Detail: "dae executable does not match the configured SHA-256", Cause: ErrUnavailable}
	}
	return p, digest, nil
}

// Health checks real executable bytes and the configured PID's executable.
// A running process alone is explicitly not traffic or policy verification.
func (e *StockEngine) Health(ctx context.Context) (Health, error) {
	h := Health{Status: "unavailable", Implementation: "dae-stock", ObservedAt: time.Now().UTC(), Details: []string{"Process observation does not verify traffic, policy generation, provider inventory, or eBPF attachment health."}}
	executable, digest, err := e.executable()
	h.ExecutableSHA256 = digest
	if err != nil {
		h.Details = append(h.Details, err.Error())
		return h, nil
	}
	h.ExecutableAvailable = true
	ctx, cancel := context.WithTimeout(ctx, e.options.Timeout)
	defer cancel()
	output, err := boundedCommand(ctx, executable, "--version")
	if err != nil {
		h.Details = append(h.Details, "dae --version did not complete successfully")
		return h, nil
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(output)), "\n")
	h.EngineVersion = line
	h.Status = "degraded"
	b, err := os.ReadFile(e.options.PIDFile)
	if err != nil {
		h.Details = append(h.Details, "No readable daemon PID file.")
		return h, nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		h.Details = append(h.Details, "Daemon PID file is invalid.")
		return h, nil
	}
	processInfo, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		h.Details = append(h.Details, "Daemon PID is not observable.")
		return h, nil
	}
	executableInfo, err := os.Stat(executable)
	if err != nil || !os.SameFile(processInfo, executableInfo) {
		h.Details = append(h.Details, "Daemon PID does not refer to the configured executable.")
		return h, nil
	}
	h.EnginePID = pid
	h.ProcessObserved = true
	// degraded is deliberate: stock dae has no readback contract for applied
	// generations, tc identities, or the provider/selection state we manage.
	return h, nil
}

func (e *StockEngine) Capabilities(ctx context.Context) (Capabilities, error) {
	health, _ := e.Health(ctx)
	c := Capabilities{Implementation: "dae-stock", Version: health.EngineVersion, Items: make([]Capability, 0, len(AllCapabilities))}
	for _, name := range AllCapabilities {
		item := Capability{Name: name, Implementation: "dae-stock", Restrictions: []string{"Unavailable in the inspected stock dae command interface; runtime extension and qualification required."}}
		if name == CapabilityPolicyValidate {
			item.Supported = health.ExecutableAvailable && health.EngineVersion != ""
			item.Restrictions = []string{"Only standalone native dae configuration in payload.native_config is accepted; includes are disabled.", "Executes dae validate --config against a private temporary file; does not prove traffic or BPF behavior."}
		}
		if name == CapabilityPolicyApply {
			item.Restrictions = []string{"Stock dae reload is a whole configuration/control-plane replacement.", "No applied generation readback or cross-system safe rollback is qualified; automatic application is disabled."}
		}
		if name == CapabilityProviderPublish {
			item.Restrictions = []string{"Stock reload traverses subscriptions and constructs a new control plane; it is not single-provider hot publication."}
		}
		c.Items = append(c.Items, item)
	}
	return c, nil
}

type nativePolicyPayload struct {
	NativeConfig string `json:"native_config"`
}

var includeWord = regexp.MustCompile(`(?i)\binclude\b`)

// ValidatePolicy invokes the stock CLI without a shell and returns only a
// redacted failure. Native parser diagnostics may contain credentials.
func (e *StockEngine) ValidatePolicy(ctx context.Context, p Policy) error {
	if strings.TrimSpace(p.ID) == "" || p.Generation < 0 {
		return fmt.Errorf("%w: policy ID and nonnegative generation required", ErrValidation)
	}
	var payload nativePolicyPayload
	dec := json.NewDecoder(bytes.NewReader(p.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil || strings.TrimSpace(payload.NativeConfig) == "" {
		return fmt.Errorf("%w: payload.native_config is required", ErrValidation)
	}
	if len(payload.NativeConfig) > 1<<20 {
		return fmt.Errorf("%w: native configuration exceeds 1 MiB", ErrValidation)
	}
	if includeWord.MatchString(payload.NativeConfig) {
		return fmt.Errorf("%w: includes are disabled in submitted configuration", ErrValidation)
	}
	executable, _, err := e.executable()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp(e.options.ValidationRoot, "egressdeck-validate-")
	if err != nil {
		return &Error{Code: "unavailable", Detail: "cannot create private validation directory", Cause: ErrUnavailable}
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "config.dae")
	if err := os.WriteFile(file, []byte(payload.NativeConfig), 0o600); err != nil {
		return &Error{Code: "unavailable", Detail: "cannot write validation configuration", Cause: ErrUnavailable}
	}
	ctx, cancel := context.WithTimeout(ctx, e.options.Timeout)
	defer cancel()
	if _, err := boundedCommand(ctx, executable, "validate", "--config", file); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%w: validator timed out or was canceled", ErrValidation)
		}
		return fmt.Errorf("%w: dae rejected the configuration; diagnostics withheld because they may contain credentials", ErrValidation)
	}
	return nil
}

type limitedOutput struct{ data []byte }

func (w *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := 8192 - len(w.data); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		w.data = append(w.data, p...)
	}
	return n, nil
}
func boundedCommand(ctx context.Context, executable string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	var output limitedOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	return output.data, err
}

// Typed rejection is preferable to synthetic inventories or optimistic
// generation acknowledgements when the real runtime does not expose them.
func (*StockEngine) Inventory(context.Context) (Snapshot, error) {
	return Snapshot{}, unsupported("inventory.read")
}
func (*StockEngine) StageProvider(context.Context, ProviderRevision, int64) (string, error) {
	return "", unsupported("provider.stage")
}
func (*StockEngine) PublishProvider(context.Context, string) (Snapshot, error) {
	return Snapshot{}, unsupported("provider.publish_hot")
}
func (*StockEngine) SetRuntimeSelection(context.Context, SelectionScope, string, int64) (Selection, error) {
	return Selection{}, unsupported("selection.set_runtime")
}
func (*StockEngine) PersistSelection(context.Context, SelectionScope, string, int64) (Selection, error) {
	return Selection{}, unsupported("selection.persist_restart")
}
func (*StockEngine) ApplyPolicyGeneration(context.Context, Policy, int64) (Snapshot, error) {
	return Snapshot{}, unsupported("policy.apply_generation")
}
func (*StockEngine) ProbeNode(context.Context, string) (ProbeResult, error) {
	return ProbeResult{}, unsupported("probe.node")
}
func (*StockEngine) ProbeGroup(context.Context, string) (ProbeResult, error) {
	return ProbeResult{}, unsupported("probe.group")
}
func (*StockEngine) ObserveConnections(context.Context) ([]Connection, error) {
	return nil, unsupported("connections.observe")
}
func (*StockEngine) CloseFiltered(context.Context, ConnectionFilter) (int, error) {
	return 0, unsupported("connections.close_filtered")
}
func (*StockEngine) Counters(context.Context) (Counters, error) {
	return Counters{}, unsupported("traffic.counters")
}
func (*StockEngine) ResumeEvents(context.Context, int64) ([]Event, error) {
	return nil, unsupported("events.resume")
}

var _ Engine = (*StockEngine)(nil)
