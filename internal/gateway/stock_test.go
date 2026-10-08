package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These executable fixtures exercise the command boundary; they are not dae
// runtime/network qualification. No test starts a real packet-processing daemon.
func stockFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "dae-fixture")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf 'dae version fixture-only\n'
  exit 0
fi
if [ "$1" != "validate" ] || [ "$2" != "--config" ]; then
  exit 90
fi
if [ "$(stat -c %a "$3")" != "600" ]; then exit 91; fi
case "$(cat "$3")" in
 *INVALID*) printf 'secret-subscription-token\n' >&2; exit 4 ;;
 *STALL*) sleep 10; exit 0 ;;
 *) exit 0 ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(script))
	return binary, hex.EncodeToString(h[:])
}

func nativePolicy(config string) Policy {
	raw, _ := json.Marshal(map[string]string{"native_config": config})
	return Policy{ID: "policy", Payload: raw}
}

func TestStockUnavailableDoesNotAdvertiseCapabilities(t *testing.T) {
	e := NewStockEngine(StockOptions{Executable: filepath.Join(t.TempDir(), "missing")})
	c, err := e.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range c.Items {
		if item.Supported {
			t.Errorf("unavailable binary advertises %s", item.Name)
		}
	}
	h, err := e.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != "unavailable" || h.ExecutableAvailable || h.ProcessObserved {
		t.Fatalf("health=%+v", h)
	}
}

func TestStockValidationUsesExecutablePrivateFileAndRedactsErrors(t *testing.T) {
	binary, digest := stockFixture(t)
	root := t.TempDir()
	e := NewStockEngine(StockOptions{Executable: binary, ExpectedSHA256: digest, ValidationRoot: root, PIDFile: filepath.Join(root, "absent.pid")})
	if err := e.ValidatePolicy(context.Background(), nativePolicy("global{} routing{fallback:direct}")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("validation left files: %+v", entries)
	}
	err = e.ValidatePolicy(context.Background(), nativePolicy("INVALID"))
	if !errors.Is(err, ErrValidation) || strings.Contains(err.Error(), "secret-subscription-token") {
		t.Fatalf("validation error=%v", err)
	}
	c, _ := e.Capabilities(context.Background())
	for _, item := range c.Items {
		if item.Supported != (item.Name == CapabilityPolicyValidate) {
			t.Errorf("unexpected capability %+v", item)
		}
	}
	h, _ := e.Health(context.Background())
	if h.ExecutableSHA256 != digest || h.ProcessObserved || h.Status != "degraded" {
		t.Fatalf("health=%+v", h)
	}
}

func TestStockRejectsDigestMismatchAndUnsafePayload(t *testing.T) {
	binary, _ := stockFixture(t)
	e := NewStockEngine(StockOptions{Executable: binary, ExpectedSHA256: strings.Repeat("0", 64)})
	if err := e.ValidatePolicy(context.Background(), nativePolicy("global{} routing{}")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("digest mismatch error=%v", err)
	}
	e = NewStockEngine(StockOptions{Executable: binary})
	for _, config := range []string{"include{'/etc/shadow'}", strings.Repeat("x", (1<<20)+1)} {
		if err := e.ValidatePolicy(context.Background(), nativePolicy(config)); !errors.Is(err, ErrValidation) {
			t.Fatalf("invalid configuration error=%v", err)
		}
	}
	if err := e.ValidatePolicy(context.Background(), Policy{ID: "policy", Payload: json.RawMessage(`{"unrelated":"data"}`)}); !errors.Is(err, ErrValidation) {
		t.Fatalf("foreign payload error=%v", err)
	}
}

func TestStockDoesNotInventRuntimeOperations(t *testing.T) {
	e := NewStockEngine(StockOptions{})
	ctx := context.Background()
	if _, err := e.Inventory(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := e.StageProvider(ctx, ProviderRevision{}, 0); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := e.PublishProvider(ctx, "stage"); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := e.ApplyPolicyGeneration(ctx, Policy{}, 0); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := e.SetRuntimeSelection(ctx, SelectionScope{}, "", 0); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := e.ProbeNode(ctx, "node"); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
	if _, err := e.Counters(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatal(err)
	}
}

func TestStockValidationDeadline(t *testing.T) {
	binary, _ := stockFixture(t)
	e := NewStockEngine(StockOptions{Executable: binary, Timeout: 20 * time.Millisecond})
	started := time.Now()
	err := e.ValidatePolicy(context.Background(), nativePolicy("STALL"))
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("timeout error=%v", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("validator ignored deadline")
	}
}
