package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

type diagnosticFixture struct {
	caps  gateway.Capabilities
	probe gateway.ProbeResult
	err   error
	calls int
}

func (d *diagnosticFixture) Capabilities(context.Context) (gateway.Capabilities, error) {
	d.calls++
	return d.caps, nil
}
func (d *diagnosticFixture) ProbeNode(context.Context, string) (gateway.ProbeResult, error) {
	d.calls++
	return d.probe, d.err
}
func (d *diagnosticFixture) ProbeGroup(context.Context, string) (gateway.ProbeResult, error) {
	d.calls++
	return d.probe, d.err
}
func (d *diagnosticFixture) ObserveConnections(context.Context) ([]gateway.Connection, error) {
	d.calls++
	return nil, d.err
}
func (d *diagnosticFixture) Counters(context.Context) (gateway.Counters, error) {
	d.calls++
	return gateway.Counters{}, d.err
}

func newDiagnosticAPIFixture(t *testing.T) (*Server, *diagnosticFixture) {
	t.Helper()
	s := NewServer(store.NewMemoryStore(), nil)
	if _, err := s.Store.CreateGateway(context.Background(), domain.Gateway{ID: "lab", Name: "Lab gateway", Endpoint: "https://gateway.invalid"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Services.Outbounds.Create(outbounds.Group{ID: "exit", Name: "Exit", GatewayID: "lab", NodeIDs: []string{"node"}}); err != nil {
		t.Fatal(err)
	}
	d := &diagnosticFixture{caps: gateway.DefaultCapabilities("test", "1"), probe: gateway.ProbeResult{Target: "node", OK: true, Latency: time.Millisecond, Observed: time.Now().UTC()}}
	s.Services.GatewayDiagnostics = func(context.Context, domain.Gateway) (GatewayDiagnostics, error) { return d, nil }
	return s, d
}

func TestGatewayDiagnosticsRejectCallerProbeDestinations(t *testing.T) {
	for _, body := range []string{`{"url":"http://169.254.169.254/latest"}`, `{"target":"elsewhere"}`, `null`, `[]`, `{} {}`, strings.Repeat(" ", 1025)} {
		t.Run(body[:min(len(body), 35)], func(t *testing.T) {
			s, d := newDiagnosticAPIFixture(t)
			response := httptest.NewRecorder()
			s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/gateways/lab/probes/nodes/node", strings.NewReader(body)))
			if response.Code != http.StatusBadRequest || d.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, d.calls, response.Body.String())
			}
		})
	}
	for _, path := range []string{"/probes/nodes/node?url=https://arbitrary.invalid", "/connections?gateway_id=elsewhere", "/counters?url=https://arbitrary.invalid"} {
		s, d := newDiagnosticAPIFixture(t)
		method := http.MethodGet
		if strings.Contains(path, "probes") {
			method = http.MethodPost
		}
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, httptest.NewRequest(method, "/api/v1/gateways/lab"+path, nil))
		if response.Code != http.StatusBadRequest || d.calls != 0 {
			t.Fatalf("path=%s status=%d calls=%d", path, response.Code, d.calls)
		}
	}
}

func TestGatewayDiagnosticsUnsupportedAndWrongMethods(t *testing.T) {
	for _, path := range []string{"/probes/nodes/node", "/probes/groups/exit", "/connections", "/counters"} {
		s, d := newDiagnosticAPIFixture(t)
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/api/v1/gateways/lab"+path, nil))
		if response.Code != http.StatusMethodNotAllowed || d.calls != 0 {
			t.Fatalf("path=%s status=%d calls=%d", path, response.Code, d.calls)
		}
	}
	s, d := newDiagnosticAPIFixture(t)
	d.err = gateway.ErrUnsupported
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/gateways/lab/probes/nodes/node", nil))
	if response.Code != http.StatusNotImplemented || !strings.Contains(response.Body.String(), "unsupported_capability") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestGatewayDiagnosticsValidateAndSanitizeProbeReadback(t *testing.T) {
	for _, change := range []func(*gateway.ProbeResult){func(p *gateway.ProbeResult) { p.Target = "other" }, func(p *gateway.ProbeResult) { p.Observed = time.Time{} }, func(p *gateway.ProbeResult) { p.Latency = -1 }} {
		s, d := newDiagnosticAPIFixture(t)
		change(&d.probe)
		response := httptest.NewRecorder()
		s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/gateways/lab/probes/nodes/node", nil))
		if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "invalid_gateway_response") {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
	s, d := newDiagnosticAPIFixture(t)
	d.probe.OK = false
	d.probe.Error = "dial socks5://user:secret@private.invalid:1080 failed"
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/gateways/lab/probes/nodes/node", nil))
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "secret") || !strings.Contains(response.Body.String(), `"ok":false`) || !strings.Contains(response.Body.String(), "Gateway probe did not succeed") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	d.err = errors.New("token=private-secret transport detail")
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/gateways/lab/counters", nil))
	if response.Code != http.StatusBadGateway || strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
