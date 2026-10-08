package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
	"github.com/egressdeck/homelab-proxy-controller/internal/opnsense"
	"github.com/egressdeck/homelab-proxy-controller/internal/outbounds"
	"github.com/egressdeck/homelab-proxy-controller/internal/providers"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func TestManagementFlowProviderGroupPolicyPreview(t *testing.T) {
	mem := store.NewMemoryStore()
	server := NewServer(mem, nil)
	server.Services.Providers = providers.NewRegistry(providers.DefaultLimits(), func(context.Context, domain.Provider) ([]byte, error) {
		return []byte("socks5://user:secret@example.org:1080#edge\n"), nil
	})
	server.Services.ProviderStageEnabled = true
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	provider := postJSON(t, ts.URL+"/api/v1/providers", `{"id":"provider-1","name":"test","source":"https://example.invalid/list","format":"links"}`, http.StatusCreated)
	var p domain.Provider
	if err := json.Unmarshal(provider, &p); err != nil {
		t.Fatal(err)
	}
	refresh := postJSON(t, ts.URL+"/api/v1/providers/provider-1/refresh", `{}`, http.StatusAccepted)
	var staged struct {
		Revision providers.Revision `json:"revision"`
	}
	if err := json.Unmarshal(refresh, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.Revision.Number == 0 || len(staged.Revision.Nodes) != 1 {
		t.Fatalf("staged=%+v", staged.Revision)
	}
	postJSON(t, ts.URL+"/api/v1/gateways", `{"id":"gateway-1","name":"Test gateway","endpoint":"https://gateway.invalid"}`, http.StatusCreated)

	groupBody, _ := json.Marshal(outbounds.Group{ID: "outbound-1", Name: "Test exit", GatewayID: "gateway-1", NodeIDs: []string{staged.Revision.Nodes[0].ID}, Mode: outbounds.SelectionManual, Replacement: outbounds.ReplacementBlock})
	postJSON(t, ts.URL+"/api/v1/outbound-groups", string(groupBody), http.StatusCreated)
	postJSON(t, ts.URL+"/api/v1/policies", `{"id":"policy-1","name":"test","default_action":{"kind":"direct"}}`, http.StatusCreated)

	preview := `{"gateway":{"id":"gateway-1","name":"Gateway","supported_transports":["tcp"],"supports_ipv6":false,"distinguishes_networks":true},"devices":[{"id":"device-1","name":"Laptop","addresses":[{"address":"192.0.2.10"}],"enabled":true}],"device_groups":[{"id":"group-1","name":"Test","gateway_id":"gateway-1","policy_id":"policy-1","device_ids":["device-1"],"enabled":true}],"policies":[{"id":"policy-1","name":"test","entries":[{"rule":{"id":"proxy-rule","match":{"domain_suffix":["example.com"]},"action":{"kind":"outbound_group","outbound_group_id":"outbound-1"},"enabled":true}}],"default_action":{"kind":"direct"},"proxy_failure_action":{"kind":"block"}}],"outbound_groups":[{"id":"outbound-1","name":"Test exit","node_ids":["` + staged.Revision.Nodes[0].ID + `"],"allow_empty":false}],"options":{"gateway_id":"gateway-1","supported_transports":{"tcp":true},"supports_ipv6":false,"distinguishes_networks":true}}`
	result := postJSON(t, ts.URL+"/api/v1/deployments/preview", preview, http.StatusOK)
	var decoded struct {
		Manifest struct {
			ContentHash string `json:"content_hash"`
		} `json:"manifest"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Manifest.ContentHash == "" {
		t.Fatalf("preview omitted manifest hash: %s", result)
	}
}

func postJSON(t *testing.T, url, body string, want int) []byte {
	t.Helper()
	response, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var data []byte
	data, err = io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("POST %s status=%d want=%d body=%s", url, response.StatusCode, want, data)
	}
	return data
}

func TestUnsupportedRemoteMutationDoesNotChangeSelectionOrPublish(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	_, err := server.Store.CreateProvider(context.Background(), domain.Provider{ID: "p", Name: "p", Source: "inline", Format: "local"})
	if err != nil {
		t.Fatal(err)
	}
	revision, _, err := server.Services.Providers.Stage("p", []byte("socks5://host.example:1080#node"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.Services.Outbounds.Create(outbounds.Group{ID: "g", Name: "g", GatewayID: "gw", NodeIDs: []string{revision.Nodes[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	postJSON(t, ts.URL+"/api/v1/providers/p/revisions/1/apply", `{}`, http.StatusNotImplemented)
	postJSON(t, ts.URL+"/api/v1/outbound-groups/g/selection", `{"node_id":"`+revision.Nodes[0].ID+`","gateway_id":"gw"}`, http.StatusNotImplemented)
	if got := server.Services.Providers.Status("p").Active; got != 0 {
		t.Fatalf("unsupported publish changed active revision: %d", got)
	}
	if len(server.Services.Outbounds.Selections("g")) != 0 {
		t.Fatal("unsupported selection persisted intent")
	}
}

func TestFirewallAttachUsesAdapterReadback(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	if _, err := server.Store.CreateGateway(context.Background(), domain.Gateway{ID: "gw", Name: "Gateway", Endpoint: "https://gateway.example.invalid", Adapter: "dae"}); err != nil {
		t.Fatal(err)
	}
	client := opnsense.NewFakeClient(opnsense.AliasRecord{Name: "managed", UUID: "alias-1", Type: opnsense.HostAlias, Addresses: []string{"192.0.2.5"}})
	adapter, err := opnsense.NewAdapter(client)
	if err != nil {
		t.Fatal(err)
	}
	server.Services.Firewall = adapter
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	postJSON(t, ts.URL+"/api/v1/firewall-bindings", `{"id":"binding-1","gateway_id":"gw","alias":"managed","family":"ipv4","interface_scope":"lan"}`, http.StatusCreated)
	response, err := http.Get(ts.URL + "/api/v1/firewall-bindings/binding-1/readback")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("readback status=%d", response.StatusCode)
	}
}

func TestProviderApplyPreconditionsAndLostAcknowledgement(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	_, err := server.Store.CreateProvider(context.Background(), domain.Provider{ID: "p", Name: "p", Source: "inline", Format: "local"})
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := server.Services.Providers.Stage("p", []byte("socks5://one.example:1080#one"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.Services.Providers.Publish("p", first.Number, 0); err != nil {
		t.Fatal(err)
	}
	second, _, err := server.Services.Providers.Stage("p", []byte("socks5://two.example:1080#two"), providers.FormatLinks)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	observed := first.Number
	server.Services.ProviderPublisher = func(_ context.Context, _ domain.Provider, revision providers.Revision) error {
		calls++
		observed = revision.Number
		return errors.New("acknowledgement lost")
	}
	server.Services.ProviderReadback = func(context.Context, domain.Provider) (int64, error) { return observed, nil }
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/providers/p/revisions/2/apply", strings.NewReader(`{}`))
	req.Header.Set("If-Match", "99")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed || calls != 0 {
		t.Fatalf("CAS failed status=%d calls=%d", resp.StatusCode, calls)
	}
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/v1/providers/p/revisions/"+strconv.FormatInt(second.Number, 10)+"/apply", strings.NewReader(`{}`))
	req.Header.Set("If-Match", strconv.FormatInt(first.Number, 10))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("confirmed publication status=%d", resp.StatusCode)
	}
	if calls != 1 || server.Services.Providers.Status("p").Active != second.Number {
		t.Fatalf("confirmed publication not applied calls=%d", calls)
	}
}

func TestStageIdempotencyRejectsChangedPayloadAndDoesNotExposeHash(t *testing.T) {
	server := NewServer(store.NewMemoryStore(), nil)
	_, err := server.Store.CreateProvider(context.Background(), domain.Provider{ID: "p", Name: "p", Source: "inline", Format: "local"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	for index, content := range []string{"socks5://one.example:1080#one", "socks5://two.example:1080#two"} {
		payload, _ := json.Marshal(map[string]string{"content": content, "format": "links"})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/providers/p/stage", strings.NewReader(string(payload)))
		req.Header.Set("Idempotency-Key", "fixed")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		want := http.StatusAccepted
		if index == 1 {
			want = http.StatusConflict
		}
		if resp.StatusCode != want {
			t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, want, data)
		}
	}
	resp, err := http.Get(ts.URL + "/api/v1/operations")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(data), "request_hash") {
		t.Fatalf("public operation exposed request hash: %s", data)
	}
}
