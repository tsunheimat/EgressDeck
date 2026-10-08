package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

func TestAgentPublishesProviderAndReadsGeneration(t *testing.T) {
	a := &agent{engine: gateway.NewFakeEngine(), token: "secret"}
	ts := httptest.NewServer(a.routes())
	defer ts.Close()
	client := ts.Client()
	payload := map[string]any{"revision": gateway.ProviderRevision{ProviderID: "p", Revision: 1, Nodes: []gateway.Node{{ID: "n", Name: "node"}}}}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/providers/stage", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("stage status = %d", resp.StatusCode)
	}
	var staged struct {
		StageID string `json:"stage_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&staged); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	publishBody, _ := json.Marshal(map[string]string{"stage_id": staged.StageID})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/v1/providers/publish", bytes.NewReader(publishBody))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("publish status = %d", resp.StatusCode)
	}
	var result struct {
		Snapshot gateway.Snapshot `json:"snapshot"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	inventory := result.Snapshot
	if inventory.Generation != 1 || inventory.Providers["p"].Nodes[0].Handle == 0 {
		t.Fatalf("inventory = %+v", inventory)
	}
}

func TestAgentRequiresBearerToken(t *testing.T) {
	a := &agent{engine: gateway.NewFakeEngine(), token: "secret"}
	req := httptest.NewRequest(http.MethodGet, "/v1/inventory", nil)
	rr := httptest.NewRecorder()
	a.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rr.Code)
	}
}

func TestDefaultStockBackendDoesNotExposeFakeRuntime(t *testing.T) {
	engine := chooseEngine("", gateway.StockOptions{Executable: "/does-not-exist/dae"}, nil)
	if _, fake := engine.(*gateway.FakeEngine); fake {
		t.Fatal("default backend is fake")
	}
	a := &agent{engine: engine, token: "secret"}
	for _, path := range []string{"/v1/capabilities", "/v1/health", "/v1/inventory"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer secret")
		rr := httptest.NewRecorder()
		a.routes().ServeHTTP(rr, req)
		if path == "/v1/inventory" {
			if rr.Code != http.StatusNotImplemented {
				t.Fatalf("inventory status=%d body=%s", rr.Code, rr.Body.String())
			}
			continue
		}
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, rr.Code)
		}
		if path == "/v1/capabilities" {
			var caps gateway.Capabilities
			if err := json.Unmarshal(rr.Body.Bytes(), &caps); err != nil {
				t.Fatal(err)
			}
			for _, c := range caps.Items {
				if c.Supported {
					t.Fatalf("missing stock binary advertises %+v", c)
				}
			}
		}
		if path == "/v1/health" {
			var health gateway.Health
			if err := json.Unmarshal(rr.Body.Bytes(), &health); err != nil {
				t.Fatal(err)
			}
			if health.Status != "unavailable" || health.ProcessObserved {
				t.Fatalf("health=%+v", health)
			}
		}
	}
	if _, ok := chooseEngine("fake", gateway.StockOptions{}, nil).(*gateway.FakeEngine); !ok {
		t.Fatal("explicit fake backend unavailable")
	}
}

func TestAgentBearerSchemeIsRequired(t *testing.T) {
	a := &agent{engine: gateway.NewFakeEngine(), token: "secret"}
	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	req.Header.Set("Authorization", "secret")
	rr := httptest.NewRecorder()
	a.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestOnlyLiteralLoopbackAllowsPlaintext(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9090", "[::1]:9090"} {
		if !loopbackListen(address) {
			t.Fatalf("rejected loopback %s", address)
		}
	}
	for _, address := range []string{":9090", "0.0.0.0:9090", "localhost:9090", "192.168.1.2:9090"} {
		if loopbackListen(address) {
			t.Fatalf("accepted non-loopback %s", address)
		}
	}
}
