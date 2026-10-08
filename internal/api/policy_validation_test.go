package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/policy"
	"github.com/egressdeck/homelab-proxy-controller/internal/store"
)

func TestPolicyResourcePOSTAcceptsModelTransports(t *testing.T) {
	for _, resource := range []string{"policies", "rule-sets"} {
		for _, transport := range []policy.Transport{policy.TransportTCP, policy.TransportUDP, policy.TransportQUIC} {
			t.Run(resource+"/"+string(transport), func(t *testing.T) {
				server := httptest.NewServer(NewServer(store.NewMemoryStore(), nil).Handler())
				defer server.Close()
				endpoint := server.URL + "/api/v1/" + resource
				body := policyResourceTestBody(t, resource, "resource-1", policy.Match{Transport: []policy.Transport{transport}})
				postJSON(t, endpoint, body, http.StatusCreated)

				response, err := http.Get(endpoint + "/resource-1")
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatalf("readback status=%d", response.StatusCode)
				}
				var saved struct {
					ID       string               `json:"id"`
					Revision int64                `json:"revision"`
					Rules    []policy.Rule        `json:"rules"`
					Entries  []policy.PolicyEntry `json:"entries"`
				}
				if err := json.NewDecoder(response.Body).Decode(&saved); err != nil {
					t.Fatal(err)
				}
				if saved.ID != "resource-1" || saved.Revision != 1 {
					t.Fatalf("saved identity/revision=%+v", saved)
				}
				var match policy.Match
				if resource == "policies" {
					if len(saved.Entries) != 1 || saved.Entries[0].Rule == nil {
						t.Fatalf("saved entries=%+v", saved.Entries)
					}
					match = saved.Entries[0].Rule.Match
				} else {
					if len(saved.Rules) != 1 {
						t.Fatalf("saved rules=%+v", saved.Rules)
					}
					match = saved.Rules[0].Match
				}
				if len(match.Transport) != 1 || match.Transport[0] != transport {
					t.Fatalf("saved transport=%v want=%s", match.Transport, transport)
				}
			})
		}
	}
}

func TestPolicyResourcePOSTRejectsUnresolvedDomainSets(t *testing.T) {
	for _, resource := range []string{"policies", "rule-sets"} {
		t.Run(resource, func(t *testing.T) {
			server := httptest.NewServer(NewServer(store.NewMemoryStore(), nil).Handler())
			defer server.Close()
			endpoint := server.URL + "/api/v1/" + resource
			body := policyResourceTestBody(t, resource, "resource-1", policy.Match{
				Transport: []policy.Transport{policy.TransportTCP}, DomainSets: []string{"unregistered-domains"},
			})
			data := postJSON(t, endpoint, body, http.StatusUnprocessableEntity)
			if !strings.Contains(string(data), "unresolved_domain_set") || strings.Contains(string(data), "unsupported_transport") {
				t.Fatalf("expected only reference validation failure: %s", data)
			}
			response, err := http.Get(endpoint + "/resource-1")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusNotFound {
				t.Fatalf("invalid resource was stored: status=%d", response.StatusCode)
			}
			body = policyResourceTestBody(t, resource, "resource-1", policy.Match{Transport: []policy.Transport{policy.TransportTCP}})
			postJSON(t, endpoint, body, http.StatusCreated)
		})
	}
}

func TestPolicyPreviewStillRejectsUnsupportedGatewayTransport(t *testing.T) {
	server := httptest.NewServer(NewServer(store.NewMemoryStore(), nil).Handler())
	defer server.Close()
	request := policy.CompileInput{
		Gateway:      policy.Gateway{ID: "tcp-only", SupportedTransports: []policy.Transport{policy.TransportTCP}},
		Devices:      []policy.Device{{ID: "device-1", Enabled: true, Addresses: []policy.DeviceAddress{{Address: "192.0.2.10"}}}},
		DeviceGroups: []policy.DeviceGroup{{ID: "group-1", GatewayID: "tcp-only", PolicyID: "policy-1", DeviceIDs: []string{"device-1"}, Enabled: true}},
		Policies: []policy.Policy{{ID: "policy-1", DefaultAction: policy.Block(), Rules: []policy.Rule{{
			ID: "udp-rule", Enabled: true, Action: policy.Direct(), Match: policy.Match{Transport: []policy.Transport{policy.TransportUDP}},
		}}}},
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	data := postJSON(t, server.URL+"/api/v1/deployments/preview", string(body), http.StatusUnprocessableEntity)
	if !strings.Contains(string(data), "unsupported_transport") {
		t.Fatalf("expected gateway capability failure: %s", data)
	}
	response, err := http.Get(server.URL + "/api/v1/gateways")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err = io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	var gateways struct {
		Items []json.RawMessage `json:"items"`
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &gateways) != nil || len(gateways.Items) != 0 {
		t.Fatalf("validation registered a gateway: status=%d body=%s", response.StatusCode, data)
	}
}

func policyResourceTestBody(t *testing.T, resource, id string, match policy.Match) string {
	t.Helper()
	rule := policy.Rule{ID: "rule-1", Enabled: true, Action: policy.Block(), Match: match}
	var value any = policy.RuleSet{ID: id, Name: "Transport rules", Rules: []policy.Rule{rule}}
	if resource == "policies" {
		value = policy.Policy{ID: id, Name: "Transport policy", DefaultAction: policy.Direct(), Entries: []policy.PolicyEntry{{Rule: &rule}}}
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
