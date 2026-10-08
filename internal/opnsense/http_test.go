package opnsense

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const nativeAlias = "egress_managed"
const nativeUUID = "e9b12e71-3462-4098-aa1b-79d5d2bdbb30"
const nativeRuleUUID = "58c26507-f540-4d53-8506-e92dc44daa28"

type nativeFixture struct {
	mu           sync.Mutex
	t            *testing.T
	persisted    []string
	active       []string
	typeName     string
	description  string
	enabled      string
	version      string
	activate     bool
	status       string
	missingTable bool
	truncated    bool
	listFails    bool
	countMissing bool
	rule         map[string]any
	mutations    []Call
}

func nativeOptions(selected string) map[string]any {
	return map[string]any{selected: map[string]any{"selected": 1, "value": "localized display text"}}
}

func newNativeFixture(t *testing.T) *nativeFixture {
	return &nativeFixture{t: t, persisted: []string{"192.0.2.1"}, active: []string{"192.0.2.1"}, typeName: "host", description: "Reviewed managed clients", enabled: "1", version: SupportedRelease, activate: true, status: "done", rule: map[string]any{
		"enabled": "1", "quick": "1", "source_not": "0", "interfacenot": "0", "source_net": nativeAlias,
		"source_port": "", "destination_port": "", "destination_net": "local_and_management", "destination_not": "1",
		"sequence": "100", "prio_group": "400000", "sort_order": "400000.0000100", "tagged": "", "action": nativeOptions("pass"), "direction": nativeOptions("in"),
		"ipprotocol": nativeOptions("inet"), "interface": nativeOptions("lan"), "gateway": nativeOptions("DAE_GW"),
		"protocol": nativeOptions("any"), "statetype": nativeOptions("keep"), "sched": nativeOptions(""), "divert-to": nativeOptions(""), "replyto": nativeOptions(""), "prio": nativeOptions(""), "tos": nativeOptions(""), "categories": []any{},
	}}
}

func (f *nativeFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key, secret, ok := r.BasicAuth()
	if !ok || key != "api-key" || secret != "api-secret" {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Header.Get("Accept") != "application/json" {
		f.t.Error("missing Accept header")
	}
	w.Header().Set("Content-Type", "application/json")
	emit := func(value any) {
		if err := json.NewEncoder(w).Encode(value); err != nil {
			f.t.Error(err)
		}
	}
	checkMethod := func(method string) {
		if r.Method != method {
			f.t.Errorf("%s method=%s, want %s", r.URL.Path, r.Method, method)
		}
	}
	checkSearch := func(search string) {
		checkMethod(http.MethodPost)
		if r.Header.Get("Content-Type") != "application/json" {
			f.t.Error("search body is not JSON")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["current"] != float64(1) || body["rowCount"] != float64(-1) || body["searchPhrase"] != search || len(body) != 3 {
			f.t.Errorf("native search request = %#v", body)
		}
	}
	switch r.URL.Path {
	case "/api/core/firmware/info":
		checkMethod(http.MethodGet)
		emit(map[string]any{"product_id": "opnsense", "product_version": f.version})
	case "/api/firewall/alias/search_item":
		checkSearch(nativeAlias)
		emit(map[string]any{"current": 1, "total": 2, "rows": []any{map[string]any{"name": nativeAlias + "_other", "uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}, map[string]any{"name": nativeAlias, "uuid": nativeUUID}}})
	case "/api/firewall/alias/get_item/" + nativeUUID:
		checkMethod(http.MethodGet)
		content := map[string]any{"unused_nested_alias": map[string]any{"selected": 0, "value": "unused nested alias"}}
		for _, address := range f.persisted {
			content[address] = map[string]any{"selected": 1, "value": address}
		}
		emit(map[string]any{"alias": map[string]any{"name": nativeAlias, "description": f.description, "type": nativeOptions(f.typeName), "enabled": f.enabled, "content": content}})
	case "/api/firewall/alias_util/aliases":
		checkMethod(http.MethodGet)
		if f.missingTable {
			emit([]string{})
		} else {
			emit([]string{nativeAlias})
		}
	case "/api/firewall/alias_util/list/" + nativeAlias:
		checkSearch("")
		rows := []any{}
		for _, address := range f.active {
			rows = append(rows, map[string]any{"ip": address, "in_pass_p": 0})
		}
		if f.listFails {
			rows = []any{}
		}
		total := len(rows)
		if f.truncated {
			total++
		}
		emit(map[string]any{"current": 1, "total": total, "rows": rows})
	case "/api/firewall/alias/get_table_size":
		checkMethod(http.MethodGet)
		details := map[string]any{}
		if !f.countMissing {
			details[nativeAlias] = map[string]any{"count": len(f.active)}
		}
		emit(map[string]any{"status": "ok", "details": details})
	case "/api/firewall/filter/get_rule/" + nativeRuleUUID:
		checkMethod(http.MethodGet)
		emit(map[string]any{"rule": f.rule})
	case "/api/firewall/alias_util/add/" + nativeAlias, "/api/firewall/alias_util/delete/" + nativeAlias:
		checkMethod(http.MethodPost)
		if r.Header.Get("Content-Type") != "application/json" {
			f.t.Error("mutation body is not JSON")
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["address"] == "" || len(body) != 1 {
			f.t.Errorf("mutation must contain a single address: %#v", body)
		}
		op := "add"
		if strings.Contains(r.URL.Path, "/delete/") {
			op = "delete"
		}
		f.mutations = append(f.mutations, Call{Operation: op, Alias: nativeAlias, Addresses: []string{body["address"]}})
		if f.status == "done" {
			if op == "add" {
				f.persisted = append(f.persisted, body["address"])
			} else {
				remaining := []string{}
				for _, address := range f.persisted {
					if address != body["address"] {
						remaining = append(remaining, address)
					}
				}
				f.persisted = remaining
			}
			if f.activate {
				f.active = append([]string(nil), f.persisted...)
			}
		}
		emit(map[string]string{"status": f.status, "status_msg": "never echo appliance message with api-secret"})
	default:
		f.t.Errorf("unexpected endpoint %s", r.URL.Path)
		http.NotFound(w, r)
	}
}

func fixtureClient(t *testing.T, fixture *nativeFixture) (*HTTPClient, HTTPConfig) {
	t.Helper()
	server := httptest.NewTLSServer(fixture)
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	cfg := HTTPConfig{BaseURL: server.URL, APIKey: "api-key", APISecret: "api-secret", Release: SupportedRelease, RootCAs: roots}
	client, err := NewHTTPClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	rule, err := client.ReadSteeringRule(context.Background(), nativeRuleUUID)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ManagedAliases = []ManagedAlias{{Shape: AliasShape{Name: nativeAlias, UUID: nativeUUID, Type: HostAlias, Description: fixture.description}, GatewayID: "gateway-1", InterfaceScope: "lan", Family: IPv4Family, Rules: []RuleExpectation{{UUID: nativeRuleUUID, SnapshotHash: rule.SnapshotHash, Gateway: "DAE_GW", Destination: "local_and_management", DestinationNot: true}}, Review: PolicyReview{Reviewer: "admin", ReviewedAt: time.Now().UTC(), EvidenceReference: "review-1", PacketPathEvidence: "isolated-capture-1", ExistingDeniesPreserved: true, ManagementExcluded: true, TransitExcluded: true}}}
	client, err = NewHTTPClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, cfg
}

func TestHTTPNativeAttachDeltaAndReadback(t *testing.T) {
	f := newNativeFixture(t)
	client, _ := fixtureClient(t, f)
	adapter, _ := NewAdapter(client)
	request := AttachRequest{ID: "binding", GatewayID: "gateway-1", Alias: nativeAlias, AliasUUID: nativeUUID, AliasType: HostAlias, Family: IPv4Family, InterfaceScope: "lan", RuleIDs: []string{nativeRuleUUID}}
	binding, rb, err := adapter.Attach(context.Background(), request)
	if err != nil || rb.Drift.Drifted {
		t.Fatalf("attach: %#v %v", rb, err)
	}
	result, err := adapter.Sync(context.Background(), binding, []string{"192.0.2.3", "192.0.2.2", "192.0.2.2"})
	if err != nil || !result.Complete {
		t.Fatalf("sync: %#v %v", result, err)
	}
	if _, err := adapter.Sync(context.Background(), result.Binding, []string{"192.0.2.2", "192.0.2.3"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	want := []Call{{Operation: "add", Alias: nativeAlias, Addresses: []string{"192.0.2.2"}}, {Operation: "add", Alias: nativeAlias, Addresses: []string{"192.0.2.3"}}, {Operation: "delete", Alias: nativeAlias, Addresses: []string{"192.0.2.1"}}}
	if !reflect.DeepEqual(f.mutations, want) {
		t.Fatalf("native mutation calls = %#v", f.mutations)
	}
	if !reflect.DeepEqual(f.persisted, f.active) {
		t.Fatalf("persisted/active disagree: %v %v", f.persisted, f.active)
	}
}

func TestHTTPRejectsDriftVersionAndUnreviewedScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*nativeFixture)
		want error
	}{
		{"description", func(f *nativeFixture) { f.description = "administrator edit" }, ErrDrift},
		{"disabled", func(f *nativeFixture) { f.enabled = "0" }, ErrShapeChanged},
		{"external alias", func(f *nativeFixture) { f.typeName = "external" }, ErrShapeChanged},
		{"rule sequence", func(f *nativeFixture) { f.rule["sequence"] = "1" }, ErrDrift},
		{"rule source", func(f *nativeFixture) { f.rule["source_net"] = "any" }, ErrDrift},
		{"version", func(f *nativeFixture) { f.version = "26.7.1" }, ErrVersion},
		{"active contents", func(f *nativeFixture) { f.active = []string{"198.51.100.1"} }, ErrDrift},
		{"out of family", func(f *nativeFixture) { f.active = []string{"2001:db8::1"}; f.persisted = []string{"2001:db8::1"} }, ErrInvalidBinding},
		{"active table missing", func(f *nativeFixture) { f.missingTable = true }, ErrNotFound},
		{"active table truncated", func(f *nativeFixture) { f.truncated = true }, ErrProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNativeFixture(t)
			client, _ := fixtureClient(t, f)
			f.mu.Lock()
			tc.edit(f)
			f.mu.Unlock()
			err := client.AddAliasAddresses(context.Background(), nativeAlias, []string{"192.0.2.2"})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want %v", err, tc.want)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.mutations) != 0 {
				t.Fatalf("unexpected mutation %#v", f.mutations)
			}
		})
	}
	f := newNativeFixture(t)
	client, cfg := fixtureClient(t, f)
	if err := client.AddAliasAddresses(context.Background(), "unmanaged", []string{"192.0.2.2"}); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
	cfg.ManagedAliases = nil
	readonly, err := NewHTTPClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer readonly.Close()
	if err := readonly.AddAliasAddresses(context.Background(), nativeAlias, []string{"192.0.2.2"}); !errors.Is(err, ErrScope) {
		t.Fatal(err)
	}
}

func TestHTTPMutationAcknowledgementDoesNotProveReadback(t *testing.T) {
	for _, tc := range []struct {
		name     string
		activate bool
		status   string
	}{
		{"active unchanged", false, "done"}, {"rejected response", true, "not_an_address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNativeFixture(t)
			client, _ := fixtureClient(t, f)
			f.mu.Lock()
			f.activate = tc.activate
			f.status = tc.status
			f.mu.Unlock()
			err := client.AddAliasAddresses(context.Background(), nativeAlias, []string{"192.0.2.2", "192.0.2.3"})
			if !errors.Is(err, ErrPartialUpdate) || strings.Contains(err.Error(), "api-secret") {
				t.Fatalf("error=%v", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.mutations) != 1 {
				t.Fatalf("must halt at first failure: %#v", f.mutations)
			}
		})
	}
}

func TestHTTPRejectsUnverifiedEmptyActiveTable(t *testing.T) {
	for _, tc := range []struct {
		name         string
		countMissing bool
		listFails    bool
	}{
		{"count missing", true, false},
		{"pf list failed", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newNativeFixture(t)
			if !tc.listFails {
				f.active = nil
			}
			f.countMissing = tc.countMissing
			f.listFails = tc.listFails
			client, _ := fixtureClient(t, f)
			if _, err := client.ReadActiveAlias(context.Background(), nativeAlias); !errors.Is(err, ErrProtocol) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestHTTPDeletesExactPersistedSpelling(t *testing.T) {
	f := newNativeFixture(t)
	f.persisted = []string{"192.0.2.1/32"}
	client, _ := fixtureClient(t, f)
	if err := client.DeleteAliasAddresses(context.Background(), nativeAlias, []string{"192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.mutations) != 1 || !reflect.DeepEqual(f.mutations[0].Addresses, []string{"192.0.2.1/32"}) || len(f.persisted) != 0 || len(f.active) != 0 {
		t.Fatalf("exact persisted deletion failed: calls=%#v persisted=%v active=%v", f.mutations, f.persisted, f.active)
	}
}

func TestHTTPRejectsUnsafeReviewedRule(t *testing.T) {
	for _, tc := range []struct{ field, value string }{{"action", "block"}, {"protocol", "tcp"}, {"statetype", "none"}, {"interface", "wan"}, {"sched", "weekends"}, {"divert-to", "proxy"}} {
		t.Run(tc.field, func(t *testing.T) {
			f := newNativeFixture(t)
			f.rule[tc.field] = nativeOptions(tc.value)
			client, _ := fixtureClient(t, f) // Pins the unsafe shape to exercise validation independently from the hash.
			if err := client.AddAliasAddresses(context.Background(), nativeAlias, []string{"192.0.2.2"}); !errors.Is(err, ErrScope) {
				t.Fatalf("error=%v", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.mutations) != 0 {
				t.Fatalf("unsafe rule mutated alias: %#v", f.mutations)
			}
		})
	}
}

func TestHTTPRuleHashExcludesDisplayAndVolatileFields(t *testing.T) {
	f := newNativeFixture(t)
	client, _ := fixtureClient(t, f)
	first, err := client.ReadSteeringRule(context.Background(), nativeRuleUUID)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.rule["%source_net"] = "localized alias description"
	f.rule["last_updated"] = "new timestamp"
	f.rule["eval_match"] = "999"
	f.mu.Unlock()
	second, err := client.ReadSteeringRule(context.Background(), nativeRuleUUID)
	if err != nil {
		t.Fatal(err)
	}
	if first.SnapshotHash != second.SnapshotHash {
		t.Fatalf("presentation/telemetry changed hash: %s %s", first.SnapshotHash, second.SnapshotHash)
	}
}

func TestHTTPRequestTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewHTTPClient(HTTPConfig{BaseURL: server.URL, APIKey: "key", APISecret: "secret", Release: SupportedRelease, RootCAs: roots, Timeout: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.VerifyConnection(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatalf("timeout error=%v", err)
	}
}

func TestHTTPSecurityAndResponseBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		limit  int64
		want   error
	}{
		{"denied", 403, `{"secret":"api-secret"}`, 0, ErrAuthentication},
		{"malformed", 200, `not-json`, 0, ErrProtocol},
		{"oversize", 200, strings.Repeat("x", 100), 32, ErrProtocol},
		{"server error", 500, `api-secret`, 0, ErrProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			client, err := NewHTTPClient(HTTPConfig{BaseURL: server.URL, APIKey: "key", APISecret: "api-secret", Release: SupportedRelease, RootCAs: roots, MaxResponseBytes: tc.limit})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			err = client.VerifyConnection(context.Background())
			if !errors.Is(err, tc.want) || strings.Contains(err.Error(), "api-secret") {
				t.Fatalf("error=%v", err)
			}
		})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"product_id":"opnsense","product_version":"26.7"}`)
	}))
	defer server.Close()
	client, err := NewHTTPClient(HTTPConfig{BaseURL: server.URL, APIKey: "key", APISecret: "secret", Release: SupportedRelease})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.VerifyConnection(context.Background()); !errors.Is(err, ErrTransport) {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
	for _, origin := range []string{"http://router", "https://key:secret@router", "https://router/path", "https://router?token=secret"} {
		if _, err := NewHTTPClient(HTTPConfig{BaseURL: origin, APIKey: "key", APISecret: "secret", Release: SupportedRelease}); err == nil {
			t.Fatalf("accepted unsafe origin %s", origin)
		}
	}
}

func TestHTTPNeverFollowsRedirectAndHonorsContext(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	roots.AddCert(target.Certificate())
	client, err := NewHTTPClient(HTTPConfig{BaseURL: server.URL, APIKey: "key", APISecret: "secret", Release: SupportedRelease, RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.VerifyConnection(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("redirect error=%v", err)
	}
	if leaked.Load() != 0 {
		t.Fatal("credentials followed redirect")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.VerifyConnection(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}
}
