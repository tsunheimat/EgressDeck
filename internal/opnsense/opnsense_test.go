package opnsense

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func testAlias(addresses ...string) AliasRecord {
	return AliasRecord{Name: "egress-managed", UUID: "alias-1", Type: HostAlias, OwnerTag: "egressdeck", Addresses: addresses}
}

func testRequest() AttachRequest {
	return AttachRequest{ID: "binding-1", GatewayID: "gateway-1", Alias: "egress-managed", AliasUUID: "alias-1", AliasType: HostAlias, OwnerTag: "egressdeck", Family: IPv4Family, InterfaceScope: "lan"}
}

func TestCanonicalAddressAndDelta(t *testing.T) {
	tests := []struct {
		input  string
		want   string
		family AddressFamily
	}{
		{" 192.0.2.1 ", "192.0.2.1", IPv4Family},
		{"192.0.2.0/24", "192.0.2.0/24", IPv4Family},
		{"2001:db8::1", "2001:db8::1", IPv6Family},
		{"2001:0DB8:0:0::/32", "2001:db8::/32", IPv6Family},
	}
	for _, tc := range tests {
		got, family, err := CanonicalAddress(tc.input)
		if err != nil || got != tc.want || family != tc.family {
			t.Fatalf("CanonicalAddress(%q) = %q, %q, %v; want %q, %q", tc.input, got, family, err, tc.want, tc.family)
		}
	}
	got, err := CanonicalAddresses([]string{"192.0.2.2", "192.0.2.1", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"192.0.2.1", "192.0.2.2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CanonicalAddresses = %#v; want %#v", got, want)
	}
	delta, err := ComputeAddressDelta([]string{"192.0.2.2", "192.0.2.1"}, []string{"192.0.2.3", "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(delta, AddressDelta{Add: []string{"192.0.2.3"}, Remove: []string{"192.0.2.2"}}) {
		t.Fatalf("delta = %#v", delta)
	}
	if _, _, err := CanonicalAddress("not-an-address"); err == nil {
		t.Fatal("invalid address accepted")
	}
}

func TestAttachReadsPersistedAndActiveAndReportsDrift(t *testing.T) {
	fake := NewFakeClient(testAlias("192.0.2.2", "192.0.2.1"))
	// Keep active state old to prove attach does not collapse the two sources.
	fake.AutoActivate = false
	if err := fake.SetActive("egress-managed", testAlias("192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewAdapter(fake)
	if err != nil {
		t.Fatal(err)
	}
	binding, readback, err := adapter.Attach(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(binding.ManagedAddresses, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("managed addresses = %#v", binding.ManagedAddresses)
	}
	if !readback.Drift.Drifted || len(readback.Drift.Items) == 0 {
		t.Fatalf("expected active drift, got %#v", readback.Drift)
	}
	if readback.Persisted.Addresses[0] != "192.0.2.1" || readback.Active.Addresses[0] != "192.0.2.1" {
		t.Fatalf("readback was not canonical: %#v", readback)
	}
}

func TestSyncIsIdempotentAndUpdatesBothTables(t *testing.T) {
	fake := NewFakeClient(testAlias("192.0.2.1", "192.0.2.2"))
	adapter, _ := NewAdapter(fake)
	binding, before, err := adapter.Attach(context.Background(), testRequest())
	if err != nil || before.Drift.Drifted {
		t.Fatalf("attach = %#v, %#v, %v", binding, before, err)
	}
	result, err := adapter.Sync(context.Background(), binding, []string{"192.0.2.2", "192.0.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.After.Drift.Drifted {
		t.Fatalf("sync result = %#v", result)
	}
	if !reflect.DeepEqual(result.Delta, AddressDelta{Add: []string{"192.0.2.3"}, Remove: []string{"192.0.2.1"}}) {
		t.Fatalf("delta = %#v", result.Delta)
	}
	adds, removes := fake.PersistedCalls()
	if !reflect.DeepEqual(adds, [][]string{{"192.0.2.3"}}) || !reflect.DeepEqual(removes, [][]string{{"192.0.2.1"}}) {
		t.Fatalf("calls = %#v, %#v", adds, removes)
	}
	// A second sync with equivalent input does not flush or repeat mutations.
	if _, err := adapter.Sync(context.Background(), result.Binding, []string{"192.0.2.3", "192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	adds, removes = fake.PersistedCalls()
	if len(adds) != 1 || len(removes) != 1 {
		t.Fatalf("idempotence failed: %#v, %#v", adds, removes)
	}
}

func TestSyncRefusesUnexpectedDriftWithoutMutating(t *testing.T) {
	fake := NewFakeClient(testAlias("192.0.2.1"))
	adapter, _ := NewAdapter(fake)
	binding, _, err := adapter.Attach(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.SetActive("egress-managed", testAlias("198.51.100.9")); err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Sync(context.Background(), binding, []string{"192.0.2.2"})
	if !errors.Is(err, ErrDrift) {
		t.Fatalf("error = %v; want ErrDrift", err)
	}
	if result.Before.Drift.Drifted {
		adds, removes := fake.PersistedCalls()
		if len(adds) != 0 || len(removes) != 0 {
			t.Fatalf("drift caused mutation: %#v %#v", adds, removes)
		}
	}
}

func TestSyncReportsPartialDeleteAndAllowsReadbackRecovery(t *testing.T) {
	fake := NewFakeClient(testAlias("192.0.2.1"))
	fake.DeleteErr = errors.New("temporary API failure")
	fake.DeleteBeforeError = true
	adapter, _ := NewAdapter(fake)
	binding, _, err := adapter.Attach(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Sync(context.Background(), binding, []string{"192.0.2.2"})
	if !errors.Is(err, ErrPartialUpdate) {
		t.Fatalf("error = %v; want partial update", err)
	}
	if result.After.ReadAt.IsZero() {
		t.Fatal("partial update did not include readback")
	}
	if !result.After.Drift.Drifted {
		t.Fatal("partial update should expose desired-state drift")
	}
}

func TestSyncTreatsLostAddAcknowledgementAsPartial(t *testing.T) {
	fake := NewFakeClient(testAlias("192.0.2.1"))
	fake.AddErr = errors.New("request timeout")
	fake.AddBeforeError = true
	adapter, _ := NewAdapter(fake)
	binding, _, err := adapter.Attach(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Sync(context.Background(), binding, []string{"192.0.2.1", "192.0.2.2"})
	if !errors.Is(err, ErrPartialUpdate) {
		t.Fatalf("error = %v; want partial update", err)
	}
	if !reflect.DeepEqual(result.After.Persisted.Addresses, []string{"192.0.2.1", "192.0.2.2"}) {
		t.Fatalf("lost-ack readback = %#v", result.After)
	}
}

func TestAttachRejectsShapeChange(t *testing.T) {
	fake := NewFakeClient(testAlias("192.0.2.1"))
	adapter, _ := NewAdapter(fake)
	request := testRequest()
	request.AliasUUID = "different"
	if _, _, err := adapter.Attach(context.Background(), request); !errors.Is(err, ErrShapeChanged) {
		t.Fatalf("error = %v; want ErrShapeChanged", err)
	}
}
