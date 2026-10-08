package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeAddressCanonicalizesFamilies(t *testing.T) {
	address, family, err := NormalizeAddress(" 192.0.2.10 ")
	if err != nil || address != "192.0.2.10" || family != IPv4 {
		t.Fatalf("got %q/%q/%v", address, family, err)
	}
	address, family, err = NormalizeAddress("2001:0db8::1")
	if err != nil || address != "2001:db8::1" || family != IPv6 {
		t.Fatalf("got %q/%q/%v", address, family, err)
	}
}

func TestDeviceValidateRejectsDuplicateAndInvalidAddresses(t *testing.T) {
	d := Device{Name: "builder", Addresses: []DeviceAddress{{Address: "192.0.2.1"}, {Address: "192.0.2.1"}, {Address: "not-an-ip"}}}
	if err := d.Validate(); err == nil {
		t.Fatal("expected address validation error")
	}
}

func TestDeviceDefaultsEnrollmentState(t *testing.T) {
	d := Device{Name: "builder"}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if d.EnrollmentState != EnrollmentUnenrolled {
		t.Fatalf("state=%q", d.EnrollmentState)
	}
}

func TestDeviceExceptionsRequireJSONObjects(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", "true", "1", `"block"`, `{"action":`, `{} {}`} {
		t.Run(raw, func(t *testing.T) {
			d := Device{Name: "client", Exceptions: []json.RawMessage{json.RawMessage(raw)}}
			if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "exceptions[0]") {
				t.Fatalf("accepted invalid exception %q: %v", raw, err)
			}
		})
	}
	// The domain validates storage shape; the policy layer owns rule semantics.
	d := Device{Name: "client", Exceptions: []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{"action":{"type":"block"},"match":{"domain_exact":["example.test"]}}`)}}
	if err := d.Validate(); err != nil {
		t.Fatalf("rejected JSON object exceptions: %v", err)
	}
}
