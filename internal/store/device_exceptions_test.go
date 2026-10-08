package store

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/egressdeck/homelab-proxy-controller/internal/domain"
)

func assertDeviceExceptions(t *testing.T, got, want []json.RawMessage) {
	t.Helper()
	decode := func(value []json.RawMessage) any {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	if !reflect.DeepEqual(decode(got), decode(want)) {
		t.Fatalf("device exceptions = %s, want %s", got, want)
	}
}

func TestMemoryDeviceExceptionOwnership(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	original := []json.RawMessage{json.RawMessage(`{"id":"exception-1","action":{"type":"block"}}`)}
	input := domain.Device{Name: "client", Exceptions: []json.RawMessage{append(json.RawMessage(nil), original[0]...)}}
	created, err := s.CreateDevice(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	input.Exceptions[0][0] = '['
	created.Exceptions[0][0] = '['
	read, err := s.GetDevice(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertDeviceExceptions(t, read.Exceptions, original)
	read.Exceptions[0][0] = '['
	listed, err := s.ListDevices(ctx)
	if err != nil || len(listed) != 1 {
		t.Fatalf("list devices: %+v, %v", listed, err)
	}
	assertDeviceExceptions(t, listed[0].Exceptions, original)
	listed[0].Exceptions[0][0] = '['
	read, err = s.GetDevice(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertDeviceExceptions(t, read.Exceptions, original)
	replacement := []json.RawMessage{json.RawMessage(`{"id":"exception-2","action":{"type":"direct"}}`)}
	read.Exceptions = []json.RawMessage{append(json.RawMessage(nil), replacement[0]...)}
	updated, err := s.UpdateDevice(ctx, read, read.Revision)
	if err != nil {
		t.Fatal(err)
	}
	read.Exceptions[0][0] = '['
	updated.Exceptions[0][0] = '['
	persisted, err := s.GetDevice(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertDeviceExceptions(t, persisted.Exceptions, replacement)
}
