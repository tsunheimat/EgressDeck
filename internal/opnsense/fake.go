package opnsense

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// FakeClient is a deterministic in-memory client for adapter contract tests.
// Persisted and active aliases are intentionally independent so tests can
// model delayed reloads, drift, partial calls, and administrator edits.
type FakeClient struct {
	mu                sync.Mutex
	persisted         map[string]AliasRecord
	active            map[string]AliasRecord
	addCalls          [][]string
	deleteCalls       [][]string
	calls             []Call
	ReadPersistedErr  error
	ReadActiveErr     error
	AddErr            error
	DeleteErr         error
	AddBeforeError    bool
	DeleteBeforeError bool
	// AutoActivate models the normal OPNsense behavior where a successful
	// mutation is loaded into the active table. Set false to test delayed
	// reloads or persisted/active drift.
	AutoActivate bool
}

// Call records one mutation request. It is intentionally limited to alias
// name and canonical address arguments so tests never need to parse HTTP.
type Call struct {
	Operation string
	Alias     string
	Addresses []string
}

// Calls returns a copy of all mutation calls in order.
func (f *FakeClient) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Call, len(f.calls))
	for i, call := range f.calls {
		out[i] = Call{Operation: call.Operation, Alias: call.Alias, Addresses: append([]string(nil), call.Addresses...)}
	}
	return out
}

func NewFakeClient(records ...AliasRecord) *FakeClient {
	f := &FakeClient{persisted: map[string]AliasRecord{}, active: map[string]AliasRecord{}, AutoActivate: true}
	for _, record := range records {
		if normalized, err := canonicalRecord(record); err == nil {
			f.persisted[normalized.Name] = cloneAlias(normalized)
			f.active[normalized.Name] = cloneAlias(normalized)
		}
	}
	return f
}

// SeedAlias replaces both persisted and active state for an alias. It is
// useful when a test wants to build state incrementally rather than passing a
// record to NewFakeClient.
func (f *FakeClient) SeedAlias(record AliasRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	normalized, err := canonicalRecord(record)
	if err != nil {
		return err
	}
	f.persisted[normalized.Name] = cloneAlias(normalized)
	f.active[normalized.Name] = cloneAlias(normalized)
	return nil
}

// SetPersisted replaces only configuration readback, leaving the active table
// untouched so a test can model a pending reload.
func (f *FakeClient) SetPersisted(record AliasRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	normalized, err := canonicalRecord(record)
	if err != nil {
		return err
	}
	f.persisted[normalized.Name] = cloneAlias(normalized)
	return nil
}

// PersistedAlias and ActiveAlias expose safe copies for assertions.
func (f *FakeClient) PersistedAlias(name string) (AliasRecord, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.persisted[name]
	return cloneAlias(record), ok
}

func (f *FakeClient) ActiveAlias(name string) (AliasRecord, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.active[name]
	return cloneAlias(record), ok
}

func (f *FakeClient) ReadPersistedAlias(_ context.Context, name string) (AliasRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ReadPersistedErr != nil {
		return AliasRecord{}, f.ReadPersistedErr
	}
	record, ok := f.persisted[name]
	if !ok {
		return AliasRecord{}, fmt.Errorf("%w: alias %q", ErrNotFound, name)
	}
	return cloneAlias(record), nil
}

func (f *FakeClient) ReadActiveAlias(_ context.Context, name string) (AliasRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ReadActiveErr != nil {
		return AliasRecord{}, f.ReadActiveErr
	}
	record, ok := f.active[name]
	if !ok {
		return AliasRecord{}, fmt.Errorf("%w: alias %q", ErrNotFound, name)
	}
	return cloneAlias(record), nil
}

func (f *FakeClient) AddAliasAddresses(_ context.Context, name string, addresses []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCalls = append(f.addCalls, append([]string(nil), addresses...))
	f.calls = append(f.calls, Call{Operation: "add", Alias: name, Addresses: append([]string(nil), addresses...)})
	if f.AddErr != nil && !f.AddBeforeError {
		return f.AddErr
	}
	record, ok := f.persisted[name]
	if !ok {
		return fmt.Errorf("%w: alias %q", ErrNotFound, name)
	}
	merged := append(append([]string(nil), record.Addresses...), addresses...)
	canonical, err := CanonicalAddresses(merged)
	if err != nil {
		return err
	}
	record.Addresses = canonical
	record.Revision++
	f.persisted[name] = cloneAlias(record)
	if f.AutoActivate {
		f.active[name] = cloneAlias(record)
	}
	if f.AddErr != nil {
		return f.AddErr
	}
	return nil
}

func (f *FakeClient) DeleteAliasAddresses(_ context.Context, name string, addresses []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls = append(f.deleteCalls, append([]string(nil), addresses...))
	f.calls = append(f.calls, Call{Operation: "delete", Alias: name, Addresses: append([]string(nil), addresses...)})
	if f.DeleteErr != nil && !f.DeleteBeforeError {
		return f.DeleteErr
	}
	record, ok := f.persisted[name]
	if !ok {
		return fmt.Errorf("%w: alias %q", ErrNotFound, name)
	}
	remove := map[string]struct{}{}
	canonical, err := CanonicalAddresses(addresses)
	if err != nil {
		return err
	}
	for _, address := range canonical {
		remove[address] = struct{}{}
	}
	remaining := make([]string, 0, len(record.Addresses))
	for _, address := range record.Addresses {
		if _, found := remove[address]; !found {
			remaining = append(remaining, address)
		}
	}
	record.Addresses = remaining
	record.Revision++
	f.persisted[name] = cloneAlias(record)
	if f.AutoActivate {
		f.active[name] = cloneAlias(record)
	}
	if f.DeleteErr != nil {
		return f.DeleteErr
	}
	return nil
}

// SetActive replaces the active table for an alias, which lets tests model a
// reload or an administrator changing a live alias without persistence.
func (f *FakeClient) SetActive(name string, record AliasRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	normalized, err := canonicalRecord(record)
	if err != nil {
		return err
	}
	if normalized.Name != name {
		return fmt.Errorf("alias name mismatch")
	}
	f.active[name] = cloneAlias(normalized)
	return nil
}

// Reload copies persisted configuration to the active table.
func (f *FakeClient) Reload(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record, ok := f.persisted[name]
	if !ok {
		return fmt.Errorf("%w: alias %q", ErrNotFound, name)
	}
	f.active[name] = cloneAlias(record)
	return nil
}

func (f *FakeClient) PersistedCalls() (adds, deletes [][]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneCalls(f.addCalls), cloneCalls(f.deleteCalls)
}

func cloneAlias(in AliasRecord) AliasRecord {
	in.Addresses = append([]string(nil), in.Addresses...)
	return in
}

func cloneCalls(in [][]string) [][]string {
	out := make([][]string, len(in))
	for i := range in {
		out[i] = append([]string(nil), in[i]...)
	}
	return out
}

// Ensure a fake record's addresses remain deterministic in tests that build it
// directly and inspect it through the fake.
func sortedAddresses(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
