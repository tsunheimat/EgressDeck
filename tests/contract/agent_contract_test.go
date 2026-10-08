package contract_test

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/egressdeck/homelab-proxy-controller/internal/gateway"
)

func TestAgentJournalFixtureIsOrderedAndReplayable(t *testing.T) {
	scanner := bufio.NewScanner(strings.NewReader(string(fixture(t, "agent", "journal.jsonl"))))
	var entries []gateway.JournalEntry
	for scanner.Scan() {
		var entry gateway.JournalEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("decode journal entry: %v", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("journal entries = %d, want 3", len(entries))
	}
	for i, entry := range entries {
		if entry.ID == "" || entry.Operation == "" || entry.Target == "" || entry.Status == "" {
			t.Fatalf("entry %d is missing required identity/status: %+v", i, entry)
		}
		if entry.StartedAt.IsZero() || entry.FinishedAt.IsZero() || !entry.FinishedAt.After(entry.StartedAt) {
			t.Fatalf("entry %d has invalid lifecycle timestamps: %+v", i, entry)
		}
		if i > 0 && entry.Generation < entries[i-1].Generation {
			t.Fatalf("generation regressed at entry %d: %d then %d", i, entries[i-1].Generation, entry.Generation)
		}
	}
	if entries[0].Operation != "provider.stage" || entries[1].Operation != "provider.publish_hot" || entries[2].Operation != "selection.persist_restart" {
		t.Fatalf("agent lifecycle order changed: %+v", entries)
	}
	if entries[1].Generation != 3 || entries[2].Generation != 3 {
		t.Fatalf("publication/readback generation changed: %+v", entries)
	}
	// Guard against silently accepting local timestamps without a stable UTC
	// representation in fixture data.
	if entries[0].StartedAt.Location() != time.UTC {
		t.Fatalf("fixture timestamp is not UTC: %v", entries[0].StartedAt)
	}
}
