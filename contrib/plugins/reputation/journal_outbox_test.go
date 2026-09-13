package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestJournalOutboxRetainsUnacknowledgedRecords reproduces lost learning during a broker outage.
func TestJournalOutboxRetainsUnacknowledgedRecords(t *testing.T) {
	dir := t.TempDir()
	box, err := openJournalOutbox(dir, 2, 1024)
	requireNoError(t, err)
	requireNoError(t, box.put(context.Background(), "event-one", []byte("frozen-plan")))
	box, err = openJournalOutbox(dir, 2, 1024)
	requireNoError(t, err)

	brokerUnavailable := errors.New("broker unavailable")

	err = box.drain(context.Background(), func(context.Context, string, []byte) error { return brokerUnavailable })
	if !errors.Is(err, brokerUnavailable) {
		t.Fatal("unacknowledged event was not retained")
	}

	delivered := 0

	requireNoError(t, box.drain(context.Background(), func(_ context.Context, key string, value []byte) error {
		if key != "event-one" || string(value) != "frozen-plan" {
			t.Fatal("recovered record changed")
		}

		delivered++

		return nil
	}))
	requireNoError(t, box.drain(context.Background(), func(context.Context, string, []byte) error {
		t.Fatal("acknowledged record was not removed")
		return nil
	}))

	if delivered != 1 {
		t.Fatal("recovered record was not delivered")
	}
}

// TestJournalOutboxBoundsAndConflicts keeps exact retries usable even at capacity.
func TestJournalOutboxBoundsAndConflicts(t *testing.T) {
	box, err := openJournalOutbox(t.TempDir(), 1, 1024)
	requireNoError(t, err)
	requireNoError(t, box.put(context.Background(), "same-event", []byte("original")))
	requireNoError(t, box.put(context.Background(), "same-event", []byte("original")))

	if !errors.Is(box.put(context.Background(), "same-event", []byte("changed")), errEventConflict) {
		t.Fatal("conflicting retry replaced durable evidence")
	}

	if !errors.Is(box.put(context.Background(), "new-event", []byte("new")), errQuotaExceeded) {
		t.Fatal("outbox exceeded its record budget")
	}
}

// TestJournalOutboxRejectsSymlinkRecords prevents recovery from following an unexpected file.
func TestJournalOutboxRejectsSymlinkRecords(t *testing.T) {
	dir := t.TempDir()
	box, err := openJournalOutbox(dir, 2, 1024)
	requireNoError(t, err)
	requireNoError(t, os.Symlink(filepath.Join(t.TempDir(), "absent"), filepath.Join(dir, "unexpected.record")))
	requireError(t, box.drain(context.Background(), func(context.Context, string, []byte) error {
		t.Fatal("unsafe record was delivered")
		return nil
	}))
}
