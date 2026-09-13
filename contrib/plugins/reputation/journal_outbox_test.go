package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// TestJournalOutboxAdmissionDoesNotWaitForBroker prevents recovery from monopolizing the shared capacity lock.
func TestJournalOutboxAdmissionDoesNotWaitForBroker(t *testing.T) {
	box, err := openJournalOutbox(t.TempDir(), 4, 4096)
	requireNoError(t, err)
	requireNoError(t, box.put(t.Context(), "pending", []byte("first")))

	started, release := make(chan struct{}), make(chan struct{})

	done := make(chan error, 1)
	go func() {
		done <- box.drain(t.Context(), func(context.Context, string, []byte) error {
			close(started)
			<-release

			return errStateUnavailable
		})
	}()

	t.Cleanup(func() { close(release); <-done })
	<-started

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	requireNoError(t, box.put(ctx, "new-event", []byte("second")))
}

// TestJournalOutboxAcknowledgementPreservesChangedRecord rejects stale receipts for replaced filesystem entries.
func TestJournalOutboxAcknowledgementPreservesChangedRecord(t *testing.T) {
	box, err := openJournalOutbox(t.TempDir(), 4, 4096)
	requireNoError(t, err)
	requireNoError(t, box.put(t.Context(), "event", []byte("original")))
	requireNoError(t, os.Remove(filepath.Join(box.directory, recordName("event"))))
	requireNoError(t, box.put(t.Context(), "event", []byte("replacement")))

	if !errors.Is(box.acknowledge(t.Context(), outboxRecord{Key: "event", Value: []byte("original")}), errEventConflict) {
		t.Fatal("a stale delivery receipt removed a different immutable record")
	}

	current, err := box.readRecord(recordName("event"))
	requireNoError(t, err)

	if string(current.Value) != "replacement" {
		t.Fatal("the replacement record was not preserved")
	}
}
