package main

import (
	"context"
	"time"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/telemetry"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	journalOutcomeRetry      = "retry"
	journalOutcomeOutboxFull = "outbox_full"
)

type journalTelemetry struct {
	outcome           *telemetry.Counter
	outboxRecords     pluginapi.Gauge
	outboxBytes       pluginapi.Gauge
	outboxRecordLimit pluginapi.Gauge
	outboxByteLimit   pluginapi.Gauge
	outboxAvailable   pluginapi.Gauge
	lastApplied       pluginapi.Gauge
	replayRemaining   pluginapi.Gauge
	processing        pluginapi.Histogram
}

// newJournalTelemetry exposes bounded durability, freshness and fallback capacity signals.
func newJournalTelemetry(host pluginapi.Metrics) (*journalTelemetry, error) {
	metrics := &journalTelemetry{}

	counter, err := telemetry.RegisterCounter(host, "journal_total", "Durable reputation journal outcomes.",
		telemetry.Dimension{Name: metricResult, Values: []string{"published", "outboxed", storageApplied, storageDuplicate, journalOutcomeRetry, "quarantined", journalOutcomeOutboxFull}})
	if err != nil {
		return nil, err
	}

	metrics.outcome = counter

	for _, definition := range []struct {
		target *pluginapi.Gauge
		name   string
	}{
		{&metrics.outboxRecords, "journal_outbox_records"},
		{&metrics.outboxBytes, "journal_outbox_bytes"},
		{&metrics.outboxRecordLimit, "journal_outbox_record_limit"},
		{&metrics.outboxByteLimit, "journal_outbox_byte_limit"},
		{&metrics.outboxAvailable, "journal_outbox_available"},
		{&metrics.lastApplied, "journal_last_applied_timestamp_seconds"},
		{&metrics.replayRemaining, "journal_replay_remaining_seconds"},
	} {
		gauge, err := host.Gauge(pluginapi.MetricDefinition{Name: definition.name, Help: "Reputation " + definition.name + "."})
		if err != nil {
			return nil, err
		}

		*definition.target = gauge
	}

	metrics.processing, err = host.Histogram(pluginapi.MetricDefinition{Name: "journal_processing_seconds",
		Help: "Time spent applying a complete journal contribution.", Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5, 10}})
	if err != nil {
		return nil, err
	}

	return metrics, nil
}

// recordOutbox observes shared persistent occupancy under the same lock as capacity admission.
func (m *journalTelemetry) recordOutbox(ctx context.Context, box *journalOutbox) {
	if m.outboxRecords == nil {
		return
	}

	m.outboxRecordLimit.Set(ctx, float64(box.maxRecords))
	m.outboxByteLimit.Set(ctx, float64(box.maxBytes))

	err := box.withLock(ctx, func() error {
		records, bytes, err := box.inventory()
		if err != nil {
			return err
		}

		m.outboxRecords.Set(ctx, float64(len(records)))
		m.outboxBytes.Set(ctx, float64(bytes))

		return nil
	})
	if err != nil {
		m.outboxAvailable.Set(ctx, 0)
		return
	}

	m.outboxAvailable.Set(ctx, 1)
}

// recordApplied separates score freshness and replay headroom from successful Kafka acceptance.
func (m *journalTelemetry) recordApplied(ctx context.Context, started time.Time, expiry float64, applied int, err error) {
	if m.processing == nil {
		return
	}

	now := time.Now()
	m.processing.Observe(ctx, now.Sub(started).Seconds())
	m.replayRemaining.Set(ctx, expiry-float64(now.UnixNano())/1e9)

	if err == nil && applied > 0 {
		m.lastApplied.Set(ctx, float64(now.Unix()))
	}
}
