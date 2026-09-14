package main

import (
	"context"
	"time"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/telemetry"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	journalOutcomeRetry = "retry"
)

type journalTelemetry struct {
	outcome         *telemetry.Counter
	lastApplied     pluginapi.Gauge
	replayRemaining pluginapi.Gauge
	processing      pluginapi.Histogram
	delivery        pluginapi.Histogram
}

// newJournalTelemetry exposes bounded acknowledgement and consumer freshness signals.
func newJournalTelemetry(host pluginapi.Metrics) (*journalTelemetry, error) {
	metrics := &journalTelemetry{}

	counter, err := telemetry.RegisterCounter(host, "journal_total", "Durable reputation journal outcomes.",
		telemetry.Dimension{Name: metricResult, Values: []string{"published", storageApplied, storageDuplicate, journalOutcomeRetry, "quarantined"}})
	if err != nil {
		return nil, err
	}

	metrics.outcome = counter

	for _, definition := range []struct {
		target *pluginapi.Gauge
		name   string
	}{
		{&metrics.lastApplied, "journal_last_applied_timestamp_seconds"},
		{&metrics.replayRemaining, "journal_replay_remaining_seconds"},
	} {
		gauge, err := host.Gauge(pluginapi.MetricDefinition{Name: definition.name, Help: "Reputation " + definition.name + "."})
		if err != nil {
			return nil, err
		}

		*definition.target = gauge
	}

	for _, definition := range []struct {
		target     *pluginapi.Histogram
		name, help string
	}{
		{&metrics.processing, "journal_processing_seconds", "Time spent applying a complete journal contribution."},
		{&metrics.delivery, "journal_delivery_seconds", "Time awaiting Kafka acknowledgement, including failed attempts."},
	} {
		histogram, err := host.Histogram(pluginapi.MetricDefinition{Name: definition.name, Help: definition.help, Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5, 10}})
		if err != nil {
			return nil, err
		}

		*definition.target = histogram
	}

	return metrics, nil
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
