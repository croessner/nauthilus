package main

import (
	"context"
	"errors"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/telemetry"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	metricChannel          = "channel"
	metricResult           = "result"
	learningExternal       = "external"
	learningAuthentication = "authentication"
	learningRejected       = "rejected"
	learningUnavailable    = "unavailable"
	learningSkipped        = "skipped"
	learningPartial        = "partial"
	learningQueued         = "queued"
)

// initializeLearningMetrics requires one host-owned bounded collector before accepting evidence.
func (p *Plugin) initializeLearningMetrics(host pluginapi.Host) error {
	counter, err := telemetry.RegisterCounter(host.Metrics(pluginName), "learning_total", "Reputation learning lifecycle events by bounded channel and outcome.",
		learningMetricDimensions()...)
	if err != nil {
		return err
	}

	queueMetrics, err := newLearningQueueTelemetry(host.Metrics(pluginName))
	if err != nil {
		return err
	}

	p.learningCounter = counter
	p.learningQueueMetrics = queueMetrics

	return nil
}

// learningMetricDimensions supplies the single closed learning vocabulary to registration and test sinks.
func learningMetricDimensions() []telemetry.Dimension {
	return []telemetry.Dimension{
		{Name: metricChannel, Values: []string{learningExternal, learningAuthentication}},
		{Name: metricResult, Values: []string{learningRejected, learningUnavailable, learningSkipped, learningPartial, learningQueued, learningBuffered, learningQueueFull, learningExpired, learningShutdown, learningPanic, learningRetried, storageQuotaExceeded, storageApplied, storageDuplicate}},
	}
}

// recordLearning emits no caller identifiers, raw subjects, event IDs or contribution details.
func (p *Plugin) recordLearning(ctx context.Context, channel, result string) {
	if p == nil {
		return
	}

	p.mu.RLock()
	counter := p.learningCounter
	p.mu.RUnlock()

	if counter != nil {
		counter.Add(ctx, channel, result)
	}
}

// learningIngestionResult distinguishes harmless retries from newly applied and partially acknowledged work.
func learningIngestionResult(result ingestionResult, err error) string {
	if err != nil {
		if result.Applied > 0 || result.Duplicates > 0 {
			return learningPartial
		}

		if errors.Is(err, errQuotaExceeded) {
			return storageQuotaExceeded
		}

		return learningUnavailable
	}

	if result.Queued {
		return learningQueued
	}

	if result.Applied == 0 && result.Duplicates > 0 {
		return "duplicate"
	}

	return "applied"
}
