package main

import (
	"context"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/telemetry"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	metricProjectionInvalid  = "projection_invalid"
	metricReputationInvalid  = "reputation_invalid"
	metricCorrelationInvalid = "correlation_invalid"
	metricGeoIPInvalid       = "geoip_invalid"
	metricCompositionInvalid = "composition_invalid"
	metricCompleted          = "completed"
)

// registerCompositionMetric exposes closed enrichment outcomes without signer, hop or peer labels.
func registerCompositionMetric(metrics pluginapi.Metrics) (*telemetry.Counter, error) {
	return telemetry.RegisterCounter(metrics, "composition_total", "DKIM2 intelligence enrichment outcomes.",
		telemetry.Dimension{Name: "result", Values: []string{valueUnavailable, metricProjectionInvalid, metricReputationInvalid,
			metricCorrelationInvalid, metricGeoIPInvalid, metricCompositionInvalid, metricCompleted}})
}

// recordComposition preserves decision authority even when a telemetry exporter fails.
func (p *Plugin) recordComposition(ctx context.Context, result string) {
	if p == nil {
		return
	}

	p.mu.RLock()
	counter := p.compositionCounter
	p.mu.RUnlock()
	counter.Add(ctx, result)
}
