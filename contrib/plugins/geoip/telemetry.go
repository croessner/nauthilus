package main

import (
	"context"
	"errors"

	"github.com/croessner/nauthilus/v4/contrib/plugins/internal/telemetry"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

var errTelemetryLookup = errors.New("geoip lookup unavailable")

// redactedLookupError preserves cancellation while withholding raw database details from parent spans.
func redactedLookupError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}

	return errTelemetryLookup
}

// registerFreshnessMetric exposes only the closed source-age state, never the queried address or ASN.
func registerFreshnessMetric(metrics pluginapi.Metrics) (*telemetry.Counter, error) {
	return telemetry.RegisterCounter(metrics, "freshness_total", "GeoIP lookup freshness and availability.",
		telemetry.Dimension{Name: metricLabelState, Values: []string{lookupStateFresh, lookupStateStale, lookupStateMissing, lookupStateUnavailable}})
}

// recordFreshness isolates exporter failures from the immutable geographic result.
func (p *Plugin) recordFreshness(ctx context.Context, state string) {
	p.mu.RLock()
	counter := p.freshnessCounter
	p.mu.RUnlock()
	counter.Add(ctx, state)
}
