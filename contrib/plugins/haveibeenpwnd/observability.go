// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	metricChecks        = "haveibeenpwnd_checks_total"
	metricHTTPDuration  = "haveibeenpwnd_http_duration_seconds"
	metricLabelResult   = "result"
	traceAttrComponent  = "plugin.component"
	traceAttrModule     = "plugin.module"
	traceAttrOperation  = "haveibeenpwnd.operation"
	traceAttrResult     = "haveibeenpwnd.result"
	operationCheck      = "check"
	operationHTTP       = "http_lookup"
	resultCacheNegative = "cache_negative"
	resultCachePositive = "cache_positive"
	resultGateSkipped   = "gate_skipped"
	resultHTTPError     = "http_error"
	resultHTTPNegative  = "http_negative"
	resultHTTPPositive  = "http_positive"
	resultRedisNegative = "redis_negative"
	resultRedisPositive = "redis_positive"
	resultSkipped       = "skipped"
	resultStatusError   = "status_error"
	logFieldResult      = "result"
	logFieldRuntimeGap  = "runtime_gap"
	logFieldRedisPool   = "redis_pool"
)

type pluginMetrics struct {
	checks      pluginapi.Counter
	httpLatency pluginapi.Histogram
}

// registerMetrics creates low-cardinality plugin-owned metrics.
func registerMetrics(metrics pluginapi.Metrics) (pluginMetrics, error) {
	if metrics == nil {
		return pluginMetrics{}, nil
	}

	checks, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   metricChecks,
		Help:   "Have I Been Pwned post-action check outcomes.",
		Labels: []string{metricLabelResult},
	})
	if err != nil {
		return pluginMetrics{}, err
	}

	httpLatency, err := metrics.Histogram(pluginapi.MetricDefinition{
		Name:    metricHTTPDuration,
		Help:    "Have I Been Pwned range API lookup duration.",
		Labels:  []string{metricLabelResult},
		Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	})
	if err != nil {
		return pluginMetrics{}, err
	}

	return pluginMetrics{
		checks:      checks,
		httpLatency: httpLatency,
	}, nil
}

// recordCheckResult increments the check-result metric when available.
func (m pluginMetrics) recordCheckResult(ctx context.Context, result string) {
	if m.checks == nil {
		return
	}

	m.checks.Add(ctx, 1, pluginapi.LabelValue{Name: metricLabelResult, Value: result})
}

// recordHTTPResult observes one HTTP lookup duration when available.
func (m pluginMetrics) recordHTTPResult(ctx context.Context, result string, duration time.Duration) {
	if m.httpLatency == nil {
		return
	}

	m.httpLatency.Observe(ctx, duration.Seconds(), pluginapi.LabelValue{Name: metricLabelResult, Value: result})
}

// startHIBPSpan starts a bounded HIBP child span.
func startHIBPSpan(ctx context.Context, tracer pluginapi.Tracer, operation string) (context.Context, pluginapi.Span) {
	if ctx == nil {
		ctx = context.Background()
	}

	if tracer == nil {
		return ctx, noopSpan{}
	}

	return tracer.Start(
		ctx,
		"haveibeenpwnd.post_action."+operation,
		pluginapi.TraceAttribute{Key: traceAttrModule, Value: pluginName},
		pluginapi.TraceAttribute{Key: traceAttrComponent, Value: componentPostAction},
		pluginapi.TraceAttribute{Key: traceAttrOperation, Value: operation},
	)
}

type noopSpan struct{}

// AddEvent discards span events when no tracer is configured.
func (noopSpan) AddEvent(string, ...pluginapi.TraceAttribute) {}

// SetAttributes discards span attributes when no tracer is configured.
func (noopSpan) SetAttributes(...pluginapi.TraceAttribute) {}

// RecordError discards span errors when no tracer is configured.
func (noopSpan) RecordError(error) {}

// End completes the no-op span.
func (noopSpan) End() {}
