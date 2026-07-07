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
	metricQueuedRows      = "clickhouse_queued_rows_total"
	metricFlushBatches    = "clickhouse_flush_batches_total"
	metricFlushDuration   = "clickhouse_flush_duration_seconds"
	metricLabelResult     = "result"
	traceAttrBatchSize    = "clickhouse.batch_size"
	traceAttrComponent    = "plugin.component"
	traceAttrModule       = "plugin.module"
	traceAttrOperation    = "clickhouse.operation"
	traceAttrResult       = "clickhouse.result"
	resultDedupSkipped    = "dedup_skipped"
	resultEncodeError     = "encode_error"
	resultHTTPError       = "http_error"
	resultNoURL           = "no_url"
	resultQueued          = "queued"
	resultRequeued        = "requeued"
	resultSkipped         = "skipped"
	resultStatusError     = "status_error"
	resultSuccess         = "success"
	operationEnqueue      = "enqueue"
	operationFlush        = "flush"
	logFieldAuthMethod    = "auth_method"
	logFieldBatchSize     = "batch_size"
	logFieldResult        = "result"
	logFieldRows          = "rows"
	logFieldThreshold     = "threshold"
	logFieldURLConfigured = "url_configured"
)

type pluginMetrics struct {
	queuedRows    pluginapi.Counter
	flushBatches  pluginapi.Counter
	flushDuration pluginapi.Histogram
}

// registerMetrics creates low-cardinality plugin-owned metrics.
func registerMetrics(metrics pluginapi.Metrics) (pluginMetrics, error) {
	if metrics == nil {
		return pluginMetrics{}, nil
	}

	queuedRows, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   metricQueuedRows,
		Help:   "ClickHouse post-action row enqueue outcomes.",
		Labels: []string{metricLabelResult},
	})
	if err != nil {
		return pluginMetrics{}, err
	}

	flushBatches, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   metricFlushBatches,
		Help:   "ClickHouse post-action batch flush outcomes.",
		Labels: []string{metricLabelResult},
	})
	if err != nil {
		return pluginMetrics{}, err
	}

	flushDuration, err := metrics.Histogram(pluginapi.MetricDefinition{
		Name:    metricFlushDuration,
		Help:    "ClickHouse post-action batch flush duration.",
		Labels:  []string{metricLabelResult},
		Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	})
	if err != nil {
		return pluginMetrics{}, err
	}

	return pluginMetrics{
		queuedRows:    queuedRows,
		flushBatches:  flushBatches,
		flushDuration: flushDuration,
	}, nil
}

// recordQueueResult increments the queue-result metric when available.
func (m pluginMetrics) recordQueueResult(ctx context.Context, result string) {
	if m.queuedRows == nil {
		return
	}

	m.queuedRows.Add(ctx, 1, pluginapi.LabelValue{Name: metricLabelResult, Value: result})
}

// recordFlushResult increments the flush-result metric and observes duration.
func (m pluginMetrics) recordFlushResult(ctx context.Context, result string, duration time.Duration) {
	if m.flushBatches != nil {
		m.flushBatches.Add(ctx, 1, pluginapi.LabelValue{Name: metricLabelResult, Value: result})
	}

	if m.flushDuration != nil {
		m.flushDuration.Observe(ctx, duration.Seconds(), pluginapi.LabelValue{Name: metricLabelResult, Value: result})
	}
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
