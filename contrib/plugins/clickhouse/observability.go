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

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	flushWorkerLogins     = "logins"
	flushWorkerEvents     = "events"
	flushWorkerBruteForce = "bruteforce"
	logFieldStream        = "stream"
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
	resultDropped         = "dropped"
	resultRequeued        = "requeued"
	resultSkipped         = "skipped"
	resultStatusError     = "status_error"
	resultSuccess         = "success"
	operationEnqueue      = "enqueue"
	operationFlush        = "flush"
	logFieldAuthMethod    = "auth_method"
	logFieldBatchSize     = "batch_size"
	logFieldField         = "field"
	logFieldFlushWorker   = "flush_worker"
	logFieldResult        = "result"
	logFieldRows          = "rows"
	logFieldThreshold     = "threshold"
	logFieldTrigger       = "trigger"
	logFieldURLConfigured = "url_configured"
)

// queueResults lists every result label recorded on metricQueuedRows.
var queueResults = []string{resultQueued, resultSkipped, resultDedupSkipped, resultEncodeError, resultDropped}

// flushResults lists every result label recorded on metricFlushBatches.
var flushResults = []string{resultSuccess, resultHTTPError, resultStatusError, resultNoURL, resultRequeued}

// metricNames names the metric family of one row stream.
type metricNames struct {
	queuedRows    string
	flushBatches  string
	flushDuration string
}

var (
	// loginMetricNames keeps the established authentication-row metric names.
	loginMetricNames = metricNames{
		queuedRows: "clickhouse_queued_rows_total", flushBatches: "clickhouse_flush_batches_total",
		flushDuration: "clickhouse_flush_duration_seconds",
	}
	// eventMetricNames counts the step-event stream separately, so event loss stays visible on its own.
	eventMetricNames = metricNames{
		queuedRows: "clickhouse_event_queued_rows_total", flushBatches: "clickhouse_event_flush_batches_total",
		flushDuration: "clickhouse_event_flush_duration_seconds",
	}
)

// streamMetricNames derives the metric family of one additional event stream.
func streamMetricNames(stream string) metricNames {
	return metricNames{
		queuedRows:    "clickhouse_" + stream + "_queued_rows_total",
		flushBatches:  "clickhouse_" + stream + "_flush_batches_total",
		flushDuration: "clickhouse_" + stream + "_flush_duration_seconds",
	}
}

type pluginMetrics struct {
	queuedRows    pluginapi.Counter
	flushBatches  pluginapi.Counter
	flushDuration pluginapi.Histogram
}

// registerMetrics creates low-cardinality plugin-owned metrics.
func registerMetrics(metrics pluginapi.Metrics, names metricNames) (pluginMetrics, error) {
	if metrics == nil {
		return pluginMetrics{}, nil
	}

	queuedRows, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   names.queuedRows,
		Help:   "ClickHouse post-action row enqueue outcomes.",
		Labels: []string{metricLabelResult},
	})
	if err != nil {
		return pluginMetrics{}, err
	}

	flushBatches, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   names.flushBatches,
		Help:   "ClickHouse post-action batch flush outcomes.",
		Labels: []string{metricLabelResult},
	})
	if err != nil {
		return pluginMetrics{}, err
	}

	flushDuration, err := metrics.Histogram(pluginapi.MetricDefinition{
		Name:    names.flushDuration,
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

// initializeResultSeries creates every known counter series with value zero.
//
// Without this, a series appears at 1 with its first increment after a restart and
// increase() over that series misses the change. The flush duration histogram is not
// pre-created because an observation would count as a real sample.
func (m pluginMetrics) initializeResultSeries(ctx context.Context) {
	initializeCounterSeries(ctx, m.queuedRows, queueResults)
	initializeCounterSeries(ctx, m.flushBatches, flushResults)
}

// initializeCounterSeries adds zero to counter for each result label.
func initializeCounterSeries(ctx context.Context, counter pluginapi.Counter, results []string) {
	if counter == nil {
		return
	}

	for _, result := range results {
		counter.Add(ctx, 0, pluginapi.LabelValue{Name: metricLabelResult, Value: result})
	}
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

// SetStatus records no status when tracing is unavailable.
func (noopSpan) SetStatus(pluginapi.SpanStatus, string) {}

// End completes the no-op span.
func (noopSpan) End() {}
