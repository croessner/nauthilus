package pluginruntime

import (
	"context"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const scriptMetricOperation = "operation"

type redisScriptTelemetry struct {
	counter  pluginapi.Counter
	duration pluginapi.Histogram
}

// newRedisScriptTelemetry obtains optional host diagnostics without changing storage availability.
func newRedisScriptTelemetry(metrics pluginapi.Metrics) *redisScriptTelemetry {
	if metrics == nil {
		return nil
	}

	counter, _ := metrics.Counter(pluginapi.MetricDefinition{Name: "script_operations_total", Help: "Native script operations by closed result.",
		Type: pluginapi.MetricTypeCounter, Labels: []string{scriptMetricOperation, httpLabelResult}})
	duration, _ := metrics.Histogram(pluginapi.MetricDefinition{Name: "script_duration_seconds", Help: "Native script operation latency.",
		Type: pluginapi.MetricTypeHistogram, Labels: []string{scriptMetricOperation, httpLabelResult}, Buckets: []float64{.001, .005, .01, .05, .1, .5, 1, 5}})

	return &redisScriptTelemetry{counter: counter, duration: duration}
}

// finish reports fixed operation/error classes without script names, keys, arguments or raw failures.
func (m *redisScriptTelemetry) finish(ctx context.Context, operation string, started time.Time, err error) {
	if m == nil || (operation != "upload" && operation != "run" && operation != "reload") {
		return
	}

	result := "success"
	if isRedisNoScript(err) {
		result = "noscript"
	} else if err != nil {
		result = "unavailable"
	}

	labels := []pluginapi.LabelValue{{Name: scriptMetricOperation, Value: operation}, {Name: httpLabelResult, Value: result}}

	defer func() { _ = recover() }()

	if m.counter != nil {
		m.counter.Add(ctx, 1, labels...)
	}

	if m.duration != nil {
		m.duration.Observe(ctx, time.Since(started).Seconds(), labels...)
	}
}
