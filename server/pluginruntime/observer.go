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

package pluginruntime

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/stats"
)

const (
	pluginCallResultOK       = "ok"
	pluginCallResultError    = "error"
	pluginCallResultPanic    = "panic"
	pluginCallResultCanceled = "canceled"
	pluginCallResultTimeout  = "timeout"
	pluginLogFieldErrorClass = "plugin_error_class"
)

// OperationalObserver records bounded metrics and secret-safe structured plugin call logs.
type OperationalObserver struct {
	logger    *slog.Logger
	metrics   stats.Metrics
	debugGate pluginDebugGate
}

// OperationalObserverOption customizes an operational observer.
type OperationalObserverOption func(*OperationalObserver)

// NewOperationalObserver returns the default operational plugin call observer.
func NewOperationalObserver(logger *slog.Logger, options ...OperationalObserverOption) *OperationalObserver {
	observer := &OperationalObserver{
		logger:  logger,
		metrics: stats.GetMetrics(),
	}
	for _, option := range options {
		option(observer)
	}

	return observer
}

// WithOperationalObserverMetrics configures metrics recording for tests.
func WithOperationalObserverMetrics(metrics stats.Metrics) OperationalObserverOption {
	return func(observer *OperationalObserver) {
		observer.metrics = metrics
	}
}

// WithOperationalObserverDebugConfig configures plugin debug selector gating for success logs.
func WithOperationalObserverDebugConfig(cfg config.File, registry *pluginregistry.Registry) OperationalObserverOption {
	return func(observer *OperationalObserver) {
		observer.debugGate = pluginDebugGate{cfg: cfg, registry: registry}
	}
}

// ObservePluginCall records one host-invoked plugin method result.
func (o *OperationalObserver) ObservePluginCall(record CallRecord) {
	if o == nil {
		return
	}

	result := pluginCallResult(record)
	o.recordMetrics(record, result)
	o.log(record, result)
}

// recordMetrics increments bounded plugin call metrics.
func (o *OperationalObserver) recordMetrics(record CallRecord, result string) {
	if o.metrics == nil {
		return
	}

	labels := []string{
		record.ModuleName,
		record.ComponentName,
		record.ExtensionPoint,
		record.Method,
		result,
	}
	o.metrics.GetPluginCallsTotal().WithLabelValues(labels...).Inc()
	o.metrics.GetPluginCallDurationSeconds().WithLabelValues(labels...).Observe(record.Duration.Seconds())
}

// log writes one bounded plugin call record without serializing raw plugin errors.
func (o *OperationalObserver) log(record CallRecord, result string) {
	if o.logger == nil {
		return
	}

	keyvals := []any{
		definitions.LogKeyMsg, pluginCallLogMessage(record, result),
		"plugin_module", record.ModuleName,
		"plugin_component", record.ComponentName,
		"plugin_extension_point", record.ExtensionPoint,
		"plugin_method", record.Method,
		"plugin_result", result,
		"duration_ms", durationMilliseconds(record.Duration),
	}
	if record.Err != nil {
		keyvals = append(keyvals, pluginLogFieldErrorClass, result)
	}

	if record.Err != nil || record.Panicked {
		_ = level.Error(o.logger).Log(keyvals...)

		return
	}

	debugModule, enabled := o.debugGate.enabled(record.ModuleName, record.ComponentName)
	if !enabled {
		return
	}

	keyvals = append(keyvals, "debug_module", debugModule)
	_ = level.Debug(o.logger).Log(keyvals...)
}

// pluginCallResult maps errors into a bounded result label.
func pluginCallResult(record CallRecord) string {
	if record.Panicked {
		return pluginCallResultPanic
	}

	switch {
	case record.Err == nil:
		return pluginCallResultOK
	case errors.Is(record.Err, context.Canceled):
		return pluginCallResultCanceled
	case errors.Is(record.Err, context.DeadlineExceeded):
		return pluginCallResultTimeout
	default:
		return pluginCallResultError
	}
}

// pluginCallLogMessage returns a stable operational message for a call result.
func pluginCallLogMessage(record CallRecord, result string) string {
	if record.Panicked {
		return "Native plugin call panicked"
	}

	if result != pluginCallResultOK {
		return "Native plugin call failed"
	}

	return "Native plugin call completed"
}

// durationMilliseconds returns a compact floating-point duration for structured logs.
func durationMilliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
