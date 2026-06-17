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
	"log/slog"
	"sync"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/pluginregistry"
	"github.com/croessner/nauthilus/server/rediscli"
)

var _ pluginapi.Host = (*Host)(nil)

// HostOption customizes the minimal plugin host facade.
type HostOption func(*Host)

// Host exposes process-owned services through the public plugin API.
type Host struct {
	serviceContext context.Context
	logger         *slog.Logger
	config         pluginapi.ConfigView
	redis          pluginapi.Redis
	ldap           pluginapi.LDAP
	tracerFactory  func(string) pluginapi.Tracer
	metricsFactory func(string) pluginapi.Metrics
	workers        sync.WaitGroup
}

// NewHost returns a minimal host facade for lifecycle-capable plugins.
func NewHost(options ...HostOption) *Host {
	host := &Host{
		serviceContext: context.Background(),
		logger:         slog.Default(),
		config:         pluginregistry.NewConfigView(nil),
		tracerFactory:  func(scope string) pluginapi.Tracer { return NewTracerFacade(scope) },
		metricsFactory: func(scope string) pluginapi.Metrics { return NewMetricsFacade(scope) },
	}
	for _, option := range options {
		option(host)
	}

	return host
}

// WithServiceContext configures the process service context exposed to plugins.
func WithServiceContext(ctx context.Context) HostOption {
	return func(host *Host) {
		if ctx != nil {
			host.serviceContext = ctx
		}
	}
}

// WithLogger configures the slog-backed plugin logger facade.
func WithLogger(logger *slog.Logger) HostOption {
	return func(host *Host) {
		if logger != nil {
			host.logger = logger
		}
	}
}

// WithConfig configures the host-wide config view exposed to plugins.
func WithConfig(view pluginapi.ConfigView) HostOption {
	return func(host *Host) {
		if view != nil {
			host.config = view
		}
	}
}

// WithRedis configures the Redis facade exposed to plugins.
func WithRedis(redis pluginapi.Redis) HostOption {
	return func(host *Host) {
		host.redis = redis
	}
}

// WithRedisClient configures the Redis facade from the central Redis client.
func WithRedisClient(client rediscli.Client) HostOption {
	return func(host *Host) {
		host.redis = NewRedisFacade(client)
	}
}

// WithLDAP configures the LDAP facade exposed to plugins.
func WithLDAP(ldap pluginapi.LDAP) HostOption {
	return func(host *Host) {
		host.ldap = ldap
	}
}

// WithLDAPExecutor configures the LDAP facade from an API-level executor.
func WithLDAPExecutor(executor LDAPExecutor) HostOption {
	return func(host *Host) {
		host.ldap = NewLDAPFacade(executor)
	}
}

// WithTracerFactory configures scoped tracer construction for plugins.
func WithTracerFactory(factory func(string) pluginapi.Tracer) HostOption {
	return func(host *Host) {
		if factory != nil {
			host.tracerFactory = factory
		}
	}
}

// WithMetricsFactory configures scoped metrics construction for plugins.
func WithMetricsFactory(factory func(string) pluginapi.Metrics) HostOption {
	return func(host *Host) {
		if factory != nil {
			host.metricsFactory = factory
		}
	}
}

// ServiceContext returns the host service context.
func (h *Host) ServiceContext() context.Context {
	if h == nil || h.serviceContext == nil {
		return context.Background()
	}

	return h.serviceContext
}

// Logger returns a scoped structured logger facade.
func (h *Host) Logger(scope string) pluginapi.Logger {
	logger := slog.Default()
	if h != nil && h.logger != nil {
		logger = h.logger
	}

	return scopedLogger{logger: logger, scope: scope}
}

// Tracer returns a scoped host tracing facade.
func (h *Host) Tracer(scope string) pluginapi.Tracer {
	if h == nil || h.tracerFactory == nil {
		return noopTracer{}
	}

	return h.tracerFactory(scope)
}

// Metrics returns a scoped host metrics facade.
func (h *Host) Metrics(scope string) pluginapi.Metrics {
	if h == nil || h.metricsFactory == nil {
		return noopMetrics{}
	}

	return h.metricsFactory(scope)
}

// Redis returns the configured host Redis facade.
func (h *Host) Redis() pluginapi.Redis {
	if h == nil {
		return nil
	}

	return h.redis
}

// LDAP returns the configured host LDAP facade.
func (h *Host) LDAP() pluginapi.LDAP {
	if h == nil {
		return nil
	}

	return h.ldap
}

// Config returns a host-wide read-only config view.
func (h *Host) Config() pluginapi.ConfigView {
	if h == nil || h.config == nil {
		return pluginregistry.NewConfigView(nil)
	}

	return h.config
}

// Go starts a host-supervised goroutine with panic recovery.
func (h *Host) Go(ctx context.Context, name string, fn func(context.Context) error) {
	if h == nil || fn == nil {
		return
	}

	if ctx == nil {
		ctx = h.ServiceContext()
	}

	workerCtx, cancel := context.WithCancel(h.ServiceContext())
	h.workers.Add(1)

	go func() {
		defer h.workers.Done()
		defer cancel()
		defer func() {
			if recovered := recover(); recovered != nil {
				h.Logger(name).Error(workerCtx, "plugin worker panicked", pluginapi.LogField{Key: "panic", Value: true})
			}
		}()

		go cancelWhenDone(workerCtx, ctx, cancel)

		if err := fn(workerCtx); err != nil {
			h.Logger(name).Error(workerCtx, "plugin worker stopped with error", pluginapi.LogField{Key: "plugin_error_class", Value: "worker"})
		}
	}()
}

// WaitWorkers waits for supervised plugin workers to exit.
func (h *Host) WaitWorkers() {
	if h == nil {
		return
	}

	h.workers.Wait()
}

// WaitWorkersContext waits for supervised plugin workers until they exit or the context ends.
func (h *Host) WaitWorkersContext(ctx context.Context) error {
	if h == nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)

		h.workers.Wait()
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// cancelWhenDone links a parent context to a worker cancellation function.
func cancelWhenDone(workerCtx context.Context, parent context.Context, cancel context.CancelFunc) {
	select {
	case <-workerCtx.Done():
	case <-parent.Done():
		cancel()
	}
}

type scopedLogger struct {
	logger *slog.Logger
	scope  string
}

// Debug writes a debug plugin log record.
func (l scopedLogger) Debug(ctx context.Context, message string, fields ...pluginapi.LogField) {
	l.log(ctx, slog.LevelDebug, message, fields...)
}

// Info writes an info plugin log record.
func (l scopedLogger) Info(ctx context.Context, message string, fields ...pluginapi.LogField) {
	l.log(ctx, slog.LevelInfo, message, fields...)
}

// Warn writes a warning plugin log record.
func (l scopedLogger) Warn(ctx context.Context, message string, fields ...pluginapi.LogField) {
	l.log(ctx, slog.LevelWarn, message, fields...)
}

// Error writes an error plugin log record.
func (l scopedLogger) Error(ctx context.Context, message string, fields ...pluginapi.LogField) {
	l.log(ctx, slog.LevelError, message, fields...)
}

// log converts plugin log fields to slog attributes.
func (l scopedLogger) log(ctx context.Context, level slog.Level, message string, fields ...pluginapi.LogField) {
	attrs := make([]any, 0, 2+len(fields)*2)
	if l.scope != "" {
		attrs = append(attrs, "plugin_scope", l.scope)
	}

	for _, field := range fields {
		attrs = append(attrs, field.Key, field.Value)
	}

	l.logger.Log(ctx, level, message, attrs...)
}

type noopTracer struct{}

// Start returns the input context and a no-op span.
func (noopTracer) Start(ctx context.Context, _ string, _ ...pluginapi.TraceAttribute) (context.Context, pluginapi.Span) {
	return ctx, noopSpan{}
}

type noopSpan struct{}

// AddEvent records no event for the no-op span.
func (noopSpan) AddEvent(string, ...pluginapi.TraceAttribute) {}

// SetAttributes records no attributes for the no-op span.
func (noopSpan) SetAttributes(...pluginapi.TraceAttribute) {}

// RecordError records no error for the no-op span.
func (noopSpan) RecordError(error) {}

// End finishes the no-op span.
func (noopSpan) End() {}

type noopMetrics struct{}

// Counter returns a no-op counter.
func (noopMetrics) Counter(pluginapi.MetricDefinition) (pluginapi.Counter, error) {
	return noopCounter{}, nil
}

// Gauge returns a no-op gauge.
func (noopMetrics) Gauge(pluginapi.MetricDefinition) (pluginapi.Gauge, error) {
	return noopGauge{}, nil
}

// Histogram returns a no-op histogram.
func (noopMetrics) Histogram(pluginapi.MetricDefinition) (pluginapi.Histogram, error) {
	return noopHistogram{}, nil
}

// Summary returns a no-op summary.
func (noopMetrics) Summary(pluginapi.MetricDefinition) (pluginapi.Summary, error) {
	return noopSummary{}, nil
}

type noopCounter struct{}

// Add records no counter value.
func (noopCounter) Add(context.Context, float64, ...pluginapi.LabelValue) {}

type noopGauge struct{}

// Set records no gauge value.
func (noopGauge) Set(context.Context, float64, ...pluginapi.LabelValue) {}

// Add records no gauge delta.
func (noopGauge) Add(context.Context, float64, ...pluginapi.LabelValue) {}

type noopHistogram struct{}

// Observe records no histogram value.
func (noopHistogram) Observe(context.Context, float64, ...pluginapi.LabelValue) {}

type noopSummary struct{}

// Observe records no summary value.
func (noopSummary) Observe(context.Context, float64, ...pluginapi.LabelValue) {}
