package monitoring

import (
	"context"
	"strings"
	"sync"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"

	b3prop "go.opentelemetry.io/contrib/propagators/b3"
	jaegerprop "go.opentelemetry.io/contrib/propagators/jaeger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
)

// Telemetry provides lifecycle management for OpenTelemetry tracing.
type Telemetry struct {
	started bool
	tp      *sdktrace.TracerProvider
	mu      sync.Mutex
	prov    TelemetryConfigProvider
}

var telemetry Telemetry

// GetTelemetry returns the Telemetry singleton.
func GetTelemetry() *Telemetry { return &telemetry }

// TelemetryConfigProvider abstracts access to configuration used by telemetry.
// This allows unit tests to inject a lightweight mock without depending on the
// full global config.File implementation.
type TelemetryConfigProvider interface {
	GetTracing() *config.Tracing
	GetInstanceName() string
}

type defaultProvider struct{}

func (defaultProvider) GetTracing() *config.Tracing {
	return config.GetFile().GetServer().GetInsights().GetTracing()
}
func (defaultProvider) GetInstanceName() string {
	return config.GetFile().GetServer().GetInstanceName()
}

// SetProvider allows injecting a custom configuration provider (primarily for tests).
// In production the default provider is used, which reads from the global config.
func (t *Telemetry) SetProvider(p TelemetryConfigProvider) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prov = p
}

// Start initializes OpenTelemetry according to configuration. Safe to call multiple times.
func (t *Telemetry) Start(ctx context.Context, appVersion string) {
	prov := t.prov
	if prov == nil {
		prov = defaultProvider{}
	}
	cfg := prov.GetTracing()
	if cfg == nil || !cfg.IsEnabled() {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.started {
		return
	}

	svcName := cfg.GetServiceName()
	if strings.TrimSpace(svcName) == "" {
		// Prefer instance name from config if present
		svcName = prov.GetInstanceName()
		if strings.TrimSpace(svcName) == "" {
			svcName = "nauthilus-server"
		}
	}

	res, _ := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(svcName),
		semconv.ServiceVersionKey.String(appVersion),
		attribute.String("instance", prov.GetInstanceName()),
	))

	// Sampler
	ratio := cfg.GetSamplerRatio()
	if ratio < 0 {
		ratio = 0
	}

	if ratio > 1 {
		ratio = 1
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))

	// Exporter (only otlphttp supported per requirements)
	var (
		exp sdktrace.SpanExporter
		err error
	)

	if strings.EqualFold(cfg.GetExporter(), "otlphttp") {
		var opts []otlptracehttp.Option
		if cfg.GetEndpoint() != "" {
			opts = append(opts, otlptracehttp.WithEndpoint(cfg.GetEndpoint()))
		}

		// Transport security selection:
		// - If a dedicated TLS block is enabled, build a tls.Config and use HTTPS.
		// - Otherwise, default to plain HTTP by explicitly setting WithInsecure().
		if cfg.GetTLS().IsEnabled() {
			if tlsConf := cfg.GetTLS().ToTLSConfig(); tlsConf != nil {
				opts = append(opts, otlptracehttp.WithTLSClientConfig(tlsConf))
			}
		} else {
			// No TLS configured at all => default to HTTP to match expectations
			opts = append(opts, otlptracehttp.WithInsecure())
		}

		exp, err = otlptracehttp.New(ctx, opts...)
		if err != nil {
			level.Warn(log.Logger).Log(definitions.LogKeyMsg, "Failed to initialize OTLP/HTTP exporter", definitions.LogKeyError, err)
		}
	}

	// Build TracerProvider
	tpOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
	}

	if exp != nil {
		// Optionally wrap exporter with a logging decorator that emits INFO on successful exports
		if cfg.IsLogExportResultsEnabled() {
			exp = newLoggingExporter(exp, true)
		} else {
			exp = newLoggingExporter(exp, false)
		}

		// WithBatcher wraps exporter with a BatchSpanProcessor
		tpOpts = append(tpOpts, sdktrace.WithBatcher(exp))
	}

	tp := sdktrace.NewTracerProvider(tpOpts...)

	// Propagators
	otel.SetTextMapPropagator(buildPropagators(cfg.GetPropagators()))
	otel.SetTracerProvider(tp)

	t.tp = tp
	t.started = true

	level.Info(log.Logger).Log(definitions.LogKeyMsg, "OpenTelemetry tracing enabled", "service", svcName, "exporter", cfg.GetExporter())
}

// loggingExporter decorates a SpanExporter to log export outcomes.
// When logSuccess is true, successful batch exports are logged at INFO level.
// Failures are always logged at WARN to aid troubleshooting.
type loggingExporter struct {
	delegate   sdktrace.SpanExporter
	logSuccess bool
}

func newLoggingExporter(delegate sdktrace.SpanExporter, logSuccess bool) sdktrace.SpanExporter {
	return &loggingExporter{delegate: delegate, logSuccess: logSuccess}
}

// ExportSpans forwards to the underlying exporter and logs the result.
func (l *loggingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	err := l.delegate.ExportSpans(ctx, spans)
	if err != nil {
		level.Warn(log.Logger).Log(
			definitions.LogKeyMsg, "OpenTelemetry trace export failed",
			definitions.LogKeyError, err,
			"span_count", len(spans),
		)

		return err
	}

	if l.logSuccess {
		level.Info(log.Logger).Log(
			definitions.LogKeyMsg, "OpenTelemetry traces exported",
			"span_count", len(spans),
		)
	}

	return nil
}

// Shutdown delegates shutdown and logs the outcome (INFO on success when enabled, WARN on error).
func (l *loggingExporter) Shutdown(ctx context.Context) error {
	err := l.delegate.Shutdown(ctx)
	if err != nil {
		level.Warn(log.Logger).Log(definitions.LogKeyMsg, "OpenTelemetry exporter shutdown failed", definitions.LogKeyError, err)

		return err
	}

	if l.logSuccess {
		level.Info(log.Logger).Log(definitions.LogKeyMsg, "OpenTelemetry exporter shutdown complete")
	}

	return nil
}

// Shutdown flushes and closes the Telemetry provider.
func (t *Telemetry) Shutdown(ctx context.Context) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.started || t.tp == nil {
		return
	}

	_ = t.tp.Shutdown(ctx)

	t.started = false
	t.tp = nil
}

func buildPropagators(names []string) propagation.TextMapPropagator {
	if len(names) == 0 {
		return propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		)
	}

	var list []propagation.TextMapPropagator
	for _, n := range names {
		switch strings.ToLower(strings.TrimSpace(n)) {
		case "tracecontext":
			list = append(list, propagation.TraceContext{})
		case "baggage":
			list = append(list, propagation.Baggage{})
		case "b3":
			list = append(list, b3prop.New())
		case "b3multi":
			list = append(list, b3prop.New(b3prop.WithInjectEncoding(b3prop.B3MultipleHeader)))
		case "jaeger":
			list = append(list, jaegerprop.Jaeger{})
		}
	}

	if len(list) == 0 {
		list = append(list, propagation.TraceContext{}, propagation.Baggage{})
	}

	return propagation.NewCompositeTextMapPropagator(list...)
}
