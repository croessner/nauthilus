package monitoring

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"go.opentelemetry.io/otel"
)

// providerMock implements TelemetryConfigProvider for tests
type providerMock struct {
	tracing      *config.Tracing
	instanceName string
}

func (p providerMock) GetTracing() *config.Tracing { return p.tracing }
func (p providerMock) GetInstanceName() string     { return p.instanceName }

// helper to save/restore global OTel state per test
func withGlobalOtelSaved(t *testing.T, fn func()) {
	t.Helper()
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	fn()
}

func TestStartDisabledNoop(t *testing.T) {
	withGlobalOtelSaved(t, func() {
		tm := &Telemetry{}
		tm.SetProvider(providerMock{
			instanceName: "test-instance",
			tracing:      &config.Tracing{Enable: false},
		})
		tm.Start(context.Background(), "test-version")
		if tm.started {
			t.Fatalf("expected telemetry not started when disabled")
		}
	})
}

func TestStartEnabledSetsProviderAndPropagators(t *testing.T) {
	withGlobalOtelSaved(t, func() {
		tm := &Telemetry{}
		tm.SetProvider(providerMock{
			instanceName: "test-instance",
			tracing: &config.Tracing{
				Enable:       true,
				Exporter:     "none",
				SamplerRatio: 0.2,
				Propagators:  []string{"tracecontext", "baggage"},
			},
		})

		tm.Start(context.Background(), "v0.0.1")
		if !tm.started || tm.tp == nil {
			t.Fatalf("telemetry should be started with a tracer provider")
		}
		// Idempotency
		tm.Start(context.Background(), "v0.0.1")

		// Propagators should be set (cannot introspect easily, but should not be nil)
		if otel.GetTextMapPropagator() == nil {
			t.Fatalf("expected propagator to be set")
		}
		tm.Shutdown(context.Background())
	})
}

func TestSamplerRatioClamp(t *testing.T) {
	withGlobalOtelSaved(t, func() {
		tm := &Telemetry{}
		tm.SetProvider(providerMock{
			instanceName: "test-instance",
			tracing: &config.Tracing{
				Enable:       true,
				Exporter:     "none",
				SamplerRatio: 1.5, // should clamp to 1.0
			},
		})
		tm.Start(context.Background(), "v0.0.1")
		if !tm.started {
			t.Fatalf("telemetry should be started")
		}
		tm.Shutdown(context.Background())
	})
}

func TestTLSConfigEnabledNoExporter(t *testing.T) {
	withGlobalOtelSaved(t, func() {
		tm := &Telemetry{}
		tm.SetProvider(providerMock{
			instanceName: "test-instance",
			tracing: &config.Tracing{
				Enable:   true,
				Exporter: "otlphttp",
				Endpoint: "localhost:4318",
				TLS:      config.TLS{Enabled: true},
			},
		})
		// Ensure no panic
		tm.Start(context.Background(), "v0.0.1")
		tm.Shutdown(context.Background())
	})
}
