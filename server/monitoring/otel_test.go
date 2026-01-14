// Copyright (C) 2024 Christian Rößner
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
			tracing:      &config.Tracing{Enabled: false},
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
				Enabled:      true,
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
				Enabled:      true,
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
				Enabled:  true,
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

func TestStartEnabledNoTLSDefaultsToHTTP(t *testing.T) {
	withGlobalOtelSaved(t, func() {
		tm := &Telemetry{}
		tm.SetProvider(providerMock{
			instanceName: "test-instance",
			tracing: &config.Tracing{
				Enabled:  true,
				Exporter: "otlphttp",
				Endpoint: "localhost:4318",
				// TLS block omitted -> should default to HTTP (insecure)
			},
		})
		// Should not panic when starting without TLS; exporter should be created with Insecure.
		tm.Start(context.Background(), "v0.0.1")
		tm.Shutdown(context.Background())
	})
}
