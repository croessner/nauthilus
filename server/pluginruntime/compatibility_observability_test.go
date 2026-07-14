// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package pluginruntime

import (
	"context"
	"errors"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/testing/tracetest"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func TestCompatibilityMetricsPublishExactAndNativeCollectorsOnce(t *testing.T) {
	registry := prometheus.NewRegistry()
	native := NewMetricsFacadeWithRegisterer("rns_auth", registry)
	metrics := NewCompatibilityMetricsFacade(native, registry, []pluginapi.MetricDefinition{{
		Compatibility: true,
		Type:          pluginapi.MetricTypeHistogram,
		Name:          "legacy_request_duration_seconds",
		Help:          "Legacy request duration",
		Labels:        []string{"service"},
		Buckets:       []float64{0.01, 0.1, 1},
	}})

	histogram, err := metrics.Histogram(pluginapi.MetricDefinition{
		Compatibility: true,
		Type:          pluginapi.MetricTypeHistogram,
		Name:          "legacy_request_duration_seconds",
		Help:          "Legacy request duration",
		Labels:        []string{"service"},
		Buckets:       []float64{0.01, 0.1, 1},
	})
	if err != nil {
		t.Fatalf("Histogram() error = %v", err)
	}

	duplicate, err := metrics.Histogram(pluginapi.MetricDefinition{
		Compatibility: true,
		Type:          pluginapi.MetricTypeHistogram,
		Name:          "legacy_request_duration_seconds",
		Help:          "Legacy request duration",
		Labels:        []string{"service"},
		Buckets:       []float64{0.01, 0.1, 1},
	})
	if err != nil {
		t.Fatalf("duplicate Histogram() error = %v", err)
	}

	histogram.Observe(context.Background(), 0.05, pluginapi.LabelValue{Name: "service", Value: "blocklist"})
	duplicate.Observe(context.Background(), 0.08, pluginapi.LabelValue{Name: "service", Value: "blocklist"})

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	assertHistogramSampleCount(t, families, "legacy_request_duration_seconds", 2)
	assertHistogramSampleCount(t, families, "nauthilus_plugin_rns_auth_legacy_request_duration_seconds", 2)
}

func TestCompatibilityMetricsRejectDefinitionDrift(t *testing.T) {
	allowed := pluginapi.MetricDefinition{
		Compatibility: true,
		Type:          pluginapi.MetricTypeCounter,
		Name:          "legacy_requests_total",
		Help:          "Legacy requests",
		Labels:        []string{"result"},
	}
	metrics := NewCompatibilityMetricsFacade(
		NewMetricsFacadeWithRegisterer("rns_auth", prometheus.NewRegistry()),
		prometheus.NewRegistry(),
		[]pluginapi.MetricDefinition{allowed},
	)

	drifted := allowed
	drifted.Help = "Changed help"

	if _, err := metrics.Counter(drifted); !errors.Is(err, ErrCompatibilityMetricDenied) {
		t.Fatalf("Counter() error = %v, want ErrCompatibilityMetricDenied", err)
	}
}

func TestCompatibilityMetricsReuseIdenticalLuaCollector(t *testing.T) {
	registry := prometheus.NewRegistry()

	existing := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "http_client_concurrent_requests_total",
		Help: "Measure the number of total concurrent HTTP client requests",
	}, []string{"service"})

	if err := registry.Register(existing); err != nil {
		t.Fatalf("pre-register exact collector: %v", err)
	}

	existing.WithLabelValues("blocklist").Set(3)

	definition := pluginapi.MetricDefinition{
		Compatibility: true,
		Type:          pluginapi.MetricTypeGauge,
		Name:          "http_client_concurrent_requests_total",
		Help:          "Measure the number of total concurrent HTTP client requests",
		Labels:        []string{"service"},
	}

	host := newSignedCompatibilityMetricsHost(registry, definition)
	metrics := host.moduleHost("rns_auth").Metrics("rns_auth")

	gauge, err := metrics.Gauge(definition)
	if err != nil {
		t.Fatalf("Gauge() error = %v", err)
	}

	duplicate, err := metrics.Gauge(definition)
	if err != nil {
		t.Fatalf("duplicate Gauge() error = %v", err)
	}

	labels := []pluginapi.LabelValue{{Name: "service", Value: "blocklist"}}
	gauge.Add(context.Background(), 2, labels...)
	duplicate.Add(context.Background(), 1, labels...)

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	assertGaugeValue(t, families, "http_client_concurrent_requests_total", 6)
	assertGaugeValue(t, families, "nauthilus_plugin_rns_auth_http_client_concurrent_requests_total", 3)
	assertMetricFamilyCount(t, families, "http_client_concurrent_requests_total", 1)

	unsigned := host.moduleHost("unsigned").Metrics("unsigned")
	if _, err := unsigned.Gauge(definition); !errors.Is(err, ErrCompatibilityMetricDenied) {
		t.Fatalf("unsigned Gauge() error = %v, want ErrCompatibilityMetricDenied", err)
	}
}

func TestCompatibilityMetricsReuseIdenticalLuaHistogram(t *testing.T) {
	registry := prometheus.NewRegistry()
	buckets := prometheus.ExponentialBuckets(0.001, 1.75, 15)

	existing := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "blocklist_duration_seconds",
		Help:    "HTTP request to the blocklist service",
		Buckets: buckets,
	}, []string{"http"})

	if err := registry.Register(existing); err != nil {
		t.Fatalf("pre-register exact collector: %v", err)
	}

	definition := pluginapi.MetricDefinition{
		Compatibility: true,
		Type:          pluginapi.MetricTypeHistogram,
		Name:          "blocklist_duration_seconds",
		Help:          "HTTP request to the blocklist service",
		Labels:        []string{"http"},
		Buckets:       buckets,
	}
	metrics := NewCompatibilityMetricsFacade(NewMetricsFacadeWithRegisterer("rns_auth", registry), registry, []pluginapi.MetricDefinition{definition})

	histogram, err := metrics.Histogram(definition)
	if err != nil {
		t.Fatalf("Histogram() error = %v", err)
	}

	existing.WithLabelValues("request").Observe(0.01)
	histogram.Observe(context.Background(), 0.02, pluginapi.LabelValue{Name: "http", Value: "request"})

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	assertHistogramSampleCount(t, families, "blocklist_duration_seconds", 2)
	assertHistogramSampleCount(t, families, "nauthilus_plugin_rns_auth_blocklist_duration_seconds", 1)
	assertMetricFamilyCount(t, families, "blocklist_duration_seconds", 1)
}

func TestCompatibilityMetricsRejectPreexistingCollectorContractDrift(t *testing.T) {
	tests := []struct {
		name       string
		definition pluginapi.MetricDefinition
		existing   prometheus.Collector
	}{
		{
			name: "type",
			definition: pluginapi.MetricDefinition{
				Compatibility: true, Type: pluginapi.MetricTypeGauge, Name: "legacy_type", Help: "Legacy type", Labels: []string{"service"},
			},
			existing: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "legacy_type", Help: "Legacy type"}, []string{"service"}),
		},
		{
			name: "help",
			definition: pluginapi.MetricDefinition{
				Compatibility: true, Type: pluginapi.MetricTypeGauge, Name: "legacy_help", Help: "Expected help", Labels: []string{"service"},
			},
			existing: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "legacy_help", Help: "Different help"}, []string{"service"}),
		},
		{
			name: "label order",
			definition: pluginapi.MetricDefinition{
				Compatibility: true, Type: pluginapi.MetricTypeGauge, Name: "legacy_labels", Help: "Legacy labels", Labels: []string{"service", "result"},
			},
			existing: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "legacy_labels", Help: "Legacy labels"}, []string{"result", "service"}),
		},
		{
			name: "histogram buckets",
			definition: pluginapi.MetricDefinition{
				Compatibility: true, Type: pluginapi.MetricTypeHistogram, Name: "legacy_buckets", Help: "Legacy buckets", Labels: []string{"service"}, Buckets: []float64{0.01, 0.1, 1},
			},
			existing: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "legacy_buckets", Help: "Legacy buckets", Buckets: []float64{0.02, 0.2, 2}}, []string{"service"}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			if err := registry.Register(test.existing); err != nil {
				t.Fatalf("pre-register exact collector: %v", err)
			}

			var err error

			metrics := NewCompatibilityMetricsFacade(NewMetricsFacadeWithRegisterer("rns_auth", registry), registry, []pluginapi.MetricDefinition{test.definition})

			switch test.definition.Type {
			case pluginapi.MetricTypeGauge:
				_, err = metrics.Gauge(test.definition)
			case pluginapi.MetricTypeHistogram:
				_, err = metrics.Histogram(test.definition)
			}

			if err == nil {
				t.Fatal("compatibility metric error = nil, want collector contract conflict")
			}
		})
	}
}

func TestTracerFacadeSupportsTypedKindAndExplicitStatus(t *testing.T) {
	collector := tracetest.Setup(t)
	tracer := NewCompatibilityTracerFacade("nauthilus/lua/blocklist")

	_, span := tracer.StartWithOptions(context.Background(), "blocklist.request", pluginapi.SpanStartOptions{
		Kind: pluginapi.SpanKindClient,
	})
	span.RecordError(errors.New("request failed"))
	span.SetStatus(pluginapi.SpanStatusError, "blocklist unavailable")
	span.End()

	var exported sdktrace.ReadOnlySpan

	for _, candidate := range collector.Spans() {
		if candidate.Name() == "blocklist.request" {
			exported = candidate
			break
		}
	}

	if exported == nil {
		t.Fatal("compatibility span was not exported")
	}

	if got := exported.SpanKind(); got != trace.SpanKindClient {
		t.Fatalf("span kind = %v, want client", got)
	}

	if got := exported.Status().Code; got != codes.Error {
		t.Fatalf("span status = %v, want error", got)
	}

	if got := exported.InstrumentationScope().Name; got != "nauthilus/lua/blocklist" {
		t.Fatalf("instrumentation scope = %q, want exact legacy scope", got)
	}
}

func TestModuleBoundCompatibilityRequiresVerifiedSignerAndExactScope(t *testing.T) {
	host := NewHost()
	host.setModuleCompatibility([]pluginloader.ModuleInstance{{
		ModuleName:     "rns_auth",
		VerifiedSigner: "release_key",
		Module: config.PluginModule{Compatibility: config.PluginCompatibility{
			TraceScopes: []string{"nauthilus/lua/blocklist"},
		}},
	}})
	moduleHost := host.moduleHost("rns_auth")

	if _, err := moduleHost.CompatibilityTracer("nauthilus/lua/blocklist"); err != nil {
		t.Fatalf("CompatibilityTracer() error = %v", err)
	}

	if _, err := moduleHost.CompatibilityTracer("nauthilus/lua/ldap"); !errors.Is(err, ErrCompatibilityObservabilityDenied) {
		t.Fatalf("CompatibilityTracer() error = %v, want ErrCompatibilityObservabilityDenied", err)
	}

	if _, err := host.moduleHost("unsigned").CompatibilityTracer("nauthilus/lua/blocklist"); !errors.Is(err, ErrCompatibilityObservabilityDenied) {
		t.Fatalf("unsigned CompatibilityTracer() error = %v, want denial", err)
	}
}

// newSignedCompatibilityMetricsHost builds a verified module host for exact-metric tests.
func newSignedCompatibilityMetricsHost(registry *prometheus.Registry, definition pluginapi.MetricDefinition) *Host {
	host := NewHost(
		WithCompatibilityRegisterer(registry),
		WithMetricsFactory(func(scope string) pluginapi.Metrics {
			return NewMetricsFacadeWithRegisterer(scope, registry)
		}),
	)
	host.setModuleCompatibility([]pluginloader.ModuleInstance{{
		ModuleName:     "rns_auth",
		VerifiedSigner: "release_key",
		Module: config.PluginModule{Compatibility: config.PluginCompatibility{Metrics: []config.PluginCompatibilityMetric{{
			Type: definition.Type, Name: definition.Name, Help: definition.Help, Labels: definition.Labels, Buckets: definition.Buckets,
		}}}},
	}})

	return host
}

// assertHistogramSampleCount checks one gathered histogram family.
func assertHistogramSampleCount(t *testing.T, families []*dto.MetricFamily, name string, want uint64) {
	t.Helper()

	family := metricFamilyByName(t, families, name)

	if got := family.GetMetric()[0].GetHistogram().GetSampleCount(); got != want {
		t.Fatalf("histogram %q sample count = %d, want %d", name, got, want)
	}
}

// assertGaugeValue checks one gathered gauge family value.
func assertGaugeValue(t *testing.T, families []*dto.MetricFamily, name string, want float64) {
	t.Helper()

	family := metricFamilyByName(t, families, name)

	if got := family.GetMetric()[0].GetGauge().GetValue(); got != want {
		t.Fatalf("gauge %q value = %v, want %v", name, got, want)
	}
}

// metricFamilyByName returns one gathered family or fails the test.
func metricFamilyByName(t *testing.T, families []*dto.MetricFamily, name string) *dto.MetricFamily {
	t.Helper()

	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}

	t.Fatalf("metric family %q was not gathered", name)

	return nil
}

// assertMetricFamilyCount checks that one metric family exists exactly once.
func assertMetricFamilyCount(t *testing.T, families []*dto.MetricFamily, name string, want int) {
	t.Helper()

	count := 0

	for _, family := range families {
		if family.GetName() == name {
			count++
		}
	}

	if count != want {
		t.Fatalf("metric family %q count = %d, want %d", name, count, want)
	}
}
