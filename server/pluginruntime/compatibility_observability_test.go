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

func TestCompatibilityMetricsRejectPreexistingExactCollector(t *testing.T) {
	registry := prometheus.NewRegistry()
	if err := registry.Register(prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "legacy_requests_total",
		Help: "Legacy requests",
	}, []string{"result"})); err != nil {
		t.Fatalf("pre-register exact collector: %v", err)
	}

	definition := pluginapi.MetricDefinition{
		Compatibility: true,
		Type:          pluginapi.MetricTypeCounter,
		Name:          "legacy_requests_total",
		Help:          "Legacy requests",
		Labels:        []string{"result"},
	}
	metrics := NewCompatibilityMetricsFacade(NewMetricsFacadeWithRegisterer("rns_auth", registry), registry, []pluginapi.MetricDefinition{definition})

	if _, err := metrics.Counter(definition); err == nil {
		t.Fatal("Counter() error = nil, want exact collector conflict")
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

// assertHistogramSampleCount checks one gathered histogram family.
func assertHistogramSampleCount(t *testing.T, families []*dto.MetricFamily, name string, want uint64) {
	t.Helper()

	for _, family := range families {
		if family.GetName() != name {
			continue
		}

		if got := family.GetMetric()[0].GetHistogram().GetSampleCount(); got != want {
			t.Fatalf("histogram %q sample count = %d, want %d", name, got, want)
		}

		return
	}

	t.Fatalf("histogram %q was not gathered", name)
}
