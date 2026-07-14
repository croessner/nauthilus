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
	"fmt"
	"slices"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// ErrCompatibilityMetricDenied marks an exact metric request outside its operator allowlist.
	ErrCompatibilityMetricDenied = errors.New("compatibility metric denied")
)

var _ pluginapi.Metrics = (*CompatibilityMetricsFacade)(nil)

// CompatibilityMetricsFacade dual-publishes allowlisted exact and native plugin metrics.
type CompatibilityMetricsFacade struct {
	native  pluginapi.Metrics
	exact   *MetricsFacade
	allowed map[string]pluginapi.MetricDefinition
}

// NewCompatibilityMetricsFacade returns a defensive exact-metric allowlist wrapper.
func NewCompatibilityMetricsFacade(
	native pluginapi.Metrics,
	registerer prometheus.Registerer,
	allowed []pluginapi.MetricDefinition,
) *CompatibilityMetricsFacade {
	definitions := make(map[string]pluginapi.MetricDefinition, len(allowed))
	for _, definition := range allowed {
		definition = cloneMetricDefinition(definition)
		definitions[compatibilityMetricKey(definition.Type, definition.Name)] = definition
	}

	return &CompatibilityMetricsFacade{
		native:  native,
		exact:   newExactMetricsFacade(registerer),
		allowed: definitions,
	}
}

// Counter returns a dual-publishing exact counter when allowlisted.
func (m *CompatibilityMetricsFacade) Counter(definition pluginapi.MetricDefinition) (pluginapi.Counter, error) {
	return compatibilityMetric(
		m,
		pluginapi.MetricTypeCounter,
		definition,
		m.native.Counter,
		m.exact.Counter,
		func(exact pluginapi.Counter, native pluginapi.Counter) pluginapi.Counter {
			return dualCounter{exact: exact, native: native}
		},
	)
}

// Gauge returns a dual-publishing exact gauge when allowlisted.
func (m *CompatibilityMetricsFacade) Gauge(definition pluginapi.MetricDefinition) (pluginapi.Gauge, error) {
	return compatibilityMetric(
		m,
		pluginapi.MetricTypeGauge,
		definition,
		m.native.Gauge,
		m.exact.Gauge,
		func(exact pluginapi.Gauge, native pluginapi.Gauge) pluginapi.Gauge {
			return dualGauge{exact: exact, native: native}
		},
	)
}

// Histogram returns a dual-publishing exact histogram when allowlisted.
func (m *CompatibilityMetricsFacade) Histogram(definition pluginapi.MetricDefinition) (pluginapi.Histogram, error) {
	return compatibilityMetric(
		m,
		pluginapi.MetricTypeHistogram,
		definition,
		m.native.Histogram,
		m.exact.Histogram,
		func(exact pluginapi.Histogram, native pluginapi.Histogram) pluginapi.Histogram {
			return dualHistogram{exact: exact, native: native}
		},
	)
}

// Summary returns a dual-publishing exact summary when allowlisted.
func (m *CompatibilityMetricsFacade) Summary(definition pluginapi.MetricDefinition) (pluginapi.Summary, error) {
	return compatibilityMetric(
		m,
		pluginapi.MetricTypeSummary,
		definition,
		m.native.Summary,
		m.exact.Summary,
		func(exact pluginapi.Summary, native pluginapi.Summary) pluginapi.Summary {
			return dualSummary{exact: exact, native: native}
		},
	)
}

// compatibilityMetric authorizes and constructs one exact-plus-native metric handle.
func compatibilityMetric[T any](
	facade *CompatibilityMetricsFacade,
	kind pluginapi.MetricType,
	definition pluginapi.MetricDefinition,
	nativeFactory func(pluginapi.MetricDefinition) (T, error),
	exactFactory func(pluginapi.MetricDefinition) (T, error),
	combine func(T, T) T,
) (T, error) {
	var zero T

	if !definition.Compatibility {
		return nativeFactory(definition)
	}

	if err := facade.authorize(kind, definition); err != nil {
		return zero, err
	}

	nativeDefinition := nativeMetricDefinition(definition)

	exact, err := exactFactory(nativeDefinition)
	if err != nil {
		return zero, err
	}

	native, err := nativeFactory(nativeDefinition)
	if err != nil {
		return zero, err
	}

	return combine(exact, native), nil
}

// authorize requires an exact match with the operator-owned metric contract.
func (m *CompatibilityMetricsFacade) authorize(kind pluginapi.MetricType, requested pluginapi.MetricDefinition) error {
	if m == nil || m.native == nil || m.exact == nil {
		return fmt.Errorf("%w: facade unavailable", ErrCompatibilityMetricDenied)
	}

	allowed, ok := m.allowed[compatibilityMetricKey(kind, requested.Name)]
	if !ok || requested.Type != kind || !sameMetricDefinition(allowed, requested) {
		return fmt.Errorf("%w: %s %q does not exactly match operator configuration", ErrCompatibilityMetricDenied, kind, requested.Name)
	}

	return nil
}

// sameMetricDefinition compares every exact collector contract field.
func sameMetricDefinition(left pluginapi.MetricDefinition, right pluginapi.MetricDefinition) bool {
	return left.Compatibility == right.Compatibility &&
		left.Type == right.Type &&
		left.Name == right.Name &&
		left.Help == right.Help &&
		slices.Equal(left.Labels, right.Labels) &&
		slices.Equal(left.Buckets, right.Buckets)
}

// compatibilityMetricKey isolates collector type from exact metric name.
func compatibilityMetricKey(kind pluginapi.MetricType, name string) string {
	return string(kind) + ":" + name
}

// nativeMetricDefinition removes the compatibility request marker before registration.
func nativeMetricDefinition(definition pluginapi.MetricDefinition) pluginapi.MetricDefinition {
	definition = cloneMetricDefinition(definition)
	definition.Compatibility = false
	definition.Type = ""

	return definition
}

type dualCounter struct {
	exact  pluginapi.Counter
	native pluginapi.Counter
}

// Add publishes one counter delta to both collectors.
func (c dualCounter) Add(ctx context.Context, value float64, labels ...pluginapi.LabelValue) {
	c.exact.Add(ctx, value, labels...)
	c.native.Add(ctx, value, labels...)
}

type dualGauge struct {
	exact  pluginapi.Gauge
	native pluginapi.Gauge
}

// Set publishes one gauge value to both collectors.
func (g dualGauge) Set(ctx context.Context, value float64, labels ...pluginapi.LabelValue) {
	g.exact.Set(ctx, value, labels...)
	g.native.Set(ctx, value, labels...)
}

// Add publishes one gauge delta to both collectors.
func (g dualGauge) Add(ctx context.Context, value float64, labels ...pluginapi.LabelValue) {
	g.exact.Add(ctx, value, labels...)
	g.native.Add(ctx, value, labels...)
}

type dualHistogram struct {
	exact  pluginapi.Histogram
	native pluginapi.Histogram
}

// Observe publishes one histogram sample to both collectors.
func (h dualHistogram) Observe(ctx context.Context, value float64, labels ...pluginapi.LabelValue) {
	h.exact.Observe(ctx, value, labels...)
	h.native.Observe(ctx, value, labels...)
}

type dualSummary struct {
	exact  pluginapi.Summary
	native pluginapi.Summary
}

// Observe publishes one summary sample to both collectors.
func (s dualSummary) Observe(ctx context.Context, value float64, labels ...pluginapi.LabelValue) {
	s.exact.Observe(ctx, value, labels...)
	s.native.Observe(ctx, value, labels...)
}
