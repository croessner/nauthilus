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
	"fmt"
	"regexp"
	"slices"
	"sync"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
)

var (
	// ErrInvalidMetricDefinition is returned for unsupported plugin metric definitions.
	ErrInvalidMetricDefinition = errors.New("invalid plugin metric definition")

	// ErrInvalidMetricLabels is recorded when runtime labels do not match declarations.
	ErrInvalidMetricLabels = errors.New("invalid plugin metric labels")
)

const maxMetricLabelValueLength = 256

var metricNamePattern = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

var _ pluginapi.Metrics = (*MetricsFacade)(nil)

// MetricsFacade validates plugin metric definitions and runtime label values.
type MetricsFacade struct {
	mu      sync.Mutex
	scope   string
	metrics map[string]*metricHandle
}

// NewMetricsFacade returns a scoped metrics facade.
func NewMetricsFacade(scope string) *MetricsFacade {
	return &MetricsFacade{
		scope:   scope,
		metrics: make(map[string]*metricHandle),
	}
}

// Counter returns a declared counter handle.
func (m *MetricsFacade) Counter(definition pluginapi.MetricDefinition) (pluginapi.Counter, error) {
	return m.metric(metricKindCounter, definition)
}

// Gauge returns a declared gauge handle.
func (m *MetricsFacade) Gauge(definition pluginapi.MetricDefinition) (pluginapi.Gauge, error) {
	return m.metric(metricKindGauge, definition)
}

// Histogram returns a declared histogram handle.
func (m *MetricsFacade) Histogram(definition pluginapi.MetricDefinition) (pluginapi.Histogram, error) {
	return m.metric(metricKindHistogram, definition)
}

// Summary returns a declared summary handle.
func (m *MetricsFacade) Summary(definition pluginapi.MetricDefinition) (pluginapi.Summary, error) {
	return m.metric(metricKindSummary, definition)
}

// ObservationCount reports valid observations for tests and diagnostics.
func (m *MetricsFacade) ObservationCount(name string) int {
	if m == nil {
		return 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0

	for _, handle := range m.metrics {
		if handle.definition.Name == name {
			count += handle.observations
		}
	}

	return count
}

// metric registers or returns a duplicate-safe metric handle.
func (m *MetricsFacade) metric(kind metricKind, definition pluginapi.MetricDefinition) (*metricHandle, error) {
	if m == nil {
		return nil, errors.New("plugin metrics facade is nil")
	}

	if err := validateMetricDefinition(definition); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := string(kind) + ":" + definition.Name
	if existing, ok := m.metrics[key]; ok {
		return existing, nil
	}

	handle := &metricHandle{
		owner:       m,
		kind:        kind,
		definition:  cloneMetricDefinition(definition),
		declaredSet: labelSet(definition.Labels),
	}
	m.metrics[key] = handle

	return handle, nil
}

type metricKind string

const (
	metricKindCounter   metricKind = "counter"
	metricKindGauge     metricKind = "gauge"
	metricKindHistogram metricKind = "histogram"
	metricKindSummary   metricKind = "summary"
)

type metricHandle struct {
	owner        *MetricsFacade
	declaredSet  map[string]struct{}
	definition   pluginapi.MetricDefinition
	kind         metricKind
	observations int
	invalid      int
}

// Add records a counter or gauge delta when labels are valid.
func (h *metricHandle) Add(ctx context.Context, value float64, labels ...pluginapi.LabelValue) {
	h.observe(ctx, value, labels...)
}

// Set records a gauge value when labels are valid.
func (h *metricHandle) Set(ctx context.Context, value float64, labels ...pluginapi.LabelValue) {
	h.observe(ctx, value, labels...)
}

// Observe records a histogram or summary sample when labels are valid.
func (h *metricHandle) Observe(ctx context.Context, value float64, labels ...pluginapi.LabelValue) {
	h.observe(ctx, value, labels...)
}

// observe validates labels and records one in-memory observation.
func (h *metricHandle) observe(_ context.Context, _ float64, labels ...pluginapi.LabelValue) {
	if h == nil || h.owner == nil {
		return
	}

	h.owner.mu.Lock()
	defer h.owner.mu.Unlock()

	if err := h.validateLabels(labels); err != nil {
		h.invalid++

		return
	}

	h.observations++
}

// validateLabels rejects undeclared, duplicate, empty, and overlong label values.
func (h *metricHandle) validateLabels(labels []pluginapi.LabelValue) error {
	seen := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		if _, declared := h.declaredSet[label.Name]; !declared {
			return fmt.Errorf("%w: unknown label %q", ErrInvalidMetricLabels, label.Name)
		}

		if _, duplicate := seen[label.Name]; duplicate {
			return fmt.Errorf("%w: duplicate label %q", ErrInvalidMetricLabels, label.Name)
		}

		if label.Value == "" || len(label.Value) > maxMetricLabelValueLength {
			return fmt.Errorf("%w: invalid value for label %q", ErrInvalidMetricLabels, label.Name)
		}

		seen[label.Name] = struct{}{}
	}

	return nil
}

// validateMetricDefinition checks metric naming and declared labels.
func validateMetricDefinition(definition pluginapi.MetricDefinition) error {
	if !metricNamePattern.MatchString(definition.Name) {
		return fmt.Errorf("%w: invalid name %q", ErrInvalidMetricDefinition, definition.Name)
	}

	seen := make(map[string]struct{}, len(definition.Labels))
	for _, label := range definition.Labels {
		if !metricNamePattern.MatchString(label) {
			return fmt.Errorf("%w: invalid label %q", ErrInvalidMetricDefinition, label)
		}

		if _, duplicate := seen[label]; duplicate {
			return fmt.Errorf("%w: duplicate label %q", ErrInvalidMetricDefinition, label)
		}

		seen[label] = struct{}{}
	}

	return nil
}

// cloneMetricDefinition copies mutable metric definition fields.
func cloneMetricDefinition(definition pluginapi.MetricDefinition) pluginapi.MetricDefinition {
	definition.Labels = slices.Clone(definition.Labels)
	definition.Buckets = slices.Clone(definition.Buckets)

	return definition
}

// labelSet returns declared labels as a set.
func labelSet(labels []string) map[string]struct{} {
	set := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		set[label] = struct{}{}
	}

	return set
}
