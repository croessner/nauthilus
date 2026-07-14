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
	"strings"
	"sync"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var (
	// ErrInvalidMetricDefinition is returned for unsupported plugin metric definitions.
	ErrInvalidMetricDefinition = errors.New("invalid plugin metric definition")

	// ErrInvalidMetricLabels is recorded when runtime labels do not match declarations.
	ErrInvalidMetricLabels = errors.New("invalid plugin metric labels")
)

const (
	maxMetricLabelValueLength = 256
	pluginMetricNamespace     = "nauthilus_plugin"
	pluginMetricScopeLabel    = "plugin_scope"
)

var metricNamePattern = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

var _ pluginapi.Metrics = (*MetricsFacade)(nil)

// MetricsFacade validates plugin metric definitions and runtime label values.
type MetricsFacade struct {
	mu         sync.Mutex
	registerer prometheus.Registerer
	scope      string
	metrics    map[string]*metricHandle
	exactNames bool
}

// NewMetricsFacade returns a scoped metrics facade.
func NewMetricsFacade(scope string) *MetricsFacade {
	return NewMetricsFacadeWithRegisterer(scope, prometheus.DefaultRegisterer)
}

// NewMetricsFacadeWithRegisterer returns a scoped metrics facade backed by a Prometheus registerer.
func NewMetricsFacadeWithRegisterer(scope string, registerer prometheus.Registerer) *MetricsFacade {
	return &MetricsFacade{
		scope:      scope,
		registerer: registerer,
		metrics:    make(map[string]*metricHandle),
	}
}

// newExactMetricsFacade returns a facade that preserves exact names and labels for trusted compatibility metrics.
func newExactMetricsFacade(registerer prometheus.Registerer) *MetricsFacade {
	return &MetricsFacade{
		registerer: registerer,
		metrics:    make(map[string]*metricHandle),
		exactNames: true,
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

	if definition.Compatibility {
		return nil, ErrCompatibilityMetricDenied
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

	handle, err := m.newMetricHandle(kind, definition)
	if err != nil {
		return nil, err
	}

	m.metrics[key] = handle

	return handle, nil
}

// newMetricHandle registers one Prometheus collector and returns its plugin handle.
func (m *MetricsFacade) newMetricHandle(kind metricKind, definition pluginapi.MetricDefinition) (*metricHandle, error) {
	definition = cloneMetricDefinition(definition)
	collectorName := prometheusMetricName(m.scope, definition.Name)
	labelNames := prometheusLabelNames(definition.Labels)
	if m.exactNames {
		collectorName = definition.Name
		labelNames = slices.Clone(definition.Labels)
	}
	handle := &metricHandle{
		owner:          m,
		kind:           kind,
		definition:     definition,
		declaredLabels: slices.Clone(definition.Labels),
		declaredSet:    labelSet(definition.Labels),
	}

	switch kind {
	case metricKindCounter:
		collector, err := registeredCollector(m.registerer, prometheus.NewCounterVec(
			prometheus.CounterOpts{Name: collectorName, Help: metricHelp(definition)},
			labelNames,
		), true, nil)
		if err != nil {
			return nil, err
		}

		handle.counter = collector
	case metricKindGauge:
		collector, err := registeredCollector(m.registerer, prometheus.NewGaugeVec(
			prometheus.GaugeOpts{Name: collectorName, Help: metricHelp(definition)},
			labelNames,
		), true, nil)
		if err != nil {
			return nil, err
		}

		handle.gauge = collector
	case metricKindHistogram:
		collector, err := registeredCollector(m.registerer, prometheus.NewHistogramVec(
			prometheus.HistogramOpts{Name: collectorName, Help: metricHelp(definition), Buckets: metricBuckets(definition)},
			labelNames,
		), true, func(existing *prometheus.HistogramVec) error {
			return validateHistogramBuckets(existing, len(labelNames), metricBuckets(definition))
		})
		if err != nil {
			return nil, err
		}

		handle.histogram = collector
	case metricKindSummary:
		collector, err := registeredCollector(m.registerer, prometheus.NewSummaryVec(
			prometheus.SummaryOpts{Name: collectorName, Help: metricHelp(definition)},
			labelNames,
		), true, nil)
		if err != nil {
			return nil, err
		}

		handle.summary = collector
	}

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
	owner          *MetricsFacade
	counter        *prometheus.CounterVec
	gauge          *prometheus.GaugeVec
	histogram      *prometheus.HistogramVec
	summary        *prometheus.SummaryVec
	declaredLabels []string
	declaredSet    map[string]struct{}
	definition     pluginapi.MetricDefinition
	kind           metricKind
	observations   int
	invalid        int
}

// Add records a counter or gauge delta when labels are valid.
func (h *metricHandle) Add(ctx context.Context, value float64, labels ...pluginapi.LabelValue) {
	h.observe(ctx, metricOperationAdd, value, labels...)
}

// Set records a gauge value when labels are valid.
func (h *metricHandle) Set(ctx context.Context, value float64, labels ...pluginapi.LabelValue) {
	h.observe(ctx, metricOperationSet, value, labels...)
}

// Observe records a histogram or summary sample when labels are valid.
func (h *metricHandle) Observe(ctx context.Context, value float64, labels ...pluginapi.LabelValue) {
	h.observe(ctx, metricOperationObserve, value, labels...)
}

// observe validates labels and records one Prometheus-backed observation.
func (h *metricHandle) observe(_ context.Context, operation metricOperation, value float64, labels ...pluginapi.LabelValue) {
	if h == nil || h.owner == nil {
		return
	}

	h.owner.mu.Lock()

	if err := h.validateLabels(labels); err != nil {
		h.invalid++
		h.owner.mu.Unlock()

		return
	}

	if h.kind == metricKindCounter && value < 0 {
		h.invalid++
		h.owner.mu.Unlock()

		return
	}

	labelValues := h.prometheusLabelValues(labels)
	h.observations++
	h.owner.mu.Unlock()

	h.observePrometheus(operation, value, labelValues)
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

	if len(seen) != len(h.declaredSet) {
		return fmt.Errorf("%w: missing declared labels", ErrInvalidMetricLabels)
	}

	return nil
}

// prometheusLabelValues orders plugin labels for the underlying Prometheus vector.
func (h *metricHandle) prometheusLabelValues(labels []pluginapi.LabelValue) []string {
	byName := make(map[string]string, len(labels))

	for _, label := range labels {
		byName[label.Name] = label.Value
	}

	values := make([]string, 0, len(h.declaredLabels)+1)
	if !h.owner.exactNames {
		values = append(values, h.owner.scope)
	}

	for _, label := range h.declaredLabels {
		values = append(values, byName[label])
	}

	return values
}

type metricOperation string

const (
	metricOperationAdd     metricOperation = "add"
	metricOperationSet     metricOperation = "set"
	metricOperationObserve metricOperation = "observe"
)

// observePrometheus writes the validated operation to the registered collector.
func (h *metricHandle) observePrometheus(operation metricOperation, value float64, labels []string) {
	switch h.kind {
	case metricKindCounter:
		h.counter.WithLabelValues(labels...).Add(value)
	case metricKindGauge:
		if operation == metricOperationAdd {
			h.gauge.WithLabelValues(labels...).Add(value)

			return
		}

		h.gauge.WithLabelValues(labels...).Set(value)
	case metricKindHistogram:
		h.histogram.WithLabelValues(labels...).Observe(value)
	case metricKindSummary:
		h.summary.WithLabelValues(labels...).Observe(value)
	}
}

// validateMetricDefinition checks metric naming and declared labels.
func validateMetricDefinition(definition pluginapi.MetricDefinition) error {
	if !metricNamePattern.MatchString(definition.Name) {
		return fmt.Errorf("%w: invalid name %q", ErrInvalidMetricDefinition, definition.Name)
	}

	seen := make(map[string]struct{}, len(definition.Labels))
	for _, label := range definition.Labels {
		if label == pluginMetricScopeLabel {
			return fmt.Errorf("%w: reserved label %q", ErrInvalidMetricDefinition, label)
		}

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

// prometheusMetricName returns the scoped collector name used in the host registry.
func prometheusMetricName(scope string, name string) string {
	parts := []string{pluginMetricNamespace}
	if scope != "" {
		parts = append(parts, sanitizeMetricNamePart(scope))
	}

	parts = append(parts, sanitizeMetricNamePart(name))

	return strings.Join(parts, "_")
}

// sanitizeMetricNamePart keeps plugin scope and names valid as Prometheus name fragments.
func sanitizeMetricNamePart(value string) string {
	var builder strings.Builder

	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
		case char >= 'A' && char <= 'Z':
			builder.WriteRune(char)
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
		case char == '_':
			builder.WriteRune(char)
		default:
			builder.WriteRune('_')
		}
	}

	if builder.Len() == 0 {
		return "metric"
	}

	return builder.String()
}

// prometheusLabelNames prepends the host-owned plugin scope label to declared labels.
func prometheusLabelNames(labels []string) []string {
	names := make([]string, 0, len(labels)+1)
	names = append(names, pluginMetricScopeLabel)
	names = append(names, labels...)

	return names
}

// metricHelp returns a non-empty help string for Prometheus registration.
func metricHelp(definition pluginapi.MetricDefinition) string {
	if definition.Help != "" {
		return definition.Help
	}

	return "Native plugin metric " + definition.Name
}

// metricBuckets returns explicit histogram buckets or the Prometheus default set.
func metricBuckets(definition pluginapi.MetricDefinition) []float64 {
	if len(definition.Buckets) == 0 {
		return prometheus.DefBuckets
	}

	return slices.Clone(definition.Buckets)
}

// registeredCollector registers a collector or returns an exactly compatible existing collector.
func registeredCollector[T prometheus.Collector](
	registerer prometheus.Registerer,
	collector T,
	reuse bool,
	validateExisting func(T) error,
) (T, error) {
	var zero T

	if registerer == nil {
		return collector, nil
	}

	if err := registerer.Register(collector); err != nil {
		var already prometheus.AlreadyRegisteredError
		if reuse && errors.As(err, &already) {
			if !sameCollectorDescriptors(already.ExistingCollector, collector) {
				return zero, errors.New("existing plugin metric descriptor differs from requested contract")
			}

			existing, ok := already.ExistingCollector.(T)
			if !ok {
				return zero, err
			}

			if validateExisting != nil {
				if validateErr := validateExisting(existing); validateErr != nil {
					return zero, validateErr
				}
			}

			return existing, nil
		}

		return zero, err
	}

	return collector, nil
}

// sameCollectorDescriptors compares complete ordered descriptor strings for strict compatibility reuse.
func sameCollectorDescriptors(left prometheus.Collector, right prometheus.Collector) bool {
	return slices.Equal(collectorDescriptorStrings(left), collectorDescriptorStrings(right))
}

// collectorDescriptorStrings drains and sorts immutable collector descriptor representations.
func collectorDescriptorStrings(collector prometheus.Collector) []string {
	descriptors := make(chan *prometheus.Desc)

	go func() {
		collector.Describe(descriptors)
		close(descriptors)
	}()

	result := make([]string, 0)
	for descriptor := range descriptors {
		result = append(result, descriptor.String())
	}

	slices.Sort(result)

	return result
}

// validateHistogramBuckets rejects reuse when Prometheus descriptors match but bucket boundaries differ.
func validateHistogramBuckets(existing *prometheus.HistogramVec, labelCount int, expected []float64) error {
	actual, err := histogramBucketBounds(existing, labelCount)
	if err != nil {
		return err
	}

	if !slices.Equal(actual, expected) {
		return fmt.Errorf("existing plugin histogram buckets differ: got %v, want %v", actual, expected)
	}

	return nil
}

// histogramBucketBounds reads bucket boundaries without retaining a compatibility probe series.
func histogramBucketBounds(histogram *prometheus.HistogramVec, labelCount int) ([]float64, error) {
	metric := firstCollectedMetric(histogram)
	if metric == nil {
		labels := compatibilityProbeLabels(histogram, labelCount)

		observer, err := histogram.GetMetricWithLabelValues(labels...)
		if err != nil {
			return nil, fmt.Errorf("inspect existing plugin histogram: %w", err)
		}

		var ok bool

		metric, ok = observer.(prometheus.Metric)
		if !ok {
			return nil, errors.New("existing plugin histogram does not expose metric metadata")
		}

		defer histogram.DeleteLabelValues(labels...)
	}

	encoded := &dto.Metric{}
	if err := metric.Write(encoded); err != nil {
		return nil, fmt.Errorf("inspect existing plugin histogram buckets: %w", err)
	}

	buckets := encoded.GetHistogram().GetBucket()
	result := make([]float64, 0, len(buckets))

	for _, bucket := range buckets {
		result = append(result, bucket.GetUpperBound())
	}

	return result, nil
}

// firstCollectedMetric returns one existing series while draining the collector safely.
func firstCollectedMetric(collector prometheus.Collector) prometheus.Metric {
	metrics := make(chan prometheus.Metric)

	go func() {
		collector.Collect(metrics)
		close(metrics)
	}()

	var first prometheus.Metric
	for metric := range metrics {
		if first == nil {
			first = metric
		}
	}

	return first
}

// compatibilityProbeLabels builds collision-resistant temporary values for an uninitialized vector.
func compatibilityProbeLabels(histogram *prometheus.HistogramVec, labelCount int) []string {
	labels := make([]string, labelCount)
	for index := range labels {
		labels[index] = fmt.Sprintf("__nauthilus_compatibility_probe_%p_%d__", histogram, index)
	}

	return labels
}
