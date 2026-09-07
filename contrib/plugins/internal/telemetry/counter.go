// Package telemetry confines native plugin measurements to immutable bounded vocabularies.
package telemetry

import (
	"context"
	"errors"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

var errDimensions = errors.New("invalid bounded metric dimensions")

// maxValueLength accommodates a qualified target with two 64-byte components and its separator.
const maxValueLength = 129

// Dimension defines one operator-compiled or protocol-fixed metric vocabulary.
type Dimension struct {
	Values []string
	Name   string
}

// Counter prevents request material and sink failures from crossing the telemetry boundary.
type Counter struct {
	sink    pluginapi.Counter
	allowed []map[string]struct{}
	names   []string
}

// BindCounter freezes finite dimensions independently of the caller's source slices.
func BindCounter(sink pluginapi.Counter, dimensions []Dimension) (*Counter, error) {
	if sink == nil || len(dimensions) == 0 || len(dimensions) > 6 {
		return nil, errDimensions
	}

	result := &Counter{sink: sink}

	names := make(map[string]struct{}, len(dimensions))
	for _, dimension := range dimensions {
		if dimension.Name == "" || len(dimension.Name) > 64 || len(dimension.Values) == 0 || len(dimension.Values) > 128 {
			return nil, errDimensions
		}

		if _, exists := names[dimension.Name]; exists {
			return nil, errDimensions
		}

		names[dimension.Name] = struct{}{}

		values, err := compileDimension(dimension)
		if err != nil {
			return nil, err
		}

		result.names = append(result.names, dimension.Name)
		result.allowed = append(result.allowed, values)
	}

	return result, nil
}

// compileDimension validates one finite value set without retaining caller-owned slices.
func compileDimension(dimension Dimension) (map[string]struct{}, error) {
	values := make(map[string]struct{}, len(dimension.Values))
	for _, value := range dimension.Values {
		if _, exists := values[value]; exists || value == "" || len(value) > maxValueLength {
			return nil, errDimensions
		}

		values[value] = struct{}{}
	}

	return values, nil
}

// RegisterCounter creates a host-owned collector whose label order matches its closed dimensions.
func RegisterCounter(metrics pluginapi.Metrics, name, help string, dimensions ...Dimension) (*Counter, error) {
	if metrics == nil {
		return nil, errDimensions
	}

	labels := make([]string, 0, len(dimensions))
	for _, dimension := range dimensions {
		labels = append(labels, dimension.Name)
	}

	sink, err := metrics.Counter(pluginapi.MetricDefinition{Name: name, Help: help, Type: pluginapi.MetricTypeCounter, Labels: labels})
	if err != nil {
		return nil, err
	}

	return BindCounter(sink, dimensions)
}

// Add emits only a complete allowlisted tuple and isolates a failing optional diagnostic sink.
func (c *Counter) Add(ctx context.Context, values ...string) {
	if c == nil || len(values) != len(c.names) {
		return
	}

	labels := make([]pluginapi.LabelValue, len(values))
	for index, value := range values {
		if _, ok := c.allowed[index][value]; !ok {
			return
		}

		labels[index] = pluginapi.LabelValue{Name: c.names[index], Value: value}
	}

	defer func() { _ = recover() }()

	c.sink.Add(ctx, 1, labels...)
}
