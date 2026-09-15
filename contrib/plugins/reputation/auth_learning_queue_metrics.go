package main

import (
	"context"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type learningQueueTelemetry struct {
	pending pluginapi.Gauge
	active  pluginapi.Gauge
}

// newLearningQueueTelemetry exposes bounded queue occupancy independently of durable Kafka receipts.
func newLearningQueueTelemetry(metrics pluginapi.Metrics) (*learningQueueTelemetry, error) {
	result := &learningQueueTelemetry{}

	for _, entry := range []struct {
		target *pluginapi.Gauge
		name   string
	}{
		{&result.pending, "learning_queue_pending"},
		{&result.active, "learning_queue_active"},
	} {
		gauge, err := metrics.Gauge(pluginapi.MetricDefinition{Name: entry.name, Help: "Current authentication learning " + entry.name + "."})
		if err != nil {
			return nil, err
		}

		*entry.target = gauge
	}

	return result, nil
}

// change isolates optional metric sink failures from queue ownership and worker execution.
func (m *learningQueueTelemetry) change(pending, active float64) {
	if m == nil {
		return
	}

	defer func() { _ = recover() }()

	m.pending.Add(context.Background(), pending)
	m.active.Add(context.Background(), active)
}
