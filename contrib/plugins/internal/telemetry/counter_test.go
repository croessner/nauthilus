package telemetry

import (
	"context"
	"reflect"
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

type captureCounter struct {
	labels     []pluginapi.LabelValue
	calls      int
	panicOnAdd bool
}

// Add records detached dimensions or simulates an unavailable telemetry sink.
func (c *captureCounter) Add(_ context.Context, _ float64, labels ...pluginapi.LabelValue) {
	if c.panicOnAdd {
		panic("sink unavailable")
	}

	c.calls++

	c.labels = append([]pluginapi.LabelValue(nil), labels...)
}

func TestCounterMetricRejectsUnboundedLabels(t *testing.T) {
	sink := &captureCounter{}
	dimensions := []Dimension{{Name: "result", Values: []string{"accepted", "rejected"}}}

	counter, err := BindCounter(sink, dimensions)
	if err != nil {
		t.Fatal(err)
	}

	dimensions[0].Values[0] = "mutated-subject"

	for _, value := range []string{"192.0.2.1", "example.test", "account", "event-id", "redis:key", "mutated-subject"} {
		counter.Add(context.Background(), value)
	}

	if sink.calls != 0 {
		t.Fatal("unbounded labels reached the sink")
	}

	counter.Add(context.Background(), "accepted")

	if sink.calls != 1 {
		t.Fatal("known label was not emitted")
	}

	if !reflect.DeepEqual([]pluginapi.LabelValue{{Name: "result", Value: "accepted"}}, sink.labels) {
		t.Fatal("unexpected metric dimensions")
	}

	sink.panicOnAdd = true

	counter.Add(context.Background(), "rejected")
}

func TestCounterMetricRejectsInvalidDimensions(t *testing.T) {
	for _, dimensions := range [][]Dimension{nil, {{Name: "result"}},
		{{Name: "result", Values: []string{"ok", "ok"}}},
		{{Name: "result", Values: []string{"ok"}}, {Name: "result", Values: []string{"ok"}}}} {
		_, err := BindCounter(&captureCounter{}, dimensions)
		if err == nil {
			t.Fatal("invalid dimensions accepted")
		}
	}
}
