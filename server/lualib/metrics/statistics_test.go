package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	lua "github.com/yuin/gopher-lua"
)

// Helper function to run Lua code
func runLuaCode(L *lua.LState, code string) error {
	return L.DoString(code)
}

func TestCreateAndUseSummaryVec(t *testing.T) {
	L := lua.NewState()

	defer L.Close()

	// Register the module
	L.PreloadModule("prometheus", LoaderModPrometheus)

	err := runLuaCode(L, `
		local prometheus = require("prometheus")

		-- Create a SummaryVec
		prometheus.create_summary_vec("test_summary", "Test Summary", {"label1", "label2"})

		-- Start timer
		timer = prometheus.start_summary_timer("test_summary", {label1="value1", label2="value2"})

		-- Some operation...

		-- Stop timer
		prometheus.stop_timer(timer)
	`)

	if err != nil {
		t.Fatalf("Lua code execution failed: %v", err)
	}

	// Verify the summary was created and contains the recorded value.
	summary, exists := summaries["test_summary"]

	assert.True(t, exists, "SummaryVec 'test_summary' should exist")

	// Test whether the summary has recorded data
	count := testutil.CollectAndCount(summary)
	assert.NotZero(t, count, "Expected non-zero count in SummaryVec")
}

func TestCreateAndUseCounterVec(t *testing.T) {
	L := lua.NewState()

	defer L.Close()

	// Register the module
	L.PreloadModule("prometheus", LoaderModPrometheus)

	err := runLuaCode(L, `
		local prometheus = require("prometheus")
		-- Create a CounterVec

		prometheus.create_counter_vec("test_counter", "Test Counter", {"label1", "label2"})

		-- Increment counter
		prometheus.increment_counter("test_counter", {label1="value1", label2="value2"})
	`)

	if err != nil {
		t.Fatalf("Lua code execution failed: %v", err)
	}

	// Verify the counter was incremented
	counter, exists := counters["test_counter"]
	assert.True(t, exists, "CounterVec 'test_counter' should exist")

	// Test whether the counter has the expected value
	value := testutil.ToFloat64(counter.WithLabelValues("value1", "value2"))
	assert.Equal(t, float64(1), value, "Counter value should be 1")
}

func TestCreateAndUseHistogramVec(t *testing.T) {
	L := lua.NewState()

	defer L.Close()

	// Register the module
	L.PreloadModule("prometheus", LoaderModPrometheus)

	err := runLuaCode(L, `
		local prometheus = require("prometheus")
		
		-- Create a HistogramVec
		prometheus.create_histogram_vec("test_histogram", "Histogram test", {"label1", "label2"})
		
		-- Start timer
		timer = prometheus.start_histogram_timer("test_histogram", {label1 = "value1", label2 = "value2"})
		
		-- Some operation...
		
		-- Stop timer
		prometheus.stop_timer(timer)
	`)

	if err != nil {
		t.Fatalf("Lua code execution failed: %v", err)
	}

	// Verify the histogram was created and contains the recorded value.
	histogram, exists := histograms["test_histogram"]

	assert.True(t, exists, "HistogramVec 'test_histogram' should exist")

	// Test whether the histogram has recorded data
	count := testutil.CollectAndCount(histogram)
	assert.NotZero(t, count, "Expected non-zero count in HistogramVec")
}

func TestCreateAndUseGaugeVec(t *testing.T) {
	L := lua.NewState()

	defer L.Close()

	// Register the module
	L.PreloadModule("prometheus", LoaderModPrometheus)

	err := runLuaCode(L, `
		local prometheus = require("prometheus")
		
		-- Create a GaugeVec
		prometheus.create_gauge_vec("test_gauge", "Test Gauge", {"label1", "label2"})
		
		-- Set gauge value
		prometheus.set_gauge("test_gauge", 5.5, {label1 = "value1", label2 = "value2"})
	`)

	if err != nil {
		t.Fatalf("Lua code execution failed: %v", err)
	}

	// Verify the gauge was set correctly
	gauge, exists := gauges["test_gauge"]
	assert.True(t, exists, "GaugeVec 'test_gauge' should exist")

	// Test whether the gauge has the expected value
	value := testutil.ToFloat64(gauge.WithLabelValues("value1", "value2"))
	assert.Equal(t, 5.5, value, "Gauge value should be 5.5")
}
