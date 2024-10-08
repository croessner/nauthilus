package metrics

import (
	"github.com/croessner/nauthilus/server/global"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/yuin/gopher-lua"
)

var (
	summaries  = make(map[string]*prometheus.SummaryVec)
	counters   = make(map[string]*prometheus.CounterVec)
	histograms = make(map[string]*prometheus.HistogramVec)
)

// createSummaryVec registers a new Prometheus SummaryVec metric with the provided name, help description, and label names.
func createSummaryVec(L *lua.LState) int {
	name := L.CheckString(1)
	help := L.CheckString(2)

	labelNames := make([]string, 0)

	if L.GetTop() > 2 {
		labelTable := L.CheckTable(3)
		labelTable.ForEach(func(_ lua.LValue, value lua.LValue) {
			labelNames = append(labelNames, value.String())
		})
	}

	// Check if the summary already exists
	if _, exists := summaries[name]; exists {
		return 0
	}

	summary := prometheus.NewSummaryVec(prometheus.SummaryOpts{
		Name: name,
		Help: help,
	}, labelNames)

	prometheus.MustRegister(summary)

	summaries[name] = summary

	return 0
}

// createCounterVec registers a new Prometheus CounterVec metric with the provided name, help description, and label names.
func createCounterVec(L *lua.LState) int {
	name := L.CheckString(1)
	help := L.CheckString(2)

	labelNames := make([]string, 0)

	if L.GetTop() > 2 {
		labelTable := L.CheckTable(3)
		labelTable.ForEach(func(_ lua.LValue, value lua.LValue) {
			labelNames = append(labelNames, value.String())
		})
	}

	// Check if the counter already exists
	if _, exists := counters[name]; exists {
		return 0
	}

	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: name,
		Help: help,
	}, labelNames)

	prometheus.MustRegister(counter)

	counters[name] = counter

	return 0
}

// createHistogramVec registers a new Prometheus HistogramVec with the specified name, help message, and optional label names.
func createHistogramVec(L *lua.LState) int {
	name := L.CheckString(1)
	help := L.CheckString(2)

	labelNames := make([]string, 0)

	if L.GetTop() > 2 {
		labelTable := L.CheckTable(3)
		labelTable.ForEach(func(_ lua.LValue, value lua.LValue) {
			labelNames = append(labelNames, value.String())
		})
	}

	// Check if the histogram already exists
	if _, exists := histograms[name]; exists {
		return 0
	}

	histogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: name,
		Help: help,
	}, labelNames)

	prometheus.MustRegister(histogram)

	histograms[name] = histogram

	return 0
}

// startSumaryTimer starts a Prometheus timer for a specified SummaryVec metric with the provided label values.
func startSumaryTimer(L *lua.LState) int {
	name := L.CheckString(1)
	labels := L.CheckTable(2)

	summary, exists := summaries[name]
	if !exists {
		L.ArgError(1, "SummaryVec not found")

		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	timer := prometheus.NewTimer(summary.With(labelValues))
	ud := L.NewUserData()
	ud.Value = timer

	L.Push(ud)

	return 1
}

// startHistogramTimer starts a timer for a Prometheus histogram with given name and labels.
func startHistogramTimer(L *lua.LState) int {
	name := L.CheckString(1)
	labels := L.CheckTable(2)

	histogram, exists := histograms[name]
	if !exists {
		L.ArgError(1, "HistogramVec not found")

		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	timer := prometheus.NewTimer(histogram.With(labelValues))
	ud := L.NewUserData()
	ud.Value = timer

	L.Push(ud)

	return 1
}

// stopTimer stops a running Prometheus timer, recording its duration in the underlying metric.
func stopTimer(L *lua.LState) int {
	ud := L.CheckUserData(1)

	if timer, ok := ud.Value.(*prometheus.Timer); ok {
		timer.ObserveDuration()
	}

	return 0
}

// incrementCounter increments a Prometheus counter based on the name and label values provided in the Lua state.
func incrementCounter(L *lua.LState) int {
	name := L.CheckString(1)
	labels := L.CheckTable(2)

	counter, exists := counters[name]
	if !exists {
		L.ArgError(1, "CounterVec not found")
		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	counter.With(labelValues).Inc()

	return 0
}

var exportsModPrometheus = map[string]lua.LGFunction{
	global.LuaFnCreateSummaryVec:    createSummaryVec,
	global.LuaFnCreateCounterVec:    createCounterVec,
	global.LuaFnCreateHistogramVec:  createHistogramVec,
	global.LuaFnStartSummaryTimer:   startSumaryTimer,
	global.LuaFnStartHistogramTimer: startHistogramTimer,
	global.LuaFnStopTimer:           stopTimer,
	global.LuaFnIncrementCounter:    incrementCounter,
}

// LoaderModPrometheus loads the Prometheus module into the given Lua state.
// It sets up the module's functions and pushes the module onto the stack.
// Returns 1 to indicate the number of return values for the Lua stack.
func LoaderModPrometheus(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exportsModPrometheus)

	L.Push(mod)

	return 1
}
