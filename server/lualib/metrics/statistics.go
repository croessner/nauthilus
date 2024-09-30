package metrics

import (
	"github.com/croessner/nauthilus/server/global"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/yuin/gopher-lua"
)

var (
	summaries = make(map[string]*prometheus.SummaryVec)
	counters  = make(map[string]*prometheus.CounterVec)
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

// startTimer starts a Prometheus timer for a specified SummaryVec metric with the provided label values.
func startTimer(L *lua.LState) int {
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
	global.LuaFnCreateSummaryVec: createSummaryVec,
	global.LuaFnCreateCounterVec: createCounterVec,
	global.LuaFnStartTimer:       startTimer,
	global.LuaFnStopTimer:        stopTimer,
	global.LuaFnIncrementCounter: incrementCounter,
}

func LoaderModPrometheus(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), exportsModPrometheus)

	L.Push(mod)

	return 1
}
