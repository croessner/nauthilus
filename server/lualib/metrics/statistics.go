// Copyright (C) 2024 Christian Rößner
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

package metrics

import (
	"context"
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/prometheus/client_golang/prometheus"
	lua "github.com/yuin/gopher-lua"
)

// PrometheusManager manages Prometheus metrics for Lua.
type PrometheusManager struct {
	*lualib.BaseManager
}

// NewPrometheusManager creates a new PrometheusManager.
func NewPrometheusManager(ctx context.Context, cfg config.File, logger *slog.Logger) *PrometheusManager {
	return &PrometheusManager{
		BaseManager: lualib.NewBaseManager(ctx, cfg, logger),
	}
}

var (
	summaries  = make(map[string]*prometheus.SummaryVec)
	counters   = make(map[string]*prometheus.CounterVec)
	histograms = make(map[string]*prometheus.HistogramVec)
	gauges     = make(map[string]*prometheus.GaugeVec)
)

// warnOnceMissing tracks missing metric names to avoid log flooding
var warnOnceMissing = struct{ m map[string]bool }{m: map[string]bool{}}

func warnIfMissing(kind, name string) {
	key := kind + ":" + name
	if !warnOnceMissing.m[key] {
		warnOnceMissing.m[key] = true

		level.Warn(log.Logger).Log(definitions.LogKeyMsg, "Prometheus metric not found", "kind", kind, "metric", name)
	}
}

// createSummaryVec registers a new Prometheus SummaryVec metric with the provided name, help description, and label names.
func (m *PrometheusManager) createSummaryVec(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	help := stack.CheckString(2)

	labelNames := make([]string, 0)

	if stack.GetTop() > 2 {
		labelTable := stack.CheckTable(3)
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
func (m *PrometheusManager) createCounterVec(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	help := stack.CheckString(2)

	labelNames := make([]string, 0)

	if stack.GetTop() > 2 {
		labelTable := stack.CheckTable(3)
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
func (m *PrometheusManager) createHistogramVec(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	help := stack.CheckString(2)

	labelNames := make([]string, 0)

	if stack.GetTop() > 2 {
		labelTable := stack.CheckTable(3)
		labelTable.ForEach(func(_ lua.LValue, value lua.LValue) {
			labelNames = append(labelNames, value.String())
		})
	}

	// Check if the histogram already exists
	if _, exists := histograms[name]; exists {
		return 0
	}

	histogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    name,
		Help:    help,
		Buckets: prometheus.ExponentialBuckets(0.001, 1.75, 15),
	}, labelNames)

	prometheus.MustRegister(histogram)

	histograms[name] = histogram

	return 0
}

// createGaugeVec registers a new Prometheus GaugeVec metric with the provided name, help description, and label names.
func (m *PrometheusManager) createGaugeVec(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	help := stack.CheckString(2)

	labelNames := make([]string, 0)

	if stack.GetTop() > 2 {
		labelTable := stack.CheckTable(3)
		labelTable.ForEach(func(_ lua.LValue, value lua.LValue) {
			labelNames = append(labelNames, value.String())
		})
	}

	// Check if the histogram already exists
	if _, exists := gauges[name]; exists {
		return 0
	}

	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	}, labelNames)

	prometheus.MustRegister(gauge)

	gauges[name] = gauge

	return 0
}

// startSumaryTimer starts a Prometheus timer for a specified SummaryVec metric with the provided label values.
func (m *PrometheusManager) startSumaryTimer(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	labels := stack.CheckTable(2)

	summary, exists := summaries[name]
	if !exists {
		warnIfMissing("summary", name)

		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	timer := prometheus.NewTimer(summary.With(labelValues))
	ud := L.NewUserData()
	ud.Value = timer

	return stack.PushResults(ud, lua.LNil)
}

// startHistogramTimer starts a timer for a Prometheus histogram with given name and labels.
func (m *PrometheusManager) startHistogramTimer(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	labels := stack.CheckTable(2)

	histogram, exists := histograms[name]
	if !exists {
		warnIfMissing("histogram", name)

		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	timer := prometheus.NewTimer(histogram.With(labelValues))
	ud := L.NewUserData()
	ud.Value = timer

	return stack.PushResults(ud, lua.LNil)
}

// stopTimer stops a running Prometheus timer, recording its duration in the underlying metric.
func (m *PrometheusManager) stopTimer(L *lua.LState) int {
	stack := luastack.NewManager(L)

	ud := stack.CheckUserData(1)
	if ud == nil {
		L.ArgError(1, "timer expected")

		return 0
	}

	timer, ok := ud.Value.(*prometheus.Timer)
	if !ok || timer == nil {
		L.ArgError(1, "timer expected")

		return 0
	}

	timer.ObserveDuration()

	return 0
}

// incrementCounter increments a Prometheus counter based on the name and label values provided in the Lua state.
func (m *PrometheusManager) incrementCounter(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	labels := stack.CheckTable(2)

	counter, exists := counters[name]
	if !exists {
		warnIfMissing("counter", name)

		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	counter.With(labelValues).Inc()

	return 0
}

// addGauge adds a value to a Prometheus gauge identified by name and labels, creating label mappings from Lua table.
func (m *PrometheusManager) addGauge(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	value := stack.CheckNumber(2)
	labels := stack.CheckTable(3)

	gauge, exists := gauges[name]
	if !exists {
		warnIfMissing("gauge", name)

		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	gauge.With(labelValues).Add(float64(value))

	return 0
}

// subGauge subtracts a specified value from a GaugeVec identified by name and labeled with the provided labels.
func (m *PrometheusManager) subGauge(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	value := stack.CheckNumber(2)
	labels := stack.CheckTable(3)

	gauge, exists := gauges[name]
	if !exists {
		warnIfMissing("gauge", name)

		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	gauge.With(labelValues).Sub(float64(value))

	return 0
}

// setGauge sets the value of a GaugeVec identified by the given name and labels in Lua.
func (m *PrometheusManager) setGauge(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	value := stack.CheckNumber(2)
	labels := stack.CheckTable(3)

	gauge, exists := gauges[name]
	if !exists {
		warnIfMissing("gauge", name)

		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	gauge.With(labelValues).Set(float64(value))

	return 0
}

// incrementGauge increments the value of a Prometheus GaugeVec metric based on the label values provided.
func (m *PrometheusManager) incrementGauge(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	labels := stack.CheckTable(2)

	gauge, exists := gauges[name]
	if !exists {
		warnIfMissing("gauge", name)

		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	gauge.With(labelValues).Inc()

	return 0
}

// decrementGauge decreases the value of a specified Gauge within a collection of GaugeVec, based on the provided labels.
func (m *PrometheusManager) decrementGauge(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	labels := stack.CheckTable(2)

	gauge, exists := gauges[name]
	if !exists {
		warnIfMissing("gauge", name)

		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	gauge.With(labelValues).Dec()

	return 0
}

// touchCounter creates a labeled child for a CounterVec without incrementing it.
// This ensures a zero-valued time series is exposed to Prometheus on scrape.
func (m *PrometheusManager) touchCounter(L *lua.LState) int {
	stack := luastack.NewManager(L)
	name := stack.CheckString(1)
	labels := stack.CheckTable(2)

	counter, exists := counters[name]
	if !exists {
		warnIfMissing("counter", name)

		return 0
	}

	labelValues := make(map[string]string)
	labels.ForEach(func(key, value lua.LValue) {
		labelValues[key.String()] = value.String()
	})

	// Create the child without incrementing; Go client will expose 0
	counter.With(labelValues)

	return 0
}

// LoaderModPrometheus loads and initializes the Prometheus module with metric-related functions for use in Lua scripts.
func LoaderModPrometheus(ctx context.Context, cfg config.File, logger *slog.Logger) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewPrometheusManager(ctx, cfg, logger)

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnCreateSummaryVec:    manager.createSummaryVec,
			definitions.LuaFnCreateCounterVec:    manager.createCounterVec,
			definitions.LuaFnCreateHistogramVec:  manager.createHistogramVec,
			definitions.LuaFnStartSummaryTimer:   manager.startSumaryTimer,
			definitions.LuaFnStartHistogramTimer: manager.startHistogramTimer,
			definitions.LuaFnStopTimer:           manager.stopTimer,
			definitions.LuaFnIncrementCounter:    manager.incrementCounter,
			definitions.LuaFnCreateGaugeVec:      manager.createGaugeVec,
			definitions.LuaFNAddGauge:            manager.addGauge,
			definitions.LuaFnSubGauge:            manager.subGauge,
			definitions.LuaFnSetGauge:            manager.setGauge,
			definitions.LuaFnIncrementGauge:      manager.incrementGauge,
			definitions.LuaFnDecrementGauge:      manager.decrementGauge,
			definitions.LuaFnTouchCounter:        manager.touchCounter,
		})

		return stack.PushResult(mod)
	}
}
