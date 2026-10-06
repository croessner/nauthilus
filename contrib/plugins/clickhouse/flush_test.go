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

package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const testFlushInterval = "30s"

func TestDecodeModuleConfigFlushInterval(t *testing.T) {
	cases := []struct {
		value   any
		name    string
		want    time.Duration
		wantErr bool
	}{
		{name: "unset keeps size-only batching", want: 0},
		{name: "zero disables timer", value: "0", want: 0},
		{name: "zero duration disables timer", value: "0s", want: 0},
		{name: "positive duration", value: "15s", want: 15 * time.Second},
		{name: "negative duration", value: "-1s", wantErr: true},
		{name: "unparsable duration", value: "soon", wantErr: true},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			raw := map[string]any{}
			if testCase.value != nil {
				raw["flush_interval"] = testCase.value
			}

			cfg, err := decodeModuleConfig(pluginregistry.NewConfigView(raw))
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("decodeModuleConfig(%#v) error = nil, want validation error", raw)
				}

				return
			}

			if err != nil {
				t.Fatalf("decodeModuleConfig(%#v) error = %v", raw, err)
			}

			if cfg.FlushInterval != testCase.want {
				t.Fatalf("FlushInterval = %s, want %s", cfg.FlushInterval, testCase.want)
			}
		})
	}
}

func TestStopFlushesPendingSubBatch(t *testing.T) {
	harness := startTestRunner(t, batchingModule(map[string]any{}), testRunnerOptions{})

	enqueueRows(t, harness, 2)

	if got := len(harness.transport.requests); got != 0 {
		t.Fatalf("HTTP calls before Stop = %d, want 0", got)
	}

	harness.stop(t)

	assertNDJSONLines(t, harness.transport.onlyRequest().body, 2)

	if rows := popCachedRows(t, harness.host, testCacheKey); len(rows) != 0 {
		t.Fatalf("cached rows after Stop = %d, want 0", len(rows))
	}
}

func TestStopFlushFailureDoesNotBlockShutdown(t *testing.T) {
	transport := &recordingTransport{statusCode: http.StatusInternalServerError}
	harness := startTestRunner(t, batchingModule(map[string]any{}), testRunnerOptions{transport: transport})

	enqueueRows(t, harness, 1)
	harness.stop(t)

	if got := len(transport.requests); got != 1 {
		t.Fatalf("HTTP calls on Stop = %d, want 1", got)
	}

	if err := harness.plugin.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}

	if got := len(transport.requests); got != 1 {
		t.Fatalf("HTTP calls after second Stop = %d, want 1", got)
	}
}

func TestStopWithoutStartIsSafe(t *testing.T) {
	plugin := NewPlugin()

	for range 2 {
		if err := plugin.Stop(context.Background()); err != nil {
			t.Fatalf("Stop() without Start error = %v", err)
		}
	}
}

func TestFlushIntervalFlushesSubBatch(t *testing.T) {
	tickers := &manualTickerFactory{}
	harness := startTestRunner(t, batchingModule(map[string]any{"flush_interval": testFlushInterval}), testRunnerOptions{tickers: tickers})

	defer harness.stop(t)

	ticker := tickers.only(t)
	if ticker.interval != 30*time.Second {
		t.Fatalf("ticker interval = %s, want 30s", ticker.interval)
	}

	enqueueRows(t, harness, 2)
	ticker.tickAndWait()

	assertNDJSONLines(t, harness.transport.onlyRequest().body, 2)

	ticker.tickAndWait()

	if got := len(harness.transport.requests); got != 1 {
		t.Fatalf("HTTP calls after empty tick = %d, want 1", got)
	}
}

func TestFlushIntervalUsesWallClockTicker(t *testing.T) {
	harness := startTestRunner(t, batchingModule(map[string]any{"flush_interval": "10ms"}), testRunnerOptions{})

	defer harness.stop(t)

	enqueueRows(t, harness, 1)

	deadline := time.Now().Add(5 * time.Second)
	for harness.transport.requestCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("wall-clock flush worker did not flush the sub-batch")
		}

		time.Sleep(5 * time.Millisecond)
	}
}

func TestZeroFlushIntervalKeepsSizeOnlyBatching(t *testing.T) {
	for _, value := range []any{nil, "0s"} {
		raw := map[string]any{}
		if value != nil {
			raw["flush_interval"] = value
		}

		tickers := &manualTickerFactory{}
		harness := startTestRunner(t, batchingModule(raw), testRunnerOptions{tickers: tickers})

		if got := tickers.count(); got != 0 {
			t.Fatalf("flush_interval=%v started %d tickers, want 0", value, got)
		}

		enqueueRows(t, harness, 2)

		if got := len(harness.transport.requests); got != 0 {
			t.Fatalf("flush_interval=%v HTTP calls = %d, want 0", value, got)
		}

		rows := popCachedRows(t, harness.host, testCacheKey)
		if len(rows) != 2 {
			t.Fatalf("flush_interval=%v cached rows = %d, want 2", value, len(rows))
		}

		harness.stop(t)
	}
}

func TestStopTerminatesFlushWorker(t *testing.T) {
	tickers := &manualTickerFactory{}
	harness := startTestRunner(t, batchingModule(map[string]any{"flush_interval": testFlushInterval}), testRunnerOptions{tickers: tickers})
	ticker := tickers.only(t)

	harness.stop(t)

	if !ticker.stopped.Load() {
		t.Fatal("flush worker still owns its ticker after Stop")
	}

	if ticker.tryTick() {
		t.Fatal("flush worker still receives ticks after Stop")
	}
}

func TestReconfigureRestartsFlushWorkerWithNewInterval(t *testing.T) {
	tickers := &manualTickerFactory{}
	harness := startTestRunner(t, batchingModule(map[string]any{"flush_interval": testFlushInterval}), testRunnerOptions{tickers: tickers})

	defer harness.stop(t)

	first := tickers.only(t)

	reconfigureBatching(t, harness, map[string]any{"flush_interval": testFlushInterval})

	if got := tickers.count(); got != 1 {
		t.Fatalf("unchanged interval started %d tickers, want 1", got)
	}

	reconfigureBatching(t, harness, map[string]any{"flush_interval": "5s"})

	if !first.stopped.Load() || first.tryTick() {
		t.Fatal("previous flush worker survived Reconfigure")
	}

	second := tickers.last(t)
	if second.interval != 5*time.Second {
		t.Fatalf("reconfigured ticker interval = %s, want 5s", second.interval)
	}

	enqueueRows(t, harness, 1)
	second.tickAndWait()
	assertNDJSONLines(t, harness.transport.onlyRequest().body, 1)

	reconfigureBatching(t, harness, map[string]any{"flush_interval": "0s"})

	if !second.stopped.Load() || tickers.count() != 2 {
		t.Fatalf("disabling flush_interval left a worker running (tickers = %d)", tickers.count())
	}
}

func TestSizeAndTimerFlushesDeliverEachRowOnce(t *testing.T) {
	const rowCount = 40

	tickers := &manualTickerFactory{}
	harness := startTestRunner(t, batchingModule(map[string]any{
		"batch_size":     3,
		"flush_interval": testFlushInterval,
	}), testRunnerOptions{tickers: tickers})
	ticker := tickers.only(t)

	var workers sync.WaitGroup

	done := make(chan struct{})

	workers.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
				ticker.tryTick()
			}
		}
	})

	enqueueRows(t, harness, rowCount)
	close(done)
	workers.Wait()
	harness.stop(t)

	lines := 0
	for _, request := range harness.transport.requests {
		lines += len(strings.Split(strings.TrimSpace(string(request.body)), "\n"))
	}

	if lines != rowCount {
		t.Fatalf("flushed rows = %d, want %d", lines, rowCount)
	}
}

func TestStartExposesZeroValuedResultSeries(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := pluginruntime.NewMetricsFacadeWithRegisterer(pluginName, registry)
	harness := startTestRunner(t, batchingModule(map[string]any{}), testRunnerOptions{metrics: metrics})

	defer harness.stop(t)

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	assertZeroCounterSeries(t, families, metricQueuedRows, []string{"queued", "skipped", "dedup_skipped", "encode_error", "dropped"})
	assertZeroCounterSeries(t, families, metricFlushBatches, []string{"success", "http_error", "status_error", "no_url", "requeued"})

	for _, family := range families {
		if strings.HasSuffix(family.GetName(), metricFlushDuration) && len(family.GetMetric()) != 0 {
			t.Fatalf("flush duration histogram has %d pre-created series, want 0", len(family.GetMetric()))
		}
	}
}

// batchingModule returns a module whose batch threshold is never reached by the flush tests.
func batchingModule(overrides map[string]any) config.PluginModule {
	raw := map[string]any{
		"insert_url": testInsertURL,
		"batch_size": 10,
		"cache_key":  testCacheKey,
	}

	for key, value := range overrides {
		raw[key] = value
	}

	return testModule(raw)
}

// reconfigureBatching applies a batching module config through the plugin reload hook.
func reconfigureBatching(t *testing.T, harness testHarness, overrides map[string]any) {
	t.Helper()

	if err := harness.plugin.Reconfigure(context.Background(), pluginregistry.NewConfigView(batchingModule(overrides).Config)); err != nil {
		t.Fatalf("Reconfigure() error = %v", err)
	}
}

// enqueueRows enqueues count representative unauthenticated rows.
func enqueueRows(t *testing.T, harness testHarness, count int) {
	t.Helper()

	for range count {
		if _, err := harness.enqueuePostAction(context.Background(), testRequest(t, requestOptions{})); err != nil {
			t.Fatalf("Enqueue() error = %v", err)
		}
	}
}

// assertNDJSONLines checks the number of JSONEachRow lines in one request body.
func assertNDJSONLines(t *testing.T, body []byte, want int) {
	t.Helper()

	text := strings.TrimSpace(string(body))
	if lines := strings.Split(text, "\n"); len(lines) != want {
		t.Fatalf("NDJSON lines = %d, want %d: %q", len(lines), want, text)
	}
}

// assertZeroCounterSeries checks that every expected result label exists with value zero.
func assertZeroCounterSeries(t *testing.T, families []*dto.MetricFamily, name string, results []string) {
	t.Helper()

	var got []string

	for _, family := range families {
		if !strings.HasSuffix(family.GetName(), name) {
			continue
		}

		for _, metric := range family.GetMetric() {
			if value := metric.GetCounter().GetValue(); value != 0 {
				t.Fatalf("%s series value = %v, want 0", name, value)
			}

			for _, label := range metric.GetLabel() {
				if label.GetName() == metricLabelResult {
					got = append(got, label.GetValue())
				}
			}
		}
	}

	slices.Sort(got)

	want := slices.Sorted(slices.Values(results))

	if !slices.Equal(got, want) {
		t.Fatalf("%s result series = %v, want %v", name, got, want)
	}
}

type manualTickerFactory struct {
	tickers []*manualTicker
	mu      sync.Mutex
}

// newTicker records the requested interval and returns a manually driven ticker.
func (f *manualTickerFactory) newTicker(interval time.Duration) flushTicker {
	f.mu.Lock()
	defer f.mu.Unlock()

	ticker := &manualTicker{ticks: make(chan time.Time), interval: interval}
	f.tickers = append(f.tickers, ticker)

	return ticker
}

// count returns the number of tickers created so far.
func (f *manualTickerFactory) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.tickers)
}

// only returns the single created ticker or fails the test.
func (f *manualTickerFactory) only(t *testing.T) *manualTicker {
	t.Helper()

	if got := f.count(); got != 1 {
		t.Fatalf("tickers = %d, want 1", got)
	}

	return f.last(t)
}

// last returns the most recently created ticker or fails the test.
func (f *manualTickerFactory) last(t *testing.T) *manualTicker {
	t.Helper()

	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.tickers) == 0 {
		t.Fatal("no ticker was created")
	}

	return f.tickers[len(f.tickers)-1]
}

type manualTicker struct {
	ticks    chan time.Time
	interval time.Duration
	stopped  atomic.Bool
}

// Chan exposes the unbuffered tick channel read by the flush worker.
func (t *manualTicker) Chan() <-chan time.Time {
	return t.ticks
}

// Stop records that the worker released its ticker.
func (t *manualTicker) Stop() {
	t.stopped.Store(true)
}

// tickAndWait delivers one tick and returns after the worker finished handling it.
// The second unbuffered send completes only once the worker is back in its select loop.
func (t *manualTicker) tickAndWait() {
	for range 2 {
		t.ticks <- time.Now()
	}
}

// tryTick delivers one tick only when the worker is currently waiting for it.
func (t *manualTicker) tryTick() bool {
	select {
	case t.ticks <- time.Now():
		return true
	default:
		return false
	}
}

func TestReconfigureCacheKeyChangeKeepsPendingRows(t *testing.T) {
	harness := startTestRunner(t, batchingModule(map[string]any{}), testRunnerOptions{})

	enqueueRows(t, harness, 2)
	reconfigureBatching(t, harness, map[string]any{"cache_key": testCacheKey + ":next"})
	enqueueRows(t, harness, 1)
	harness.stop(t)

	lines := 0
	for _, request := range harness.transport.requests {
		lines += len(strings.Split(strings.TrimSpace(string(request.body)), "\n"))
	}

	if lines != 3 {
		t.Fatalf("flushed rows = %d, want every row queued before and after the cache_key change", lines)
	}

	if rows := popCachedRows(t, harness.host, testCacheKey); len(rows) != 0 {
		t.Fatalf("rows left under the previous cache_key = %d, want 0", len(rows))
	}
}

func TestValidateReconfigureDecodesWithoutSideEffects(t *testing.T) {
	tickers := &manualTickerFactory{}
	harness := startTestRunner(t, batchingModule(map[string]any{"flush_interval": testFlushInterval}), testRunnerOptions{tickers: tickers})

	defer harness.stop(t)

	valid := pluginregistry.NewConfigView(batchingModule(map[string]any{"flush_interval": "5s"}).Config)
	if err := harness.plugin.ValidateReconfigure(context.Background(), valid); err != nil {
		t.Fatalf("ValidateReconfigure(valid) error = %v", err)
	}

	invalid := pluginregistry.NewConfigView(batchingModule(map[string]any{"flush_interval": "soon"}).Config)
	if err := harness.plugin.ValidateReconfigure(context.Background(), invalid); err == nil {
		t.Fatal("ValidateReconfigure(invalid) accepted an invalid flush_interval")
	}

	if tickers.count() != 1 || harness.plugin.snapshot().config.FlushInterval.String() != testFlushInterval {
		t.Fatal("ValidateReconfigure changed the running flush worker or config")
	}
}

func TestFlushWorkerStateChangesAreLogged(t *testing.T) {
	var logs bytes.Buffer

	tickers := &manualTickerFactory{}
	harness := startTestRunner(t, batchingModule(map[string]any{}), testRunnerOptions{
		tickers: tickers, logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})

	defer harness.stop(t)

	steps := []struct {
		interval string
		want     int
		state    string
	}{
		{interval: testFlushInterval, want: 1, state: "flush_worker=running"},
		{interval: testFlushInterval, want: 1, state: "flush_worker=running"},
		{interval: "0s", want: 2, state: "flush_worker=stopped"},
	}

	for _, step := range steps {
		reconfigureBatching(t, harness, map[string]any{"flush_interval": step.interval})

		if got := strings.Count(logs.String(), "clickhouse flush worker updated"); got != step.want ||
			!strings.Contains(logs.String(), step.state) {
			t.Fatalf("after flush_interval=%s: %d worker updates, want %d with %s:\n%s", step.interval, got, step.want, step.state, logs.String())
		}
	}
}

func TestRequeueAfterCacheKeyChangeUsesCurrentKey(t *testing.T) {
	harness := startTestRunner(t, batchingModule(map[string]any{}), testRunnerOptions{})

	defer harness.stop(t)

	staleState := harness.plugin.snapshot()
	nextKey := testCacheKey + ":next"

	reconfigureBatching(t, harness, map[string]any{"cache_key": nextKey})
	requeueRows(context.Background(), staleState, []any{"row"})

	if rows := popCachedRows(t, harness.host, testCacheKey); len(rows) != 0 {
		t.Fatalf("rows requeued under the previous cache_key = %d, want 0", len(rows))
	}

	if rows := popCachedRows(t, harness.host, nextKey); len(rows) != 1 {
		t.Fatalf("rows requeued under the current cache_key = %d, want 1", len(rows))
	}
}
