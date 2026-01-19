package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type manualMockSource struct {
	nextFunc  func() (Row, bool)
	resetFunc func()
	totalFunc func() int
}

func (m *manualMockSource) Next() (Row, bool) {
	if m.nextFunc != nil {
		return m.nextFunc()
	}
	return Row{}, false
}

func (m *manualMockSource) Reset() {
	if m.resetFunc != nil {
		m.resetFunc()
	}
}

func (m *manualMockSource) Total() int {
	if m.totalFunc != nil {
		return m.totalFunc()
	}
	return 0
}

type manualMockCollector struct {
	targetRPS   float64
	concurrency int64
}

func (m *manualMockCollector) AddSample(latency time.Duration, ok bool, isMatch bool, isHttpErr bool, isAborted bool, isSkipped bool, isToleratedBF bool, isTooManyRequests bool, statusCode int) {
}

func (m *manualMockCollector) Snapshot() Stats {
	return Stats{Elapsed: 50 * time.Millisecond}
}

func (m *manualMockCollector) Reset() {
}

func (m *manualMockCollector) Buckets() []atomic.Int64 {
	return nil
}

func (m *manualMockCollector) Overflow() int64 {
	return 0
}

func (m *manualMockCollector) SetTargetRPS(rps float64) {
	m.targetRPS = rps
}

func (m *manualMockCollector) SetConcurrency(c int64) {
	m.concurrency = c
}

func (m *manualMockCollector) SetPlateauActive(active bool) {
}

func (m *manualMockCollector) IncParallelMatched() {
}

func (m *manualMockCollector) IncParallelMismatched() {
}

func TestAppDuration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RunFor = 200 * time.Millisecond
	cfg.Concurrency = 1
	cfg.ProgressEvery = 0 // Disable progress loop

	src := &manualMockSource{
		nextFunc: func() (Row, bool) {
			time.Sleep(10 * time.Millisecond)
			return Row{}, true
		},
		resetFunc: func() {},
		totalFunc: func() int { return 100 },
	}

	col := &manualMockCollector{}

	client := NewAuthClient(cfg)

	app := NewApp(cfg, src, col, client, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	start := time.Now()
	err := app.Run(ctx)
	elapsed := time.Since(start)

	assert.NoError(t, err)
	// Duration was 200ms.
	assert.GreaterOrEqual(t, elapsed, 200*time.Millisecond)
	// Allow some slack for goroutine scheduling and worker finishing
	assert.Less(t, elapsed, 600*time.Millisecond)
}
