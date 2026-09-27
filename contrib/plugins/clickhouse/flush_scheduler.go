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
	"context"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const flushWorkerName = "clickhouse.batch_flush"

// flushTicker is the narrow ticker contract used by the periodic flush worker.
type flushTicker interface {
	Chan() <-chan time.Time
	Stop()
}

// flushTickerFactory creates a ticker for one flush worker run.
type flushTickerFactory func(time.Duration) flushTicker

// timeTicker adapts time.Ticker to flushTicker.
type timeTicker struct {
	*time.Ticker
}

// Chan returns the wall-clock tick channel.
func (t timeTicker) Chan() <-chan time.Time {
	return t.C
}

// newTimeTicker creates the production wall-clock ticker.
func newTimeTicker(interval time.Duration) flushTicker {
	return timeTicker{Ticker: time.NewTicker(interval)}
}

// flushScheduler owns the optional periodic flush worker of one plugin instance.
//
// It is not safe for concurrent use; Plugin serializes every call through its lifecycle mutex.
// At most one worker exists at a time, and a worker handles ticks sequentially, so timer
// flushes never overlap each other. They may overlap a size-triggered flush from Enqueue;
// both drain the batch with one atomic Cache.PopAll, so every queued row is taken by exactly
// one flush.
type flushScheduler struct {
	newTicker flushTickerFactory
	worker    *flushWorker
}

// apply ensures that a worker runs with interval, or that none runs when interval is not positive.
// An unchanged interval keeps the running worker; a changed one replaces it after the old worker
// exited. If ctx ends first, the old worker is already cancelled and only finishes its in-flight
// flush, which the atomic cache pop keeps safe next to the new worker.
func (s *flushScheduler) apply(ctx context.Context, host pluginapi.Host, interval time.Duration, flush func(context.Context)) {
	if s.worker != nil && s.worker.interval == interval && host != nil {
		return
	}

	_ = s.stop(ctx)

	if host == nil || interval <= 0 || flush == nil {
		return
	}

	newTicker := s.newTicker
	if newTicker == nil {
		newTicker = newTimeTicker
	}

	s.worker = startFlushWorker(host, interval, newTicker(interval), flush)
}

// stop cancels the running worker and waits until it exited or ctx ended.
func (s *flushScheduler) stop(ctx context.Context) error {
	if s.worker == nil {
		return nil
	}

	worker := s.worker
	s.worker = nil

	return worker.stop(ctx)
}

// flushWorker is one host-supervised goroutine that flushes the batch on every tick.
type flushWorker struct {
	cancel   context.CancelFunc
	done     chan struct{}
	interval time.Duration
}

// startFlushWorker launches the worker through Host.Go so panics are contained and host
// shutdown also ends it. The worker owns ticker and stops it on exit.
func startFlushWorker(host pluginapi.Host, interval time.Duration, ticker flushTicker, flush func(context.Context)) *flushWorker {
	parent := host.ServiceContext()
	if parent == nil {
		parent = context.Background()
	}

	ctx, cancel := context.WithCancel(parent)
	worker := &flushWorker{cancel: cancel, done: make(chan struct{}), interval: interval}

	host.Go(ctx, flushWorkerName, func(hostCtx context.Context) error {
		defer close(worker.done)

		// Host.Go detaches ctx from its cancellation, so the host lifetime is bridged explicitly.
		release := context.AfterFunc(hostCtx, cancel)
		defer release()

		worker.run(ctx, ticker, flush)

		return nil
	})

	return worker
}

// run flushes once per tick until ctx is cancelled.
//
// A flush that already started is not cancelled: aborting an insert whose body ClickHouse may
// already have accepted would requeue and later duplicate those rows. The flush stays bounded
// by the configured request timeout instead.
func (w *flushWorker) run(ctx context.Context, ticker flushTicker, flush func(context.Context)) {
	defer ticker.Stop()

	flushCtx := context.WithoutCancel(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			if ctx.Err() != nil {
				return
			}

			flush(flushCtx)
		}
	}
}

// stop cancels the worker and waits for its exit, bounded by ctx.
func (w *flushWorker) stop(ctx context.Context) error {
	w.cancel()

	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case <-w.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
