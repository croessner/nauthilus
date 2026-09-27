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
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/pluginruntime"
)

// awaitDone reports whether ctx ends within the timeout.
func awaitDone(ctx context.Context, timeout time.Duration) bool {
	select {
	case <-ctx.Done():
		return true
	case <-time.After(timeout):
		return false
	}
}

// startObservedWorker starts one worker through the plugin helper and returns
// the context the worker loop observed.
func startObservedWorker(t *testing.T, host *pluginruntime.Host) (context.Context, context.CancelFunc) {
	t.Helper()

	observed := make(chan context.Context, 1)
	cancel := goStoppableWorker(host, "geoip.test", func(ctx context.Context) error {
		observed <- ctx

		<-ctx.Done()

		return nil
	})

	select {
	case ctx := <-observed:
		return ctx, cancel
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not start")
	}

	return nil, nil
}

// TestStoppableWorkerEndsOnPluginCancel proves that stopping a worker reaches
// its loop although Host.Go detaches the start context from cancellation.
func TestStoppableWorkerEndsOnPluginCancel(t *testing.T) {
	host := pluginruntime.NewHost()
	t.Cleanup(host.CancelWorkers)

	loopCtx, cancel := startObservedWorker(t, host)
	cancel()

	if !awaitDone(loopCtx, 2*time.Second) {
		t.Fatal("worker loop kept running after its cancel function was called")
	}
}

// TestStoppableWorkerEndsWithHostLifetime proves that host shutdown still ends
// the worker loop.
func TestStoppableWorkerEndsWithHostLifetime(t *testing.T) {
	host := pluginruntime.NewHost()

	loopCtx, cancel := startObservedWorker(t, host)
	t.Cleanup(cancel)

	host.CancelWorkers()

	if !awaitDone(loopCtx, 2*time.Second) {
		t.Fatal("worker loop kept running after the host cancelled its workers")
	}
}
