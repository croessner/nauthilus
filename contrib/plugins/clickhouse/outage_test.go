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
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// TestOutageSuppressesImmediateRetriesAndBoundsBuffer reproduces an unavailable insert endpoint.
func TestOutageSuppressesImmediateRetriesAndBoundsBuffer(t *testing.T) {
	transport := &recordingTransport{statusCode: http.StatusServiceUnavailable}

	harness := startTestRunner(t, batchingModule(map[string]any{"batch_size": 1, "max_buffer_rows": 4}), testRunnerOptions{transport: transport})
	defer harness.stop(t)

	for i := range 20 {
		result, err := harness.enqueuePostAction(context.Background(), testRequest(t, requestOptions{}))
		if i >= 4 && (result.Enqueued || err != nil) {
			t.Fatalf("overflow admission = %+v, error = %v; want a non-failing drop", result, err)
		}
	}

	if got := transport.requestCount(); got != 1 {
		t.Errorf("outage insert attempts = %d, want 1 during retry pause", got)
	}

	if rows := popCachedRows(t, harness.host, testCacheKey); len(rows) > 4 {
		t.Errorf("buffered rows = %d, want at most 4", len(rows))
	}
}

// blockedInsert holds the only HTTP attempt until the test releases it.
type blockedInsert struct {
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

// Do simulates a hung ClickHouse insert followed by a transport failure.
func (b *blockedInsert) Do(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	if b.calls.Add(1) == 1 {
		close(b.entered)
	}

	<-b.release

	return pluginapi.HTTPResponse{}, errors.New("ClickHouse unavailable")
}

// TestHungInsertDoesNotOccupyAdditionalPostActions exercises concurrent admission during an outage.
func TestHungInsertDoesNotOccupyAdditionalPostActions(t *testing.T) {
	harness := startTestRunner(t, batchingModule(map[string]any{"batch_size": 1, "max_buffer_rows": 4}), testRunnerOptions{})
	defer harness.stop(t)

	blocked := &blockedInsert{entered: make(chan struct{}), release: make(chan struct{})}

	harness.plugin.mu.Lock()
	harness.plugin.http = blocked
	harness.plugin.mu.Unlock()

	request := testRequest(t, requestOptions{})

	done := make(chan struct{})
	go func() {
		defer close(done)

		_, _ = harness.enqueuePostAction(context.Background(), request)
	}()

	<-blocked.entered

	release := sync.OnceFunc(func() { close(blocked.release); <-done })
	defer release()

	admitted := make(chan struct{})
	go func() {
		defer close(admitted)

		var workers sync.WaitGroup
		for range 100 {
			workers.Go(func() { _, _ = harness.enqueuePostAction(context.Background(), request) })
		}

		workers.Wait()
	}()

	select {
	case <-admitted:
	case <-time.After(5 * time.Second):
		t.Fatal("post-actions blocked behind ClickHouse")
	}

	release()

	if rows := popCachedRows(t, harness.host, testCacheKey); len(rows) != 4 {
		t.Fatalf("buffer after failed in-flight insert = %d, want 4", len(rows))
	}

	if got := blocked.calls.Load(); got != 1 {
		t.Fatalf("concurrent inserts = %d, want 1", got)
	}
}

// TestRetryBackoffRecoveryAndReload checks capped retry delays and recovery after a buffer resize.
func TestRetryBackoffRecoveryAndReload(t *testing.T) {
	transport := &recordingTransport{statusCode: http.StatusServiceUnavailable}

	harness := startTestRunner(t, batchingModule(map[string]any{"batch_size": 1}), testRunnerOptions{transport: transport})
	defer harness.stop(t)

	for _, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, time.Minute, time.Minute} {
		harness.plugin.mu.Lock()
		harness.plugin.retryAfter = time.Time{}
		harness.plugin.mu.Unlock()

		_, _ = harness.enqueuePostAction(context.Background(), testRequest(t, requestOptions{}))
		if got := harness.plugin.retryDelay; got != want {
			t.Fatalf("retry delay = %v, want %v", got, want)
		}
	}

	reconfigureBatching(t, harness, map[string]any{"max_buffer_rows": 2})

	if harness.plugin.pendingRows != 2 {
		t.Fatalf("buffer after lowering limit = %d, want 2", harness.plugin.pendingRows)
	}

	transport.statusCode = http.StatusOK
	harness.plugin.retryAfter = time.Time{}
	harness.plugin.flushOnTick(context.Background())

	if harness.plugin.retryDelay != 0 || !harness.plugin.retryAfter.IsZero() || harness.plugin.pendingRows != 0 {
		t.Fatal("successful recovery did not clear buffer and backoff")
	}
}

// TestBufferLimitValidation covers the public default and invalid configuration boundary.
func TestBufferLimitValidation(t *testing.T) {
	for _, value := range []int{-1, 0, 4} {
		cfg, err := decodeModuleConfig(pluginregistry.NewConfigView(map[string]any{"max_buffer_rows": value}))
		if value < 0 {
			if err == nil {
				t.Fatal("negative buffer limit accepted")
			}

			continue
		}

		if err != nil {
			t.Fatal(err)
		}

		want := value
		if want == 0 {
			want = defaultMaxBufferRows
		}

		if cfg.MaxBufferRows != want {
			t.Fatalf("buffer limit = %d, want %d", cfg.MaxBufferRows, want)
		}
	}
}
