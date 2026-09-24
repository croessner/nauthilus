// Copyright (C) 2026 Christian Rößner
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

package rediscli

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"
)

// blockingPipelineHook holds every pipeline flush until the test releases it,
// so a caller deadline can expire while its command is in flight.
type blockingPipelineHook struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingPipelineHook() *blockingPipelineHook {
	return &blockingPipelineHook{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (h *blockingPipelineHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h *blockingPipelineHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return next
}

func (h *blockingPipelineHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		h.once.Do(func() { close(h.entered) })
		<-h.release

		return next(ctx, cmds)
	}
}

// panicOncePipelineHook panics in the first pipeline flush only.
type panicOncePipelineHook struct {
	once sync.Once
}

func (h *panicOncePipelineHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h *panicOncePipelineHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return next
}

func (h *panicOncePipelineHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		h.once.Do(func() { panic("simulated pipeline hook failure") })

		return next(ctx, cmds)
	}
}

// newBatchingTestClient builds a standalone client with the production hook
// layout: redisotel tracing (which formats every command, including its error,
// before the pipeline executes) plus the batching hook.
func newBatchingTestClient(t *testing.T, batching *config.RedisBatching, extraHooks ...redis.Hook) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()

	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr(), Protocol: 2})

	t.Cleanup(func() { _ = client.Close() })

	if err := redisotel.InstrumentTracing(client, redisotel.WithDBStatement(false)); err != nil {
		t.Fatalf("instrument tracing: %v", err)
	}

	for _, hook := range extraHooks {
		client.AddHook(hook)
	}

	hook := NewBatchingHook(log.GetLogger(), client, batching)
	if hook == nil {
		t.Fatal("batching hook must be enabled")
	}

	client.AddHook(hook)

	return client, srv
}

// TestBatchingHookAbandonedQueuedCommandIsNotExecuted reproduces the production
// crash path: a caller gives up on a queued command, go-redis stores the
// context error on that command, and a later flush must not read or execute
// the abandoned command concurrently.
func TestBatchingHookAbandonedQueuedCommandIsNotExecuted(t *testing.T) {
	client, srv := newBatchingTestClient(t, &config.RedisBatching{
		Enabled:      true,
		MaxBatchSize: 16,
		MaxWait:      100 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	abandoned := make(chan error, 1)

	// The abandoning caller runs on its own goroutine and is deliberately not
	// synchronized with the follow-up below, so the race detector sees any
	// flush access to the abandoned command as unordered with the caller.
	go func() {
		abandoned <- client.Set(ctx, "abandoned", "value", 0).Err()
	}()

	time.Sleep(30 * time.Millisecond)

	// The follow-up joins the pending flush; once it returns, the flush that
	// held the abandoned command has finished.
	if err := client.Set(context.Background(), "follow-up", "value", 0).Err(); err != nil {
		t.Fatalf("follow-up command: %v", err)
	}

	if err := <-abandoned; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued command error = %v, want context deadline", err)
	}

	if srv.Exists("abandoned") {
		t.Fatal("abandoned command was executed by a later flush")
	}

	if got, err := srv.Get("follow-up"); err != nil || got != "value" {
		t.Fatalf("follow-up value = %q, %v", got, err)
	}
}

// TestBatchingHookInFlightCommandStaysOwnedByFlush verifies that a caller whose
// deadline expires while its command is already part of an executing pipeline
// waits for that pipeline instead of racing it on the shared command.
func TestBatchingHookInFlightCommandStaysOwnedByFlush(t *testing.T) {
	blocker := newBlockingPipelineHook()
	client, srv := newBatchingTestClient(t, &config.RedisBatching{
		Enabled:      true,
		MaxBatchSize: 16,
		MaxWait:      time.Millisecond,
	}, blocker)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	result := make(chan error, 1)

	go func() {
		result <- client.Set(ctx, "in-flight", "value", 0).Err()
	}()

	select {
	case <-blocker.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("pipeline flush did not start")
	}

	<-ctx.Done()
	time.Sleep(20 * time.Millisecond)
	close(blocker.release)

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("in-flight command error = %v, want the executed result", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight command did not return after the flush finished")
	}

	if got, err := srv.Get("in-flight"); err != nil || got != "value" {
		t.Fatalf("in-flight value = %q, %v", got, err)
	}
}

// TestBatchingHookRecoversFlushPanic verifies that a panic on the flush
// goroutine fails the affected commands instead of crashing the process or
// leaving their callers blocked, and that the worker keeps serving commands.
func TestBatchingHookRecoversFlushPanic(t *testing.T) {
	client, srv := newBatchingTestClient(t, &config.RedisBatching{
		Enabled:      true,
		MaxBatchSize: 16,
		MaxWait:      time.Millisecond,
	}, &panicOncePipelineHook{})

	if err := client.Set(context.Background(), "first", "value", 0).Err(); !errors.Is(err, errBatchFlushPanic) {
		t.Fatalf("command in panicking flush error = %v, want %v", err, errBatchFlushPanic)
	}

	if err := client.Set(context.Background(), "second", "value", 0).Err(); err != nil {
		t.Fatalf("command after recovered flush: %v", err)
	}

	if got, err := srv.Get("second"); err != nil || got != "value" {
		t.Fatalf("second value = %q, %v", got, err)
	}
}
