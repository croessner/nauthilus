// Copyright (C) 2025 Christian Rößner
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
	"net"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/svcctx"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
)

// BatchingHook implements redis.Hook and batches individual Process calls
// into short-lived pipelines to reduce network round-trips.
//
// Design goals:
// - Preserve command ordering within a batch.
// - Respect context cancellations by unblocking waiters; actual execution may still occur.
// - Bypass batching when queue is saturated or for explicitly skipped commands.
// - Keep the public client API intact by operating at Hook level.
type BatchingHook struct {
	client redis.UniversalClient

	// config
	maxBatch int
	maxWait  time.Duration

	queue chan *batchItem

	// control
	once   sync.Once
	closed chan struct{}

	// fast lookup of commands to skip (lowercase)
	skip map[string]struct{}
}

type batchItem struct {
	ctx  context.Context
	cmd  redis.Cmder
	done chan error
}

// NewBatchingHook creates a new batching hook instance using the provided client and config.
func NewBatchingHook(client redis.UniversalClient, cfg *config.RedisBatching) *BatchingHook {
	if client == nil || cfg == nil || !cfg.IsBatchingEnabled() {
		return nil
	}

	// Build skip set with sensible defaults and user-provided additions.
	defaults := []string{
		// Blocking ops
		"blpop", "brpop", "brpoplpush", "blmove", "bzpopmin", "bzpopmax",
		"xread", "xreadgroup",
		// PubSub
		"subscribe", "psubscribe", "ssubscribe",
		// Transactions and scripting are generally safe to batch, but leave them to the caller
		// when already in pipeline/tx mode.
		"hello", "client",
	}

	skip := make(map[string]struct{}, len(defaults)+len(cfg.GetSkipCommands()))
	for _, s := range defaults {
		skip[s] = struct{}{}
	}

	for _, s := range cfg.GetSkipCommands() {
		skip[strings.ToLower(s)] = struct{}{}
	}

	qcap := cfg.GetQueueCapacity()
	if qcap < 1 {
		qcap = 8192
	}

	return &BatchingHook{
		client:   client,
		maxBatch: cfg.GetMaxBatchSize(),
		maxWait:  cfg.GetMaxWait(),
		queue:    make(chan *batchItem, qcap),
		closed:   make(chan struct{}),
		skip:     skip,
	}
}

// ensureStarted starts the background batching worker exactly once.
func (h *BatchingHook) ensureStarted() {
	h.once.Do(func() {
		go h.run()
	})
}

// run is the batcher loop assembling commands and flushing them via Pipeline.
func (h *BatchingHook) run() {
	defer close(h.closed)

	// local buffers reused across iterations
	batch := make([]*batchItem, 0, h.maxBatch)

	for {
		// Block waiting for the first item or exit when queue is closed (never in current lifecycle)
		var first *batchItem
		var ok bool
		select {
		case first, ok = <-h.queue:
			if !ok {
				return
			}
		}

		batch = batch[:0]
		batch = append(batch, first)

		// Collect until size threshold or time threshold
		timeout := time.NewTimer(h.maxWait)
		collect := true
		for collect {
			if len(batch) >= h.maxBatch {
				break
			}

			select {
			case it, ok := <-h.queue:
				if !ok {
					collect = false

					break
				}

				batch = append(batch, it)
			case <-timeout.C:
				collect = false
			}
		}

		if !timeout.Stop() {
			// Drain to prevent leaks
			select {
			case <-timeout.C:
			default:
			}
		}

		// Execute the batch via pipelined; do not propagate a single error to all cmds,
		// since each command tracks its own error/value.
		// We purposely use Background context to rely on client timeouts for stability.

		// Tracing for a single flush cycle
		tr := monittrace.New("nauthilus/redis_batch")
		base := svcctx.Get()
		fctx, fsp := tr.Start(base, "redis.uc.flush",
			attribute.Int("batch_size", len(batch)),
			attribute.Int("max_batch", h.maxBatch),
			attribute.Int("max_wait_ms", int(config.GetFile().GetServer().GetRedis().GetBatching().GetMaxWait().Milliseconds())),
		)

		// Derive a timeout context from the span context
		dCtx, cancel := context.WithTimeout(fctx, config.GetFile().GetServer().GetRedis().GetBatching().GetPipelineTimeout())

		_, execErr := h.client.Pipelined(dCtx, func(pipe redis.Pipeliner) error {
			for _, it := range batch {
				// Use each item’s context for Process; this only affects client-level timeouts.
				if perr := pipe.Process(it.ctx, it.cmd); perr != nil {
					// defensiv: Command markieren und loggen
					it.cmd.SetErr(perr)
					level.Warn(log.Logger).Log(
						definitions.LogKeyMsg, "Failed to queue command into pipeline",
						definitions.LogKeyError, perr,
						"cmd", it.cmd.FullName(),
					)
					// Important: Still continue with the next command in the batch
				}
			}

			return nil
		})

		cancel()

		if execErr != nil {
			// This is the first failing command’s error. Individual commands already have their error set by go-redis.
			level.Debug(log.Logger).Log(
				definitions.LogKeyMsg, "Redis batching pipeline returned error",
				definitions.LogKeyError, execErr,
			)

			fsp.RecordError(execErr)
		}

		fsp.End()

		// Notify waiters with their individual command error
		for _, it := range batch {
			var err error
			if it.cmd != nil {
				err = it.cmd.Err()
			}

			select {
			case it.done <- err:
			default:
				// If waiter already gave up (ctx canceled), avoid blocking
			}
		}
	}
}

// DialHook pass-through
func (h *BatchingHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

// ProcessHook implements single-command interception.
func (h *BatchingHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		name := strings.ToLower(cmd.Name())

		// Tracing for enqueue path
		tr := monittrace.New("nauthilus/redis_batch")
		ectx, esp := tr.Start(ctx, "redis.uc.enqueue",
			attribute.String("cmd", name),
			attribute.Int("max_batch", h.maxBatch),
		)

		if _, found := h.skip[name]; found || h.maxBatch <= 1 {
			// Bypass batching
			esp.SetAttributes(attribute.Bool("bypass", true))
			defer esp.End()

			return next(ctx, cmd)
		}

		h.ensureStarted()

		// Propagate span context so the worker sees it if needed
		item := &batchItem{ctx: ectx, cmd: cmd, done: make(chan error, 1)}

		// Non-blocking enqueue; on overflow, fallback to direct execution
		select {
		case h.queue <- item:
			// wait for completion or context
			select {
			case err := <-item.done:
				if err != nil {
					esp.RecordError(err)
				}

				esp.End()

				return err
			case <-ctx.Done():
				esp.RecordError(ctx.Err())
				esp.End()

				return ctx.Err()
			}
		default:
			// Queue saturated – fallback to direct execution
			esp.SetAttributes(attribute.Bool("fallback_direct", true))
			defer esp.End()

			return next(ctx, cmd)
		}
	}
}

// ProcessPipelineHook do not alter explicit caller pipelines; just pass through.
func (h *BatchingHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		return next(ctx, cmds)
	}
}

// attachBatchingHookIfEnabled attaches a batching hook to the given UniversalClient when enabled.
func attachBatchingHookIfEnabled(u redis.UniversalClient) {
	if u == nil {
		return
	}

	cfg := config.GetFile().GetServer().GetRedis().GetBatching()
	if cfg == nil || !cfg.IsBatchingEnabled() {
		return
	}

	hook := NewBatchingHook(u, cfg)
	if hook == nil {
		return
	}

	// AddHook appends to the FIFO chain
	u.AddHook(hook)
	level.Info(log.Logger).Log(
		definitions.LogKeyMsg, "Redis client-side batching enabled",
		"max_batch", hook.maxBatch,
		"max_wait", hook.maxWait.String(),
	)
}
