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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/svcctx"

	monittrace "github.com/croessner/nauthilus/v4/server/monitoring/trace"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
)

const redisCommandClient = "client"

// errBatchFlushPanic marks commands whose batching flush panicked before it
// could report a regular result.
var errBatchFlushPanic = errors.New("redis batching flush panicked")

// Ownership states of a queued command. A command is shared between its caller
// and the flush worker, so exactly one side may touch it at any time: the
// caller until the worker claims it, the worker from the claim until it
// reports back on done.
const (
	batchItemQueued int32 = iota
	batchItemClaimed
	batchItemAbandoned
)

// BatchingHook implements redis.Hook and batches individual Process calls
// into short-lived pipelines to reduce network round-trips.
//
// Design goals:
//   - Preserve command ordering within a batch.
//   - Respect context cancellations for commands that are still queued: such a command
//     is abandoned and never executed. A command already claimed by a flush stays owned
//     by that flush, so its caller waits for the flush result (bounded by the pipeline
//     and socket timeouts) instead of racing the executing pipeline on the command.
//   - Bypass batching when queue is saturated or for explicitly skipped commands.
//   - Keep the public client API intact by operating at Hook level.
type BatchingHook struct {
	client redis.UniversalClient

	// config
	maxBatch        int
	maxWait         time.Duration
	pipelineTimeout time.Duration

	logger *slog.Logger

	queue chan *batchItem

	// control
	once   sync.Once
	closed chan struct{}

	// fast lookup of commands to skip (lowercase)
	skip map[string]struct{}
}

type batchItem struct {
	ctx   context.Context
	cmd   redis.Cmder
	done  chan error
	state atomic.Int32
}

// claim transfers ownership of a queued command to the flush worker. It fails
// when the caller has already abandoned the command.
func (it *batchItem) claim() bool {
	return it.state.CompareAndSwap(batchItemQueued, batchItemClaimed)
}

// abandon returns ownership of a still queued command to its caller. It fails
// when the flush worker has already claimed the command.
func (it *batchItem) abandon() bool {
	return it.state.CompareAndSwap(batchItemQueued, batchItemAbandoned)
}

// wait blocks until the command result is available or the caller gives up.
// go-redis stores the returned error on the command right after the hook
// returns, so the caller may only return while it owns the command: either
// the command was never claimed, or the worker has reported back.
func (it *batchItem) wait(ctx context.Context) error {
	select {
	case err := <-it.done:
		return err
	case <-ctx.Done():
		if it.abandon() {
			return ctx.Err()
		}

		// The command is part of an executing pipeline; wait for the flush.
		return <-it.done
	}
}

// NewBatchingHook provides the exported NewBatchingHook function.
func NewBatchingHook(logger *slog.Logger, client redis.UniversalClient, cfg *config.RedisBatching) *BatchingHook {
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
		"hello", redisCommandClient, "config", "script",
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
		client:          client,
		maxBatch:        cfg.GetMaxBatchSize(),
		maxWait:         cfg.GetMaxWait(),
		pipelineTimeout: cfg.GetPipelineTimeout(),
		logger:          logger,
		queue:           make(chan *batchItem, qcap),
		closed:          make(chan struct{}),
		skip:            skip,
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
		var ok bool

		batch, ok = h.collectBatch(batch[:0])
		if !ok {
			return
		}

		h.flushBatch(batch)
	}
}

// collectBatch gathers queued commands until size or wait thresholds are reached.
func (h *BatchingHook) collectBatch(batch []*batchItem) ([]*batchItem, bool) {
	first, ok := <-h.queue
	if !ok {
		return nil, false
	}

	batch = append(batch, first)

	timeout := time.NewTimer(h.maxWait)
	defer stopBatchTimer(timeout)

	for len(batch) < h.maxBatch {
		select {
		case it, ok := <-h.queue:
			if !ok {
				return batch, true
			}

			batch = append(batch, it)
		case <-timeout.C:
			return batch, true
		}
	}

	return batch, true
}

// stopBatchTimer stops a timer and drains it when needed.
func stopBatchTimer(timeout *time.Timer) {
	if timeout.Stop() {
		return
	}

	select {
	case <-timeout.C:
	default:
	}
}

// flushBatch executes a collected command batch and notifies command waiters.
// Waiters of claimed commands are always notified, even if the flush panics,
// because they no longer honor their own context once the flush owns the command.
func (h *BatchingHook) flushBatch(batch []*batchItem) {
	claimed := claimBatchItems(batch)
	if len(claimed) == 0 {
		return
	}

	defer notifyBatchWaiters(claimed)
	defer h.recoverFlushPanic(claimed)

	h.executeBatchPipeline(claimed)
}

// claimBatchItems takes ownership of all commands whose callers are still
// waiting and drops abandoned ones. It filters the batch in place.
func claimBatchItems(batch []*batchItem) []*batchItem {
	claimed := batch[:0]

	for _, it := range batch {
		if it.claim() {
			claimed = append(claimed, it)
		}
	}

	return claimed
}

// recoverFlushPanic turns a panic on the flush goroutine into a command error
// so neither the process nor the waiting callers are taken down by it.
func (h *BatchingHook) recoverFlushPanic(batch []*batchItem) {
	recovered := recover()
	if recovered == nil {
		return
	}

	err := fmt.Errorf("%w: %v", errBatchFlushPanic, recovered)

	level.Error(h.logger).Log(
		definitions.LogKeyMsg, "Redis batching flush panicked; failing the affected commands",
		definitions.LogKeyError, err,
		"batch_size", len(batch),
		"stack", string(debug.Stack()),
	)

	for _, it := range batch {
		it.cmd.SetErr(err)
	}
}

// executeBatchPipeline traces and executes one Redis pipeline flush.
func (h *BatchingHook) executeBatchPipeline(batch []*batchItem) {
	tr := monittrace.New("nauthilus/redis_batch")
	base := svcctx.Get()
	fctx, fsp := tr.Start(base, "redis.uc.flush",
		attribute.Int("batch_size", len(batch)),
		attribute.Int("max_batch", h.maxBatch),
		attribute.Int("max_wait_ms", int(h.maxWait.Milliseconds())),
	)

	defer fsp.End()

	dCtx, cancel := context.WithTimeout(fctx, h.pipelineTimeout)
	defer cancel()

	_, execErr := h.client.Pipelined(dCtx, func(pipe redis.Pipeliner) error {
		h.queuePipelineBatch(pipe, batch)

		return nil
	})

	if execErr != nil {
		level.Debug(h.logger).Log(
			definitions.LogKeyMsg, "Redis batching pipeline returned error",
			definitions.LogKeyError, execErr,
		)

		fsp.RecordError(execErr)
	}
}

// queuePipelineBatch queues all commands into the Redis pipeline.
func (h *BatchingHook) queuePipelineBatch(pipe redis.Pipeliner, batch []*batchItem) {
	for _, it := range batch {
		// We use a background context here to ensure the command is at least queued.
		// go-redis handles its own context internally.
		if perr := pipe.Process(context.Background(), it.cmd); perr != nil {
			it.cmd.SetErr(perr)
			level.Warn(h.logger).Log(
				definitions.LogKeyMsg, "Failed to queue command into pipeline",
				definitions.LogKeyError, perr,
				"cmd", it.cmd.FullName(),
			)
		}
	}
}

// notifyBatchWaiters hands claimed commands back to their callers together with
// the command error. Each done channel is buffered for exactly this one send.
func notifyBatchWaiters(batch []*batchItem) {
	for _, it := range batch {
		var err error
		if it.cmd != nil {
			err = it.cmd.Err()
		}

		it.done <- err
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
			err := item.wait(ctx)
			if err != nil {
				esp.RecordError(err)
			}

			esp.End()

			return err
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
func attachBatchingHookIfEnabled(cfg config.File, logger *slog.Logger, u redis.UniversalClient) {
	if u == nil || cfg == nil {
		return
	}

	batchingCfg := cfg.GetServer().GetRedis().GetBatching()
	if batchingCfg == nil || !batchingCfg.IsBatchingEnabled() {
		return
	}

	hook := NewBatchingHook(logger, u, batchingCfg)
	if hook == nil {
		return
	}

	// AddHook appends to the FIFO chain
	u.AddHook(hook)
	level.Info(logger).Log(
		definitions.LogKeyMsg, "Redis client-side batching enabled",
		"max_batch", hook.maxBatch,
		"max_wait", hook.maxWait.String(),
	)
}
