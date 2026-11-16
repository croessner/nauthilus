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

package rediscli

import (
	"context"
	"errors"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/stats"
	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/redis/go-redis/v9"
)

// ErrInvalidPipelineBatchSize reports a batch size that cannot bound a pipeline.
var ErrInvalidPipelineBatchSize = errors.New("pipeline batch size must be greater than zero")

// ReadPipelineBatches executes one read command per item in bounded pipelines, one batch after another.
//
// Each batch is one pipeline execution with its own Redis read deadline. A Redis Cluster client fans a
// batch out to the nodes that own the queued keys, so keys may live in different slots. The batches run
// sequentially: no goroutine is started per item and at most BatchSize commands are buffered at once.
type ReadPipelineBatches struct {
	Client Client
	Cfg    config.File

	// RoundTripKind labels bruteforce_redis_roundtrips_total once per pipeline execution; empty skips it.
	RoundTripKind string

	BatchSize int

	// Primary reads from the write handle (the primary) instead of a possibly lagging replica.
	Primary bool
}

// pipeline returns the read pipeline, or the write-handle pipeline when the caller needs primary reads.
func (b ReadPipelineBatches) pipeline() (string, redis.Pipeliner) {
	if b.Primary {
		return "read_primary", b.Client.GetWritePipeline()
	}

	return "read", b.Client.GetReadPipeline()
}

// RunReadPipelineBatches queues one command per item and evaluates every command result in item order.
//
// queue adds the command for one item to the pipeline and returns it. evaluate receives each item with its
// command after the batch has executed; it is called only for commands that succeeded or returned
// redis.Nil, so it must check cmd.Err() for redis.Nil when the distinction matters. The first command error
// stops processing: items before it have been evaluated, items after it have not, and no further batch is
// started. A context that is canceled or past its deadline also prevents the next batch from starting.
//
// The Redis read counter grows by the number of queued commands; the round-trip counter grows by one per
// pipeline execution, so commands and network rounds stay distinguishable.
func RunReadPipelineBatches[T any, C redis.Cmder](
	ctx context.Context,
	batches ReadPipelineBatches,
	items []T,
	queue func(ctx context.Context, pipe redis.Pipeliner, item T) C,
	evaluate func(item T, cmd C) error,
) error {
	if batches.BatchSize <= 0 {
		return ErrInvalidPipelineBatchSize
	}

	for start := 0; start < len(items); start += batches.BatchSize {
		if err := ctx.Err(); err != nil {
			return err
		}

		end := min(start+batches.BatchSize, len(items))

		if err := runReadPipelineBatch(ctx, batches, items[start:end], queue, evaluate); err != nil {
			return err
		}
	}

	return nil
}

// runReadPipelineBatch executes one bounded batch and evaluates its commands in order.
func runReadPipelineBatch[T any, C redis.Cmder](
	ctx context.Context,
	batches ReadPipelineBatches,
	batch []T,
	queue func(ctx context.Context, pipe redis.Pipeliner, item T) C,
	evaluate func(item T, cmd C) error,
) error {
	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx, batches.Cfg)
	defer cancel()

	cmds := make([]C, len(batch))

	mode, pipeline := batches.pipeline()

	_, execErr := executePipeline(dCtx, mode, pipeline, func(pipe redis.Pipeliner) error {
		for index, item := range batch {
			cmds[index] = queue(dCtx, pipe, item)
		}

		return nil
	})

	recordReadPipelineBatch(batches.RoundTripKind, len(batch))

	evaluated, cmdErr := firstFailedPipelineCommand(cmds)

	// A pipeline that failed as a whole (for example in a hook) has unset results that must not be evaluated.
	if err := UnattributedPipelineError(execErr, cmds); err != nil {
		return err
	}

	for index := range evaluated {
		if err := evaluate(batch[index], cmds[index]); err != nil {
			return err
		}
	}

	return cmdErr
}

// UnattributedPipelineError returns the pipeline error when no queued command carries an error of its own.
//
// Callers that evaluate every command individually use it so that a pipeline-wide failure (for example one
// returned by a hook before any command was sent) is never mistaken for success. redis.Nil is not an error.
func UnattributedPipelineError[C redis.Cmder](execErr error, cmds []C) error {
	if execErr == nil || errors.Is(execErr, redis.Nil) {
		return nil
	}

	if _, cmdErr := firstFailedPipelineCommand(cmds); cmdErr != nil {
		return nil
	}

	return execErr
}

// firstFailedPipelineCommand returns how many leading commands succeeded and the first command error.
// redis.Nil counts as success because it is a regular empty reply.
func firstFailedPipelineCommand[C redis.Cmder](cmds []C) (int, error) {
	for index, cmd := range cmds {
		if err := cmd.Err(); err != nil && !errors.Is(err, redis.Nil) {
			// The command error is returned unchanged so callers keep their existing error texts.
			return index, err
		}
	}

	return len(cmds), nil
}

// recordReadPipelineBatch counts the queued read commands and one pipeline execution.
func recordReadPipelineBatch(roundTripKind string, commands int) {
	metrics := stats.GetMetrics()

	metrics.GetRedisReadCounter().Add(float64(commands))

	if roundTripKind != "" {
		metrics.GetRedisRoundtripsTotal().WithLabelValues(roundTripKind).Inc()
	}
}
