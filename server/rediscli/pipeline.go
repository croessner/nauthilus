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

package rediscli

import (
	"context"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
)

// PipelineFunc is a function that executes Redis commands on a pipeline.
type PipelineFunc func(pipe redis.Pipeliner) error

// executePipeline is the shared implementation for pipeline execution.
// It handles tracing, error recording, and op-count reporting for both read and write pipelines.
func executePipeline(ctx context.Context, mode string, pipe redis.Pipeliner, fn PipelineFunc) ([]redis.Cmder, error) {
	tr := monittrace.New("nauthilus/redis_batch")
	pctx, sp := tr.Start(ctx, "redis.pipeline.exec",
		attribute.String("mode", mode),
	)

	_ = pctx

	if sp != nil {
		defer sp.End()
	}

	if err := fn(pipe); err != nil {
		if sp != nil {
			sp.RecordError(err)
		}

		return nil, err
	}

	// best effort op count before exec
	if l, ok := any(pipe).(interface{ Len() int }); ok {
		if sp != nil {
			sp.SetAttributes(attribute.Int("op_count", l.Len()))
		}
	}

	cmds, err := pipe.Exec(pctx)
	if err != nil {
		if sp != nil {
			sp.RecordError(err)
		}
	}

	return cmds, err
}

// ExecuteWritePipeline executes multiple Redis write commands in a pipeline to reduce network round trips.
func ExecuteWritePipeline(ctx context.Context, redisClient Client, fn PipelineFunc) ([]redis.Cmder, error) {
	return executePipeline(ctx, "write", redisClient.GetWritePipeline(), fn)
}

// ExecuteReadPipeline executes multiple Redis read commands in a pipeline to reduce network round trips.
func ExecuteReadPipeline(ctx context.Context, redisClient Client, fn PipelineFunc) ([]redis.Cmder, error) {
	return executePipeline(ctx, "read", redisClient.GetReadPipeline(), fn)
}
