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

	"github.com/redis/go-redis/v9"
)

// PipelineFunc is a function that executes Redis commands on a pipeline.
type PipelineFunc func(pipe redis.Pipeliner) error

// ExecuteWritePipeline executes multiple Redis write commands in a pipeline to reduce network round trips.
// It takes a context and a function that defines the commands to execute.
// The function should add commands to the pipeline but not execute them.
// Returns the command results and any error that occurred.
func ExecuteWritePipeline(ctx context.Context, fn PipelineFunc) ([]redis.Cmder, error) {
	pipe := GetClient().GetWritePipeline()
	if err := fn(pipe); err != nil {
		return nil, err
	}

	return pipe.Exec(ctx)
}

// ExecuteReadPipeline executes multiple Redis read commands in a pipeline to reduce network round trips.
// It takes a context and a function that defines the commands to execute.
// The function should add commands to the pipeline but not execute them.
// Returns the command results and any error that occurred.
func ExecuteReadPipeline(ctx context.Context, fn PipelineFunc) ([]redis.Cmder, error) {
	pipe := GetClient().GetReadPipeline()
	if err := fn(pipe); err != nil {
		return nil, err
	}

	return pipe.Exec(ctx)
}
