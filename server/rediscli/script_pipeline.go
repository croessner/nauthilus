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
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/log/level"
	"github.com/croessner/nauthilus/v4/server/stats"

	monittrace "github.com/croessner/nauthilus/v4/server/monitoring/trace"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"
)

// noScriptErrorPrefix is the Redis error prefix for an EVALSHA whose script is not loaded on the node.
const noScriptErrorPrefix = "NOSCRIPT"

// ScriptCall is one EVALSHA queued in a ScriptPipeline.
//
// A call that failed with NOSCRIPT is executed again with a new command, so callers read the reply through
// the call and never keep the raw command.
type ScriptCall struct {
	name   string
	keys   []string
	args   []any
	cmd    *redis.Cmd
	queued bool
}

// Name returns the LuaScripts name of the queued script.
func (c *ScriptCall) Name() string {
	return c.name
}

// Result returns the reply of the last execution of this script call.
func (c *ScriptCall) Result() (any, error) {
	return c.cmd.Result()
}

// Err returns the error of the last execution of this script call.
func (c *ScriptCall) Err() error {
	return c.cmd.Err()
}

// ScriptPipeline runs one Redis pipeline that mixes plain commands with EVALSHA calls to LuaScripts.
//
// It keeps the guarantees of ExecuteScript for pipelined scripts: SHAs are resolved (and uploaded when
// needed) before the pipeline starts, keys are normalized for Redis Cluster, every execution is counted once
// as a Redis write (callers must not count the script again), a script that is missing on a node is re-uploaded once and only the calls that failed with
// NOSCRIPT run again, and failed calls are logged like ExecuteScript does. Plain commands are never repeated,
// so the retry is safe for pipelines that write.
type ScriptPipeline struct {
	client Client
	handle redis.UniversalClient
	calls  []*ScriptCall
}

// NewScriptPipeline creates a script-aware pipeline for one Redis handle of client.
func NewScriptPipeline(client Client, handle redis.UniversalClient) *ScriptPipeline {
	return &ScriptPipeline{client: client, handle: handle}
}

// EvalSha queues one call of the LuaScripts entry scriptName into pipe.
// If the script SHA cannot be resolved, the call is not queued and carries the upload error instead.
func (p *ScriptPipeline) EvalSha(ctx context.Context, pipe redis.Pipeliner, scriptName string, keys []string, args ...any) *ScriptCall {
	call := &ScriptCall{
		name: scriptName,
		keys: scriptKeysForClient(p.handle, keys),
		args: args,
	}

	p.calls = append(p.calls, call)

	sha1, err := resolveScriptSHA(ctx, p.client, scriptName, LuaScripts[scriptName])
	if err != nil {
		call.cmd = redis.NewCmd(ctx)
		call.cmd.SetErr(err)

		return call
	}

	stats.GetMetrics().GetRedisWriteCounter().Inc()

	call.cmd = pipe.EvalSha(ctx, sha1, call.keys, call.args...)
	call.queued = true

	return call
}

// Exec runs queue in one pipeline and retries script calls that failed with NOSCRIPT once.
// queue receives the context of the redis.script_pipeline span and must build every command and every
// EvalSha call with it, so that Redis hook spans nest under the pipeline span.
// It returns the first failed command after that retry, in queue order. Callers must still evaluate every
// command and every ScriptCall on its own because a pipeline only reports its first failure.
func (p *ScriptPipeline) Exec(ctx context.Context, queue func(ctx context.Context, pipe redis.Pipeliner)) error {
	tr := monittrace.New("nauthilus/redis_batch")

	sctx, sp := tr.Start(ctx, "redis.script_pipeline")
	defer sp.End()

	cmds, _ := p.handle.Pipelined(sctx, func(pipe redis.Pipeliner) error {
		queue(sctx, pipe)

		return nil
	})

	failed := p.noScriptCalls()
	if len(failed) > 0 {
		sp.SetAttributes(attribute.String("retry_reason", "noscript"), attribute.Int("retried", len(failed)))
	}

	retried := p.retryNoScript(sctx, failed)

	p.logFailedCalls()

	sp.SetAttributes(attribute.Int("scripts_count", len(p.calls)))

	err := p.firstError(cmds, retried)
	if err != nil {
		sp.RecordError(err)
	}

	return err
}

// firstError returns the first failed command in queue order, reading retried script calls from their
// latest execution, followed by script calls that were never queued.
func (p *ScriptPipeline) firstError(cmds []redis.Cmder, retried map[redis.Cmder]*ScriptCall) error {
	for _, cmd := range cmds {
		if call, ok := retried[cmd]; ok {
			if err := call.Err(); err != nil {
				return err
			}

			continue
		}

		if err := cmd.Err(); err != nil {
			return err
		}
	}

	for _, call := range p.calls {
		if !call.queued {
			return call.Err()
		}
	}

	return nil
}

// retryNoScript re-uploads scripts missing on a node and executes only their failed calls again.
// It maps each replaced command to its call so that errors can be read from the latest execution.
func (p *ScriptPipeline) retryNoScript(ctx context.Context, failed []*ScriptCall) map[redis.Cmder]*ScriptCall {
	if len(failed) == 0 {
		return nil
	}

	retried := make(map[redis.Cmder]*ScriptCall, len(failed))
	for _, call := range failed {
		retried[call.cmd] = call
	}

	shas := p.reuploadScripts(ctx, failed)

	_, _ = p.handle.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		for _, call := range failed {
			sha1, ok := shas[call.name]
			if !ok {
				continue
			}

			stats.GetMetrics().GetRedisWriteCounter().Inc()

			call.cmd = pipe.EvalSha(ctx, sha1, call.keys, call.args...)
		}

		return nil
	})

	return retried
}

// noScriptCalls returns the queued calls whose last execution failed with NOSCRIPT.
func (p *ScriptPipeline) noScriptCalls() []*ScriptCall {
	var failed []*ScriptCall

	for _, call := range p.calls {
		if err := call.cmd.Err(); err != nil && strings.HasPrefix(err.Error(), noScriptErrorPrefix) {
			failed = append(failed, call)
		}
	}

	return failed
}

// reuploadScripts invalidates and uploads every script named by calls once and returns the new SHAs.
func (p *ScriptPipeline) reuploadScripts(ctx context.Context, calls []*ScriptCall) map[string]string {
	shas := make(map[string]string, len(calls))
	attempted := make(map[string]bool, len(calls))

	for _, call := range calls {
		if attempted[call.name] {
			continue
		}

		attempted[call.name] = true

		level.Warn(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Pipeline NOSCRIPT for Redis Lua script '%s', re-uploading script to all nodes", call.name),
		)

		InvalidateScript(call.name)

		sha1, err := UploadScript(ctx, p.client, call.name, LuaScripts[call.name])
		if err != nil {
			continue
		}

		shas[call.name] = sha1
	}

	return shas
}

// logFailedCalls logs every executed script call that still failed after the NOSCRIPT retry.
// Calls that were never queued already reported their upload failure.
func (p *ScriptPipeline) logFailedCalls() {
	for _, call := range p.calls {
		if err := call.cmd.Err(); err != nil && call.queued {
			level.Error(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to execute Redis Lua script '%s'", call.name),
				definitions.LogKeyError, err,
			)
		}
	}
}
