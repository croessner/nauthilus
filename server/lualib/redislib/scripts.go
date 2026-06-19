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

package redislib

import (
	"context"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib/convert"
	"github.com/croessner/nauthilus/v3/server/lualib/luastack"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisRunScript executes a Lua script on the Redis server.
func (rm *RedisManager) RedisRunScript(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		script := stack.CheckString(2)
		uploadScriptName := stack.OptString(3, "")
		keys := rm.getLuaTableAsStringSlice(stack.CheckTable(4))
		top := stack.GetTop()

		var args []any

		// Check if the 5th argument is a table. If so, use it as the arguments list.
		// Otherwise, collect all arguments from the 5th onwards.
		if top == 5 && stack.L.Get(5).Type() == lua.LTTable {
			tbl := stack.CheckTable(5)

			tbl.ForEach(func(_, value lua.LValue) {
				val, err := convert.LuaValue(value)
				if err != nil {
					// In case of error during conversion, we might still want to try to convert it to string
					// to keep it backward compatible with the stateless version which uses v.String().
					args = append(args, value.String())
				} else {
					args = append(args, val)
				}
			})
		} else {
			for i := 5; i <= top; i++ {
				val, err := convert.LuaValue(stack.CheckAny(i))
				if err != nil {
					args = append(args, stack.CheckAny(i).String())
				} else {
					args = append(args, val)
				}
			}
		}

		result, err := rm.evaluateRedisScript(ctx, conn, script, uploadScriptName, keys, args...)
		if err != nil {
			return stack.PushError(err)
		}

		return stack.PushResults(convert.GoToLuaValue(L, result), lua.LNil)
	})
}

// evaluateRedisScript is an internal helper to execute Redis Lua scripts.
func (rm *RedisManager) evaluateRedisScript(ctx context.Context, conn redis.Cmdable, script string, uploadScriptName string, keys []string, args ...any) (any, error) {
	var (
		err    error
		result any
	)

	// Check if we're using Redis Cluster and ensure keys hash to the same slot if needed
	if uc, ok := conn.(redis.UniversalClient); ok && rediscli.IsClusterClient(uc) && len(keys) > 1 {
		keys = rediscli.EnsureKeysInSameSlot(keys, defaultHashTag)
	}

	if uploadScriptName != "" {
		uploadedScript, found := scriptsRepository.Get(uploadScriptName)
		if !found {
			return nil, fmt.Errorf("could not find script with name %s", uploadScriptName)
		}

		result, err = conn.EvalSha(ctx, uploadedScript.SHA1, keys, args...).Result()

		// Handle CROSSSLOT errors
		if isCrossSlotError(err) {
			keys = rediscli.EnsureKeysInSameSlot(keys, defaultHashTag)
			result, err = conn.EvalSha(ctx, uploadedScript.SHA1, keys, args...).Result()
		}

		if isNoScriptError(err) {
			result, err = rm.reuploadAndEvaluateNamedScript(ctx, conn, uploadScriptName, uploadedScript, keys, args...)
		}
	} else {
		result, err = conn.Eval(ctx, script, keys, args...).Result()

		// Handle CROSSSLOT errors
		if isCrossSlotError(err) {
			keys = rediscli.EnsureKeysInSameSlot(keys, defaultHashTag)
			result, err = conn.Eval(ctx, script, keys, args...).Result()
		}
	}

	return result, err
}

// reuploadAndEvaluateNamedScript restores a named custom script after Redis lost its script cache.
func (rm *RedisManager) reuploadAndEvaluateNamedScript(ctx context.Context, conn redis.Cmdable, uploadScriptName string, uploadedScript UploadedScript, keys []string, args ...any) (any, error) {
	_ = level.Warn(log.Logger).Log(
		definitions.LogKeyMsg, fmt.Sprintf("Custom Redis Lua script '%s' not found on Redis server, re-uploading", uploadScriptName),
		"operation", "redis_run_script",
	)

	sha1, err := rm.uploadRedisScript(ctx, conn, uploadedScript.Source, uploadScriptName)
	if err != nil {
		_ = level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to re-upload custom Redis Lua script '%s'", uploadScriptName),
			definitions.LogKeyError, err,
			"operation", "redis_run_script",
		)

		return nil, err
	}

	scriptsRepository.Set(uploadScriptName, sha1, uploadedScript.Source)

	result, err := conn.EvalSha(ctx, sha1, keys, args...).Result()
	if err != nil {
		_ = level.Error(log.Logger).Log(
			definitions.LogKeyMsg, fmt.Sprintf("Failed to execute custom Redis Lua script '%s' after re-upload", uploadScriptName),
			definitions.LogKeyError, err,
			"operation", "redis_run_script",
		)

		return nil, err
	}

	return result, nil
}

// isNoScriptError reports whether Redis returned any NOSCRIPT variant.
func isNoScriptError(err error) bool {
	return err != nil && strings.HasPrefix(strings.ToUpper(err.Error()), "NOSCRIPT")
}

// isCrossSlotError reports whether Redis rejected script keys for spanning slots.
func isCrossSlotError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "CROSSSLOT Keys in request don't hash to the same slot")
}

// RedisUploadScript uploads a Lua script to the Redis server and returns its SHA1 hash.
func (rm *RedisManager) RedisUploadScript(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		script := stack.CheckString(2)
		uploadScriptName := stack.OptString(3, "")

		sha1, err := rm.uploadRedisScript(ctx, conn, script, uploadScriptName)
		if err != nil {
			return stack.PushError(err)
		}

		if uploadScriptName != "" {
			scriptsRepository.Set(uploadScriptName, sha1, script)
		}

		return stack.PushResults(lua.LString(sha1), lua.LNil)
	})
}

// uploadRedisScript uploads a Lua script to the primary Redis handle and then
// distributes it to all read handles so that EvalSha works on replicas as well.
func (rm *RedisManager) uploadRedisScript(ctx context.Context, conn redis.Cmdable, script string, uploadScriptName string) (string, error) {
	sha1, err := conn.ScriptLoad(ctx, script).Result()
	if err != nil {
		return "", err
	}

	// Distribute to all read handles (replicas / read-only cluster nodes)
	for _, rh := range rm.client.GetReadHandles() {
		if _, err = rh.ScriptLoad(ctx, script).Result(); err != nil {
			_ = level.Warn(log.Logger).Log(
				definitions.LogKeyMsg, fmt.Sprintf("Failed to upload custom Redis Lua script '%s' to read handle (non-fatal)", uploadScriptName),
				definitions.LogKeyError, err,
				"operation", "redis_upload_script",
			)
		}
	}

	return sha1, nil
}

// getLuaTableAsStringSlice extracts string values from a Lua table and returns them as a slice of strings.
func (rm *RedisManager) getLuaTableAsStringSlice(tbl *lua.LTable) []string {
	var result []string

	tbl.ForEach(func(_, value lua.LValue) {
		result = append(result, value.String())
	})

	return result
}
