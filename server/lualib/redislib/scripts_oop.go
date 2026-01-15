//go:build redislib_oop

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

	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/croessner/nauthilus/server/rediscli"
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
		script = scriptsRepository.Get(uploadScriptName)
		if script == "" {
			return nil, fmt.Errorf("could not find script with name %s", uploadScriptName)
		}

		result, err = conn.EvalSha(ctx, script, keys, args...).Result()

		// Handle CROSSSLOT errors
		if err != nil && strings.Contains(err.Error(), "CROSSSLOT Keys in request don't hash to the same slot") {
			keys = rediscli.EnsureKeysInSameSlot(keys, defaultHashTag)
			result, err = conn.EvalSha(ctx, script, keys, args...).Result()
		}

		// Handle NOSCRIPT error by falling back to Eval
		if err != nil && strings.HasPrefix(err.Error(), "NOSCRIPT") {
			return nil, err
		}
	} else {
		result, err = conn.Eval(ctx, script, keys, args...).Result()

		// Handle CROSSSLOT errors
		if err != nil && strings.Contains(err.Error(), "CROSSSLOT Keys in request don't hash to the same slot") {
			keys = rediscli.EnsureKeysInSameSlot(keys, defaultHashTag)
			result, err = conn.Eval(ctx, script, keys, args...).Result()
		}
	}

	return result, err
}

// RedisUploadScript uploads a Lua script to the Redis server and returns its SHA1 hash.
func (rm *RedisManager) RedisUploadScript(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		script := stack.CheckString(2)
		uploadScriptName := stack.OptString(3, "")

		result, err := rm.uploadRedisScript(ctx, conn, script)
		if err != nil {
			return stack.PushError(err)
		}

		sha1, ok := result.(string)
		if ok && uploadScriptName != "" {
			scriptsRepository.Set(uploadScriptName, sha1)
		}

		return stack.PushResults(lua.LString(sha1), lua.LNil)
	})
}

// uploadRedisScript is an internal helper to upload a script to Redis.
func (rm *RedisManager) uploadRedisScript(ctx context.Context, conn redis.Cmdable, script string) (any, error) {
	return conn.ScriptLoad(ctx, script).Result()
}

// getLuaTableAsStringSlice extracts string values from a Lua table and returns them as a slice of strings.
func (rm *RedisManager) getLuaTableAsStringSlice(tbl *lua.LTable) []string {
	var result []string

	tbl.ForEach(func(_, value lua.LValue) {
		result = append(result, value.String())
	})

	return result
}
