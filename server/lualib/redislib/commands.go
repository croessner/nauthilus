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

// Package redislib provides redislib functionality.
package redislib

import (
	"context"
	"errors"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib/convert"
	"github.com/croessner/nauthilus/v3/server/lualib/luastack"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisPing checks the connectivity to the Redis server.
func (rm *RedisManager) RedisPing(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		cmd := conn.Ping(ctx)
		if cmd.Err() != nil {
			return stack.PushError(cmd.Err())
		}

		L.Push(lua.LString(cmd.Val()))
		L.Push(lua.LNil)

		return 2
	})
}

// RedisGet retrieves a value from Redis using the given key and pushes it to the Lua state based on a specified type.
func (rm *RedisManager) RedisGet(L *lua.LState) int {
	return rm.ExecuteRead(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)
		valueType := definitions.TypeString

		if stack.GetTop() == 3 {
			valueType = stack.CheckString(3)
		}

		err := convert.StringCmd(conn.Get(ctx, key), valueType, L)
		if err != nil {
			return stack.PushError(err)
		}

		return 2
	})
}

// RedisSet provides a Lua function for setting a Redis key to a given value with optional expiration time in seconds.
func (rm *RedisManager) RedisSet(L *lua.LState) int {
	return rm.ExecuteWrite(L, func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int {
		key := stack.CheckString(2)

		value, err := convert.LuaValue(stack.CheckAny(3))
		if err != nil {
			return stack.PushError(err)
		}

		options, err := parseRedisSetOptions(L, stack)
		if err != nil {
			return stack.PushError(err)
		}

		return executeRedisSet(ctx, conn, stack, key, value, options)
	})
}

type redisSetOptions struct {
	args    redis.SetArgs
	useArgs bool
}

// parseRedisSetOptions parses legacy TTL and modern SET option arguments.
func parseRedisSetOptions(L *lua.LState, stack *luastack.Manager) (redisSetOptions, error) {
	var options redisSetOptions
	if stack.GetTop() < 4 {
		return options, nil
	}

	value := L.Get(4)
	if tbl, ok := value.(*lua.LTable); ok {
		options.useArgs = true
		options.args = parseRedisSetTableOptions(tbl)

		return options, nil
	}

	if value.Type() != lua.LTNumber {
		return options, nil
	}

	ttlSeconds := int64(stack.CheckInt(4))
	if ttlSeconds < 0 {
		return options, errors.New("expiration seconds must be >= 0")
	}

	options.args.TTL = time.Duration(ttlSeconds) * time.Second

	return options, nil
}

// parseRedisSetTableOptions maps Lua SET option fields into redis.SetArgs.
func parseRedisSetTableOptions(tbl *lua.LTable) redis.SetArgs {
	var args redis.SetArgs

	applyRedisSetModeOptions(tbl, &args)
	applyRedisSetBooleanOptions(tbl, &args)
	applyRedisSetExpiryAtOptions(tbl, &args)
	applyRedisSetTTLOptions(tbl, &args)

	return args
}

// applyRedisSetModeOptions applies mutually exclusive NX and XX mode flags.
func applyRedisSetModeOptions(tbl *lua.LTable, args *redis.SetArgs) {
	if luaBoolField(tbl, "nx") {
		args.Mode = "NX"
	}

	if luaBoolField(tbl, "xx") {
		args.Mode = "XX"
	}
}

// applyRedisSetBooleanOptions applies GET and KEEPTTL flags.
func applyRedisSetBooleanOptions(tbl *lua.LTable, args *redis.SetArgs) {
	args.Get = luaBoolField(tbl, "get")
	args.KeepTTL = luaBoolField(tbl, "keepttl")
}

// luaBoolField reports whether a Lua table field is a true boolean.
func luaBoolField(tbl *lua.LTable, key string) bool {
	value := tbl.RawGetString(key)

	return value.Type() == lua.LTBool && lua.LVAsBool(value)
}

// applyRedisSetExpiryAtOptions applies absolute expiration options.
func applyRedisSetExpiryAtOptions(tbl *lua.LTable, args *redis.SetArgs) {
	if sec, ok := luaPositiveIntField(tbl, "exat"); ok {
		args.ExpireAt = time.Unix(sec, 0)
	}

	if ms, ok := luaPositiveIntField(tbl, "pxat"); ok {
		args.ExpireAt = time.Unix(0, ms*int64(time.Millisecond))
	}
}

// applyRedisSetTTLOptions applies relative expiration options.
func applyRedisSetTTLOptions(tbl *lua.LTable, args *redis.SetArgs) {
	if sec, ok := luaPositiveIntField(tbl, "ex"); ok {
		args.TTL = time.Duration(sec) * time.Second
	}

	if ms, ok := luaPositiveIntField(tbl, "px"); ok {
		args.TTL = time.Duration(ms) * time.Millisecond
	}
}

// luaPositiveIntField returns a positive numeric Lua table field.
func luaPositiveIntField(tbl *lua.LTable, key string) (int64, bool) {
	value := tbl.RawGetString(key)
	if value.Type() != lua.LTNumber {
		return 0, false
	}

	number := int64(lua.LVAsNumber(value))
	if number <= 0 {
		return 0, false
	}

	return number, true
}

// executeRedisSet executes SET or SET with redis.SetArgs and pushes normalized results.
func executeRedisSet(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager, key string, value any, options redisSetOptions) int {
	if options.useArgs {
		cmd := conn.SetArgs(ctx, key, value, options.args)

		return pushRedisSetResult(stack, cmd.Val(), cmd.Err())
	}

	cmd := conn.Set(ctx, key, value, options.args.TTL)

	return pushRedisSetResult(stack, cmd.Val(), cmd.Err())
}

// pushRedisSetResult handles Redis nil and error results for SET variants.
func pushRedisSetResult(stack *luastack.Manager, value string, err error) int {
	if err == nil {
		return stack.PushResults(lua.LString(value), lua.LNil)
	}

	if errors.Is(err, redis.Nil) {
		return stack.PushResults(lua.LNil, lua.LNil)
	}

	return stack.PushError(err)
}

// RedisIncr increments the value of a key in Redis.
func (rm *RedisManager) RedisIncr(L *lua.LState) int {
	return executeKeyCmd(rm, L, true, func(ctx context.Context, conn redis.Cmdable, key string) *redis.IntCmd {
		return conn.Incr(ctx, key)
	}, luaNumberValue[int64])
}

// RedisDel deletes a key from Redis.
func (rm *RedisManager) RedisDel(L *lua.LState) int {
	return executeKeyCmd(rm, L, true, func(ctx context.Context, conn redis.Cmdable, key string) *redis.IntCmd {
		return conn.Del(ctx, key)
	}, luaNumberValue[int64])
}

// RedisRename renames a key in Redis.
func (rm *RedisManager) RedisRename(L *lua.LState) int {
	return executeTwoStringCmd(rm, L, true, func(ctx context.Context, conn redis.Cmdable, oldKey, newKey string) *redis.StatusCmd {
		return conn.Rename(ctx, oldKey, newKey)
	}, luaStringValue)
}

// RedisExpire sets an expiration time on a key.
func (rm *RedisManager) RedisExpire(L *lua.LState) int {
	return executeExpireCmd(rm, L, func(ctx context.Context, conn redis.Cmdable, key string, ttl time.Duration) *redis.BoolCmd {
		return conn.Expire(ctx, key, ttl)
	})
}

// RedisExists checks if a key exists in Redis.
func (rm *RedisManager) RedisExists(L *lua.LState) int {
	return executeKeyCmd(rm, L, false, func(ctx context.Context, conn redis.Cmdable, key string) *redis.IntCmd {
		return conn.Exists(ctx, key)
	}, luaNumberValue[int64])
}
