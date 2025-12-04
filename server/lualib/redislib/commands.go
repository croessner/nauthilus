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

package redislib

import (
	"context"
	"errors"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisGet retrieves a value from Redis using the given key and pushes it to the Lua state based on a specified type.
func RedisGet(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)
		valueType := definitions.TypeString

		if L.GetTop() == 3 {
			valueType = L.CheckString(3)
		}

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
		defer cancel()

		err := convert.StringCmd(client.Get(dCtx, key), valueType, L)
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		return 1
	}
}

// RedisSet provides a Lua function for setting a Redis key to a given value with optional expiration time in seconds.
func RedisSet(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)

		value, err := convert.LuaValue(L.Get(3))
		if err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(err.Error()))

			return 2
		}

		// Backward compatible: 4th arg can be numeric seconds expiration.
		// New behavior: 4th arg can be a table of options supporting Redis SET options.
		var (
			useArgs bool
			args    redis.SetArgs
		)

		if L.GetTop() >= 4 {
			if tbl, ok := L.Get(4).(*lua.LTable); ok {
				useArgs = true

				// Options table:
				// nx, xx, get, keepttl as booleans
				// ex (seconds), px (milliseconds), exat (unix seconds), pxat (unix milliseconds)
				if v := tbl.RawGetString("nx"); v.Type() == lua.LTBool && lua.LVAsBool(v) {
					args.Mode = "NX"
				}

				if v := tbl.RawGetString("xx"); v.Type() == lua.LTBool && lua.LVAsBool(v) {
					args.Mode = "XX"
				}

				if v := tbl.RawGetString("get"); v.Type() == lua.LTBool && lua.LVAsBool(v) {
					args.Get = true
				}

				if v := tbl.RawGetString("keepttl"); v.Type() == lua.LTBool && lua.LVAsBool(v) {
					args.KeepTTL = true
				}

				// Expiration by absolute time has precedence if provided
				if v := tbl.RawGetString("exat"); v.Type() == lua.LTNumber {
					sec := int64(lua.LVAsNumber(v))
					if sec > 0 {
						args.ExpireAt = time.Unix(sec, 0)
					}
				}

				if v := tbl.RawGetString("pxat"); v.Type() == lua.LTNumber {
					ms := int64(lua.LVAsNumber(v))
					if ms > 0 {
						args.ExpireAt = time.Unix(0, ms*int64(time.Millisecond))
					}
				}

				// Relative expiration
				if v := tbl.RawGetString("ex"); v.Type() == lua.LTNumber {
					sec := int64(lua.LVAsNumber(v))
					if sec > 0 {
						args.TTL = time.Duration(sec) * time.Second
					}
				}

				if v := tbl.RawGetString("px"); v.Type() == lua.LTNumber {
					ms := int64(lua.LVAsNumber(v))
					if ms > 0 {
						args.TTL = time.Duration(ms) * time.Millisecond
					}
				}
			} else if L.Get(4).Type() == lua.LTNumber {
				// Legacy seconds TTL
				ttlSeconds := int64(L.CheckInt(4))
				if ttlSeconds < 0 {
					L.Push(lua.LNil)
					L.Push(lua.LString("expiration seconds must be >= 0"))

					return 2
				}

				useArgs = false

				// We'll call plain Set with seconds TTL
				// below in the execution path.
				// Keep ttlSeconds in local for use
				// by closing over variable.
				// To keep scope simple, we re-read from stack later.
			}
		}

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		if useArgs {
			cmd := client.SetArgs(dCtx, key, value, args)
			if cmd.Err() != nil {
				// Redis-conformant semantics for options-table path: redis.Nil means a legitimate nil reply
				// e.g., NX/XX condition not met or GET with no previous value.
				if errors.Is(cmd.Err(), redis.Nil) {
					L.Push(lua.LNil)

					return 1
				}

				L.Push(lua.LNil)
				L.Push(lua.LString(cmd.Err().Error()))

				return 2
			}

			// Return whatever server returned as string (typically "OK"; with GET, may be previous value)
			L.Push(lua.LString(cmd.Val()))

			return 1
		}

		// Legacy simple Set path
		expiration := time.Duration(0)
		if L.GetTop() == 4 && L.Get(4).Type() == lua.LTNumber {
			expiration = time.Duration(L.CheckInt(4)) * time.Second
		}

		cmd := client.Set(dCtx, key, value, expiration)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LString(cmd.Val()))

		return 1
	}
}

// RedisIncr increments the integer value of a Redis key by 1 and returns the new value or an error if it fails.
func RedisIncr(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.Incr(dCtx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisDel deletes a given Redis key and reports the number of keys removed or an error if the operation fails.
func RedisDel(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.Del(dCtx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}

// RedisExpire sets an expiration time on a Redis key and returns true if successful, or nil and an error if it fails.
func RedisExpire(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		key := L.CheckString(2)
		expiration := L.CheckNumber(3)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.Expire(dCtx, key, time.Duration(expiration)*time.Second)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LBool(cmd.Val()))

		return 1
	}
}

// RedisRename renames a Redis key to a new key; returns an error if the operation fails.
func RedisRename(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetWriteHandle())
		oldKey := L.CheckString(2)
		newKey := L.CheckString(3)

		defer stats.GetMetrics().GetRedisWriteCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx)
		defer cancel()

		cmd := client.Rename(dCtx, oldKey, newKey)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LString(cmd.Val()))

		return 1
	}
}

// RedisPing executes a Redis PING command and returns the result or an error message if it fails. Increases Redis read counter on success.
func RedisPing(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
		defer cancel()

		cmd := client.Ping(dCtx)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))

			return 2
		}

		L.Push(lua.LString(cmd.Val()))

		return 1
	}
}

// RedisExists checks if a given key exists in Redis, returning the count of matching keys as a Lua number.
func RedisExists(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		client := getRedisConnectionWithFallback(L, rediscli.GetClient().GetReadHandle())
		key := L.CheckString(2)

		defer stats.GetMetrics().GetRedisReadCounter().Inc()

		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(ctx)
		defer cancel()

		cmd := client.Exists(dCtx, key)
		if cmd.Err() != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(cmd.Err().Error()))
		}

		L.Push(lua.LNumber(cmd.Val()))

		return 1
	}
}
