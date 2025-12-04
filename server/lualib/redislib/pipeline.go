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
	"errors"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/redis/go-redis/v9"

	lua "github.com/yuin/gopher-lua"
)

// setPipelineItem writes a standardized result object into item (ok, value|err)
// This replaces the per-iteration closure to avoid re-allocations in the loop.
func setPipelineItem(L *lua.LState, item *lua.LTable, val any, err error) {
	if errors.Is(err, redis.Nil) {
		item.RawSetString("ok", lua.LBool(true))
		item.RawSetString("value", lua.LNil)

		return
	}

	if err != nil {
		item.RawSetString("ok", lua.LBool(false))
		item.RawSetString("err", lua.LString(err.Error()))

		return
	}

	item.RawSetString("ok", lua.LBool(true))
	item.RawSetString("value", convert.GoToLuaValue(L, val))
}

// RedisPipeline provides a Lua API to execute multiple Redis commands in a single pipeline round-trip.
// Usage from Lua:
//
//	nauthilus_redis.redis_pipeline(handle, "write", {
//	    {"run_script", "ZAddRemExpire", {key}, {timestamp, member, 0, timestamp-window, expire}},
//	    {"expire", key, 3600},
//	    {"hget", some_hash, field},
//	})
//
// Returns a Lua table of results (one entry per command). For write-only commands the result is their native reply.
func RedisPipeline(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		// Args:
		// 1: redis handle (userdata or "default")
		// 2: mode ("write"|"read")
		// 3: commands table
		mode := L.CheckString(2)
		cmds := L.CheckTable(3)

		// Choose fallback client based on mode
		var fallback redis.UniversalClient
		var dCtx context.Context
		var cancel context.CancelFunc

		if mode == "read" {
			fallback = rediscli.GetClient().GetReadHandle()
			dCtx, cancel = util.GetCtxWithDeadlineRedisRead(ctx)

			defer cancel()
		} else {
			fallback = rediscli.GetClient().GetWriteHandle()
			dCtx, cancel = util.GetCtxWithDeadlineRedisWrite(ctx)

			defer cancel()
		}

		client := getRedisConnectionWithFallback(L, fallback)

		// Create pipeline on selected client
		pipe := client.Pipeline()

		// build pipeline
		var innerErr error

		idx := 1

		for {
			row := cmds.RawGetInt(idx)
			if row == lua.LNil {
				break
			}

			idx++

			rowTbl, ok := row.(*lua.LTable)
			if !ok {
				L.Push(lua.LNil)
				L.Push(lua.LString(fmt.Sprintf("pipeline command at index %d must be a table", idx-1)))

				return 2
			}

			cmdName := rowTbl.RawGetInt(1).String()

			switch cmdName {
			case "set":
				key := rowTbl.RawGetInt(2).String()
				val, _ := convert.LuaValue(rowTbl.RawGetInt(3))
				exp := time.Duration(0)

				if v := rowTbl.RawGetInt(4); v != lua.LNil {
					exp = time.Duration(lua.LVAsNumber(v)) * time.Second
				}

				pipe.Set(dCtx, key, val, exp)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "ping":
				pipe.Ping(dCtx)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "incr":
				key := rowTbl.RawGetInt(2).String()

				pipe.Incr(dCtx, key)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "get":
				key := rowTbl.RawGetInt(2).String()

				pipe.Get(dCtx, key)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "del":
				key := rowTbl.RawGetInt(2).String()

				pipe.Del(dCtx, key)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "expire":
				key := rowTbl.RawGetInt(2).String()
				sec := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))

				pipe.Expire(dCtx, key, time.Duration(sec)*time.Second)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "hget":
				hash := rowTbl.RawGetInt(2).String()
				field := rowTbl.RawGetInt(3).String()

				pipe.HGet(dCtx, hash, field)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "hmget":
				// HMGET hash field [field ...] | fields can also be provided as a Lua table at index 3
				hash := rowTbl.RawGetInt(2).String()

				var fields []string
				if t, ok := rowTbl.RawGetInt(3).(*lua.LTable); ok {
					// fields provided as table
					t.ForEach(func(_ lua.LValue, v lua.LValue) { fields = append(fields, v.String()) })
				} else {
					// fields provided as varargs starting at index 3
					j := 3
					for {
						v := rowTbl.RawGetInt(j)
						if v == lua.LNil {
							break
						}

						fields = append(fields, v.String())
						j++
					}
				}

				if len(fields) == 0 {
					fields = []string{""}
				}

				pipe.HMGet(dCtx, hash, fields...)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "hgetall":
				hash := rowTbl.RawGetInt(2).String()

				pipe.HGetAll(dCtx, hash)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "hexists":
				hash := rowTbl.RawGetInt(2).String()
				field := rowTbl.RawGetInt(3).String()

				pipe.HExists(dCtx, hash, field)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "hset":
				hash := rowTbl.RawGetInt(2).String()
				field := rowTbl.RawGetInt(3).String()
				val, _ := convert.LuaValue(rowTbl.RawGetInt(4))

				pipe.HSet(dCtx, hash, field, val)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "hincrby":
				hash := rowTbl.RawGetInt(2).String()
				field := rowTbl.RawGetInt(3).String()
				inc := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.HIncrBy(dCtx, hash, field, inc)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "sadd":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.SAdd(dCtx, key, member)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "sismember":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.SIsMember(dCtx, key, member)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "smembers":
				key := rowTbl.RawGetInt(2).String()

				pipe.SMembers(dCtx, key)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zadd":
				key := rowTbl.RawGetInt(2).String()
				score := float64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				member := rowTbl.RawGetInt(4).String()

				pipe.ZAdd(dCtx, key, redis.Z{Score: score, Member: member})
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "zrem":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.ZRem(dCtx, key, member)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "zremrangebyscore":
				key := rowTbl.RawGetInt(2).String()
				minStr := rowTbl.RawGetInt(3).String()
				maxStr := rowTbl.RawGetInt(4).String()

				pipe.ZRemRangeByScore(dCtx, key, minStr, maxStr)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "zremrangebyrank":
				key := rowTbl.RawGetInt(2).String()
				start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.ZRemRangeByRank(dCtx, key, start, stop)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "zcount":
				key := rowTbl.RawGetInt(2).String()
				minStr := rowTbl.RawGetInt(3).String()
				maxStr := rowTbl.RawGetInt(4).String()

				pipe.ZCount(dCtx, key, minStr, maxStr)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zscore":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.ZScore(dCtx, key, member)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zincrby":
				key := rowTbl.RawGetInt(2).String()
				score := float64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				member := rowTbl.RawGetInt(4).String()

				pipe.ZIncrBy(dCtx, key, score, member)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			// Additional supported commands
			case "exists":
				key := rowTbl.RawGetInt(2).String()

				pipe.Exists(dCtx, key)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "hdel":
				hash := rowTbl.RawGetInt(2).String()

				// allow fields as table or varargs starting at idx3
				var fields []string
				if t, ok := rowTbl.RawGetInt(3).(*lua.LTable); ok {
					t.ForEach(func(_ lua.LValue, v lua.LValue) { fields = append(fields, v.String()) })
				} else {
					j := 3
					for {
						v := rowTbl.RawGetInt(j)
						if v == lua.LNil {
							break
						}

						fields = append(fields, v.String())

						j++
					}
				}

				if len(fields) == 0 {
					fields = []string{""}
				}

				pipe.HDel(dCtx, hash, fields...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "hlen":
				hash := rowTbl.RawGetInt(2).String()

				pipe.HLen(dCtx, hash)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "hincrbyfloat":
				hash := rowTbl.RawGetInt(2).String()
				field := rowTbl.RawGetInt(3).String()
				inc := float64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.HIncrByFloat(dCtx, hash, field, inc)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "rename":
				oldKey := rowTbl.RawGetInt(2).String()
				newKey := rowTbl.RawGetInt(3).String()

				pipe.Rename(dCtx, oldKey, newKey)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "srem":
				key := rowTbl.RawGetInt(2).String()

				var members []any
				if t, ok := rowTbl.RawGetInt(3).(*lua.LTable); ok {
					t.ForEach(func(_ lua.LValue, v lua.LValue) { members = append(members, v.String()) })
				} else {
					j := 3
					for {
						v := rowTbl.RawGetInt(j)
						if v == lua.LNil {
							break
						}

						members = append(members, v.String())

						j++
					}
				}

				pipe.SRem(dCtx, key, members...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "scard":
				key := rowTbl.RawGetInt(2).String()

				pipe.SCard(dCtx, key)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zrank":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.ZRank(dCtx, key, member)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zrevrank":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.ZRevRank(dCtx, key, member)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zrange":
				key := rowTbl.RawGetInt(2).String()
				start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.ZRange(dCtx, key, start, stop)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zrevrange":
				key := rowTbl.RawGetInt(2).String()
				start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.ZRevRange(dCtx, key, start, stop)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zrangebyscore":
				key := rowTbl.RawGetInt(2).String()
				minStr := rowTbl.RawGetInt(3).String()
				maxStr := rowTbl.RawGetInt(4).String()
				optsTbl, _ := rowTbl.RawGetInt(5).(*lua.LTable)
				opts := &redis.ZRangeBy{Min: minStr, Max: maxStr}

				if optsTbl != nil {
					if off := optsTbl.RawGetString("offset"); off != lua.LNil {
						opts.Offset = int64(lua.LVAsNumber(off))
					}

					if cnt := optsTbl.RawGetString("count"); cnt != lua.LNil {
						opts.Count = int64(lua.LVAsNumber(cnt))
					}
				}

				pipe.ZRangeByScore(dCtx, key, opts)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "lpush":
				key := rowTbl.RawGetInt(2).String()

				var values []any
				if t, ok := rowTbl.RawGetInt(3).(*lua.LTable); ok {
					t.ForEach(func(_ lua.LValue, v lua.LValue) { values = append(values, v.String()) })
				} else {
					j := 3
					for {
						v := rowTbl.RawGetInt(j)
						if v == lua.LNil {
							break
						}

						values = append(values, v.String())

						j++
					}
				}

				if len(values) == 0 {
					values = []any{""}
				}

				pipe.LPush(dCtx, key, values...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "rpush":
				key := rowTbl.RawGetInt(2).String()

				var values []any
				if t, ok := rowTbl.RawGetInt(3).(*lua.LTable); ok {
					t.ForEach(func(_ lua.LValue, v lua.LValue) { values = append(values, v.String()) })
				} else {
					j := 3
					for {
						v := rowTbl.RawGetInt(j)
						if v == lua.LNil {
							break
						}

						values = append(values, v.String())

						j++
					}
				}

				if len(values) == 0 {
					values = []any{""}
				}

				pipe.RPush(dCtx, key, values...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "lpop":
				key := rowTbl.RawGetInt(2).String()

				pipe.LPop(dCtx, key)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "rpop":
				key := rowTbl.RawGetInt(2).String()

				pipe.RPop(dCtx, key)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "lrange":
				key := rowTbl.RawGetInt(2).String()
				start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.LRange(dCtx, key, start, stop)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "llen":
				key := rowTbl.RawGetInt(2).String()

				pipe.LLen(dCtx, key)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "mget":
				// keys can be a table or varargs
				var keys []string

				j := 2

				for {
					v := rowTbl.RawGetInt(j)
					if v == lua.LNil {
						break
					}

					if tbl, ok := v.(*lua.LTable); ok {
						tbl.ForEach(func(_ lua.LValue, vv lua.LValue) { keys = append(keys, vv.String()) })
					} else {
						keys = append(keys, v.String())
					}

					j++
				}

				pipe.MGet(dCtx, keys...)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "mset":
				// values can be a flat array table [key1,val1,key2,val2,...] or varargs
				var kv []any

				j := 2

				for {
					v := rowTbl.RawGetInt(j)
					if v == lua.LNil {
						break
					}

					if tbl, ok := v.(*lua.LTable); ok {
						tbl.ForEach(func(_ lua.LValue, vv lua.LValue) { kv = append(kv, vv.String()) })
					} else {
						kv = append(kv, v.String())
					}

					j++
				}

				pipe.MSet(dCtx, kv...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "keys":
				pattern := rowTbl.RawGetInt(2).String()

				pipe.Keys(dCtx, pattern)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "scan":
				cursor := uint64(lua.LVAsNumber(rowTbl.RawGetInt(2)))

				match := rowTbl.RawGetInt(3).String()
				if rowTbl.RawGetInt(3) == lua.LNil {
					match = "*"
				}

				count := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))
				if rowTbl.RawGetInt(4) == lua.LNil {
					count = 10
				}

				pipe.Scan(ctx, cursor, match, count)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "pfadd":
				key := rowTbl.RawGetInt(2).String()

				var values []any
				if t, ok := rowTbl.RawGetInt(3).(*lua.LTable); ok {
					t.ForEach(func(_ lua.LValue, v lua.LValue) { values = append(values, v.String()) })
				} else {
					j := 3
					for {
						v := rowTbl.RawGetInt(j)
						if v == lua.LNil {
							break
						}

						values = append(values, v.String())

						j++
					}
				}

				pipe.PFAdd(dCtx, key, values...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "pfcount":
				var keys2 []string
				if t, ok := rowTbl.RawGetInt(2).(*lua.LTable); ok {
					t.ForEach(func(_ lua.LValue, v lua.LValue) { keys2 = append(keys2, v.String()) })
				} else {
					j := 2
					for {
						v := rowTbl.RawGetInt(j)
						if v == lua.LNil {
							break
						}

						keys2 = append(keys2, v.String())

						j++
					}
				}

				pipe.PFCount(dCtx, keys2...)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "pfmerge":
				dest := rowTbl.RawGetInt(2).String()

				var sources []string
				if t, ok := rowTbl.RawGetInt(3).(*lua.LTable); ok {
					t.ForEach(func(_ lua.LValue, v lua.LValue) { sources = append(sources, v.String()) })
				} else {
					j := 3
					for {
						v := rowTbl.RawGetInt(j)
						if v == lua.LNil {
							break
						}

						sources = append(sources, v.String())

						j++
					}
				}

				pipe.PFMerge(dCtx, dest, sources...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "evalsha", "run_script":
				// row: {"run_script", uploadScriptName, {keys...}, {args...}}
				uploadName := rowTbl.RawGetInt(2).String()
				keysTbl, _ := rowTbl.RawGetInt(3).(*lua.LTable)
				argsTbl, _ := rowTbl.RawGetInt(4).(*lua.LTable)

				var keys []string
				var args []any

				if keysTbl != nil {
					keysTbl.ForEach(func(_ lua.LValue, v lua.LValue) { keys = append(keys, v.String()) })
				}

				if argsTbl != nil {
					argsTbl.ForEach(func(_ lua.LValue, v lua.LValue) { args = append(args, v.String()) })
				}

				sha1 := uploads.Get(uploadName)
				if sha1 == "" {
					innerErr = fmt.Errorf("unknown uploaded script name: %s", uploadName)

					break
				}

				pipe.EvalSha(dCtx, sha1, keys, args...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			default:
				innerErr = fmt.Errorf("unsupported pipeline command: %s", cmdName)
			}

			if innerErr != nil {
				break
			}
		}

		if innerErr != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(innerErr.Error()))

			return 2
		}

		captured, execErr := pipe.Exec(dCtx)
		if execErr != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(execErr.Error()))

			return 2
		}

		// Convert results to Lua table (structured per-entry: { ok=bool, value=?, err=string|nil })
		out := L.NewTable()
		for _, cmd := range captured {
			item := L.NewTable()

			switch c := cmd.(type) {
			case *redis.StringCmd:
				val, err := c.Result()
				setPipelineItem(L, item, val, err)
			case *redis.IntCmd:
				val, err := c.Result()
				setPipelineItem(L, item, val, err)
			case *redis.BoolCmd:
				val, err := c.Result()
				setPipelineItem(L, item, val, err)
			case *redis.StatusCmd:
				val, err := c.Result()
				setPipelineItem(L, item, val, err)
			case *redis.StringSliceCmd:
				val, err := c.Result()
				setPipelineItem(L, item, val, err)
			case *redis.MapStringStringCmd:
				val, err := c.Result()
				setPipelineItem(L, item, val, err)
			case *redis.FloatCmd:
				val, err := c.Result()
				setPipelineItem(L, item, val, err)
			case *redis.SliceCmd:
				val, err := c.Result()
				setPipelineItem(L, item, val, err)
			case *redis.ZSliceCmd:
				val, err := c.Result()
				setPipelineItem(L, item, val, err)
			case *redis.ScanCmd:
				keys, cursor, err := c.Result()
				if errors.Is(err, redis.Nil) {
					item.RawSetString("ok", lua.LBool(true))
					item.RawSetString("value", lua.LNil)
				} else if err != nil {
					item.RawSetString("ok", lua.LBool(false))
					item.RawSetString("err", lua.LString(err.Error()))
				} else {
					item.RawSetString("ok", lua.LBool(true))

					valTbl := L.NewTable()

					// keys
					keysTbl := L.NewTable()
					for _, k := range keys {
						keysTbl.Append(lua.LString(k))
					}

					valTbl.RawSetString("keys", keysTbl)
					valTbl.RawSetString("cursor", lua.LNumber(cursor))
					item.RawSetString("value", valTbl)
				}
			default:
				if cmd.Err() != nil {
					item.RawSetString("ok", lua.LBool(false))
					item.RawSetString("err", lua.LString(cmd.Err().Error()))
				} else {
					item.RawSetString("ok", lua.LBool(true))
					item.RawSetString("value", lua.LString(cmd.String()))
				}
			}

			out.Append(item)
		}

		L.Push(out)
		L.Push(lua.LNil)

		return 2
	}
}
