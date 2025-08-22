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
	"time"

	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

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
		if mode == "read" {
			fallback = rediscli.GetClient().GetReadHandle()
		} else {
			fallback = rediscli.GetClient().GetWriteHandle()
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

				pipe.Set(ctx, key, val, exp)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "ping":
				pipe.Ping(ctx)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "incr":
				key := rowTbl.RawGetInt(2).String()

				pipe.Incr(ctx, key)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "get":
				key := rowTbl.RawGetInt(2).String()

				pipe.Get(ctx, key)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "del":
				key := rowTbl.RawGetInt(2).String()

				pipe.Del(ctx, key)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "expire":
				key := rowTbl.RawGetInt(2).String()
				sec := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))

				pipe.Expire(ctx, key, time.Duration(sec)*time.Second)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "hget":
				hash := rowTbl.RawGetInt(2).String()
				field := rowTbl.RawGetInt(3).String()

				pipe.HGet(ctx, hash, field)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "hgetall":
				hash := rowTbl.RawGetInt(2).String()

				pipe.HGetAll(ctx, hash)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "hexists":
				hash := rowTbl.RawGetInt(2).String()
				field := rowTbl.RawGetInt(3).String()

				pipe.HExists(ctx, hash, field)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "hset":
				hash := rowTbl.RawGetInt(2).String()
				field := rowTbl.RawGetInt(3).String()
				val, _ := convert.LuaValue(rowTbl.RawGetInt(4))

				pipe.HSet(ctx, hash, field, val)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "hincrby":
				hash := rowTbl.RawGetInt(2).String()
				field := rowTbl.RawGetInt(3).String()
				inc := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.HIncrBy(ctx, hash, field, inc)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "sadd":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.SAdd(ctx, key, member)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "sismember":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.SIsMember(ctx, key, member)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "smembers":
				key := rowTbl.RawGetInt(2).String()

				pipe.SMembers(ctx, key)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zadd":
				key := rowTbl.RawGetInt(2).String()
				score := float64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				member := rowTbl.RawGetInt(4).String()

				pipe.ZAdd(ctx, key, redis.Z{Score: score, Member: member})
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "zrem":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.ZRem(ctx, key, member)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "zremrangebyscore":
				key := rowTbl.RawGetInt(2).String()
				minStr := rowTbl.RawGetInt(3).String()
				maxStr := rowTbl.RawGetInt(4).String()

				pipe.ZRemRangeByScore(ctx, key, minStr, maxStr)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "zremrangebyrank":
				key := rowTbl.RawGetInt(2).String()
				start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.ZRemRangeByRank(ctx, key, start, stop)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "zcount":
				key := rowTbl.RawGetInt(2).String()
				minStr := rowTbl.RawGetInt(3).String()
				maxStr := rowTbl.RawGetInt(4).String()

				pipe.ZCount(ctx, key, minStr, maxStr)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zscore":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.ZScore(ctx, key, member)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zincrby":
				key := rowTbl.RawGetInt(2).String()
				score := float64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				member := rowTbl.RawGetInt(4).String()

				pipe.ZIncrBy(ctx, key, score, member)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			// Additional supported commands
			case "exists":
				key := rowTbl.RawGetInt(2).String()

				pipe.Exists(ctx, key)
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

				pipe.HDel(ctx, hash, fields...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "hlen":
				hash := rowTbl.RawGetInt(2).String()

				pipe.HLen(ctx, hash)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "hincrbyfloat":
				hash := rowTbl.RawGetInt(2).String()
				field := rowTbl.RawGetInt(3).String()
				inc := float64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.HIncrByFloat(ctx, hash, field, inc)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "rename":
				oldKey := rowTbl.RawGetInt(2).String()
				newKey := rowTbl.RawGetInt(3).String()

				pipe.Rename(ctx, oldKey, newKey)
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

				pipe.SRem(ctx, key, members...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "scard":
				key := rowTbl.RawGetInt(2).String()

				pipe.SCard(ctx, key)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zrank":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.ZRank(ctx, key, member)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zrevrank":
				key := rowTbl.RawGetInt(2).String()
				member := rowTbl.RawGetInt(3).String()

				pipe.ZRevRank(ctx, key, member)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zrange":
				key := rowTbl.RawGetInt(2).String()
				start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.ZRange(ctx, key, start, stop)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "zrevrange":
				key := rowTbl.RawGetInt(2).String()
				start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.ZRevRange(ctx, key, start, stop)
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

				pipe.ZRangeByScore(ctx, key, opts)
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

				pipe.LPush(ctx, key, values...)
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

				pipe.RPush(ctx, key, values...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "lpop":
				key := rowTbl.RawGetInt(2).String()

				pipe.LPop(ctx, key)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "rpop":
				key := rowTbl.RawGetInt(2).String()

				pipe.RPop(ctx, key)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "lrange":
				key := rowTbl.RawGetInt(2).String()
				start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
				stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))

				pipe.LRange(ctx, key, start, stop)
				stats.GetMetrics().GetRedisReadCounter().Inc()

			case "llen":
				key := rowTbl.RawGetInt(2).String()

				pipe.LLen(ctx, key)
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

				pipe.MGet(ctx, keys...)
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

				pipe.MSet(ctx, kv...)
				stats.GetMetrics().GetRedisWriteCounter().Inc()

			case "keys":
				pattern := rowTbl.RawGetInt(2).String()

				pipe.Keys(ctx, pattern)
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

				pipe.PFAdd(ctx, key, values...)
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

				pipe.PFCount(ctx, keys2...)
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

				pipe.PFMerge(ctx, dest, sources...)
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

				pipe.EvalSha(ctx, sha1, keys, args...)
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

		captured, execErr := pipe.Exec(ctx)
		if execErr != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(execErr.Error()))

			return 2
		}

		// Convert results to Lua table
		out := L.NewTable()
		for _, cmd := range captured {
			// Attempt generic conversion via String() or dedicated Val methods
			switch c := cmd.(type) {
			case *redis.StringCmd:
				val, _ := c.Result()

				out.Append(convert.GoToLuaValue(L, val))
			case *redis.IntCmd:
				val, _ := c.Result()

				out.Append(convert.GoToLuaValue(L, val))
			case *redis.BoolCmd:
				val, _ := c.Result()

				out.Append(convert.GoToLuaValue(L, val))
			case *redis.StatusCmd:
				val, _ := c.Result()

				out.Append(convert.GoToLuaValue(L, val))
			case *redis.StringSliceCmd:
				val, _ := c.Result()

				out.Append(convert.GoToLuaValue(L, val))
			case *redis.MapStringStringCmd:
				val, _ := c.Result()

				out.Append(convert.GoToLuaValue(L, val))
			case *redis.FloatCmd:
				val, _ := c.Result()

				out.Append(convert.GoToLuaValue(L, val))
			case *redis.SliceCmd:
				val, _ := c.Result()

				out.Append(convert.GoToLuaValue(L, val))
			case *redis.ZSliceCmd:
				val, _ := c.Result()

				out.Append(convert.GoToLuaValue(L, val))
			default:
				// Fallback to Err or Text
				if cmd.Err() != nil {
					out.Append(lua.LString(cmd.Err().Error()))
				} else {
					out.Append(lua.LString(cmd.String()))
				}
			}
		}

		L.Push(out)
		L.Push(lua.LNil)

		return 2
	}
}
