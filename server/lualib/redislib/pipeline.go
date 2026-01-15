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
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisPipeline provides a Lua API to execute multiple Redis commands in a single pipeline round-trip.
func (rm *RedisManager) RedisPipeline(L *lua.LState) int {
	mode := L.CheckString(2)
	cmds := L.CheckTable(3)

	var (
		fallback redis.UniversalClient
		dCtx     context.Context
		cancel   context.CancelFunc
	)

	if mode == "read" {
		fallback = rm.client.GetReadHandle()
		dCtx, cancel = util.GetCtxWithDeadlineRedisRead(rm.ctx, rm.cfg)
	} else {
		fallback = rm.client.GetWriteHandle()
		dCtx, cancel = util.GetCtxWithDeadlineRedisWrite(rm.ctx, rm.cfg)
	}

	defer cancel()

	conn := rm.getConn(L, fallback)
	pipe := conn.Pipeline()

	var readOps, writeOps int

	idx := 1

	for {
		row := cmds.RawGetInt(idx)
		if row == lua.LNil {
			break
		}

		idx++

		rowTbl, ok := row.(*lua.LTable)
		if !ok {
			return luastack.NewManager(L).PushError(fmt.Errorf("pipeline command at index %d must be a table", idx-1))
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
			writeOps++
		case "ping":
			pipe.Ping(dCtx)
			readOps++
		case "incr":
			key := rowTbl.RawGetInt(2).String()
			pipe.Incr(dCtx, key)
			writeOps++
		case "get":
			key := rowTbl.RawGetInt(2).String()
			pipe.Get(dCtx, key)
			readOps++
		case "del":
			key := rowTbl.RawGetInt(2).String()
			pipe.Del(dCtx, key)
			writeOps++
		case "expire":
			key := rowTbl.RawGetInt(2).String()
			sec := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
			pipe.Expire(dCtx, key, time.Duration(sec)*time.Second)
			writeOps++
		case "hget":
			hash := rowTbl.RawGetInt(2).String()
			field := rowTbl.RawGetInt(3).String()
			pipe.HGet(dCtx, hash, field)
			readOps++
		case "hset":
			hash := rowTbl.RawGetInt(2).String()
			field := rowTbl.RawGetInt(3).String()
			val, _ := convert.LuaValue(rowTbl.RawGetInt(4))
			pipe.HSet(dCtx, hash, field, val)
			writeOps++
		case "hmget":
			hash := rowTbl.RawGetInt(2).String()

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

			pipe.HMGet(dCtx, hash, fields...)
			readOps++
		case "hgetall":
			hash := rowTbl.RawGetInt(2).String()
			pipe.HGetAll(dCtx, hash)
			readOps++
		case "hexists":
			hash := rowTbl.RawGetInt(2).String()
			field := rowTbl.RawGetInt(3).String()
			pipe.HExists(dCtx, hash, field)
			readOps++
		case "hincrby":
			hash := rowTbl.RawGetInt(2).String()
			field := rowTbl.RawGetInt(3).String()
			inc := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))
			pipe.HIncrBy(dCtx, hash, field, inc)
			writeOps++
		case "sadd":
			key := rowTbl.RawGetInt(2).String()
			member := rowTbl.RawGetInt(3).String()
			pipe.SAdd(dCtx, key, member)
			writeOps++
		case "sismember":
			key := rowTbl.RawGetInt(2).String()
			member := rowTbl.RawGetInt(3).String()
			pipe.SIsMember(dCtx, key, member)
			readOps++
		case "smembers":
			key := rowTbl.RawGetInt(2).String()
			pipe.SMembers(dCtx, key)
			readOps++
		case "zadd":
			key := rowTbl.RawGetInt(2).String()
			score := float64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
			member := rowTbl.RawGetInt(4).String()
			pipe.ZAdd(dCtx, key, redis.Z{Score: score, Member: member})
			writeOps++
		case "zrem":
			key := rowTbl.RawGetInt(2).String()
			member := rowTbl.RawGetInt(3).String()
			pipe.ZRem(dCtx, key, member)
			writeOps++
		case "zremrangebyscore":
			key := rowTbl.RawGetInt(2).String()
			minStr := rowTbl.RawGetInt(3).String()
			maxStr := rowTbl.RawGetInt(4).String()
			pipe.ZRemRangeByScore(dCtx, key, minStr, maxStr)
			writeOps++
		case "zremrangebyrank":
			key := rowTbl.RawGetInt(2).String()
			start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
			stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))
			pipe.ZRemRangeByRank(dCtx, key, start, stop)
			writeOps++
		case "zcount":
			key := rowTbl.RawGetInt(2).String()
			minStr := rowTbl.RawGetInt(3).String()
			maxStr := rowTbl.RawGetInt(4).String()
			pipe.ZCount(dCtx, key, minStr, maxStr)
			readOps++
		case "zscore":
			key := rowTbl.RawGetInt(2).String()
			member := rowTbl.RawGetInt(3).String()
			pipe.ZScore(dCtx, key, member)
			readOps++
		case "zincrby":
			key := rowTbl.RawGetInt(2).String()
			score := float64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
			member := rowTbl.RawGetInt(4).String()
			pipe.ZIncrBy(dCtx, key, score, member)
			writeOps++
		case "exists":
			key := rowTbl.RawGetInt(2).String()
			pipe.Exists(dCtx, key)
			readOps++
		case "hdel":
			hash := rowTbl.RawGetInt(2).String()

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
			writeOps++
		case "hlen":
			hash := rowTbl.RawGetInt(2).String()
			pipe.HLen(dCtx, hash)
			readOps++
		case "hincrbyfloat":
			hash := rowTbl.RawGetInt(2).String()
			field := rowTbl.RawGetInt(3).String()
			inc := float64(lua.LVAsNumber(rowTbl.RawGetInt(4)))
			pipe.HIncrByFloat(dCtx, hash, field, inc)
			writeOps++
		case "rename":
			oldKey := rowTbl.RawGetInt(2).String()
			newKey := rowTbl.RawGetInt(3).String()
			pipe.Rename(dCtx, oldKey, newKey)
			writeOps++
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
			writeOps++
		case "scard":
			key := rowTbl.RawGetInt(2).String()
			pipe.SCard(dCtx, key)
			readOps++
		case "zrank":
			key := rowTbl.RawGetInt(2).String()
			member := rowTbl.RawGetInt(3).String()
			pipe.ZRank(dCtx, key, member)
			readOps++
		case "zrevrank":
			key := rowTbl.RawGetInt(2).String()
			member := rowTbl.RawGetInt(3).String()
			pipe.ZRevRank(dCtx, key, member)
			readOps++
		case "zrange":
			key := rowTbl.RawGetInt(2).String()
			start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
			stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))
			pipe.ZRange(dCtx, key, start, stop)
			readOps++
		case "zrevrange":
			key := rowTbl.RawGetInt(2).String()
			start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
			stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))
			pipe.ZRevRange(dCtx, key, start, stop)
			readOps++
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
			readOps++
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
			writeOps++
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
			writeOps++
		case "lpop":
			key := rowTbl.RawGetInt(2).String()
			pipe.LPop(dCtx, key)
			writeOps++
		case "rpop":
			key := rowTbl.RawGetInt(2).String()
			pipe.RPop(dCtx, key)
			writeOps++
		case "lrange":
			key := rowTbl.RawGetInt(2).String()
			start := int64(lua.LVAsNumber(rowTbl.RawGetInt(3)))
			stop := int64(lua.LVAsNumber(rowTbl.RawGetInt(4)))
			pipe.LRange(dCtx, key, start, stop)
			readOps++
		case "llen":
			key := rowTbl.RawGetInt(2).String()
			pipe.LLen(dCtx, key)
			readOps++
		case "mget":
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
			readOps++
		case "mset":
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
			writeOps++
		case "keys":
			pattern := rowTbl.RawGetInt(2).String()
			pipe.Keys(dCtx, pattern)
			readOps++
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

			pipe.Scan(dCtx, cursor, match, count)
			readOps++
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
			writeOps++
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
			readOps++
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
			writeOps++
		case "run_script":
			script := rowTbl.RawGetInt(2).String()
			uploadScriptName := ""

			if v := rowTbl.RawGetInt(3); v != lua.LNil {
				uploadScriptName = v.String()
			}

			var keys []string
			if kt, ok := rowTbl.RawGetInt(4).(*lua.LTable); ok {
				kt.ForEach(func(_, v lua.LValue) { keys = append(keys, v.String()) })
			}

			var args []any
			if at, ok := rowTbl.RawGetInt(5).(*lua.LTable); ok {
				at.ForEach(func(_, v lua.LValue) {
					gv, _ := convert.LuaValue(v)
					args = append(args, gv)
				})
			}

			_, err := rm.evaluateRedisScript(dCtx, pipe, script, uploadScriptName, keys, args...)
			if err != nil {
				return luastack.NewManager(L).PushError(err)
			}

			writeOps++
		default:
			return luastack.NewManager(L).PushError(fmt.Errorf("unsupported pipeline command: %s", cmdName))
		}
	}

	cmders, err := pipe.Exec(dCtx)
	if err != nil && err != redis.Nil {
		return luastack.NewManager(L).PushError(err)
	}

	if readOps > 0 {
		stats.GetMetrics().GetRedisReadCounter().Add(float64(readOps))
	}
	if writeOps > 0 {
		stats.GetMetrics().GetRedisWriteCounter().Add(float64(writeOps))
	}

	resultTbl := L.NewTable()
	for _, cmd := range cmders {
		item := L.NewTable()
		if cmd.Err() != nil && cmd.Err() != redis.Nil {
			item.RawSetString("ok", lua.LBool(false))
			item.RawSetString("err", lua.LString(cmd.Err().Error()))
		} else {
			item.RawSetString("ok", lua.LBool(true))

			if errors.Is(cmd.Err(), redis.Nil) {
				item.RawSetString("value", lua.LNil)
			} else {
				// Convert various Cmd types to Lua values
				switch c := cmd.(type) {
				case *redis.StringCmd:
					item.RawSetString("value", lua.LString(c.Val()))
				case *redis.IntCmd:
					item.RawSetString("value", lua.LNumber(c.Val()))
				case *redis.BoolCmd:
					item.RawSetString("value", lua.LBool(c.Val()))
				case *redis.StatusCmd:
					item.RawSetString("value", lua.LString(c.Val()))
				case *redis.SliceCmd:
					t := L.NewTable()
					for _, v := range c.Val() {
						t.Append(convert.GoToLuaValue(L, v))
					}

					item.RawSetString("value", t)
				case *redis.StringSliceCmd:
					t := L.NewTable()
					for _, v := range c.Val() {
						t.Append(lua.LString(v))
					}

					item.RawSetString("value", t)
				case *redis.FloatCmd:
					item.RawSetString("value", lua.LNumber(c.Val()))
				case *redis.ScanCmd:
					keys, cursor, err := c.Result()
					if errors.Is(err, redis.Nil) {
						item.RawSetString("value", lua.LNil)
					} else if err != nil {
						item.RawSetString("ok", lua.LBool(false))
						item.RawSetString("err", lua.LString(err.Error()))
					} else {
						valTbl := L.NewTable()
						keysTbl := L.NewTable()
						for _, k := range keys {
							keysTbl.Append(lua.LString(k))
						}
						valTbl.RawSetString("keys", keysTbl)
						valTbl.RawSetString("cursor", lua.LNumber(cursor))
						item.RawSetString("value", valTbl)
					}
				case *redis.ZSliceCmd:
					t := L.NewTable()
					for _, v := range c.Val() {
						itemTbl := L.NewTable()
						itemTbl.RawSetString("member", lua.LString(v.Member.(string)))
						itemTbl.RawSetString("score", lua.LNumber(v.Score))
						t.Append(itemTbl)
					}

					item.RawSetString("value", t)
				case *redis.MapStringStringCmd:
					t := L.NewTable()
					for k, v := range c.Val() {
						t.RawSetString(k, lua.LString(v))
					}

					item.RawSetString("value", t)
				case *redis.Cmd:
					item.RawSetString("value", convert.GoToLuaValue(L, c.Val()))
				default:
					item.RawSetString("value", lua.LNil)
				}
			}
		}

		resultTbl.Append(item)
	}

	L.Push(resultTbl)
	L.Push(lua.LNil)

	return 2
}
