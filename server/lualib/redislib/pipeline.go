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

	"github.com/croessner/nauthilus/v3/server/lualib/convert"
	"github.com/croessner/nauthilus/v3/server/lualib/luastack"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// pipelineStringArgs reads string arguments from a pipeline row, expanding table values.
func pipelineStringArgs(rowTbl *lua.LTable, start int) []string {
	var values []string

	for index := start; ; index++ {
		value := rowTbl.RawGetInt(index)
		if value == lua.LNil {
			break
		}

		if tbl, ok := value.(*lua.LTable); ok {
			tbl.ForEach(func(_ lua.LValue, item lua.LValue) {
				values = append(values, item.String())
			})
		} else {
			values = append(values, value.String())
		}
	}

	return values
}

// pipelineStringArgsOrDefault returns a legacy placeholder when no string arguments were supplied.
func pipelineStringArgsOrDefault(rowTbl *lua.LTable, start int, fallback string) []string {
	values := pipelineStringArgs(rowTbl, start)
	if len(values) == 0 {
		return []string{fallback}
	}

	return values
}

// pipelineAnyStringArgs reads pipeline arguments as string-backed interface values.
func pipelineAnyStringArgs(rowTbl *lua.LTable, start int) []any {
	strings := pipelineStringArgs(rowTbl, start)

	values := make([]any, 0, len(strings))
	for _, value := range strings {
		values = append(values, value)
	}

	return values
}

// pipelineAnyStringArgsOrDefault returns interface values with a legacy fallback for empty inputs.
func pipelineAnyStringArgsOrDefault(rowTbl *lua.LTable, start int, fallback string) []any {
	values := pipelineAnyStringArgs(rowTbl, start)
	if len(values) == 0 {
		return []any{fallback}
	}

	return values
}

type pipelineExecutor struct {
	rm       *RedisManager
	L        *lua.LState
	ctx      context.Context
	pipe     redis.Pipeliner
	readOps  int
	writeOps int
}

type pipelineCommandHandler func(*pipelineExecutor, *lua.LTable) error

var pipelineCommandHandlers = map[string]pipelineCommandHandler{
	"set":              (*pipelineExecutor).queueSet,
	"ping":             (*pipelineExecutor).queuePing,
	"incr":             (*pipelineExecutor).queueIncr,
	"get":              (*pipelineExecutor).queueGet,
	"del":              (*pipelineExecutor).queueDel,
	"expire":           (*pipelineExecutor).queueExpire,
	"hget":             (*pipelineExecutor).queueHGet,
	"hset":             (*pipelineExecutor).queueHSet,
	"hmget":            (*pipelineExecutor).queueHMGet,
	"hgetall":          (*pipelineExecutor).queueHGetAll,
	"hexists":          (*pipelineExecutor).queueHExists,
	"hincrby":          (*pipelineExecutor).queueHIncrBy,
	"sadd":             (*pipelineExecutor).queueSAdd,
	"sismember":        (*pipelineExecutor).queueSIsMember,
	"smembers":         (*pipelineExecutor).queueSMembers,
	"zadd":             (*pipelineExecutor).queueZAdd,
	"zrem":             (*pipelineExecutor).queueZRem,
	"zremrangebyscore": (*pipelineExecutor).queueZRemRangeByScore,
	"zremrangebyrank":  (*pipelineExecutor).queueZRemRangeByRank,
	"zcount":           (*pipelineExecutor).queueZCount,
	"zscore":           (*pipelineExecutor).queueZScore,
	"zincrby":          (*pipelineExecutor).queueZIncrBy,
	"exists":           (*pipelineExecutor).queueExists,
	"hdel":             (*pipelineExecutor).queueHDel,
	"hlen":             (*pipelineExecutor).queueHLen,
	"hincrbyfloat":     (*pipelineExecutor).queueHIncrByFloat,
	"rename":           (*pipelineExecutor).queueRename,
	"srem":             (*pipelineExecutor).queueSRem,
	"scard":            (*pipelineExecutor).queueSCard,
	"zrank":            (*pipelineExecutor).queueZRank,
	"zrevrank":         (*pipelineExecutor).queueZRevRank,
	"zrange":           (*pipelineExecutor).queueZRange,
	"zrevrange":        (*pipelineExecutor).queueZRevRange,
	"zrangebyscore":    (*pipelineExecutor).queueZRangeByScore,
	"lpush":            (*pipelineExecutor).queueLPush,
	"rpush":            (*pipelineExecutor).queueRPush,
	"lpop":             (*pipelineExecutor).queueLPop,
	"rpop":             (*pipelineExecutor).queueRPop,
	"lrange":           (*pipelineExecutor).queueLRange,
	"llen":             (*pipelineExecutor).queueLLen,
	"mget":             (*pipelineExecutor).queueMGet,
	"mset":             (*pipelineExecutor).queueMSet,
	"keys":             (*pipelineExecutor).queueKeys,
	"scan":             (*pipelineExecutor).queueScan,
	"pfadd":            (*pipelineExecutor).queuePFAdd,
	"pfcount":          (*pipelineExecutor).queuePFCount,
	"pfmerge":          (*pipelineExecutor).queuePFMerge,
	"run_script":       (*pipelineExecutor).queueRunScript,
}

// RedisPipeline provides a Lua API to execute multiple Redis commands in a single pipeline round-trip.
func (rm *RedisManager) RedisPipeline(L *lua.LState) int {
	mode := L.CheckString(2)
	cmds := L.CheckTable(3)

	fallback, dCtx, cancel := rm.pipelineContext(L, mode)
	defer cancel()

	conn := rm.getConn(L, fallback)
	pipe := conn.Pipeline()

	executor := &pipelineExecutor{rm: rm, L: L, ctx: dCtx, pipe: pipe}
	if err := executor.queueCommands(cmds); err != nil {
		return luastack.NewManager(L).PushError(err)
	}

	cmders, err := pipe.Exec(dCtx)
	if err != nil && !errors.Is(err, redis.Nil) {
		return luastack.NewManager(L).PushError(err)
	}

	executor.recordMetrics()
	resultTbl := executor.resultTable(cmders)

	L.Push(resultTbl)
	L.Push(lua.LNil)

	return 2
}

// pipelineContext selects read or write handles and deadlines for a pipeline mode.
func (rm *RedisManager) pipelineContext(L *lua.LState, mode string) (redis.UniversalClient, context.Context, context.CancelFunc) {
	if mode == "read" {
		ctx, cancel := util.GetCtxWithDeadlineRedisRead(rm.currentContext(L), rm.cfg)

		return rm.client.GetReadHandle(), ctx, cancel
	}

	ctx, cancel := util.GetCtxWithDeadlineRedisWrite(rm.currentContext(L), rm.cfg)

	return rm.client.GetWriteHandle(), ctx, cancel
}

// queueCommands validates and queues all Lua pipeline command rows.
func (e *pipelineExecutor) queueCommands(cmds *lua.LTable) error {
	for idx := 1; ; idx++ {
		row := cmds.RawGetInt(idx)
		if row == lua.LNil {
			return nil
		}

		if err := e.queueCommandRow(idx, row); err != nil {
			return err
		}
	}
}

// queueCommandRow validates one command row and dispatches it to the command handler.
func (e *pipelineExecutor) queueCommandRow(idx int, row lua.LValue) error {
	rowTbl, ok := row.(*lua.LTable)
	if !ok {
		return fmt.Errorf("pipeline command at index %d must be a table", idx)
	}

	cmdName := rowTbl.RawGetInt(1).String()

	handler, ok := pipelineCommandHandlers[cmdName]
	if !ok {
		return fmt.Errorf("unsupported pipeline command: %s", cmdName)
	}

	return handler(e, rowTbl)
}

// queueSet queues a SET command.
func (e *pipelineExecutor) queueSet(row *lua.LTable) error {
	value, _ := convert.LuaValue(row.RawGetInt(3))

	exp := time.Duration(0)
	if v := row.RawGetInt(4); v != lua.LNil {
		exp = time.Duration(lua.LVAsNumber(v)) * time.Second
	}

	e.pipe.Set(e.ctx, row.RawGetInt(2).String(), value, exp)
	e.writeOps++

	return nil
}

// queuePing queues a PING command.
func (e *pipelineExecutor) queuePing(_ *lua.LTable) error {
	e.pipe.Ping(e.ctx)
	e.readOps++

	return nil
}

// queueIncr queues an INCR command.
func (e *pipelineExecutor) queueIncr(row *lua.LTable) error {
	e.pipe.Incr(e.ctx, row.RawGetInt(2).String())
	e.writeOps++

	return nil
}

// queueGet queues a GET command.
func (e *pipelineExecutor) queueGet(row *lua.LTable) error {
	e.pipe.Get(e.ctx, row.RawGetInt(2).String())
	e.readOps++

	return nil
}

// queueDel queues a DEL command.
func (e *pipelineExecutor) queueDel(row *lua.LTable) error {
	e.pipe.Del(e.ctx, row.RawGetInt(2).String())
	e.writeOps++

	return nil
}

// queueExpire queues an EXPIRE command.
func (e *pipelineExecutor) queueExpire(row *lua.LTable) error {
	sec := int64(lua.LVAsNumber(row.RawGetInt(3)))
	e.pipe.Expire(e.ctx, row.RawGetInt(2).String(), time.Duration(sec)*time.Second)
	e.writeOps++

	return nil
}

// queueHGet queues an HGET command.
func (e *pipelineExecutor) queueHGet(row *lua.LTable) error {
	e.pipe.HGet(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String())
	e.readOps++

	return nil
}

// queueHSet queues an HSET command.
func (e *pipelineExecutor) queueHSet(row *lua.LTable) error {
	value, _ := convert.LuaValue(row.RawGetInt(4))
	e.pipe.HSet(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String(), value)
	e.writeOps++

	return nil
}

// queueHMGet queues an HMGET command.
func (e *pipelineExecutor) queueHMGet(row *lua.LTable) error {
	e.pipe.HMGet(e.ctx, row.RawGetInt(2).String(), pipelineStringArgsOrDefault(row, 3, "")...)
	e.readOps++

	return nil
}

// queueHGetAll queues an HGETALL command.
func (e *pipelineExecutor) queueHGetAll(row *lua.LTable) error {
	e.pipe.HGetAll(e.ctx, row.RawGetInt(2).String())
	e.readOps++

	return nil
}

// queueHExists queues an HEXISTS command.
func (e *pipelineExecutor) queueHExists(row *lua.LTable) error {
	e.pipe.HExists(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String())
	e.readOps++

	return nil
}

// queueHIncrBy queues an HINCRBY command.
func (e *pipelineExecutor) queueHIncrBy(row *lua.LTable) error {
	inc := int64(lua.LVAsNumber(row.RawGetInt(4)))
	e.pipe.HIncrBy(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String(), inc)
	e.writeOps++

	return nil
}

// queueSAdd queues an SADD command.
func (e *pipelineExecutor) queueSAdd(row *lua.LTable) error {
	e.pipe.SAdd(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String())
	e.writeOps++

	return nil
}

// queueSIsMember queues an SISMEMBER command.
func (e *pipelineExecutor) queueSIsMember(row *lua.LTable) error {
	e.pipe.SIsMember(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String())
	e.readOps++

	return nil
}

// queueSMembers queues an SMEMBERS command.
func (e *pipelineExecutor) queueSMembers(row *lua.LTable) error {
	e.pipe.SMembers(e.ctx, row.RawGetInt(2).String())
	e.readOps++

	return nil
}

// queueZAdd queues a ZADD command.
func (e *pipelineExecutor) queueZAdd(row *lua.LTable) error {
	score := float64(lua.LVAsNumber(row.RawGetInt(3)))
	member := row.RawGetInt(4).String()
	e.pipe.ZAdd(e.ctx, row.RawGetInt(2).String(), redis.Z{Score: score, Member: member})
	e.writeOps++

	return nil
}

// queueZRem queues a ZREM command.
func (e *pipelineExecutor) queueZRem(row *lua.LTable) error {
	e.pipe.ZRem(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String())
	e.writeOps++

	return nil
}

// queueZRemRangeByScore queues a ZREMRANGEBYSCORE command.
func (e *pipelineExecutor) queueZRemRangeByScore(row *lua.LTable) error {
	e.pipe.ZRemRangeByScore(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String(), row.RawGetInt(4).String())
	e.writeOps++

	return nil
}

// queueZRemRangeByRank queues a ZREMRANGEBYRANK command.
func (e *pipelineExecutor) queueZRemRangeByRank(row *lua.LTable) error {
	start := int64(lua.LVAsNumber(row.RawGetInt(3)))
	stop := int64(lua.LVAsNumber(row.RawGetInt(4)))
	e.pipe.ZRemRangeByRank(e.ctx, row.RawGetInt(2).String(), start, stop)
	e.writeOps++

	return nil
}

// queueZCount queues a ZCOUNT command.
func (e *pipelineExecutor) queueZCount(row *lua.LTable) error {
	e.pipe.ZCount(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String(), row.RawGetInt(4).String())
	e.readOps++

	return nil
}

// queueZScore queues a ZSCORE command.
func (e *pipelineExecutor) queueZScore(row *lua.LTable) error {
	e.pipe.ZScore(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String())
	e.readOps++

	return nil
}

// queueZIncrBy queues a ZINCRBY command.
func (e *pipelineExecutor) queueZIncrBy(row *lua.LTable) error {
	score := float64(lua.LVAsNumber(row.RawGetInt(3)))
	e.pipe.ZIncrBy(e.ctx, row.RawGetInt(2).String(), score, row.RawGetInt(4).String())
	e.writeOps++

	return nil
}

// queueExists queues an EXISTS command.
func (e *pipelineExecutor) queueExists(row *lua.LTable) error {
	e.pipe.Exists(e.ctx, row.RawGetInt(2).String())
	e.readOps++

	return nil
}

// queueHDel queues an HDEL command.
func (e *pipelineExecutor) queueHDel(row *lua.LTable) error {
	e.pipe.HDel(e.ctx, row.RawGetInt(2).String(), pipelineStringArgsOrDefault(row, 3, "")...)
	e.writeOps++

	return nil
}

// queueHLen queues an HLEN command.
func (e *pipelineExecutor) queueHLen(row *lua.LTable) error {
	e.pipe.HLen(e.ctx, row.RawGetInt(2).String())
	e.readOps++

	return nil
}

// queueHIncrByFloat queues an HINCRBYFLOAT command.
func (e *pipelineExecutor) queueHIncrByFloat(row *lua.LTable) error {
	inc := float64(lua.LVAsNumber(row.RawGetInt(4)))
	e.pipe.HIncrByFloat(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String(), inc)
	e.writeOps++

	return nil
}

// queueRename queues a RENAME command.
func (e *pipelineExecutor) queueRename(row *lua.LTable) error {
	e.pipe.Rename(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String())
	e.writeOps++

	return nil
}

// queueSRem queues an SREM command.
func (e *pipelineExecutor) queueSRem(row *lua.LTable) error {
	e.pipe.SRem(e.ctx, row.RawGetInt(2).String(), pipelineAnyStringArgs(row, 3)...)
	e.writeOps++

	return nil
}

// queueSCard queues an SCARD command.
func (e *pipelineExecutor) queueSCard(row *lua.LTable) error {
	e.pipe.SCard(e.ctx, row.RawGetInt(2).String())
	e.readOps++

	return nil
}

// queueZRank queues a ZRANK command.
func (e *pipelineExecutor) queueZRank(row *lua.LTable) error {
	e.pipe.ZRank(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String())
	e.readOps++

	return nil
}

// queueZRevRank queues a ZREVRANK command.
func (e *pipelineExecutor) queueZRevRank(row *lua.LTable) error {
	e.pipe.ZRevRank(e.ctx, row.RawGetInt(2).String(), row.RawGetInt(3).String())
	e.readOps++

	return nil
}

// queueZRange queues a ZRANGE command.
func (e *pipelineExecutor) queueZRange(row *lua.LTable) error {
	start, stop := pipelineRangeBounds(row)
	e.pipe.ZRange(e.ctx, row.RawGetInt(2).String(), start, stop)
	e.readOps++

	return nil
}

// queueZRevRange queues a ZREVRANGE command.
func (e *pipelineExecutor) queueZRevRange(row *lua.LTable) error {
	start, stop := pipelineRangeBounds(row)
	e.pipe.ZRevRange(e.ctx, row.RawGetInt(2).String(), start, stop)
	e.readOps++

	return nil
}

// pipelineRangeBounds reads start and stop values from a row.
func pipelineRangeBounds(row *lua.LTable) (int64, int64) {
	start := int64(lua.LVAsNumber(row.RawGetInt(3)))
	stop := int64(lua.LVAsNumber(row.RawGetInt(4)))

	return start, stop
}

// queueZRangeByScore queues a ZRANGEBYSCORE command.
func (e *pipelineExecutor) queueZRangeByScore(row *lua.LTable) error {
	opts := pipelineZRangeByScore(row)
	e.pipe.ZRangeByScore(e.ctx, row.RawGetInt(2).String(), opts)
	e.readOps++

	return nil
}

// pipelineZRangeByScore builds Redis score-range options from a row.
func pipelineZRangeByScore(row *lua.LTable) *redis.ZRangeBy {
	opts := &redis.ZRangeBy{
		Min: row.RawGetInt(3).String(),
		Max: row.RawGetInt(4).String(),
	}

	if optsTbl, ok := row.RawGetInt(5).(*lua.LTable); ok {
		applyPipelineZRangeLimit(opts, optsTbl)
	}

	return opts
}

// applyPipelineZRangeLimit applies optional offset and count fields.
func applyPipelineZRangeLimit(opts *redis.ZRangeBy, optsTbl *lua.LTable) {
	if off := optsTbl.RawGetString("offset"); off != lua.LNil {
		opts.Offset = int64(lua.LVAsNumber(off))
	}

	if cnt := optsTbl.RawGetString("count"); cnt != lua.LNil {
		opts.Count = int64(lua.LVAsNumber(cnt))
	}
}

// queueLPush queues an LPUSH command.
func (e *pipelineExecutor) queueLPush(row *lua.LTable) error {
	e.pipe.LPush(e.ctx, row.RawGetInt(2).String(), pipelineAnyStringArgsOrDefault(row, 3, "")...)
	e.writeOps++

	return nil
}

// queueRPush queues an RPUSH command.
func (e *pipelineExecutor) queueRPush(row *lua.LTable) error {
	e.pipe.RPush(e.ctx, row.RawGetInt(2).String(), pipelineAnyStringArgsOrDefault(row, 3, "")...)
	e.writeOps++

	return nil
}

// queueLPop queues an LPOP command.
func (e *pipelineExecutor) queueLPop(row *lua.LTable) error {
	e.pipe.LPop(e.ctx, row.RawGetInt(2).String())
	e.writeOps++

	return nil
}

// queueRPop queues an RPOP command.
func (e *pipelineExecutor) queueRPop(row *lua.LTable) error {
	e.pipe.RPop(e.ctx, row.RawGetInt(2).String())
	e.writeOps++

	return nil
}

// queueLRange queues an LRANGE command.
func (e *pipelineExecutor) queueLRange(row *lua.LTable) error {
	start, stop := pipelineRangeBounds(row)
	e.pipe.LRange(e.ctx, row.RawGetInt(2).String(), start, stop)
	e.readOps++

	return nil
}

// queueLLen queues an LLEN command.
func (e *pipelineExecutor) queueLLen(row *lua.LTable) error {
	e.pipe.LLen(e.ctx, row.RawGetInt(2).String())
	e.readOps++

	return nil
}

// queueMGet queues an MGET command.
func (e *pipelineExecutor) queueMGet(row *lua.LTable) error {
	e.pipe.MGet(e.ctx, pipelineStringArgs(row, 2)...)
	e.readOps++

	return nil
}

// queueMSet queues an MSET command.
func (e *pipelineExecutor) queueMSet(row *lua.LTable) error {
	e.pipe.MSet(e.ctx, pipelineAnyStringArgs(row, 2)...)
	e.writeOps++

	return nil
}

// queueKeys queues a KEYS command.
func (e *pipelineExecutor) queueKeys(row *lua.LTable) error {
	e.pipe.Keys(e.ctx, row.RawGetInt(2).String())
	e.readOps++

	return nil
}

// queueScan queues a SCAN command.
func (e *pipelineExecutor) queueScan(row *lua.LTable) error {
	cursor := uint64(lua.LVAsNumber(row.RawGetInt(2)))
	match := pipelineOptionalString(row, 3, "*")
	count := pipelineOptionalInt64(row, 4, 10)
	e.pipe.Scan(e.ctx, cursor, match, count)
	e.readOps++

	return nil
}

// pipelineOptionalString reads an optional string row value.
func pipelineOptionalString(row *lua.LTable, idx int, fallback string) string {
	if value := row.RawGetInt(idx); value != lua.LNil {
		return value.String()
	}

	return fallback
}

// pipelineOptionalInt64 reads an optional numeric row value.
func pipelineOptionalInt64(row *lua.LTable, idx int, fallback int64) int64 {
	if value := row.RawGetInt(idx); value != lua.LNil {
		return int64(lua.LVAsNumber(value))
	}

	return fallback
}

// queuePFAdd queues a PFADD command.
func (e *pipelineExecutor) queuePFAdd(row *lua.LTable) error {
	e.pipe.PFAdd(e.ctx, row.RawGetInt(2).String(), pipelineAnyStringArgs(row, 3)...)
	e.writeOps++

	return nil
}

// queuePFCount queues a PFCOUNT command.
func (e *pipelineExecutor) queuePFCount(row *lua.LTable) error {
	e.pipe.PFCount(e.ctx, pipelineStringArgs(row, 2)...)
	e.readOps++

	return nil
}

// queuePFMerge queues a PFMERGE command.
func (e *pipelineExecutor) queuePFMerge(row *lua.LTable) error {
	e.pipe.PFMerge(e.ctx, row.RawGetInt(2).String(), pipelineStringArgs(row, 3)...)
	e.writeOps++

	return nil
}

// queueRunScript queues a script evaluation command.
func (e *pipelineExecutor) queueRunScript(row *lua.LTable) error {
	_, err := e.rm.evaluateRedisScript(
		e.ctx,
		e.pipe,
		row.RawGetInt(2).String(),
		pipelineOptionalString(row, 3, ""),
		pipelineStringTable(row, 4),
		pipelineAnyTable(row, 5)...,
	)
	if err != nil {
		return err
	}

	e.writeOps++

	return nil
}

// pipelineStringTable converts a Lua table argument into strings.
func pipelineStringTable(row *lua.LTable, idx int) []string {
	var values []string

	if tbl, ok := row.RawGetInt(idx).(*lua.LTable); ok {
		tbl.ForEach(func(_, value lua.LValue) {
			values = append(values, value.String())
		})
	}

	return values
}

// pipelineAnyTable converts a Lua table argument into Go values.
func pipelineAnyTable(row *lua.LTable, idx int) []any {
	var values []any

	if tbl, ok := row.RawGetInt(idx).(*lua.LTable); ok {
		tbl.ForEach(func(_, value lua.LValue) {
			goValue, _ := convert.LuaValue(value)
			values = append(values, goValue)
		})
	}

	return values
}

// recordMetrics increments Redis operation counters for the queued commands.
func (e *pipelineExecutor) recordMetrics() {
	if e.readOps > 0 {
		stats.GetMetrics().GetRedisReadCounter().Add(float64(e.readOps))
	}

	if e.writeOps > 0 {
		stats.GetMetrics().GetRedisWriteCounter().Add(float64(e.writeOps))
	}
}

// resultTable converts pipeline command results to the Lua response table.
func (e *pipelineExecutor) resultTable(cmders []redis.Cmder) *lua.LTable {
	resultTbl := e.L.NewTable()
	for _, cmd := range cmders {
		resultTbl.Append(e.resultItem(cmd))
	}

	return resultTbl
}

// resultItem converts one Redis command result to a Lua table.
func (e *pipelineExecutor) resultItem(cmd redis.Cmder) *lua.LTable {
	item := e.L.NewTable()
	if cmd.Err() != nil && !errors.Is(cmd.Err(), redis.Nil) {
		item.RawSetString("ok", lua.LBool(false))
		item.RawSetString("err", lua.LString(cmd.Err().Error()))

		return item
	}

	item.RawSetString("ok", lua.LBool(true))

	if errors.Is(cmd.Err(), redis.Nil) {
		item.RawSetString("value", lua.LNil)

		return item
	}

	e.setResultValue(item, cmd)

	return item
}

// setResultValue maps Redis command result types onto Lua values.
func (e *pipelineExecutor) setResultValue(item *lua.LTable, cmd redis.Cmder) {
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
		item.RawSetString("value", e.sliceResultValue(c))
	case *redis.StringSliceCmd:
		item.RawSetString("value", e.stringSliceResultValue(c))
	case *redis.FloatCmd:
		item.RawSetString("value", lua.LNumber(c.Val()))
	case *redis.ScanCmd:
		e.setScanResultValue(item, c)
	case *redis.ZSliceCmd:
		item.RawSetString("value", e.zSliceResultValue(c))
	case *redis.MapStringStringCmd:
		item.RawSetString("value", e.stringMapResultValue(c))
	case *redis.Cmd:
		item.RawSetString("value", convert.GoToLuaValue(e.L, c.Val()))
	default:
		item.RawSetString("value", lua.LNil)
	}
}

// sliceResultValue converts a Redis slice result into a Lua table.
func (e *pipelineExecutor) sliceResultValue(cmd *redis.SliceCmd) *lua.LTable {
	table := e.L.NewTable()
	for _, value := range cmd.Val() {
		table.Append(convert.GoToLuaValue(e.L, value))
	}

	return table
}

// stringSliceResultValue converts a Redis string-slice result into a Lua table.
func (e *pipelineExecutor) stringSliceResultValue(cmd *redis.StringSliceCmd) *lua.LTable {
	table := e.L.NewTable()
	for _, value := range cmd.Val() {
		table.Append(lua.LString(value))
	}

	return table
}

// setScanResultValue converts a Redis scan result or error into the Lua item table.
func (e *pipelineExecutor) setScanResultValue(item *lua.LTable, cmd *redis.ScanCmd) {
	keys, cursor, err := cmd.Result()
	if errors.Is(err, redis.Nil) {
		item.RawSetString("value", lua.LNil)

		return
	}

	if err != nil {
		item.RawSetString("ok", lua.LBool(false))
		item.RawSetString("err", lua.LString(err.Error()))

		return
	}

	item.RawSetString("value", e.scanResultValue(keys, cursor))
}

// scanResultValue converts scan keys and cursor into a Lua table.
func (e *pipelineExecutor) scanResultValue(keys []string, cursor uint64) *lua.LTable {
	valueTbl := e.L.NewTable()

	keysTbl := e.L.NewTable()
	for _, key := range keys {
		keysTbl.Append(lua.LString(key))
	}

	valueTbl.RawSetString("keys", keysTbl)
	valueTbl.RawSetString("cursor", lua.LNumber(cursor))

	return valueTbl
}

// zSliceResultValue converts sorted-set results into Lua member-score tables.
func (e *pipelineExecutor) zSliceResultValue(cmd *redis.ZSliceCmd) *lua.LTable {
	table := e.L.NewTable()
	for _, value := range cmd.Val() {
		item := e.L.NewTable()
		item.RawSetString("member", lua.LString(value.Member.(string)))
		item.RawSetString("score", lua.LNumber(value.Score))
		table.Append(item)
	}

	return table
}

// stringMapResultValue converts Redis string maps into Lua tables.
func (e *pipelineExecutor) stringMapResultValue(cmd *redis.MapStringStringCmd) *lua.LTable {
	table := e.L.NewTable()
	for key, value := range cmd.Val() {
		table.RawSetString(key, lua.LString(value))
	}

	return table
}
