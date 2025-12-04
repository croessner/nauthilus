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

	lua "github.com/yuin/gopher-lua"
)

// This file exposes WithCtx factory aliases that mirror the existing command factories,
// allowing per-request binding by simply delegating to the current ctx-bound implementations.

func RedisPingWithCtx(ctx context.Context) lua.LGFunction          { return RedisPing(ctx) }
func RedisGetWithCtx(ctx context.Context) lua.LGFunction           { return RedisGet(ctx) }
func RedisSetWithCtx(ctx context.Context) lua.LGFunction           { return RedisSet(ctx) }
func RedisIncrWithCtx(ctx context.Context) lua.LGFunction          { return RedisIncr(ctx) }
func RedisDelWithCtx(ctx context.Context) lua.LGFunction           { return RedisDel(ctx) }
func RedisExpireWithCtx(ctx context.Context) lua.LGFunction        { return RedisExpire(ctx) }
func RedisExistsWithCtx(ctx context.Context) lua.LGFunction        { return RedisExists(ctx) }
func RedisHGetWithCtx(ctx context.Context) lua.LGFunction          { return RedisHGet(ctx) }
func RedisHSetWithCtx(ctx context.Context) lua.LGFunction          { return RedisHSet(ctx) }
func RedisHDelWithCtx(ctx context.Context) lua.LGFunction          { return RedisHDel(ctx) }
func RedisHLenWithCtx(ctx context.Context) lua.LGFunction          { return RedisHLen(ctx) }
func RedisHGetAllWithCtx(ctx context.Context) lua.LGFunction       { return RedisHGetAll(ctx) }
func RedisHMGetWithCtx(ctx context.Context) lua.LGFunction         { return RedisHMGet(ctx) }
func RedisHIncrByWithCtx(ctx context.Context) lua.LGFunction       { return RedisHIncrBy(ctx) }
func RedisHIncrByFloatWithCtx(ctx context.Context) lua.LGFunction  { return RedisHIncrByFloat(ctx) }
func RedisHExistsWithCtx(ctx context.Context) lua.LGFunction       { return RedisHExists(ctx) }
func RedisRenameWithCtx(ctx context.Context) lua.LGFunction        { return RedisRename(ctx) }
func RedisSAddWithCtx(ctx context.Context) lua.LGFunction          { return RedisSAdd(ctx) }
func RedisSIsMemberWithCtx(ctx context.Context) lua.LGFunction     { return RedisSIsMember(ctx) }
func RedisSMembersWithCtx(ctx context.Context) lua.LGFunction      { return RedisSMembers(ctx) }
func RedisSRemWithCtx(ctx context.Context) lua.LGFunction          { return RedisSRem(ctx) }
func RedisSCardWithCtx(ctx context.Context) lua.LGFunction         { return RedisSCard(ctx) }
func RedisRunScriptWithCtx(ctx context.Context) lua.LGFunction     { return RedisRunScript(ctx) }
func RedisUploadScriptWithCtx(ctx context.Context) lua.LGFunction  { return RedisUploadScript(ctx) }
func RedisPipelineWithCtx(ctx context.Context) lua.LGFunction      { return RedisPipeline(ctx) }
func RedisZAddWithCtx(ctx context.Context) lua.LGFunction          { return RedisZAdd(ctx) }
func RedisZRemWithCtx(ctx context.Context) lua.LGFunction          { return RedisZRem(ctx) }
func RedisZRankWithCtx(ctx context.Context) lua.LGFunction         { return RedisZRank(ctx) }
func RedisZRangeWithCtx(ctx context.Context) lua.LGFunction        { return RedisZRange(ctx) }
func RedisZRevRangeWithCtx(ctx context.Context) lua.LGFunction     { return RedisZRevRange(ctx) }
func RedisZRangeByScoreWithCtx(ctx context.Context) lua.LGFunction { return RedisZRangeByScore(ctx) }
func RedisZRemRangeByScoreWithCtx(ctx context.Context) lua.LGFunction {
	return RedisZRemRangeByScore(ctx)
}
func RedisZRemRangeByRankWithCtx(ctx context.Context) lua.LGFunction {
	return RedisZRemRangeByRank(ctx)
}
func RedisZCountWithCtx(ctx context.Context) lua.LGFunction   { return RedisZCount(ctx) }
func RedisZScoreWithCtx(ctx context.Context) lua.LGFunction   { return RedisZScore(ctx) }
func RedisZRevRankWithCtx(ctx context.Context) lua.LGFunction { return RedisZRevRank(ctx) }
func RedisZIncrByWithCtx(ctx context.Context) lua.LGFunction  { return RedisZIncrBy(ctx) }
func RedisLPushWithCtx(ctx context.Context) lua.LGFunction    { return RedisLPush(ctx) }
func RedisRPushWithCtx(ctx context.Context) lua.LGFunction    { return RedisRPush(ctx) }
func RedisLPopWithCtx(ctx context.Context) lua.LGFunction     { return RedisLPop(ctx) }
func RedisRPopWithCtx(ctx context.Context) lua.LGFunction     { return RedisRPop(ctx) }
func RedisLRangeWithCtx(ctx context.Context) lua.LGFunction   { return RedisLRange(ctx) }
func RedisLLenWithCtx(ctx context.Context) lua.LGFunction     { return RedisLLen(ctx) }
func RedisMGetWithCtx(ctx context.Context) lua.LGFunction     { return RedisMGet(ctx) }
func RedisMSetWithCtx(ctx context.Context) lua.LGFunction     { return RedisMSet(ctx) }
func RedisKeysWithCtx(ctx context.Context) lua.LGFunction     { return RedisKeys(ctx) }
func RedisScanWithCtx(ctx context.Context) lua.LGFunction     { return RedisScan(ctx) }
func RedisPFAddWithCtx(ctx context.Context) lua.LGFunction    { return RedisPFAdd(ctx) }
func RedisPFCountWithCtx(ctx context.Context) lua.LGFunction  { return RedisPFCount(ctx) }
func RedisPFMergeWithCtx(ctx context.Context) lua.LGFunction  { return RedisPFMerge(ctx) }
