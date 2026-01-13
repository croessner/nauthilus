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

	"github.com/croessner/nauthilus/server/config"
	lua "github.com/yuin/gopher-lua"
)

// This file exposes WithCtx factory aliases that mirror the existing command factories,
// allowing per-request binding by simply delegating to the current ctx-bound implementations.

func RedisPingWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisPing(ctx, cfg)
}
func RedisGetWithCtx(ctx context.Context, cfg config.File) lua.LGFunction { return RedisGet(ctx, cfg) }
func RedisSetWithCtx(ctx context.Context, cfg config.File) lua.LGFunction { return RedisSet(ctx, cfg) }
func RedisIncrWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisIncr(ctx, cfg)
}
func RedisDelWithCtx(ctx context.Context, cfg config.File) lua.LGFunction { return RedisDel(ctx, cfg) }
func RedisExpireWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisExpire(ctx, cfg)
}
func RedisExistsWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisExists(ctx, cfg)
}
func RedisHGetWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisHGet(ctx, cfg)
}
func RedisHSetWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisHSet(ctx, cfg)
}
func RedisHDelWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisHDel(ctx, cfg)
}
func RedisHLenWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisHLen(ctx, cfg)
}
func RedisHGetAllWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisHGetAll(ctx, cfg)
}
func RedisHMGetWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisHMGet(ctx, cfg)
}
func RedisHIncrByWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisHIncrBy(ctx, cfg)
}
func RedisHIncrByFloatWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisHIncrByFloat(ctx, cfg)
}
func RedisHExistsWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisHExists(ctx, cfg)
}
func RedisRenameWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisRename(ctx, cfg)
}
func RedisSAddWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisSAdd(ctx, cfg)
}
func RedisSIsMemberWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisSIsMember(ctx, cfg)
}
func RedisSMembersWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisSMembers(ctx, cfg)
}
func RedisSRemWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisSRem(ctx, cfg)
}
func RedisSCardWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisSCard(ctx, cfg)
}
func RedisRunScriptWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisRunScript(ctx, cfg)
}
func RedisUploadScriptWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisUploadScript(ctx, cfg)
}
func RedisPipelineWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisPipeline(ctx, cfg)
}
func RedisZAddWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZAdd(ctx, cfg)
}
func RedisZRemWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZRem(ctx, cfg)
}
func RedisZRankWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZRank(ctx, cfg)
}
func RedisZRangeWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZRange(ctx, cfg)
}
func RedisZRevRangeWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZRevRange(ctx, cfg)
}
func RedisZRangeByScoreWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZRangeByScore(ctx, cfg)
}
func RedisZRemRangeByScoreWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZRemRangeByScore(ctx, cfg)
}
func RedisZRemRangeByRankWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZRemRangeByRank(ctx, cfg)
}
func RedisZCountWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZCount(ctx, cfg)
}
func RedisZScoreWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZScore(ctx, cfg)
}
func RedisZRevRankWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZRevRank(ctx, cfg)
}
func RedisZIncrByWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisZIncrBy(ctx, cfg)
}
func RedisLPushWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisLPush(ctx, cfg)
}
func RedisRPushWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisRPush(ctx, cfg)
}
func RedisLPopWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisLPop(ctx, cfg)
}
func RedisRPopWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisRPop(ctx, cfg)
}
func RedisLRangeWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisLRange(ctx, cfg)
}
func RedisLLenWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisLLen(ctx, cfg)
}
func RedisMGetWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisMGet(ctx, cfg)
}
func RedisMSetWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisMSet(ctx, cfg)
}
func RedisKeysWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisKeys(ctx, cfg)
}
func RedisScanWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisScan(ctx, cfg)
}
func RedisPFAddWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisPFAdd(ctx, cfg)
}
func RedisPFCountWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisPFCount(ctx, cfg)
}
func RedisPFMergeWithCtx(ctx context.Context, cfg config.File) lua.LGFunction {
	return RedisPFMerge(ctx, cfg)
}
