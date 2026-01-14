//go:build !redislib_oop

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
	"github.com/croessner/nauthilus/server/rediscli"
	lua "github.com/yuin/gopher-lua"
)

// This file exposes WithCtx factory aliases that mirror the existing command factories,
// allowing per-request binding by simply delegating to the current ctx-bound implementations.

func RedisPingWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisPing(ctx, cfg, client)
}
func RedisGetWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisGet(ctx, cfg, client)
}
func RedisSetWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisSet(ctx, cfg, client)
}
func RedisIncrWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisIncr(ctx, cfg, client)
}
func RedisDelWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisDel(ctx, cfg, client)
}
func RedisExpireWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisExpire(ctx, cfg, client)
}
func RedisExistsWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisExists(ctx, cfg, client)
}
func RedisHGetWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisHGet(ctx, cfg, client)
}
func RedisHSetWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisHSet(ctx, cfg, client)
}
func RedisHDelWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisHDel(ctx, cfg, client)
}
func RedisHLenWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisHLen(ctx, cfg, client)
}
func RedisHGetAllWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisHGetAll(ctx, cfg, client)
}
func RedisHMGetWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisHMGet(ctx, cfg, client)
}
func RedisHIncrByWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisHIncrBy(ctx, cfg, client)
}
func RedisHIncrByFloatWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisHIncrByFloat(ctx, cfg, client)
}
func RedisHExistsWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisHExists(ctx, cfg, client)
}
func RedisRenameWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisRename(ctx, cfg, client)
}
func RedisSAddWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisSAdd(ctx, cfg, client)
}
func RedisSIsMemberWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisSIsMember(ctx, cfg, client)
}
func RedisSMembersWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisSMembers(ctx, cfg, client)
}
func RedisSRemWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisSRem(ctx, cfg, client)
}
func RedisSCardWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisSCard(ctx, cfg, client)
}
func RedisRunScriptWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisRunScript(ctx, cfg, client)
}
func RedisUploadScriptWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisUploadScript(ctx, cfg, client)
}
func RedisPipelineWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisPipeline(ctx, cfg, client)
}
func RedisZAddWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZAdd(ctx, cfg, client)
}
func RedisZRemWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZRem(ctx, cfg, client)
}
func RedisZRankWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZRank(ctx, cfg, client)
}
func RedisZRangeWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZRange(ctx, cfg, client)
}
func RedisZRevRangeWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZRevRange(ctx, cfg, client)
}
func RedisZRangeByScoreWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZRangeByScore(ctx, cfg, client)
}
func RedisZRemRangeByScoreWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZRemRangeByScore(ctx, cfg, client)
}
func RedisZRemRangeByRankWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZRemRangeByRank(ctx, cfg, client)
}
func RedisZCountWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZCount(ctx, cfg, client)
}
func RedisZScoreWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZScore(ctx, cfg, client)
}
func RedisZRevRankWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZRevRank(ctx, cfg, client)
}
func RedisZIncrByWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisZIncrBy(ctx, cfg, client)
}
func RedisLPushWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisLPush(ctx, cfg, client)
}
func RedisRPushWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisRPush(ctx, cfg, client)
}
func RedisLPopWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisLPop(ctx, cfg, client)
}
func RedisRPopWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisRPop(ctx, cfg, client)
}
func RedisLRangeWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisLRange(ctx, cfg, client)
}
func RedisLLenWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisLLen(ctx, cfg, client)
}
func RedisMGetWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisMGet(ctx, cfg, client)
}
func RedisMSetWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisMSet(ctx, cfg, client)
}
func RedisKeysWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisKeys(ctx, cfg, client)
}
func RedisScanWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisScan(ctx, cfg, client)
}
func RedisPFAddWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisPFAdd(ctx, cfg, client)
}
func RedisPFCountWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisPFCount(ctx, cfg, client)
}
func RedisPFMergeWithCtx(ctx context.Context, cfg config.File, client rediscli.Client) lua.LGFunction {
	return RedisPFMerge(ctx, cfg, client)
}
