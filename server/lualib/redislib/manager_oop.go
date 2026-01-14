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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisManager encapsulates the logic for executing Redis commands from Lua.
type RedisManager struct {
	ctx    context.Context
	cfg    config.File
	client rediscli.Client
}

// NewRedisManager creates a new RedisManager.
func NewRedisManager(ctx context.Context, cfg config.File, client rediscli.Client) *RedisManager {
	return &RedisManager{
		ctx:    ctx,
		cfg:    cfg,
		client: client,
	}
}

// getConn retrieves the Redis connection from the Lua stack or falls back to the default handle.
func (rm *RedisManager) getConn(L *lua.LState, fallback redis.UniversalClient) redis.UniversalClient {
	ud := L.Get(1)
	if ud.Type() == lua.LTString && ud.String() == "default" {
		return fallback
	}

	userData, okay := ud.(*lua.LUserData)
	if !okay || userData == nil {
		return fallback
	}

	client, okay := userData.Value.(redis.UniversalClient)
	if !okay {
		return fallback
	}

	return client
}

// ExecuteRead executes a Redis read operation with the necessary boilerplate.
func (rm *RedisManager) ExecuteRead(L *lua.LState, fn func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int) int {
	stack := luastack.NewManager(L)
	conn := rm.getConn(L, rm.client.GetReadHandle())

	defer stats.GetMetrics().GetRedisReadCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisRead(rm.ctx, rm.cfg)
	defer cancel()

	return fn(dCtx, conn, stack)
}

// ExecuteWrite executes a Redis write operation with the necessary boilerplate.
func (rm *RedisManager) ExecuteWrite(L *lua.LState, fn func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int) int {
	stack := luastack.NewManager(L)
	conn := rm.getConn(L, rm.client.GetWriteHandle())

	defer stats.GetMetrics().GetRedisWriteCounter().Inc()

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(rm.ctx, rm.cfg)
	defer cancel()

	return fn(dCtx, conn, stack)
}
