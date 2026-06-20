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

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/luastack"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/redis/go-redis/v9"
	lua "github.com/yuin/gopher-lua"
)

// RedisManager encapsulates the logic for executing Redis commands from Lua.
type RedisManager struct {
	cfg    config.File
	client rediscli.Client
}

// NewRedisManager creates a new RedisManager.
func NewRedisManager(cfg config.File, client rediscli.Client) *RedisManager {
	return &RedisManager{
		cfg:    cfg,
		client: client,
	}
}

func (rm *RedisManager) currentContext(L *lua.LState) context.Context {
	return lualib.RequireRuntimeContext(L, "nauthilus_redis")
}

// getConn retrieves the Redis connection from the Lua stack or falls back to the default handle.
func (rm *RedisManager) getConn(L *lua.LState, fallback redis.UniversalClient) redis.UniversalClient {
	ud := L.Get(1)
	if ud.Type() == lua.LTString && ud.String() == redisLuaPoolDefault {
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

// executeWithDeadline runs a Redis operation with a selected handle, counter, and deadline policy.
func (rm *RedisManager) executeWithDeadline(
	L *lua.LState,
	fallback redis.UniversalClient,
	incrementCounter func(),
	deadline func(context.Context, config.File) (context.Context, context.CancelFunc),
	fn func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int,
) int {
	stack := luastack.NewManager(L)
	conn := rm.getConn(L, fallback)

	defer incrementCounter()

	dCtx, cancel := deadline(rm.currentContext(L), rm.cfg)
	defer cancel()

	return fn(dCtx, conn, stack)
}

// ExecuteRead executes a Redis read operation with the necessary boilerplate.
func (rm *RedisManager) ExecuteRead(L *lua.LState, fn func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int) int {
	return rm.executeWithDeadline(
		L,
		rm.client.GetReadHandle(),
		func() { stats.GetMetrics().GetRedisReadCounter().Inc() },
		util.GetCtxWithDeadlineRedisRead,
		fn,
	)
}

// ExecuteWrite executes a Redis write operation with the necessary boilerplate.
func (rm *RedisManager) ExecuteWrite(L *lua.LState, fn func(ctx context.Context, conn redis.Cmdable, stack *luastack.Manager) int) int {
	return rm.executeWithDeadline(
		L,
		rm.client.GetWriteHandle(),
		func() { stats.GetMetrics().GetRedisWriteCounter().Inc() },
		util.GetCtxWithDeadlineRedisWrite,
		fn,
	)
}
