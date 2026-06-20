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
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

func TestRegisterRedisConnection(t *testing.T) {
	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})

	L := lua.NewState()
	defer L.Close()

	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), nil))

	for _, tt := range registerRedisConnectionCases(L) {
		t.Run(tt.name, func(t *testing.T) {
			runRegisterRedisConnectionCase(t, L, tt)
		})
	}
}

type registerRedisConnectionCase struct {
	name    string
	args    []lua.LValue
	want    []lua.LValue
	wantErr bool
}

// registerRedisConnectionCases returns Redis pool registration cases.
func registerRedisConnectionCases(L *lua.LState) []registerRedisConnectionCase {
	return []registerRedisConnectionCase{
		{
			name:    "Standalone mode with new connection",
			args:    []lua.LValue{lua.LString("standalone"), lua.LString("standalone"), L.NewTable()},
			want:    []lua.LValue{lua.LString("OK")},
			wantErr: false,
		},
		{
			name:    "Sentinel mode with new connection",
			args:    []lua.LValue{lua.LString("sentinel"), lua.LString("sentinel"), L.NewTable()},
			want:    []lua.LValue{lua.LString("OK")},
			wantErr: false,
		},
		{
			name:    "Sentinel_replica mode with new connection",
			args:    []lua.LValue{lua.LString("sentinel_replica"), lua.LString("sentinel_replica"), L.NewTable()},
			want:    []lua.LValue{lua.LString("OK")},
			wantErr: false,
		},
		{
			name:    "Cluster mode with new connection",
			args:    []lua.LValue{lua.LString("cluster"), lua.LString("cluster"), L.NewTable()},
			want:    []lua.LValue{lua.LString("OK")},
			wantErr: false,
		},
		{
			name:    "Unknown mode",
			args:    []lua.LValue{lua.LString("unknown"), lua.LString("unknown"), L.NewTable()},
			want:    []lua.LValue{lua.LNil, lua.LString("Unknown mode: unknown")},
			wantErr: false,
		},
	}
}

// runRegisterRedisConnectionCase executes one Redis pool registration scenario.
func runRegisterRedisConnectionCase(t *testing.T, L *lua.LState, tt registerRedisConnectionCase) {
	t.Helper()

	setRegisterRedisConnectionGlobals(L, tt.args)

	if !runRedisPoolLuaCall(t, L, tt.wantErr, registerRedisPoolLuaCode()) {
		return
	}

	assertRegisterRedisConnectionResult(t, L, tt)
	runRedisPoolLuaCall(t, L, tt.wantErr, getRedisConnectionLuaCode())
}

// setRegisterRedisConnectionGlobals installs the Lua globals used by pool registration calls.
func setRegisterRedisConnectionGlobals(L *lua.LState, args []lua.LValue) {
	L.SetGlobal("pool_name", args[0])
	L.SetGlobal("pool_mode", args[1])
	L.SetGlobal("pool_options", args[2])
}

// runRedisPoolLuaCall executes a Redis pool Lua snippet and reports expected failures.
func runRedisPoolLuaCall(t *testing.T, L *lua.LState, wantErr bool, luaCode string) bool {
	t.Helper()

	if err := L.DoString(luaCode); (err != nil) != wantErr {
		t.Errorf("Redis pool Lua call error = %v, wantErr %v", err, wantErr)

		return false
	}

	return true
}

// assertRegisterRedisConnectionResult checks pool registration result and error globals.
func assertRegisterRedisConnectionResult(t *testing.T, L *lua.LState, tt registerRedisConnectionCase) {
	t.Helper()

	gotResult := L.GetGlobal("result")
	gotErr := L.GetGlobal("err")

	if tt.wantErr {
		if gotErr == lua.LNil {
			t.Errorf("register_redis_pool() expected error, but got nil")
		}

		return
	}

	if gotResult.Type() != tt.want[0].Type() || gotResult.String() != tt.want[0].String() {
		t.Errorf("register_redis_pool() result = %v, want %v", gotResult, tt.want[0])
	}

	if len(tt.want) > 1 {
		if gotErr.Type() != tt.want[1].Type() || gotErr.String() != tt.want[1].String() {
			t.Errorf("register_redis_pool() error = %v, want %v", gotErr, tt.want[1])
		}

		return
	}

	if gotErr != lua.LNil {
		t.Errorf("register_redis_pool() error = %v, want nil", gotErr)
	}
}

// registerRedisPoolLuaCode returns the Lua snippet for registering a Redis pool.
func registerRedisPoolLuaCode() string {
	return `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.register_redis_pool(pool_name, pool_mode, pool_options)`
}

// getRedisConnectionLuaCode returns the Lua snippet for retrieving a Redis pool.
func getRedisConnectionLuaCode() string {
	return `local nauthilus_redis = require("nauthilus_redis"); result, err = nauthilus_redis.get_redis_connection(pool_name)`
}
