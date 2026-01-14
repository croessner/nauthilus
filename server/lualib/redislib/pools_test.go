//go:build !redislib_oop

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
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

func TestRegisterRedisConnection(t *testing.T) {
	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})

	L := lua.NewState()
	defer L.Close()
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), nil))

	tests := []struct {
		name    string
		args    []lua.LValue
		want    []lua.LValue
		wantErr bool
	}{
		{
			"Standalone mode with new connection",
			[]lua.LValue{lua.LString("standalone"), lua.LString("standalone"), L.NewTable()},
			[]lua.LValue{lua.LString("OK")},
			false,
		},
		{
			"Sentinel mode with new connection",
			[]lua.LValue{lua.LString("sentinel"), lua.LString("sentinel"), L.NewTable()},
			[]lua.LValue{lua.LString("OK")},
			false,
		},
		{
			"Sentinel_replica mode with new connection",
			[]lua.LValue{lua.LString("sentinel_replica"), lua.LString("sentinel_replica"), L.NewTable()},
			[]lua.LValue{lua.LString("OK")},
			false,
		},
		{
			"Cluster mode with new connection",
			[]lua.LValue{lua.LString("cluster"), lua.LString("cluster"), L.NewTable()},
			[]lua.LValue{lua.LString("OK")},
			false,
		},
		{
			"Unknown mode",
			[]lua.LValue{lua.LString("unknown"), lua.LString("unknown"), L.NewTable()},
			[]lua.LValue{lua.LString("Unknown mode: unknown"), lua.LNil},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L.SetGlobal("pool_name", tt.args[0])
			L.SetGlobal("pool_mode", tt.args[1])
			L.SetGlobal("pool_options", tt.args[2])

			if err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); return nauthilus_redis.register_redis_pool(pool_name, pool_mode, pool_options)`); (err != nil) != tt.wantErr {
				t.Errorf("register_redis_pool() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			got := L.Get(-1)
			if !reflect.DeepEqual(got, tt.want[len(tt.want)-1]) {
				t.Errorf("register_redis_pool() = %v, want %v", got, tt.want)

				return
			}

			if err := L.DoString(`local nauthilus_redis = require("nauthilus_redis"); return nauthilus_redis.get_redis_connection(pool_name)`); (err != nil) != tt.wantErr {
				t.Errorf("get_redis_connection() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
