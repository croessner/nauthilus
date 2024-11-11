package redislib

import (
	"context"
	"reflect"
	"testing"

	"github.com/croessner/nauthilus/server/global"
	lua "github.com/yuin/gopher-lua"
)

func TestRegisterRedisConnection(t *testing.T) {
	L := lua.NewState()

	defer L.Close()

	L.PreloadModule(global.LuaModRedis, LoaderModRedis(context.Background()))

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
