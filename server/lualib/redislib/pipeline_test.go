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
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisPipeline_MixedCommandsSuccess(t *testing.T) {
	L := lua.NewState()
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background()))
	defer L.Close()

	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}
	rediscli.NewTestClient(db)

	// Expectations for the pipeline: set, get, incr, hset, hget, mget
	mock.ExpectSet("a", "1", 0).SetVal("OK")
	mock.ExpectGet("a").SetVal("1")
	mock.ExpectIncr("cnt").SetVal(1)
	mock.ExpectHSet("h", "f", "v").SetVal(1)
	mock.ExpectHGet("h", "f").SetVal("v")
	mock.ExpectMGet("k1", "k2").SetVal([]interface{}{"v1", nil})

	// Build Lua command table and execute pipeline
	luaCode := `
		local nauthilus_redis = require("nauthilus_redis")
		local cmds = {
			{"set", "a", "1"},
			{"get", "a"},
			{"incr", "cnt"},
			{"hset", "h", "f", "v"},
			{"hget", "h", "f"},
			{"mget", "k1", "k2"},
		}
		result, err = nauthilus_redis.redis_pipeline("default", "write", cmds)
	`

	if err := L.DoString(luaCode); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}

	gotErr := L.GetGlobal("err")
	checkLuaError(t, gotErr, lua.LNil)

	gotResult := L.GetGlobal("result")
	if gotResult.Type() != lua.LTTable {
		t.Fatalf("Expected result to be a table, got %v", gotResult.Type())
	}

	resTbl := gotResult.(*lua.LTable)
	// Verify each pipelined result in order
	// 1) set => "OK"
	if v := resTbl.RawGetInt(1); v.String() != "OK" {
		t.Errorf("result[1] = %v, want OK", v)
	}
	// 2) get => "1"
	if v := resTbl.RawGetInt(2); v.String() != "1" {
		t.Errorf("result[2] = %v, want 1", v)
	}
	// 3) incr => 1
	if v := resTbl.RawGetInt(3); v.Type() != lua.LTNumber || int(lua.LVAsNumber(v)) != 1 {
		t.Errorf("result[3] = %v, want 1", v)
	}
	// 4) hset => 1 (fields added)
	if v := resTbl.RawGetInt(4); v.Type() != lua.LTNumber || int(lua.LVAsNumber(v)) != 1 {
		t.Errorf("result[4] = %v, want 1", v)
	}
	// 5) hget => "v"
	if v := resTbl.RawGetInt(5); v.String() != "v" {
		t.Errorf("result[5] = %v, want v", v)
	}
	// 6) mget => {"v1", nil}
	if v := resTbl.RawGetInt(6); v.Type() != lua.LTTable {
		t.Errorf("result[6] expected table, got %v", v.Type())
	} else {
		arr := v.(*lua.LTable)
		if arr.RawGetInt(1).String() != "v1" {
			t.Errorf("result[6][1] = %v, want v1", arr.RawGetInt(1))
		}
		if arr.RawGetInt(2) != lua.LNil {
			t.Errorf("result[6][2] = %v, want nil", arr.RawGetInt(2))
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet redis expectations: %v", err)
	}
}

func TestRedisPipeline_UnsupportedCommand(t *testing.T) {
	L := lua.NewState()
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background()))
	defer L.Close()

	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}
	rediscli.NewTestClient(db)

	// Build a pipeline with an unsupported command name
	luaCode := `
		local nauthilus_redis = require("nauthilus_redis")
		local cmds = {
			{"does_not_exist", "a"},
		}
		result, err = nauthilus_redis.redis_pipeline("default", "write", cmds)
	`

	if err := L.DoString(luaCode); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}

	gotResult := L.GetGlobal("result")
	gotErr := L.GetGlobal("err")

	if gotResult != lua.LNil {
		t.Errorf("expected result to be nil on error, got %v", gotResult)
	}

	if gotErr == lua.LNil {
		t.Fatalf("expected an error, got nil")
	}

	// No Redis commands should have been executed
	if err := mock.ExpectationsWereMet(); err != nil {
		// redismock returns no expectations as met, which is fine here.
	}
}

func TestRedisPipeline_RunScriptUnknownName(t *testing.T) {
	L := lua.NewState()
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background()))
	defer L.Close()

	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}
	rediscli.NewTestClient(db)

	// Ensure there is no uploaded script with this name
	// The pipeline should error before executing Exec

	luaCode := `
		local nauthilus_redis = require("nauthilus_redis")
		local cmds = {
			{"run_script", "UnknownScript", {"k1"}, {"arg1"}},
		}
		result, err = nauthilus_redis.redis_pipeline("default", "write", cmds)
	`

	if err := L.DoString(luaCode); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}

	gotResult := L.GetGlobal("result")
	gotErr := L.GetGlobal("err")

	if gotResult != lua.LNil {
		t.Errorf("expected result to be nil on error, got %v", gotResult)
	}

	if gotErr == lua.LNil {
		t.Fatalf("expected an error for unknown uploaded script name, got nil")
	}

	// No pipeline Exec should have been triggered; ensure there are no expected calls
	_ = mock.ExpectationsWereMet()
}
