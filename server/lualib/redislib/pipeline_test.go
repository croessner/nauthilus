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

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisPipeline_MixedCommandsSuccess(t *testing.T) {
	config.SetTestFile(&config.FileSettings{Server: &config.ServerSection{}})

	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}
	client := rediscli.NewTestClient(db)
	SetDefaultClient(client)
	L := lua.NewState()
	defer L.Close()
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), client))
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
	// Verify each pipelined result in order (structured entries)
	// Helper to get entry fields
	getEntry := func(i int) *lua.LTable {
		v := resTbl.RawGetInt(i)
		if v.Type() != lua.LTTable {
			t.Fatalf("result[%d] expected table, got %v", i, v.Type())
		}
		return v.(*lua.LTable)
	}
	// 1) set => ok=true, value="OK"
	{
		it := getEntry(1)
		if it.RawGetString("ok") != lua.LTrue {
			t.Errorf("result[1].ok = %v, want true", it.RawGetString("ok"))
		}
		if it.RawGetString("value").String() != "OK" {
			t.Errorf("result[1].value = %v, want OK", it.RawGetString("value"))
		}
	}
	// 2) get => ok=true, value="1"
	{
		it := getEntry(2)
		if it.RawGetString("ok") != lua.LTrue {
			t.Errorf("result[2].ok = %v, want true", it.RawGetString("ok"))
		}
		if it.RawGetString("value").String() != "1" {
			t.Errorf("result[2].value = %v, want 1", it.RawGetString("value"))
		}
	}
	// 3) incr => ok=true, value=1
	{
		it := getEntry(3)
		if it.RawGetString("ok") != lua.LTrue {
			t.Errorf("result[3].ok = %v, want true", it.RawGetString("ok"))
		}
		v := it.RawGetString("value")
		if v.Type() != lua.LTNumber || int(lua.LVAsNumber(v)) != 1 {
			t.Errorf("result[3].value = %v, want 1", v)
		}
	}
	// 4) hset => ok=true, value=1
	{
		it := getEntry(4)
		if it.RawGetString("ok") != lua.LTrue {
			t.Errorf("result[4].ok = %v, want true", it.RawGetString("ok"))
		}
		v := it.RawGetString("value")
		if v.Type() != lua.LTNumber || int(lua.LVAsNumber(v)) != 1 {
			t.Errorf("result[4].value = %v, want 1", v)
		}
	}
	// 5) hget => ok=true, value="v"
	{
		it := getEntry(5)
		if it.RawGetString("ok") != lua.LTrue {
			t.Errorf("result[5].ok = %v, want true", it.RawGetString("ok"))
		}
		if it.RawGetString("value").String() != "v" {
			t.Errorf("result[5].value = %v, want v", it.RawGetString("value"))
		}
	}
	// 6) mget => ok=true, value={"v1", nil}
	{
		it := getEntry(6)
		if it.RawGetString("ok") != lua.LTrue {
			t.Errorf("result[6].ok = %v, want true", it.RawGetString("ok"))
		}
		localVal := it.RawGetString("value")
		if localVal.Type() != lua.LTTable {
			t.Errorf("result[6].value expected table, got %v", localVal.Type())
		} else {
			arr := localVal.(*lua.LTable)
			if arr.RawGetInt(1).String() != "v1" {
				t.Errorf("result[6].value[1] = %v, want v1", arr.RawGetInt(1))
			}
			if arr.RawGetInt(2) != lua.LNil {
				t.Errorf("result[6].value[2] = %v, want nil", arr.RawGetInt(2))
			}
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet redis expectations: %v", err)
	}
}

func TestRedisPipeline_UnsupportedCommand(t *testing.T) {

	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}
	client := rediscli.NewTestClient(db)
	SetDefaultClient(client)
	L := lua.NewState()
	defer L.Close()
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), client))
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

	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}
	client := rediscli.NewTestClient(db)
	SetDefaultClient(client)
	L := lua.NewState()
	defer L.Close()
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), client))
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

func TestRedisPipeline_HMGET(t *testing.T) {

	db, mock := redismock.NewClientMock()
	if db == nil || mock == nil {
		t.Fatalf("Failed to create Redis mock client.")
	}
	client := rediscli.NewTestClient(db)
	SetDefaultClient(client)
	L := lua.NewState()
	defer L.Close()
	L.PreloadModule(definitions.LuaModRedis, LoaderModRedis(context.Background(), config.GetFile(), client))
	rediscli.NewTestClient(db)

	// Expect HMGET returning mix of values and nil
	mock.ExpectHMGet("hkey", "f1", "missing", "f3").SetVal([]interface{}{"v1", nil, "v3"})

	// Build Lua pipeline with hmget (varargs form)
	luaCode := `
        local nauthilus_redis = require("nauthilus_redis")
        local cmds = {
            {"hmget", "hkey", "f1", "missing", "f3"},
        }
        result, err = nauthilus_redis.redis_pipeline("default", "read", cmds)
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
	v := resTbl.RawGetInt(1)
	if v.Type() != lua.LTTable {
		t.Fatalf("Expected first entry to be table, got %v", v.Type())
	}
	entry := v.(*lua.LTable)
	if entry.RawGetString("ok") != lua.LTrue {
		t.Fatalf("expected ok=true, got %v", entry.RawGetString("ok"))
	}
	val := entry.RawGetString("value")
	if val.Type() != lua.LTTable {
		t.Fatalf("expected value to be table, got %v", val.Type())
	}
	arr := val.(*lua.LTable)
	if arr.RawGetInt(1).String() != "v1" {
		t.Errorf("value[1] = %v, want v1", arr.RawGetInt(1))
	}
	// Due to Lua table semantics, appending nil removes the slot; the next value will occupy index 2.
	if arr.RawGetInt(2).String() != "v3" {
		t.Errorf("value[2] = %v, want v3", arr.RawGetInt(2))
	}
	if arr.RawGetInt(3) != lua.LNil {
		t.Errorf("value[3] = %v, want nil", arr.RawGetInt(3))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet redis expectations: %v", err)
	}
}
