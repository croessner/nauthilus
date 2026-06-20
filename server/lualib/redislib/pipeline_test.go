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
	"testing"

	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

func TestRedisPipeline_MixedCommandsSuccess(t *testing.T) {
	L, mock, _ := newRedisLuaCommandState(t)
	expectMixedPipelineCommands(mock)
	runRedisPipelineLua(t, L, mixedPipelineLuaCode())
	assertMixedPipelineResult(t, pipelineResultTable(t, L))

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet redis expectations: %v", err)
	}
}

// expectMixedPipelineCommands configures the mixed pipeline Redis expectations.
func expectMixedPipelineCommands(mock redismock.ClientMock) {
	mock.ExpectSet("a", "1", 0).SetVal("OK")
	mock.ExpectGet("a").SetVal("1")
	mock.ExpectIncr("cnt").SetVal(1)
	mock.ExpectHSet("h", "f", "v").SetVal(1)
	mock.ExpectHGet("h", "f").SetVal("v")
	mock.ExpectMGet("k1", "k2").SetVal([]any{"v1", nil})
}

// mixedPipelineLuaCode returns the Lua command table for the mixed pipeline test.
func mixedPipelineLuaCode() string {
	return `
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
}

// runRedisPipelineLua runs Lua pipeline code and verifies the error result.
func runRedisPipelineLua(t *testing.T, L *lua.LState, luaCode string) {
	t.Helper()

	if err := L.DoString(luaCode); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}

	gotErr := L.GetGlobal("err")
	checkLuaError(t, gotErr, lua.LNil)
}

// pipelineResultTable returns the pipeline result table from Lua globals.
func pipelineResultTable(t *testing.T, L *lua.LState) *lua.LTable {
	t.Helper()

	gotResult := L.GetGlobal("result")
	if gotResult.Type() != lua.LTTable {
		t.Fatalf("Expected result to be a table, got %v", gotResult.Type())
	}

	return gotResult.(*lua.LTable)
}

// assertMixedPipelineResult verifies all structured mixed pipeline entries.
func assertMixedPipelineResult(t *testing.T, result *lua.LTable) {
	t.Helper()
	assertPipelineStringEntry(t, result, 1, "OK")
	assertPipelineStringEntry(t, result, 2, "1")
	assertPipelineNumberEntry(t, result, 3, 1)
	assertPipelineNumberEntry(t, result, 4, 1)
	assertPipelineStringEntry(t, result, 5, "v")
	assertPipelineMGetEntry(t, result, 6)
}

// pipelineEntry returns one structured result entry.
func pipelineEntry(t *testing.T, result *lua.LTable, idx int) *lua.LTable {
	t.Helper()

	value := result.RawGetInt(idx)
	if value.Type() != lua.LTTable {
		t.Fatalf("result[%d] expected table, got %v", idx, value.Type())
	}

	return value.(*lua.LTable)
}

// assertPipelineEntryOK verifies the ok flag for one structured result entry.
func assertPipelineEntryOK(t *testing.T, entry *lua.LTable, idx int) {
	t.Helper()

	if entry.RawGetString("ok") != lua.LTrue {
		t.Errorf("result[%d].ok = %v, want true", idx, entry.RawGetString("ok"))
	}
}

// assertPipelineStringEntry verifies a string-valued pipeline entry.
func assertPipelineStringEntry(t *testing.T, result *lua.LTable, idx int, expected string) {
	t.Helper()
	entry := pipelineEntry(t, result, idx)
	assertPipelineEntryOK(t, entry, idx)

	if entry.RawGetString("value").String() != expected {
		t.Errorf("result[%d].value = %v, want %s", idx, entry.RawGetString("value"), expected)
	}
}

// assertPipelineNumberEntry verifies a numeric pipeline entry.
func assertPipelineNumberEntry(t *testing.T, result *lua.LTable, idx int, expected int) {
	t.Helper()
	entry := pipelineEntry(t, result, idx)
	assertPipelineEntryOK(t, entry, idx)

	value := entry.RawGetString("value")
	if value.Type() != lua.LTNumber || int(lua.LVAsNumber(value)) != expected {
		t.Errorf("result[%d].value = %v, want %d", idx, value, expected)
	}
}

// assertPipelineMGetEntry verifies the Lua table returned by MGET.
func assertPipelineMGetEntry(t *testing.T, result *lua.LTable, idx int) {
	t.Helper()
	entry := pipelineEntry(t, result, idx)
	assertPipelineEntryOK(t, entry, idx)

	value := entry.RawGetString("value")
	if value.Type() != lua.LTTable {
		t.Errorf("result[%d].value expected table, got %v", idx, value.Type())

		return
	}

	arr := value.(*lua.LTable)
	if arr.RawGetInt(1).String() != "v1" {
		t.Errorf("result[%d].value[1] = %v, want v1", idx, arr.RawGetInt(1))
	}

	if arr.RawGetInt(2) != lua.LNil {
		t.Errorf("result[%d].value[2] = %v, want nil", idx, arr.RawGetInt(2))
	}
}

func TestRedisPipeline_UnsupportedCommand(t *testing.T) {
	runPipelineErrorCase(t, `
		local nauthilus_redis = require("nauthilus_redis")
		local cmds = {
			{"does_not_exist", "a"},
		}
		result, err = nauthilus_redis.redis_pipeline("default", "write", cmds)
	`, "expected an error, got nil")
}

func TestRedisPipeline_RunScriptUnknownName(t *testing.T) {
	runPipelineErrorCase(t, `
		local nauthilus_redis = require("nauthilus_redis")
		local cmds = {
			{"run_script", "UnknownScript", {"k1"}, {"arg1"}},
		}
		result, err = nauthilus_redis.redis_pipeline("default", "write", cmds)
	`, "expected an error for unknown uploaded script name, got nil")
}

// runPipelineErrorCase executes a pipeline script that must fail before Redis commands run.
func runPipelineErrorCase(t *testing.T, luaCode string, missingErrorMessage string) {
	t.Helper()

	L, mock, _ := newRedisLuaCommandState(t)

	if err := L.DoString(luaCode); err != nil {
		t.Fatalf("Running Lua code failed: %v", err)
	}

	gotResult := L.GetGlobal("result")
	if gotResult != lua.LNil {
		t.Errorf("expected result to be nil on error, got %v", gotResult)
	}

	if gotErr := L.GetGlobal("err"); gotErr == lua.LNil {
		t.Fatal(missingErrorMessage)
	}

	_ = mock.ExpectationsWereMet()
}

func TestRedisPipeline_HMGET(t *testing.T) {
	L, mock, _ := newRedisLuaCommandState(t)
	mock.ExpectHMGet("hkey", "f1", "missing", "f3").SetVal([]any{"v1", nil, "v3"})
	runRedisPipelineLua(t, L, redisPipelineHMGetLuaCode())
	assertPipelineHMGetResult(t, pipelineResultTable(t, L))

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet redis expectations: %v", err)
	}
}

// redisPipelineHMGetLuaCode returns the Lua command table for the HMGET pipeline test.
func redisPipelineHMGetLuaCode() string {
	return `
        local nauthilus_redis = require("nauthilus_redis")
        local cmds = {
            {"hmget", "hkey", "f1", "missing", "f3"},
        }
        result, err = nauthilus_redis.redis_pipeline("default", "read", cmds)
    `
}

// assertPipelineHMGetResult verifies the compacted Lua table returned by HMGET.
func assertPipelineHMGetResult(t *testing.T, result *lua.LTable) {
	t.Helper()

	entry := pipelineEntry(t, result, 1)
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
}
