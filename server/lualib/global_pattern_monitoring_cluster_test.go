// Copyright (C) 2026 Christian Roessner
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

package lualib

import (
	"path/filepath"
	"strings"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestGlobalPatternMonitoringPassesPerAttemptKeyAsRedisKey(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	L.PreloadModule("nauthilus_util", func(L *lua.LState) int {
		mod := L.NewTable()
		L.SetFuncs(mod, map[string]lua.LGFunction{
			"getenv": func(L *lua.LState) int {
				L.Push(lua.LString(L.OptString(2, "")))
				return 1
			},
			"get_redis_key": func(L *lua.LState) int {
				L.Push(lua.LString("nt:" + L.CheckString(2)))
				return 1
			},
			"if_error_raise": func(L *lua.LState) int {
				if L.Get(1) != lua.LNil {
					L.RaiseError("unexpected error")
				}
				return 0
			},
			"is_table": func(L *lua.LState) int {
				L.Push(lua.LBool(L.Get(1).Type() == lua.LTTable))
				return 1
			},
			"log_info": func(L *lua.LState) int {
				return 0
			},
		})
		L.Push(mod)
		return 1
	})

	L.PreloadModule("nauthilus_policy_facts", func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("emit_many", L.NewFunction(func(L *lua.LState) int {
			return 0
		}))
		L.Push(mod)
		return 1
	})

	L.PreloadModule("nauthilus_redis", func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("redis_run_script", L.NewFunction(func(L *lua.LState) int {
			L.SetGlobal("last_keys", L.CheckTable(4))
			L.SetGlobal("last_args", L.CheckTable(5))

			res := L.NewTable()
			for range 6 {
				res.Append(lua.LNumber(0))
			}
			L.Push(res)
			L.Push(lua.LNil)
			return 2
		}))
		L.Push(mod)
		return 1
	})

	L.PreloadModule("nauthilus_context", func(L *lua.LState) int {
		state := map[string]lua.LValue{}
		mod := L.NewTable()
		mod.RawSetString("context_get", L.NewFunction(func(L *lua.LState) int {
			if value, ok := state[L.CheckString(1)]; ok {
				L.Push(value)
			} else {
				L.Push(lua.LNil)
			}
			return 1
		}))
		mod.RawSetString("context_set", L.NewFunction(func(L *lua.LState) int {
			state[L.CheckString(1)] = L.CheckAny(2)
			return 0
		}))
		L.Push(mod)
		return 1
	})

	preloadFixedTimeModule(L, "2023-11-14-22")

	builtin := L.NewTable()
	builtin.RawSetString("ENVIRONMENT_TRIGGER_NO", lua.LNumber(0))
	builtin.RawSetString("ENVIRONMENT_ABORT_NO", lua.LNumber(0))
	builtin.RawSetString("ENVIRONMENT_RESULT_OK", lua.LNumber(0))
	L.SetGlobal("nauthilus_builtin", builtin)

	scriptPath := filepath.Join("..", "lua-plugins.d", "environment", "global_pattern_monitoring.lua")
	if err := L.DoFile(scriptPath); err != nil {
		t.Fatalf("failed to load script: %v", err)
	}

	req := L.NewTable()
	req.RawSetString("no_auth", lua.LBool(false))
	req.RawSetString("username", lua.LString("alice"))
	req.RawSetString("client_ip", lua.LString("203.0.113.10"))
	req.RawSetString("authenticated", lua.LBool(false))
	req.RawSetString("session", lua.LString("s-1"))

	if err := L.CallByParam(lua.P{
		Fn:      L.GetGlobal("nauthilus_call_environment"),
		NRet:    3,
		Protect: true,
	}, req); err != nil {
		t.Fatalf("failed to call environment source: %v", err)
	}

	keysTbl, ok := L.GetGlobal("last_keys").(*lua.LTable)
	if !ok {
		t.Fatalf("expected keys table, got %v", L.GetGlobal("last_keys").Type())
	}
	argsTbl, ok := L.GetGlobal("last_args").(*lua.LTable)
	if !ok {
		t.Fatalf("expected args table, got %v", L.GetGlobal("last_args").Type())
	}

	var perAttemptKeys []string
	keyCount := 0
	keysTbl.ForEach(func(_ lua.LValue, v lua.LValue) {
		keyCount++
		if strings.Contains(v.String(), "multilayer:global:metrics:1700000000") {
			perAttemptKeys = append(perAttemptKeys, v.String())
		}
	})

	if keyCount != 21 {
		t.Fatalf("key count = %d, want 21", keyCount)
	}
	if len(perAttemptKeys) != 1 {
		t.Fatalf("per-attempt key occurrences in KEYS = %d, want 1", len(perAttemptKeys))
	}

	argsTbl.ForEach(func(_ lua.LValue, v lua.LValue) {
		if strings.Contains(v.String(), "multilayer:global:metrics:1700000000") {
			t.Fatalf("per-attempt key leaked into ARGV: %q", v.String())
		}
	})
}
