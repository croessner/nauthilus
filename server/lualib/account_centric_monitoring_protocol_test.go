// Copyright (C) 2026 Christian Rößner
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

// Package lualib provides lualib functionality.
package lualib

import (
	"path/filepath"
	"strings"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestAccountCentricMonitoringKeysIncludeProtocol(t *testing.T) {
	L := newAccountCentricMonitoringTestState(t)
	defer L.Close()

	loadAccountCentricMonitoringSubject(t, L)
	callAccountCentricMonitoringSubject(t, L)
	assertAccountMonitoringKeysIncludeProtocol(t, requireLuaTableGlobal(t, L, "last_keys"))
}

// newAccountCentricMonitoringTestState prepares the Lua state for the monitoring subject script.
func newAccountCentricMonitoringTestState(t *testing.T) *lua.LState {
	t.Helper()

	L := lua.NewState()
	preloadAccountMonitoringModules(t, L)
	addLuaPluginSharePath(t, L)

	return L
}

// preloadAccountMonitoringModules installs module stubs required by the account monitoring script.
func preloadAccountMonitoringModules(t *testing.T, L *lua.LState) {
	t.Helper()

	preloadAccountMonitoringUtilModule(L)
	preloadAccountMonitoringKeysModule(L)
	preloadAccountMonitoringRedisModule(L)
	preloadInMemoryContextModule(L)
	L.PreloadModule("nauthilus_policy", LoaderPolicyStatelessForTest())
	preloadAccountMonitoringOTELModule(L)
	preloadFixedTimeModule(L, "")
	preloadAccountMonitoringBuiltin(L)
}

// preloadAccountMonitoringUtilModule installs the util functions used by the script.
func preloadAccountMonitoringUtilModule(L *lua.LState) {
	L.PreloadModule("nauthilus_util", func(L *lua.LState) int {
		mod := L.NewTable()
		L.SetFuncs(mod, map[string]lua.LGFunction{
			"getenv": func(L *lua.LState) int {
				def := L.OptString(2, "")
				L.Push(lua.LString(def))

				return 1
			},
			"toboolean": func(L *lua.LState) int {
				v := L.ToString(1)
				L.Push(lua.LBool(v == "true" || v == "1"))

				return 1
			},
			"get_redis_key": func(L *lua.LState) int {
				key := L.CheckString(2)
				L.Push(lua.LString(key))

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
			"log_info": func(_ *lua.LState) int {
				return 0
			},
		})
		L.Push(mod)

		return 1
	})
}

// preloadAccountMonitoringKeysModule installs the key helper functions used by the script.
func preloadAccountMonitoringKeysModule(L *lua.LState) {
	preloadStringFunctionModule(L, "nauthilus_keys", "account_tag", "")
}

// preloadAccountMonitoringRedisModule captures Redis script keys for assertions.
func preloadAccountMonitoringRedisModule(L *lua.LState) {
	L.PreloadModule("nauthilus_redis", func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("redis_run_script", L.NewFunction(func(L *lua.LState) int {
			keys := L.CheckTable(4)
			L.SetGlobal("last_keys", keys)

			res := L.NewTable()
			for range 9 {
				res.Append(lua.LNumber(0))
			}

			L.Push(res)
			L.Push(lua.LNil)

			return 2
		}))
		L.Push(mod)

		return 1
	})
}

// preloadAccountMonitoringOTELModule disables tracing in the Lua subject script.
func preloadAccountMonitoringOTELModule(L *lua.LState) {
	L.PreloadModule("nauthilus_opentelemetry", func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("is_enabled", L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LBool(false))
			return 1
		}))
		L.Push(mod)

		return 1
	})
}

// preloadAccountMonitoringBuiltin installs the builtin values used by the subject script.
func preloadAccountMonitoringBuiltin(L *lua.LState) {
	builtin := L.NewTable()
	builtin.RawSetString("SUBJECT_ACCEPT", lua.LBool(false))
	builtin.RawSetString("SUBJECT_RESULT_OK", lua.LNumber(0))
	builtin.RawSetString("custom_log_add", L.NewFunction(func(_ *lua.LState) int {
		return 0
	}))
	L.SetGlobal("nauthilus_builtin", builtin)
}

// loadAccountCentricMonitoringSubject loads the Lua subject plugin under test.
func loadAccountCentricMonitoringSubject(t *testing.T, L *lua.LState) {
	t.Helper()

	scriptPath := filepath.Join("..", "lua-plugins.d", "subject", "account_centric_monitoring.lua")
	if err := L.DoFile(scriptPath); err != nil {
		t.Fatalf("failed to load script: %v", err)
	}
}

// callAccountCentricMonitoringSubject invokes the subject plugin with an IMAP request.
func callAccountCentricMonitoringSubject(t *testing.T, L *lua.LState) {
	t.Helper()

	req := L.NewTable()
	req.RawSetString("no_auth", lua.LBool(false))
	req.RawSetString("username", lua.LString("alice"))
	req.RawSetString("client_ip", lua.LString("203.0.113.10"))
	req.RawSetString("authenticated", lua.LBool(false))
	req.RawSetString("session", lua.LString("s-1"))
	req.RawSetString("protocol", lua.LString("imap"))

	if err := L.CallByParam(lua.P{
		Fn:      L.GetGlobal("nauthilus_call_subject"),
		NRet:    2,
		Protect: true,
	}, req); err != nil {
		t.Fatalf("failed to call subject source: %v", err)
	}
}

// assertAccountMonitoringKeysIncludeProtocol verifies that every Redis key carries the protocol segment.
func assertAccountMonitoringKeysIncludeProtocol(t *testing.T, keysTbl *lua.LTable) {
	t.Helper()

	expectedSegment := ":proto:imap"

	var missing []string

	count := 0

	keysTbl.ForEach(func(_ lua.LValue, v lua.LValue) {
		count++

		key := v.String()
		if !strings.Contains(key, expectedSegment) {
			missing = append(missing, key)
		}
	})

	if count == 0 {
		t.Fatal("no keys captured")
	}

	if len(missing) > 0 {
		t.Fatalf("keys missing protocol segment: %v", missing)
	}
}

func LoaderPolicyStatelessForTest() lua.LGFunction {
	return func(L *lua.LState) int {
		mod := L.NewTable()
		mod.RawSetString("emit_attribute", L.NewFunction(func(_ *lua.LState) int {
			return 0
		}))
		L.Push(mod)

		return 1
	}
}

func addLuaPluginSharePath(t *testing.T, L *lua.LState) {
	t.Helper()

	pkg, ok := L.GetGlobal("package").(*lua.LTable)
	if !ok {
		t.Fatal("Lua package table missing")
	}

	current := L.GetField(pkg, "path").String()
	pattern := filepath.ToSlash(filepath.Join("..", "lua-plugins.d", "share", "?.lua"))
	L.SetField(pkg, "path", lua.LString(pattern+";"+current))
}
