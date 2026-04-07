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

package cacheflush

import (
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	lua "github.com/yuin/gopher-lua"
)

func TestResolveLuaFunction_PrefersRequestEnvThenFallsBackToGlobal(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	globalFn := L.NewFunction(func(luaState *lua.LState) int {
		luaState.Push(lua.LString("global"))

		return 1
	})
	reqEnvFn := L.NewFunction(func(luaState *lua.LState) int {
		luaState.Push(lua.LString("request_env"))

		return 1
	})

	L.SetGlobal(definitions.LuaFnCacheFlushHook, globalFn)

	requestEnv := L.NewTable()
	L.SetField(requestEnv, definitions.LuaFnCacheFlushHook, reqEnvFn)
	L.SetGlobal("__NAUTH_REQ_ENV", requestEnv)

	resolved := resolveLuaFunction(L, definitions.LuaFnCacheFlushHook)
	got := callLuaStringFunction(t, L, resolved)

	if got != "request_env" {
		t.Fatalf("expected request env function, got %q", got)
	}

	L.SetField(requestEnv, definitions.LuaFnCacheFlushHook, lua.LNil)

	resolved = resolveLuaFunction(L, definitions.LuaFnCacheFlushHook)
	got = callLuaStringFunction(t, L, resolved)

	if got != "global" {
		t.Fatalf("expected global fallback function, got %q", got)
	}
}

func TestNauthilusCacheFlushLuaFunctionReturnContract(t *testing.T) {
	for _, tc := range cacheFlushContractCases() {
		t.Run(tc.name, func(t *testing.T) {
			result := executeLuaCacheFlush(t, tc.script)
			assertCacheFlushResult(t, result, tc.wantAdditionalKeys, tc.wantAccountName)
		})
	}
}

type cacheFlushContractCase struct {
	name               string
	script             string
	wantAdditionalKeys []string
	wantAccountName    string
}

func cacheFlushContractCases() []cacheFlushContractCase {
	return []cacheFlushContractCase{
		{
			name: "GlobalFunction",
			script: `
function nauthilus_cache_flush(request)
  return {"user:alice", "user:alice:stats"}, "alice"
end
`,
			wantAdditionalKeys: []string{"user:alice", "user:alice:stats"},
			wantAccountName:    "alice",
		},
		{
			name: "RequestEnvFunctionWinsAndNonStringsAreIgnored",
			script: `
__NAUTH_REQ_ENV = {}

function __NAUTH_REQ_ENV.nauthilus_cache_flush(request)
  return {"req:key", 42, false, "req:key:2"}, "from_env"
end

function nauthilus_cache_flush(request)
  return {"global:key"}, "from_global"
end
`,
			wantAdditionalKeys: []string{"req:key", "req:key:2"},
			wantAccountName:    "from_env",
		},
		{
			name: "NilAdditionalKeysAndAccountName",
			script: `
function nauthilus_cache_flush(request)
  return nil, nil
end
`,
			wantAdditionalKeys: nil,
			wantAccountName:    "",
		},
	}
}

func assertCacheFlushResult(t *testing.T, result *Result, wantAdditionalKeys []string, wantAccountName string) {
	t.Helper()

	if len(result.AdditionalKeys) != len(wantAdditionalKeys) {
		t.Fatalf("expected %d additional keys, got %d", len(wantAdditionalKeys), len(result.AdditionalKeys))
	}

	for index, wantKey := range wantAdditionalKeys {
		gotKey := result.AdditionalKeys[index]

		if gotKey != wantKey {
			t.Fatalf("expected key[%d]=%q, got %q", index, wantKey, gotKey)
		}
	}

	if result.AccountName != wantAccountName {
		t.Fatalf("expected account name %q, got %q", wantAccountName, result.AccountName)
	}
}

func executeLuaCacheFlush(t *testing.T, script string) *Result {
	t.Helper()

	L := lua.NewState()
	defer L.Close()

	if err := L.DoString(script); err != nil {
		t.Fatalf("lua setup failed: %v", err)
	}

	entryFn := resolveLuaFunction(L, definitions.LuaFnCacheFlushHook)

	if entryFn.Type() != lua.LTFunction {
		t.Fatalf("entry function %q not found", definitions.LuaFnCacheFlushHook)
	}

	requestTable := L.NewTable()

	if err := L.CallByParam(lua.P{
		Fn:      entryFn,
		NRet:    2,
		Protect: true,
	}, requestTable); err != nil {
		t.Fatalf("lua call failed: %v", err)
	}

	return parseReturnValues(L)
}

func callLuaStringFunction(t *testing.T, L *lua.LState, fn lua.LValue) string {
	t.Helper()

	if fn.Type() != lua.LTFunction {
		t.Fatalf("expected function, got %s", fn.Type())
	}

	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}); err != nil {
		t.Fatalf("lua function call failed: %v", err)
	}

	ret := L.Get(-1)

	if ret.Type() != lua.LTString {
		t.Fatalf("expected string return type, got %s", ret.Type())
	}

	L.Pop(1)

	return ret.String()
}
