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

package luapool

import (
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/lualib"
	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// jitRequestScript mixes work the compiler translates (numeric loops, number arrays) with what stays in the
// interpreter (request-scoped globals, library calls, string building), like a plugin callback does.
const jitRequestScript = `
local weights = {}
for i = 1, 64 do weights[i] = (i * request_seed) % 17 end

local score = 0
for round = 1, 40 do
	for i = 1, #weights do
		score = score + weights[i] * round % 11
	end
end

local parts = {}
for i = 1, 5 do parts[#parts + 1] = tostring(math.floor(score / i)) end

request_result = request_label .. ":" .. score .. ":" .. table.concat(parts, ",")
`

// newJITTestState creates a pooled VM whose Lua configuration carries the given JIT switch.
func newJITTestState(t *testing.T, jit *bool) *lua.LState {
	t.Helper()

	cfg := &config.FileSettings{
		Server: &config.ServerSection{},
		Lua:    &config.LuaSection{Config: &config.LuaConf{JIT: jit}},
	}
	state := NewLuaState(nil, cfg)

	t.Cleanup(state.Close)

	return state
}

// compileJITRequestScript compiles the request script once, as a configuration generation does.
func compileJITRequestScript(t *testing.T) *lua.FunctionProto {
	t.Helper()

	chunk, err := parse.Parse(strings.NewReader(jitRequestScript), "jit_request.lua")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	proto, err := lua.Compile(chunk, "jit_request.lua")
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	return proto
}

// runJITRequest executes one request cycle on a pooled VM and returns what the script stored in its request
// environment.
func runJITRequest(t *testing.T, state *lua.LState, proto *lua.FunctionProto, request int) string {
	t.Helper()

	req := PrepareRequestEnv(state)
	state.SetField(req, "request_seed", lua.LNumber(request+3))
	state.SetField(req, "request_label", lua.LString(fmt.Sprintf("request-%d", request)))

	if err := lualib.DoCompiledFile(state, proto); err != nil {
		t.Fatalf("request %d failed: %v", request, err)
	}

	result := lua.LVAsString(state.GetField(req, "request_result"))

	if leaked := state.GetGlobal("request_result"); leaked != lua.LNil {
		t.Fatalf("request %d wrote into the base environment: %v", request, leaked)
	}

	ResetLuaState(state)

	return result
}

func TestNewLuaStateFollowsTheJITSwitch(t *testing.T) {
	disabled := false

	if stats := newJITTestState(t, &disabled).JITStats(); stats.Enabled {
		t.Fatalf("jit: false left the compiler enabled: %s", stats)
	}

	stats := newJITTestState(t, nil).JITStats()
	if stats.Supported && !stats.Enabled {
		t.Fatalf("the compiler is not enabled by default: %s", stats)
	}
}

func TestJITMatchesInterpreterAcrossPooledRequests(t *testing.T) {
	disabled := false
	proto := compileJITRequestScript(t)
	interpreted := newJITTestState(t, &disabled)
	compiled := newJITTestState(t, nil)

	for request := 1; request <= 25; request++ {
		want := runJITRequest(t, interpreted, proto, request)
		if !strings.HasPrefix(want, fmt.Sprintf("request-%d:", request)) {
			t.Fatalf("request %d: unexpected interpreter result %q", request, want)
		}

		if got := runJITRequest(t, compiled, proto, request); got != want {
			t.Fatalf("request %d: JIT returned %q, the interpreter %q", request, got, want)
		}
	}

	stats := compiled.JITStats()
	if !stats.Supported {
		t.Skip("the compiler does not support this platform")
	}

	if stats.Compiled == 0 || stats.Entries == 0 {
		t.Fatalf("no loop of the request script ran as native code: %s", stats)
	}

	if stats.Compiled > 12 {
		t.Fatalf("native code is not reused across requests: %s", stats)
	}
}
