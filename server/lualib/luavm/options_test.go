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

package luavm

import (
	"testing"

	lua "github.com/yuin/gopher-lua"
)

// jitProbe is a numeric loop the compiler can translate completely.
const jitProbe = `local sum = 0 for i = 1, 10000 do sum = sum + i % 7 end return sum`

// runProbe executes the probe chunk and returns its numeric result.
func runProbe(t *testing.T, state *lua.LState) lua.LNumber {
	t.Helper()

	if err := state.DoString(jitProbe); err != nil {
		t.Fatalf("probe failed: %v", err)
	}

	result, ok := state.Get(-1).(lua.LNumber)
	if !ok {
		t.Fatalf("probe returned %s, want a number", state.Get(-1).Type())
	}

	state.Pop(1)

	return result
}

func TestNewStateHonorsTheJITSwitch(t *testing.T) {
	interpreted := NewState(false)
	defer interpreted.Close()

	want := runProbe(t, interpreted)
	if stats := interpreted.JITStats(); stats.Enabled || stats.Compiled != 0 {
		t.Fatalf("interpreter-only VM used the compiler: %s", stats)
	}

	compiled := NewState(true)
	defer compiled.Close()

	if got := runProbe(t, compiled); got != want {
		t.Fatalf("compiled VM returned %v, the interpreter %v", got, want)
	}

	stats := compiled.JITStats()
	if !stats.Supported {
		t.Skip("the compiler does not support this platform")
	}

	if !stats.Enabled || stats.Compiled == 0 || stats.Entries == 0 {
		t.Fatalf("the hot loop did not run as native code: %s", stats)
	}
}
