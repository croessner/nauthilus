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

// Package luaapiprobe provides one shared Lua host API probe for stage parity tests.
//
// Environment sources, subject sources, and actions must expose the same Lua API as custom hooks and
// Lua backends. Each stage test wraps the probe in its own entry point, so the expected surface has a
// single definition.
package luaapiprobe

import (
	_ "embed"
	"testing"
)

// EnvironmentVariable is the process environment variable the probe reads through os.getenv.
const EnvironmentVariable = "NAUTHILUS_LUA_API_PROBE"

//go:embed probe.lua
var probeSource string

// Script returns a complete Lua chunk that defines the probe table followed by the stage entry point.
//
// The entry point refers to the probe through the local variable "probe", for example
// "function nauthilus_call_environment(request) probe.run() return 0, 0, 0 end".
func Script(t *testing.T, entryPoint string) string {
	t.Helper()
	t.Setenv(EnvironmentVariable, "set")

	return probeSource + "\n" + entryPoint + "\n"
}
