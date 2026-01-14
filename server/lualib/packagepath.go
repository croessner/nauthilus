// Copyright (C) 2024 Christian Rößner
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
	"strings"

	"github.com/croessner/nauthilus/server/config"
	lua "github.com/yuin/gopher-lua"
)

// PackagePath ensures Lua package.path contains our required paths exactly once, without unbounded growth.
func PackagePath(L *lua.LState, cfg config.File) error {
	const defaultPath = "/usr/local/share/nauthilus/lua/?.lua;/usr/share/nauthilus/lua/?.lua;/usr/app/lua-plugins.d/share/?.lua"

	cfgPath := cfg.GetLuaPackagePath()
	add := defaultPath
	if cfgPath != "" {
		add += ";" + cfgPath
	}

	pkg := L.GetGlobal("package")
	tbl, ok := pkg.(*lua.LTable)
	if !ok {
		// package should exist after OpenLibs; if not, nothing to do
		return nil
	}

	curVal := tbl.RawGetString("path")
	cur := curVal.String()

	// Idempotence: if paths already present, do nothing
	already := strings.Contains(cur, defaultPath)
	if cfgPath != "" {
		already = already && strings.Contains(cur, cfgPath)
	}

	if already {
		return nil
	}

	newPath := cur
	if newPath != "" && !strings.HasSuffix(newPath, ";") {
		newPath += ";"
	}

	newPath += add

	tbl.RawSetString("path", lua.LString(newPath))

	return nil
}
