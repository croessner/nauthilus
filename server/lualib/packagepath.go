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
	"fmt"

	"github.com/croessner/nauthilus/server/config"
	lua "github.com/yuin/gopher-lua"
)

// PackagePath sets the Lua package path to include the directory where the Lua modules reside.
// It appends the Lua package path with the value returned by `config.LoadableConfig.GetLuaPackagePath()`.
// This function takes a Lua state (`*lua.LState`) as an argument and returns an error.
func PackagePath(L *lua.LState) error {
	defaultPath := "/usr/local/share/nauthilus/lua/?.lua;/usr/share/nauthilus/lua/?.lua;/usr/app/lua-plugins.d/share/?.lua"

	return L.DoString(fmt.Sprintf(`package.path = package.path .. ';%s;%s'`, defaultPath, config.LoadableConfig.GetLuaPackagePath()))
}
