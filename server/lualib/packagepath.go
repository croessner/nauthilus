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

// PackagePath sets the Lua `package.path` by appending default and additional configured paths to the existing value.
// It modifies the Lua state `L` to include paths necessary for locating Lua modules. Returns an error if the operation fails.
func PackagePath(L *lua.LState) error {
	defaultPath := "/usr/local/share/nauthilus/lua/?.lua;/usr/share/nauthilus/lua/?.lua;/usr/app/lua-plugins.d/share/?.lua"

	return L.DoString(fmt.Sprintf(`package.path = package.path .. ';%s;%s'`, defaultPath, config.GetFile().GetLuaPackagePath()))
}
