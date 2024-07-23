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
