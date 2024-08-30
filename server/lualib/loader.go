package lualib

import (
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	lua "github.com/yuin/gopher-lua"
)

// RegisterLibraries registers various libraries to the given LState.
// It preloads libraries, registers the backend result type, and preloads a module.
func RegisterLibraries(L *lua.LState) {
	L.PreloadModule(global.LuaModPassword, LoaderModPassword)
	L.PreloadModule(global.LuaModRedis, redislib.LoaderModRedis)
}
