package lualib

import (
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/lualib/smtp"
	lua "github.com/yuin/gopher-lua"
)

// RegisterLibraries registers various libraries to the given LState.
// It preloads libraries, registers the backend result type, and preloads a module.
func RegisterLibraries(L *lua.LState) {
	SmtpClient = &smtp.EmailClient{}

	L.PreloadModule(global.LuaModPassword, LoaderModPassword)
	L.PreloadModule(global.LuaModRedis, redislib.LoaderModRedis)
	L.PreloadModule(global.LuaModMail, LoaderModMail)
	L.PreloadModule(global.LuaModMisc, LoaderModMisc)
}
