package lualib

import (
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/lualib/smtp"
	"github.com/tengattack/gluacrypto"
	libs "github.com/vadv/gopher-lua-libs"
	lua "github.com/yuin/gopher-lua"
)

// RegisterLibraries registers various libraries to the given LState.
// It preloads libraries, registers the backend result type, and preloads a module.
func RegisterLibraries(L *lua.LState) {
	SmtpClient = &smtp.EmailClient{}

	libs.Preload(L)
	gluacrypto.Preload(L)

	L.PreloadModule(global.LuaModPassword, LoaderModPassword)
	L.PreloadModule(global.LuaModRedis, redislib.LoaderModRedis)
	L.PreloadModule(global.LuaModMail, LoaderModMail)
	L.PreloadModule(global.LuaModMisc, LoaderModMisc)
}
