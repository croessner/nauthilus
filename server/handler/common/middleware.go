package common

import (
	"github.com/croessner/nauthilus/server/definitions"
	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"
	"github.com/croessner/nauthilus/server/core"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gwatts/gin-adapter"
	"github.com/justinas/nosurf"
)

// CreateMiddlewareChain constructs the standard middleware chain for frontend routes
// including sessions, CSRF, Lua context, language handling and endpoint protection.
func CreateMiddlewareChain(sessionStore sessions.Store) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		sessions.Sessions(definitions.SessionName, sessionStore),
		adapter.Wrap(nosurf.NewPure),
		mdlua.LuaContextMiddleware(),
		core.WithLanguageMiddleware(),
		mdauth.ProtectEndpointMiddleware(),
	}
}
