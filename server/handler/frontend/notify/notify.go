package notify

import (
	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type Handler struct{ Store sessions.Store }

func New(store sessions.Store) *Handler { return &Handler{Store: store} }

func (h *Handler) Register(r gin.IRouter) {
	g := r.Group(viper.GetString("notify_page"))
	g.Use(sessions.Sessions(definitions.SessionName, h.Store))
	g.GET("/", mdlua.LuaContextMiddleware(), mdauth.ProtectEndpointMiddleware(), core.WithLanguageMiddleware(), core.NotifyGETHandler)
	g.GET("/:languageTag", mdlua.LuaContextMiddleware(), mdauth.ProtectEndpointMiddleware(), core.WithLanguageMiddleware(), core.NotifyGETHandler)
}
