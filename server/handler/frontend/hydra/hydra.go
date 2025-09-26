package hydra

import (
	"github.com/croessner/nauthilus/server/handler/common"
	"github.com/croessner/nauthilus/server/core"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type Handler struct{ Store sessions.Store }

func New(store sessions.Store) *Handler { return &Handler{Store: store} }

func (h *Handler) Register(r gin.IRouter) {
	// login
	lg := r.Group(viper.GetString("login_page"), common.CreateMiddlewareChain(h.Store)...)
	lg.GET("/", core.LoginGETHandler)
	lg.GET("/:languageTag", core.LoginGETHandler)
	lg.POST("/post", core.LoginPOSTHandler)
	lg.POST("/post/:languageTag", core.LoginPOSTHandler)

	// device
	dg := r.Group(viper.GetString("device_page"), common.CreateMiddlewareChain(h.Store)...)
	dg.GET("/", core.DeviceGETHandler)
	dg.GET("/:languageTag", core.DeviceGETHandler)
	dg.POST("/post", core.DevicePOSTHandler)
	dg.POST("/post/:languageTag", core.DevicePOSTHandler)

	// consent
	cg := r.Group(viper.GetString("consent_page"), common.CreateMiddlewareChain(h.Store)...)
	cg.GET("/", core.ConsentGETHandler)
	cg.GET("/:languageTag", core.ConsentGETHandler)
	cg.POST("/post", core.ConsentPOSTHandler)
	cg.POST("/post/:languageTag", core.ConsentPOSTHandler)

	// logout
	og := r.Group(viper.GetString("logout_page"), common.CreateMiddlewareChain(h.Store)...)
	og.GET("/", core.LogoutGETHandler)
	og.GET("/:languageTag", core.LogoutGETHandler)
	og.POST("/post", core.LogoutPOSTHandler)
	og.POST("/post/:languageTag", core.LogoutPOSTHandler)
}
