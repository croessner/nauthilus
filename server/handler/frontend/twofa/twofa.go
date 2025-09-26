package twofa

import (
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/common"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/tags"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type Handler struct{ Store sessions.Store }

func New(store sessions.Store) *Handler { return &Handler{Store: store} }

func (h *Handler) Register(r gin.IRouter) {
	if !tags.Register2FA {
		return
	}

	group := r.Group(definitions.TwoFAv1Root)

	// twofa login
	twoFactorGroup := group.Group(viper.GetString("login_2fa_page"), common.CreateMiddlewareChain(h.Store)...)
	twoFactorGroup.GET("/", core.LoginGET2FAHandler)
	twoFactorGroup.GET("/:languageTag", core.LoginGET2FAHandler)
	twoFactorGroup.POST("/post", core.LoginPOST2FAHandler)
	twoFactorGroup.POST("/post/:languageTag", core.LoginPOST2FAHandler)
	twoFactorGroup.GET("/home", core.Register2FAHomeHandler)
	twoFactorGroup.GET("/home/:languageTag", core.Register2FAHomeHandler)

	// totp registration
	group.Group(viper.GetString("totp_page"), common.CreateMiddlewareChain(h.Store)...).
		GET("/", core.RegisterTotpGETHandler)
	group.Group(viper.GetString("totp_page"), common.CreateMiddlewareChain(h.Store)...).
		POST("/post", core.RegisterTotpPOSTHandler)
}
