package webauthn

import (
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/tags"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

type Handler struct{ Store sessions.Store }

func New(store sessions.Store) *Handler { return &Handler{Store: store} }

func (h *Handler) Register(r gin.IRouter) {
	if !tags.IsDevelopment {
		return
	}

	group := r.Group(definitions.TwoFAv1Root)
	reg := group.Group(viper.GetString("webauthn_page"))
	reg.Use(sessions.Sessions(definitions.SessionName, h.Store))
	reg.GET("/register/begin", core.BeginRegistration)
	reg.POST("/register/finish", core.FinishRegistration)
}
