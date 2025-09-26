package confighandler

import (
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

type Handler struct{ cfg config.File }

func New(cfg config.File) *Handler { return &Handler{cfg: cfg} }

func (h *Handler) Register(r gin.IRouter) {
	cg := r.Group("/" + definitions.CatConfig)

	cg.GET("/"+definitions.ServLoad, h.load)
	cg.POST("/"+definitions.ServLoad, h.load)
}

func (h *Handler) load(c *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsConfigurationDisabled() {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	core.HandleConfigLoad(c)
}
