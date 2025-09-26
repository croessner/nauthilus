package bruteforce

import (
	"github.com/gin-gonic/gin"

	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
)

type Handler struct{}

func New() *Handler { return &Handler{} }

func (h *Handler) Register(r gin.IRouter) {
	bg := r.Group("/" + definitions.CatBruteForce)
	bg.GET("/"+definitions.ServList, core.HanldeBruteForceList)
	// Keep DELETE semantics for flush identical to previous CacheHandler
	bg.DELETE("/"+definitions.ServFlush, core.HandleBruteForceRuleFlush)
}
