package custom

import (
	"github.com/gin-gonic/gin"

	"github.com/croessner/nauthilus/server/core"
)

// Handler registers custom Lua hook endpoint(s).
type Handler struct{}

func New() *Handler { return &Handler{} }

func (h *Handler) Register(r gin.IRouter) {
	// Keep exact behavior and reuse existing logic for now
	r.Any("/custom/*hook", core.CustomRequestHandler)
}
