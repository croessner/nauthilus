package health

import (
	"github.com/gin-gonic/gin"

	"github.com/croessner/nauthilus/server/core"
)

// Handler registers the health endpoints.
type Handler struct{}

func New() *Handler { return &Handler{} }

func (h *Handler) Register(r gin.IRouter) {
	// Keep exact behavior: /ping using existing HealthCheck
	r.GET("/ping", core.HealthCheck)
}
