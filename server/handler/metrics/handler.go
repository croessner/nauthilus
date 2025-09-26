package metrics

import (
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler registers the metrics endpoint with identical auth semantics as before.
type Handler struct{}

func New() *Handler { return &Handler{} }

func (h *Handler) Register(r gin.IRouter) {
	r.GET("/metrics", func(ctx *gin.Context) {
		// If JWT is enabled, allow only users with RoleSecurity
		if config.GetFile().GetServer().GetJWTAuth().IsEnabled() {
			tokenString, err := core.ExtractJWTToken(ctx)
			if err == nil {
				if claims, err := core.ValidateJWTToken(ctx, tokenString); err == nil {
					for _, role := range claims.Roles {
						if role == definitions.RoleSecurity {
							h := promhttp.HandlerFor(
								prometheus.DefaultGatherer,
								promhttp.HandlerOpts{DisableCompression: true},
							)
							h.ServeHTTP(ctx.Writer, ctx.Request)
							return
						}
					}
				}
			}
		}

		// Fallback to Basic Auth if enabled
		if mdauth.CheckAndRequireBasicAuth(ctx) {
			h := promhttp.HandlerFor(
				prometheus.DefaultGatherer,
				promhttp.HandlerOpts{DisableCompression: true},
			)
			h.ServeHTTP(ctx.Writer, ctx.Request)
			return
		}

		// If neither auth allowed request, return 401 to be safe
		ctx.AbortWithStatus(http.StatusUnauthorized)
	})
}
