// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package router

import (
	mdcmp "github.com/croessner/nauthilus/server/middleware/compression"
	mdmet "github.com/croessner/nauthilus/server/middleware/metrics"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// WithRecovery adds gin.Recovery middleware to recover from panics.
func (r *Router) WithRecovery() *Router {
	r.Engine.Use(gin.Recovery())

	return r
}

// WithTrustedProxies configures the trusted proxies for the underlying engine.
func (r *Router) WithTrustedProxies() *Router {
	r.Engine.SetTrustedProxies(viper.GetStringSlice("trusted_proxies"))

	return r
}

// WithRequestDecompression installs request decompression middlewares (gzip, zstd, br).
func (r *Router) WithRequestDecompression() *Router {
	r.Engine.Use(mdcmp.DecompressRequestMiddleware())
	r.Engine.Use(mdcmp.DecompressZstdRequestMiddleware())
	r.Engine.Use(mdcmp.DecompressBrRequestMiddleware())

	return r
}

// WithResponseCompression applies response compression according to server config.
func (r *Router) WithResponseCompression() *Router {
	mdcmp.ApplyResponseCompression(r.Engine, r.Cfg.GetServer().GetCompression())

	return r
}

// WithMetricsMiddleware enables Prometheus request metrics middleware.
func (r *Router) WithMetricsMiddleware() *Router {
	r.Engine.Use(mdmet.PrometheusMiddleware())

	return r
}

// WithMetricsRoute registers the GET /metrics handler provided by the caller.
func (r *Router) WithMetricsRoute(handler gin.HandlerFunc) *Router {
	r.Engine.GET("/metrics", handler)

	return r
}

// WithHealth registers the health endpoint using the given handler.
func (r *Router) WithHealth(handler gin.HandlerFunc) *Router {
	r.Engine.GET("/ping", handler)

	return r
}

// WithStatic runs the provided setup function to add static routes.
func (r *Router) WithStatic(setup func(*gin.Engine)) *Router {
	if setup != nil {
		setup(r.Engine)
	}

	return r
}

// WithFrontend calls the provided setup functions to register the frontend pages.
func (r *Router) WithFrontend(setupHydra, setup2FA, setupWebAuthn, setupNotify func(*gin.Engine)) *Router {
	if setupHydra != nil {
		setupHydra(r.Engine)
	}

	if setup2FA != nil {
		setup2FA(r.Engine)
	}

	if setupWebAuthn != nil {
		setupWebAuthn(r.Engine)
	}

	if setupNotify != nil {
		setupNotify(r.Engine)
	}

	return r
}

// WithBackchannel registers the backchannel API endpoints via the provided setup function.
func (r *Router) WithBackchannel(setup func(*gin.Engine)) *Router {
	if setup != nil {
		setup(r.Engine)
	}

	return r
}
