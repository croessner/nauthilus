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

package auth

import (
	"log/slog"

	"github.com/croessner/nauthilus/server/config"
	"github.com/gin-gonic/gin"
)

// protectFactory is a function reference that returns the actual ProtectEndpoint middleware.
// It is injected by the core package to avoid import cycles while exposing the middleware
// from within the middleware/auth package.
var protectFactory func(cfg config.File, logger *slog.Logger) gin.HandlerFunc

// SetProtectMiddleware registers the factory used by ProtectEndpointMiddleware.
// The core package should call this during initialization to provide the implementation.
func SetProtectMiddleware(factory func(cfg config.File, logger *slog.Logger) gin.HandlerFunc) {
	protectFactory = factory
}

// ProtectEndpointMiddleware returns the configured ProtectEndpoint middleware.
// If no factory was registered, it returns a no-op middleware that simply calls Next().
func ProtectEndpointMiddleware(cfg config.File, logger *slog.Logger) gin.HandlerFunc {
	if protectFactory == nil {
		return func(ctx *gin.Context) { ctx.Next() }
	}

	return protectFactory(cfg, logger)
}
