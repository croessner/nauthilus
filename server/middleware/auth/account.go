// Copyright (C) 2025 Christian Rößner
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

	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
)

// accountFactory is a function reference that returns the actual Account middleware.
// It is injected by the core package to avoid import cycles while exposing the middleware
// from within the middleware/auth package.
var accountFactory func(cfg config.File, logger *slog.Logger, redisClient rediscli.Client, accountCache *accountcache.Manager) gin.HandlerFunc

// SetAccountMiddleware registers the factory used by AccountMiddleware.
// The core package should call this during initialization to provide the implementation.
func SetAccountMiddleware(factory func(cfg config.File, logger *slog.Logger, redisClient rediscli.Client, accountCache *accountcache.Manager) gin.HandlerFunc) {
	accountFactory = factory
}

// AccountMiddleware returns the configured Account resolution middleware.
// If no factory was registered, it returns a no-op middleware that simply calls Next().
func AccountMiddleware(cfg config.File, logger *slog.Logger, redisClient rediscli.Client, accountCache *accountcache.Manager) gin.HandlerFunc {
	if accountFactory == nil {
		return func(ctx *gin.Context) { ctx.Next() }
	}

	return accountFactory(cfg, logger, redisClient, accountCache)
}
