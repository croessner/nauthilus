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

package core

import (
	"log/slog"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

// AccountMiddleware resolves the user's account name and makes it available
// in the Gin context under definitions.CtxAccountKey. Resolution priority:
// 1) If already set in the context, keep it.
// 2) If a username is available (header or BasicAuth), try local cache first.
// 3) Fallback to Redis lookup.
// Only the plain account string is stored; no additional fields are added.
func AccountMiddleware(cfg config.File, logger *slog.Logger, redisClient rediscli.Client, accountCache *accountcache.Manager) gin.HandlerFunc { //nolint:ireturn
	return func(c *gin.Context) {
		guid := c.GetString(definitions.CtxGUIDKey)

		// Derive username early for logging purposes
		username := c.GetHeader(cfg.GetUsername())
		if username == "" {
			// Try HTTP BasicAuth as a secondary source
			if u, _, ok := c.Request.BasicAuth(); ok {
				username = u
			}
		}

		if v, ok := c.Get(definitions.CtxAccountKey); ok && v != nil {
			util.DebugModuleWithCfg(
				c.Request.Context(),
				cfg,
				logger,
				definitions.DbgAccount,
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, username,
				definitions.LogKeyMsg, "Account already present in context (preset)",
				"account", c.GetString(definitions.CtxAccountKey),
				"source", "preset",
			)

			c.Next()

			return
		}

		if username == "" {
			util.DebugModuleWithCfg(
				c.Request.Context(),
				cfg,
				logger,
				definitions.DbgAccount,
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "No username available to resolve account",
			)

			c.Next()

			return
		}

		var source string

		// Prefer cached mapping (in-process/Redis) with bounded deadline
		dCtx, cancel := util.GetCtxWithDeadlineRedisRead(c, cfg)
		account := backend.GetUserAccountFromCache(dCtx, cfg, logger, redisClient, accountCache, username, guid)
		cancel()

		if account == "" {
			// Final fallback: direct Redis lookup with bounded deadline
			dCtx2, cancel2 := util.GetCtxWithDeadlineRedisRead(c, cfg)
			acc2, _ := backend.LookupUserAccountFromRedis(dCtx2, cfg, redisClient, username)
			cancel2()
			account = acc2

			if account != "" {
				source = "redis"
			}
		} else {
			source = "cache"
		}

		if account != "" {
			c.Set(definitions.CtxAccountKey, account)

			util.DebugModuleWithCfg(
				c.Request.Context(),
				cfg,
				logger,
				definitions.DbgAccount,
				definitions.LogKeyGUID, guid,
				definitions.LogKeyUsername, username,
				definitions.LogKeyMsg, "Resolved account and stored in context",
				"account", account,
				"source", source,
			)
		}

		c.Next()
	}
}
