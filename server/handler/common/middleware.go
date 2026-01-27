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

package common

import (
	"log/slog"

	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/config"
	corelang "github.com/croessner/nauthilus/server/core/language"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/rediscli"

	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	"github.com/croessner/nauthilus/server/middleware/i18n"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gwatts/gin-adapter"
	"github.com/justinas/nosurf"
)

// CreateMiddlewareChain constructs the standard middleware chain for frontend routes
// including sessions, CSRF, Lua context, language handling and endpoint protection.
func CreateMiddlewareChain(cfg config.File, logger *slog.Logger, _ rediscli.Client, _ *accountcache.Manager, langManager corelang.Manager, sessionStore sessions.Store) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		sessions.Sessions(definitions.SessionName, sessionStore),
		adapter.Wrap(nosurf.NewPure),
		mdlua.LuaContextMiddleware(),
		i18n.WithLanguage(cfg, logger, langManager),
		mdauth.ProtectEndpointMiddleware(cfg, logger),
	}
}
