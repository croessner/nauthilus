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

	"github.com/croessner/nauthilus/server/config"
	corelang "github.com/croessner/nauthilus/server/core/language"

	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	"github.com/croessner/nauthilus/server/middleware/csrf"
	"github.com/croessner/nauthilus/server/middleware/i18n"
	mdlua "github.com/croessner/nauthilus/server/middleware/lua"

	"github.com/gin-gonic/gin"
)

// CreateMiddlewareChain constructs the standard middleware chain for frontend routes
// including CSRF, Lua context, language handling and endpoint protection.
func CreateMiddlewareChain(cfg config.File, logger *slog.Logger, langManager corelang.Manager) []gin.HandlerFunc {
	return []gin.HandlerFunc{
		csrf.New(),
		mdlua.LuaContextMiddleware(),
		i18n.WithLanguage(cfg, logger, langManager),
		mdauth.ProtectEndpointMiddleware(cfg, logger),
	}
}
