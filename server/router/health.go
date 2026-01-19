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
	"log/slog"
	"net/http"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"

	"github.com/gin-gonic/gin"
)

// HealthCheck handles the health check functionality by logging a message and returning "pong" as the response.
func HealthCheck(ctx *gin.Context) {
	level.Info(slog.Default()).Log(definitions.LogKeyGUID, ctx.GetString(definitions.CtxGUIDKey), definitions.LogKeyMsg, "Health check")

	ctx.String(http.StatusOK, "pong")
}
