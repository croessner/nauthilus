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

package custom

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib/hook"
	"github.com/croessner/nauthilus/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
)

// CustomRequestHandler mirrors the original logic for executing custom Lua hooks.
// The validator may be nil when OIDC authentication is not configured.
func CustomRequestHandler(cfgProvider configfx.Provider, logger *slog.Logger, redis rediscli.Client, validator oidcbearer.TokenValidator) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		guid := ctx.GetString(definitions.CtxGUIDKey)
		snap := cfgProvider.Current()

		// Check if custom hooks are enabled
		if snap.File.GetServer().GetEndpoint().IsCustomHooksDisabled() {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				snap.File,
				logger,
				definitions.DbgHTTP,
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, "Custom hooks are disabled",
			)
			ctx.AbortWithStatus(http.StatusNotFound)

			return
		}

		// Get the hook name and method from the request
		hookName := ctx.Param("hook")
		hookMethod := ctx.Request.Method

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			snap.File,
			logger,
			definitions.DbgHTTP,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Processing custom hook: %s %s", hookMethod, hookName),
		)

		// Check if the user has the required scopes for this hook.
		// HasRequiredScopes handles the full auth flow (token extraction, validation,
		// scope checking) and aborts the request with the appropriate status on denial.
		if !hook.HasRequiredScopes(ctx, snap.File, logger, validator, hookName, hookMethod) {
			return
		}

		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			snap.File,
			logger,
			definitions.DbgHTTP,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("User has required roles for hook: %s %s, executing hook", hookMethod, hookName),
		)

		// Execute the hook
		if result, err := hook.RunLuaHook(ctx, snap.File, logger, redis); err != nil {
			level.Error(logger).Log(
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, fmt.Sprintf("Error executing hook: %s %s", hookMethod, hookName),
				definitions.LogKeyError, err,
			)
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{definitions.LogKeyMsg: err.Error()})
		} else if result != nil {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				snap.File,
				logger,
				definitions.DbgHTTP,
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, fmt.Sprintf("Hook executed successfully: %s %s", hookMethod, hookName),
			)

			// If Lua already wrote the response, do not override with JSON
			if ctx.GetBool(definitions.CtxResponseWrittenKey) || ctx.Writer.Written() {
				return
			}

			if ctx.Writer != nil {
				ctx.JSON(http.StatusOK, result)
			}
		} else {
			util.DebugModuleWithCfg(
				ctx.Request.Context(),
				snap.File,
				logger,
				definitions.DbgHTTP,
				definitions.LogKeyGUID, guid,
				definitions.LogKeyMsg, fmt.Sprintf("Hook executed successfully with no JSON result: %s %s status: %d size: %d written: %t encoding: %s",
					hookMethod, hookName, ctx.Writer.Status(), ctx.Writer.Size(), ctx.Writer.Written(), ctx.Writer.Header().Get("Content-Encoding")),
			)
		}
	}
}
