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
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/lualib/hook"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
)

// CustomRequestHandler mirrors the original logic for executing custom Lua hooks.
func CustomRequestHandler(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)

	// Check if custom hooks are enabled
	if config.GetFile().GetServer().GetEndpoint().IsCustomHooksDisabled() {
		util.DebugModule(
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

	util.DebugModule(
		definitions.DbgHTTP,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Processing custom hook: %s %s", hookMethod, hookName),
	)

	// Log JWT claims for debugging
	claimsValue, exists := ctx.Get(definitions.CtxJWTClaimsKey)
	if exists {
		util.DebugModule(
			definitions.DbgHTTP,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("JWT claims found in context, type: %T", claimsValue),
		)
	} else {
		util.DebugModule(
			definitions.DbgHTTP,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, "No JWT claims found in context",
		)
	}

	// Check if the user has the required roles for this hook
	if !hook.HasRequiredRoles(ctx, hookName, hookMethod) {
		util.DebugModule(
			definitions.DbgHTTP,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("User does not have required roles for hook: %s %s", hookMethod, hookName),
		)
		ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})

		return
	}

	util.DebugModule(
		definitions.DbgHTTP,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("User has required roles for hook: %s %s, executing hook", hookMethod, hookName),
	)

	// Execute the hook
	if result, err := hook.RunLuaHook(ctx); err != nil {
		level.Error(log.Logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Error executing hook: %s %s", hookMethod, hookName),
			"error", err,
		)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{definitions.LogKeyMsg: err.Error()})
	} else if result != nil {
		util.DebugModule(
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
		util.DebugModule(
			definitions.DbgHTTP,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Hook executed successfully with no JSON result: %s %s status: %d size: %d written: %t encoding: %s",
				hookMethod, hookName, ctx.Writer.Status(), ctx.Writer.Size(), ctx.Writer.Written(), ctx.Writer.Header().Get("Content-Encoding")),
		)
	}
}
