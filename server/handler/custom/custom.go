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

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib/hook"
	"github.com/croessner/nauthilus/v3/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/util"

	"github.com/gin-gonic/gin"
)

// CustomRequestHandler mirrors the original logic for executing custom Lua hooks.
// The validator may be nil when OIDC authentication is not configured.
func CustomRequestHandler(cfgProvider configfx.Provider, logger *slog.Logger, redis rediscli.Client, validator oidcbearer.TokenValidator) gin.HandlerFunc {
	return RequestHandlerWithNative(cfgProvider, logger, redis, validator, nil)
}

// RequestHandlerWithNative executes native plugin hooks before falling
// back to the existing Lua custom hook implementation.
func RequestHandlerWithNative(
	cfgProvider configfx.Provider,
	logger *slog.Logger,
	redis rediscli.Client,
	validator oidcbearer.TokenValidator,
	nativeHooks *nativeHookIndex,
) gin.HandlerFunc {
	handler := customRequestHandler{
		cfgProvider: cfgProvider,
		logger:      logger,
		redis:       redis,
		validator:   validator,
		nativeHooks: nativeHooks,
	}

	return handler.serve
}

type customRequestHandler struct {
	cfgProvider configfx.Provider
	logger      *slog.Logger
	redis       rediscli.Client
	validator   oidcbearer.TokenValidator
	nativeHooks *nativeHookIndex
}

// serve dispatches one custom hook request through native plugins or Lua.
func (h customRequestHandler) serve(ctx *gin.Context) {
	guid := ctx.GetString(definitions.CtxGUIDKey)
	snap := h.cfgProvider.Current()

	if h.customHooksDisabled(ctx, snap, guid) {
		return
	}

	hookName := hook.ResolveRequestHook(ctx)
	hookMethod := ctx.Request.Method

	h.logHookProcessing(ctx, snap, guid, hookName, hookMethod)

	if h.nativeHooks.serve(ctx, snap.File, h.logger, h.validator, hookName, hookMethod) {
		return
	}

	if !hook.HasRequiredScopes(ctx, snap.File, h.logger, h.validator, hookName, hookMethod) {
		return
	}

	h.logHookAuthorized(ctx, snap, guid, hookName, hookMethod)
	h.runLuaHook(ctx, snap, guid, hookName, hookMethod)
}

// customHooksDisabled aborts requests when the endpoint is disabled.
func (h customRequestHandler) customHooksDisabled(ctx *gin.Context, snap configfx.Snapshot, guid string) bool {
	if !snap.File.GetServer().GetEndpoint().IsCustomHooksDisabled() {
		return false
	}

	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		snap.File,
		h.logger,
		definitions.DbgHTTP,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, "Custom hooks are disabled",
	)
	ctx.AbortWithStatus(http.StatusNotFound)

	return true
}

// logHookProcessing records the selected custom hook before dispatch.
func (h customRequestHandler) logHookProcessing(ctx *gin.Context, snap configfx.Snapshot, guid string, hookName string, hookMethod string) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		snap.File,
		h.logger,
		definitions.DbgHTTP,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Processing custom hook: %s %s", hookMethod, hookName),
	)
}

// logHookAuthorized records that scope checks allowed Lua hook execution.
func (h customRequestHandler) logHookAuthorized(ctx *gin.Context, snap configfx.Snapshot, guid string, hookName string, hookMethod string) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		snap.File,
		h.logger,
		definitions.DbgHTTP,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("User has required scopes for hook: %s %s, executing hook", hookMethod, hookName),
	)
}

// runLuaHook executes the Lua hook and writes the legacy JSON response when needed.
func (h customRequestHandler) runLuaHook(ctx *gin.Context, snap configfx.Snapshot, guid string, hookName string, hookMethod string) {
	result, err := hook.RunLuaHook(ctx, snap.File, h.logger, h.redis)
	if err != nil {
		_ = level.Error(h.logger).Log(
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Error executing hook: %s %s", hookMethod, hookName),
			definitions.LogKeyError, err,
		)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{definitions.LogKeyMsg: err.Error()})

		return
	}

	if result == nil {
		util.DebugModuleWithCfg(
			ctx.Request.Context(),
			snap.File,
			h.logger,
			definitions.DbgHTTP,
			definitions.LogKeyGUID, guid,
			definitions.LogKeyMsg, fmt.Sprintf("Hook executed successfully with no JSON result: %s %s status: %d size: %d written: %t encoding: %s",
				hookMethod, hookName, ctx.Writer.Status(), ctx.Writer.Size(), ctx.Writer.Written(), ctx.Writer.Header().Get("Content-Encoding")),
		)

		return
	}

	h.writeLuaHookResult(ctx, snap, guid, hookName, hookMethod, result)
}

// writeLuaHookResult writes the JSON response unless Lua already wrote one.
func (h customRequestHandler) writeLuaHookResult(ctx *gin.Context, snap configfx.Snapshot, guid string, hookName string, hookMethod string, result any) {
	util.DebugModuleWithCfg(
		ctx.Request.Context(),
		snap.File,
		h.logger,
		definitions.DbgHTTP,
		definitions.LogKeyGUID, guid,
		definitions.LogKeyMsg, fmt.Sprintf("Hook executed successfully: %s %s", hookMethod, hookName),
	)

	if ctx.GetBool(definitions.CtxResponseWrittenKey) || ctx.Writer.Written() {
		return
	}

	if ctx.Writer != nil {
		ctx.JSON(http.StatusOK, result)
	}
}
