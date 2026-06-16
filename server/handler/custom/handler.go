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
	"log/slog"
	"sync"

	"github.com/croessner/nauthilus/server/app/configfx"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/hook"
	"github.com/croessner/nauthilus/server/middleware/oidcbearer"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
)

var aliasDispatcher = struct {
	sync.RWMutex
	handler       gin.HandlerFunc
	nativeAliases map[string]string
}{}

// Option customizes custom hook handler registration.
type Option func(*Handler)

// Handler registers custom Lua hook endpoint(s).
type Handler struct {
	cfgProvider configfx.Provider
	logger      *slog.Logger
	redis       rediscli.Client
	validator   oidcbearer.TokenValidator
	nativeHooks []NativeHook
}

// New creates a Handler with explicit dependencies.
// The validator may be nil when OIDC authentication is not configured.
func New(cfgProvider configfx.Provider, logger *slog.Logger, redis rediscli.Client, validator oidcbearer.TokenValidator, options ...Option) *Handler {
	handler := &Handler{cfgProvider: cfgProvider, logger: logger, redis: redis, validator: validator}

	for _, option := range options {
		if option != nil {
			option(handler)
		}
	}

	return handler
}

// WithNativeHooks registers native plugin hook bindings in the custom handler.
func WithNativeHooks(hooks []NativeHook) Option {
	return func(handler *Handler) {
		handler.nativeHooks = append([]NativeHook(nil), hooks...)
	}
}

// Register registers the custom hook route on the given router.
func (h *Handler) Register(r gin.IRouter) {
	nativeHooks := newNativeHookIndex(h.nativeHooks)
	handler := RequestHandlerWithNative(h.cfgProvider, h.logger, h.redis, h.validator, nativeHooks)

	r.Any("/custom/*hook", handler)

	aliasDispatcher.Lock()
	aliasDispatcher.handler = handler
	aliasDispatcher.nativeAliases = nativeHooks.aliasMap()
	aliasDispatcher.Unlock()
}

// DispatchAlias executes a configured custom hook alias for requests that did
// not match a concrete route. It returns false when the request is not an alias.
func DispatchAlias(ctx *gin.Context) bool {
	if ctx == nil || ctx.Request == nil || ctx.Request.URL == nil {
		return false
	}

	canonicalHook, found := hook.ResolveAliasLocation(ctx.Request.URL.Path, ctx.Request.Method)
	if !found {
		canonicalHook, found = resolveNativeAliasLocation(ctx.Request.URL.Path, ctx.Request.Method)
		if !found {
			return false
		}
	}

	aliasDispatcher.RLock()
	handler := aliasDispatcher.handler
	aliasDispatcher.RUnlock()
	if handler == nil {
		return false
	}

	ctx.Set(definitions.CtxCustomHookKey, canonicalHook)
	handler(ctx)

	return true
}

// resolveNativeAliasLocation returns the canonical native hook path for an alias.
func resolveNativeAliasLocation(location string, method string) (string, bool) {
	aliasDispatcher.RLock()
	defer aliasDispatcher.RUnlock()

	if len(aliasDispatcher.nativeAliases) == 0 {
		return "", false
	}

	canonicalLocation, found := aliasDispatcher.nativeAliases[nativeHookKey(location, method)]

	return canonicalLocation, found
}
