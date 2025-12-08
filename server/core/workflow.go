// Copyright (C) 2024-2025 Christian Rößner
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
	"github.com/croessner/nauthilus/server/definitions"

	"github.com/gin-gonic/gin"
)

// Fixed header name for idempotency. Not configurable by design.
const idempotencyHeaderName = "Idempotency-Key"

// setIdempotencyHeaders echoes the idempotency key and, if replayed is provided,
// sets Idempotency-Replayed to "true"/"false" accordingly.
func setIdempotencyHeaders(ctx *gin.Context, idem string, replayed *bool) {
	if idem == "" {
		return
	}

	ctx.Header(idempotencyHeaderName, idem)

	if replayed != nil {
		if *replayed {
			ctx.Header("Idempotency-Replayed", "true")
		} else {
			ctx.Header("Idempotency-Replayed", "false")
		}
	}
}

// Authenticator orchestrates the authentication flow.
// It wires the previously extracted services and keeps behavior identical
// to the legacy inline implementation in AuthState.HandlePassword.
//
// In this initial step, Authenticate delegates to existing helper methods
// on AuthState to avoid any behavior changes.
//
// Future iterations can migrate more logic from AuthState into this type.
//
//goland:nointerface
type Authenticator struct {
	Decoder  any // placeholder for future RequestDecoder
	Verifier PasswordVerifier
	Cache    CacheService
	BF       BruteForceService
	Lua      LuaFilter
	Post     PostAction
	Resp     ResponseWriter
}

var defaultAuthenticator = Authenticator{
	Verifier: getPasswordVerifier(),
	Cache:    getCacheService(),
	BF:       getBruteForceService(),
	Lua:      getLuaFilter(),
	Post:     getPostAction(),
	Resp:     defaultResponseWriter,
}

// Authenticate runs the full password authentication flow.
// Behavior mirrors the legacy HandlePassword implementation exactly.
func (aor Authenticator) Authenticate(ctx *gin.Context, auth *AuthState) (authResult definitions.AuthResult) {
	// Common validation checks
	if authResult = auth.usernamePasswordChecks(); authResult != definitions.AuthResultUnset {
		return
	}

	// Read idempotency key as early as possible so we can echo it on early return paths (e.g., memory cache).
	idem := ctx.GetHeader(idempotencyHeaderName)

	if !(auth.HaveMonitoringFlag(definitions.MonInMemory) || auth.IsMasterUser()) && ctx.GetBool(definitions.CtxLocalCacheAuthKey) {
		// Memory-cache hit is semantically a replay; if a key is present, echo it and mark replayed.
		if idem != "" {
			replayed := true

			setIdempotencyHeaders(ctx, idem, &replayed)
		}

		return auth.handleLocalCache(ctx)
	}

	if idem != "" {
		// Echo the idempotency key for observability (no replay decision yet)
		setIdempotencyHeaders(ctx, idem, nil)
	}

	useCache, backendPos, passDBs := auth.handleBackendTypes()

	return auth.authenticateUser(ctx, useCache, backendPos, passDBs)
}
