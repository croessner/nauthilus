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
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"

	"github.com/gin-gonic/gin"
)

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
func (aor Authenticator) Authenticate(ctx *gin.Context, a *AuthState) (authResult definitions.AuthResult) {
	// Common validation checks
	if authResult = a.usernamePasswordChecks(); authResult != definitions.AuthResultUnset {
		return
	}

	if !(a.HaveMonitoringFlag(definitions.MonInMemory) || a.IsMasterUser()) && ctx.GetBool(definitions.CtxLocalCacheAuthKey) {
		return a.handleLocalCache(ctx)
	}

	// In-process singleflight deduplication only
	key := a.generateSingleflightKey()
	reqCtx := ctx.Request.Context()

	// Derive wait deadline from request context, with a safety cap if none
	var timer *time.Timer
	if dl, ok := reqCtx.Deadline(); ok {
		d := time.Until(dl)
		if d <= 0 {
			backchanSF.Forget(key)

			return definitions.AuthResultTempFail
		}

		timer = time.NewTimer(d)
	} else {
		timer = time.NewTimer(definitions.SingleflightWaitCap)
	}

	defer timer.Stop()

	// Allow disabling in-process singleflight via config (default: enabled)
	if !config.GetFile().GetServer().GetDedup().IsInProcessEnabled() {
		useCache, backendPos, passDBs := a.handleBackendTypes()
		dWork := config.GetFile().GetServer().GetTimeouts().GetSingleflightWork()

		return a.withWorkCtx(dWork, func() definitions.AuthResult {
			return a.authenticateUser(ctx, useCache, backendPos, passDBs)
		})
	}

	ch := backchanSF.DoChan(key, func() (any, error) {
		useCache, backendPos, passDBs := a.handleBackendTypes()
		dWork := config.GetFile().GetServer().GetTimeouts().GetSingleflightWork()

		res := a.withWorkCtx(dWork, func() definitions.AuthResult {
			return a.authenticateUser(ctx, useCache, backendPos, passDBs)
		})

		return res, nil
	})

	select {
	case r := <-ch:
		if r.Err != nil {
			return definitions.AuthResultTempFail
		}

		return r.Val.(definitions.AuthResult)
	case <-reqCtx.Done():
		// Client disconnected or context canceled: stop waiting and attempt direct auth as fallback
		backchanSF.Forget(key)

		useCache, backendPos, passDBs := a.handleBackendTypes()
		dWork := config.GetFile().GetServer().GetTimeouts().GetSingleflightWork()

		return a.withWorkCtx(dWork, func() definitions.AuthResult {
			return a.authenticateUser(ctx, useCache, backendPos, passDBs)
		})
	case <-timer.C:
		// Wait cap/deadline reached: stop waiting and attempt direct auth as fallback
		backchanSF.Forget(key)

		useCache, backendPos, passDBs := a.handleBackendTypes()
		dWork := config.GetFile().GetServer().GetTimeouts().GetSingleflightWork()

		return a.withWorkCtx(dWork, func() definitions.AuthResult {
			return a.authenticateUser(ctx, useCache, backendPos, passDBs)
		})
	}
}
