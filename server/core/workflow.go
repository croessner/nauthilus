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

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
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

// SFOutcome is the snapshot a singleflight leader publishes to waiting followers.
// It contains the final auth view AFTER filters have run and PostActions have been dispatched.
// Followers must not execute filters/post-actions again; they only apply this snapshot to
// their own AuthState and return the final result.
type SFOutcome struct {
	Result              definitions.AuthResult
	AccountField        string
	Attributes          bktype.AttributeMapping
	TOTPSecretField     string
	UniqueUserIDField   string
	DisplayNameField    string
	SourcePassDBBackend definitions.Backend
	UsedPassDBBackend   definitions.Backend
	BackendName         string
	UsedBackendIP       string
	UsedBackendPort     int
	Authenticated       bool
	Authorized          bool
	StatusMessage       string
}

func applyOutcome(dst *AuthState, o SFOutcome) {
	dst.AccountField = o.AccountField
	// Avoid aliasing maps across AuthState instances
	dst.ReplaceAllAttributes(o.Attributes)
	dst.TOTPSecretField = o.TOTPSecretField
	dst.UniqueUserIDField = o.UniqueUserIDField
	dst.DisplayNameField = o.DisplayNameField
	dst.SourcePassDBBackend = o.SourcePassDBBackend
	dst.UsedPassDBBackend = o.UsedPassDBBackend
	dst.BackendName = o.BackendName
	dst.UsedBackendIP = o.UsedBackendIP
	dst.UsedBackendPort = o.UsedBackendPort
	dst.Authenticated = o.Authenticated
	dst.Authorized = o.Authorized
	dst.StatusMessage = o.StatusMessage
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

	// In-process singleflight deduplication only
	key := auth.generateSingleflightKey()

	if idem != "" {
		key = "idk:" + idem + "|" + key

		// Echo the idempotency key for observability (no replay decision yet)
		setIdempotencyHeaders(ctx, idem, nil)
	}

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
		useCache, backendPos, passDBs := auth.handleBackendTypes()
		dWork := config.GetFile().GetServer().GetTimeouts().GetSingleflightWork()

		// No singleflight: if an idempotency key was provided, mark as not replayed.
		if idem != "" {
			replayed := false

			setIdempotencyHeaders(ctx, idem, &replayed)
		}

		return auth.withWorkCtx(dWork, func() definitions.AuthResult {
			return auth.authenticateUser(ctx, useCache, backendPos, passDBs)
		})
	}

	ch := backchanSF.DoChan(key, func() (any, error) {
		useCache, backendPos, passDBs := auth.handleBackendTypes()
		dWork := config.GetFile().GetServer().GetTimeouts().GetSingleflightWork()

		res := auth.withWorkCtx(dWork, func() definitions.AuthResult {
			return auth.authenticateUser(ctx, useCache, backendPos, passDBs)
		})

		// Build snapshot outcome AFTER filters/post-actions have run inside authenticateUser
		out := SFOutcome{
			Result:              res,
			AccountField:        auth.AccountField,
			Attributes:          auth.Attributes,
			TOTPSecretField:     auth.TOTPSecretField,
			UniqueUserIDField:   auth.UniqueUserIDField,
			DisplayNameField:    auth.DisplayNameField,
			SourcePassDBBackend: auth.SourcePassDBBackend,
			UsedPassDBBackend:   auth.UsedPassDBBackend,
			BackendName:         auth.BackendName,
			UsedBackendIP:       auth.UsedBackendIP,
			UsedBackendPort:     auth.UsedBackendPort,
			Authenticated:       auth.Authenticated,
			Authorized:          auth.Authorized,
			StatusMessage:       auth.StatusMessage,
		}

		return out, nil
	})

	select {
	case r := <-ch:
		if r.Err != nil {
			// On error path, if an idempotency key was present, indicate not replayed
			if idem != "" {
				replayed := false

				setIdempotencyHeaders(ctx, idem, &replayed)
			}

			return definitions.AuthResultTempFail
		}

		if out, ok := r.Val.(SFOutcome); ok {
			applyOutcome(auth, out)

			// Indicate whether this response was replayed from singleflight (shared)
			if idem != "" {
				replayed := r.Shared

				setIdempotencyHeaders(ctx, idem, &replayed)
			}

			return out.Result
		}

		return definitions.AuthResultTempFail
	case <-reqCtx.Done():
		// Client disconnected or context canceled: stop waiting and attempt direct auth as fallback
		backchanSF.Forget(key)

		useCache, backendPos, passDBs := auth.handleBackendTypes()
		dWork := config.GetFile().GetServer().GetTimeouts().GetSingleflightWork()

		// Not replayed in this fallback
		if idem != "" {
			replayed := false

			setIdempotencyHeaders(ctx, idem, &replayed)
		}

		return auth.withWorkCtx(dWork, func() definitions.AuthResult {
			return auth.authenticateUser(ctx, useCache, backendPos, passDBs)
		})
	case <-timer.C:
		// Wait cap/deadline reached: stop waiting and attempt direct auth as fallback
		backchanSF.Forget(key)

		useCache, backendPos, passDBs := auth.handleBackendTypes()
		dWork := config.GetFile().GetServer().GetTimeouts().GetSingleflightWork()

		// Not replayed in this fallback
		if idem != "" {
			replayed := false

			setIdempotencyHeaders(ctx, idem, &replayed)
		}

		return auth.withWorkCtx(dWork, func() definitions.AuthResult {
			return auth.authenticateUser(ctx, useCache, backendPos, passDBs)
		})
	}
}
