//go:build auth_basic_endpoint

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

package core

import (
	"net/http"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	mdauth "github.com/croessner/nauthilus/server/middleware/auth"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
)

func (a *AuthState) preprocessBasicEndpointInput(ctx *gin.Context) bool {
	if a.Request.Service != definitions.ServBasic {
		return false
	}

	return a.processBasicAuthInput(ctx)
}

func (a *AuthState) processBasicAuthInput(ctx *gin.Context) (abort bool) {
	var httpBasicAuthOK bool

	// Decode HTTP basic Auth
	username, password, httpBasicAuthOK := ctx.Request.BasicAuth()
	a.Request.Username = username
	passwordBytes := []byte(password)
	a.Request.Password = secret.FromBytes(passwordBytes)
	clear(passwordBytes)
	password = ""
	ctx.Request.Header.Del("Authorization")
	if !httpBasicAuthOK {
		ctx.Header("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		ctx.AbortWithError(http.StatusUnauthorized, errors.ErrUnauthorized)

		return true
	}

	if a.Request.Username == "" {
		ctx.Error(errors.ErrEmptyUsername)
	} else if !util.ValidateUsername(a.Request.Username) {
		ctx.Error(errors.ErrInvalidUsername)
	}

	if a.Request.Password.IsZero() {
		ctx.Error(errors.ErrEmptyPassword)
	}

	return false
}

func (a *AuthState) handleBasicEndpointAuthPhase(ctx *gin.Context, current authFSMState) bool {
	if a.Request.Service != definitions.ServBasic {
		return false
	}

	var httpBasicAuthOK bool

	if a.deps.Cfg.GetServer().GetBasicAuth().IsEnabled() {
		if a.deps.Cfg.GetServer().GetLog().GetLogLevel() >= definitions.LogLevelDebug {
			level.Debug(a.deps.Logger).Log(
				definitions.LogKeyGUID, a.Runtime.GUID,
				definitions.LogKeyUsername, a.Request.Username,
				definitions.LogKeyMsg, "Processing HTTP Basic Auth",
			)
		}

		httpBasicAuthOK = mdauth.CheckAndRequireBasicAuth(ctx, a.deps.Cfg)
	} else {
		httpBasicAuthOK = true
	}

	event := mapBasicAuthCheckToFSMEvent(httpBasicAuthOK)
	nextState, err := nextAuthFSMState(current, event)
	if err != nil {
		ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)

		return true
	}

	a.auditAuthFSMTransition(current, event, nextState)

	// Keep previous behavior for failed basic checks: abort only (no AuthFail side effects).
	dispatchAuthFSMTerminalOutcome(nextState, authFSMTerminalHandlers{
		onAuthOK: func() {
			a.AuthOK(ctx)
		},
		onAuthFail: func() {
			ctx.Abort()
		},
		onInvalid: func() {
			ctx.AbortWithStatus(a.Runtime.StatusCodeInternalError)
		},
	})

	return true
}

func mapBasicAuthCheckToFSMEvent(ok bool) authFSMEvent {
	if ok {
		return authFSMEventBasicAuthOK
	}

	return authFSMEventBasicAuthFail
}
