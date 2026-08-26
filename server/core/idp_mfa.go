// Copyright (C) 2025 Christian Rößner
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
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/gin-gonic/gin"
)

// IDPMFAProtocolContext binds MFA audit telemetry to typed protocol state.
type IDPMFAProtocolContext struct {
	Protocol     string
	OIDCClientID string
	SAMLEntityID string
	Request      IDPRequestContext
}

// LogIDPMFAuthResult writes a Notice log for the result of a second-factor verification
// during the IDP login flow. It is intentionally not gated behind debug modules.
//
//nolint:funlen // Audit construction remains one bounded protocol-context projection.
func LogIDPMFAuthResult(
	ctx *gin.Context,
	deps AuthDeps,
	protocolContext IDPMFAProtocolContext,
	username string,
	method string,
	statusMessage string,
	successful bool,
) {
	if ctx == nil || ctx.Request == nil || deps.Cfg == nil || deps.Logger == nil {
		return
	}

	authStateRaw := NewAuthStateFromContextWithDeps(ctx, deps)

	auth, ok := authStateRaw.(*AuthState)
	if !ok || auth == nil {
		return
	}

	auth.WithClientInfo(ctx)
	auth.WithLocalInfo(ctx)
	auth.WithUserAgent(ctx)
	auth.WithXSSL(ctx)

	auth.Runtime.GUID = ctx.GetString(definitions.CtxGUIDKey)

	auth.Request.Service = ctx.GetString(definitions.CtxServiceKey)
	if auth.Request.Service == "" {
		auth.Request.Service = definitions.ServIDP
	}

	protocolContext = normalizeIDPMFAProtocolContext(protocolContext)
	protocolContext.Request.MFACompleted = successful
	protocolContext.Request.MFAMethod = normalizeMFAMethodForLogging(method)
	auth.Runtime.IDPContext = cloneIDPRequestContext(protocolContext.Request)
	auth.SetProtocol(config.NewProtocol(protocolContext.Protocol))
	auth.SetOIDCCID(protocolContext.OIDCClientID)
	auth.SetSAMLEntityID(protocolContext.SAMLEntityID)
	auth.SetUsername(username)

	logMethod := normalizeMFAMethodForLogging(method)
	auth.SetMethod(logMethod)
	auth.Runtime.Authenticated = successful
	auth.Runtime.UserFound = username != ""

	if statusMessage != "" {
		auth.Runtime.StatusMessage = statusMessage
	}

	status := "fail"
	message := "Second-factor authentication has failed"

	if successful {
		status = environmentDecisionOK
		message = "Second-factor authentication was successful"
	}

	keyvals := getLogSlice()

	defer putLogSlice(keyvals)

	keyvals = auth.fillLogLineTemplate(keyvals, status, ctx.Request.URL.Path)
	keyvals = append(
		keyvals,
		definitions.LogKeyMsg, message,
		definitions.SessionKeyMFAMethod, logMethod,
	)

	_ = level.Notice(auth.Logger()).WithContext(ctx).Log(keyvals...)
}

func normalizeMFAMethodForLogging(method string) string {
	switch method {
	case "recovery":
		return definitions.MFAMethodRecoveryCodes
	case "":
		return method
	default:
		return method
	}
}

func normalizeIDPMFAProtocolContext(protocolContext IDPMFAProtocolContext) IDPMFAProtocolContext {
	protocolContext.Request.RequestedScopes = append([]string(nil), protocolContext.Request.RequestedScopes...)
	switch protocolContext.Protocol {
	case definitions.ProtoOIDC:
		protocolContext.SAMLEntityID = ""
	case definitions.ProtoSAML:
		protocolContext.OIDCClientID = ""
	default:
		protocolContext.Protocol = definitions.ProtoIDP
		protocolContext.OIDCClientID = ""
		protocolContext.SAMLEntityID = ""
	}

	return protocolContext
}

func cloneIDPRequestContext(request IDPRequestContext) *IDPRequestContext {
	request.RequestedScopes = append([]string(nil), request.RequestedScopes...)

	return &request
}
