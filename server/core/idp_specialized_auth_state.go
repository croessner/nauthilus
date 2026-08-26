// Copyright (C) 2026 Christian Rößner
// SPDX-License-Identifier: GPL-3.0-or-later

package core

import (
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/gin-gonic/gin"
)

// NewIDPSpecializedAuthState materializes successful admitted identity data for specialized MFA operations.
// It does not execute authentication, policy evaluation, or browser-flow state transitions.
func NewIDPSpecializedAuthState(
	ctx *gin.Context,
	deps AuthDeps,
	input AuthInput,
	outcome *AuthOutcome,
) (*AuthState, error) {
	if ctx != nil && ctx.Request == nil {
		return nil, fmt.Errorf("specialized IDP AuthState requires a complete HTTP context when supplied")
	}

	if deps.Cfg == nil {
		return nil, fmt.Errorf("%w: cfg", ErrAuthApplicationDependencyMissing)
	}

	if outcome == nil || outcome.Decision != AuthDecisionOK || strings.TrimSpace(outcome.Account) == "" {
		return nil, fmt.Errorf("specialized IDP AuthState requires a successful identity outcome")
	}

	authRaw := NewAuthStateFromContextWithDeps(ctx, deps)
	auth, ok := authRaw.(*AuthState)

	if !ok || auth == nil {
		return nil, fmt.Errorf("specialized IDP AuthState construction failed")
	}

	input.IDP = input.IDP.Clone()
	input.Context.RequestMetadata = cloneRequestMetadata(input.Context.RequestMetadata)

	applyIDPSpecializedRequest(auth, ctx, input, outcome)
	applyIDPSpecializedIdentity(auth, outcome)

	return auth, nil
}

// applyIDPSpecializedRequest installs bounded request values without decoding the browser request body.
func applyIDPSpecializedRequest(auth *AuthState, ctx *gin.Context, input AuthInput, outcome *AuthOutcome) {
	service := strings.TrimSpace(input.Service)
	if service == "" {
		service = definitions.ServIDP
	}

	auth.Request.Service = service
	auth.Runtime.GUID = idpSpecializedCorrelationID(ctx, input.CorrelationID)
	auth.Runtime.Context = idpSpecializedLuaContext(ctx)
	auth.ApplyContextData(input.Context)
	applyAuthIDPContext(auth, input.IDP)
	auth.SetStatusCodes(service)
	auth.SetNoAuth(true)

	protocolName := strings.TrimSpace(outcome.Protocol)
	if protocolName == "" {
		protocolName = strings.TrimSpace(input.Context.Protocol)
	}

	if protocolName == "" {
		protocolName = definitions.ProtoIDP
	}

	auth.SetProtocol(config.NewProtocol(protocolName))
}

// applyIDPSpecializedIdentity installs detached identity and backend ownership from the admitted outcome.
func applyIDPSpecializedIdentity(auth *AuthState, outcome *AuthOutcome) {
	auth.SetUsername(outcome.Account)
	auth.SetAccount(outcome.Account)
	auth.ReplaceAllAttributes(outcome.Attributes)
	auth.SetResolvedGroups(outcome.Groups, outcome.GroupDistinguishedNames)

	auth.Runtime.AccountField = outcome.AccountField
	auth.Runtime.TOTPSecretField = outcome.TOTPSecretField
	auth.Runtime.TOTPRecoveryField = outcome.TOTPRecoveryField
	auth.Runtime.UniqueUserIDField = outcome.UniqueUserIDField
	auth.Runtime.DisplayNameField = outcome.DisplayNameField
	auth.Runtime.BackendName = outcome.BackendName
	auth.Runtime.UsedBackendIP = outcome.UsedBackendIP
	auth.Runtime.UsedBackendPort = outcome.UsedBackendPort
	auth.Runtime.SourcePassDBBackend = outcome.Backend
	auth.Runtime.UsedPassDBBackend = outcome.Backend

	if !outcome.RemoteBackendRef.IsZero() {
		auth.Runtime.RemoteBackendRef = outcome.RemoteBackendRef
	}

	auth.Runtime.StatusMessage = outcome.StatusMessage
	auth.Runtime.StatusMessageI18NKey = outcome.StatusMessageI18NKey
	auth.Runtime.ResponseLanguage = outcome.ResponseLanguage
	auth.Runtime.UserFound = true
	auth.Runtime.Authenticated = true
	auth.Runtime.Authorized = true
}

// idpSpecializedCorrelationID preserves the admitted correlation value or the existing request GUID.
func idpSpecializedCorrelationID(ctx *gin.Context, correlationID string) string {
	if strings.TrimSpace(correlationID) != "" {
		return correlationID
	}

	if ctx != nil {
		if existing := ctx.GetString(definitions.CtxGUIDKey); existing != "" {
			return existing
		}
	}

	return authApplicationCorrelationID("")
}

// idpSpecializedLuaContext reuses request-local Lua state or creates an isolated fallback.
func idpSpecializedLuaContext(ctx *gin.Context) *lualib.Context {
	if ctx != nil {
		if value, found := ctx.Get(definitions.CtxDataExchangeKey); found {
			if requestContext, ok := value.(*lualib.Context); ok && requestContext != nil {
				return requestContext
			}
		}
	}

	return lualib.NewContext()
}
