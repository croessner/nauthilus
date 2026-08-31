// Copyright (C) 2026 Christian Rößner
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
	"log/slog"
	"net/http"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"

	"github.com/gin-gonic/gin"
)

// CapturedAuthDecision is the terminal auth decision captured from the response layer.
type CapturedAuthDecision string

const (
	// CapturedAuthDecisionUnset indicates that no terminal decision was captured yet.
	CapturedAuthDecisionUnset CapturedAuthDecision = "unset"
	// CapturedAuthDecisionOK indicates successful authentication.
	CapturedAuthDecisionOK CapturedAuthDecision = "ok"
	// CapturedAuthDecisionFail indicates a terminal authentication failure.
	CapturedAuthDecisionFail CapturedAuthDecision = "fail"
	// CapturedAuthDecisionTempFail indicates a temporary terminal failure.
	CapturedAuthDecisionTempFail CapturedAuthDecision = "tempfail"
)

// CapturedAuthOutcome stores the transport-neutral terminal auth outcome.
type CapturedAuthOutcome = authOutcomeProjection[CapturedAuthDecision]

// CaptureResponseWriter captures auth terminal outcomes without rendering HTTP.
type CaptureResponseWriter struct {
	logger           *slog.Logger
	outcome          CapturedAuthOutcome
	responseSettings AuthResponseSettings
}

// NewCaptureResponseWriter creates a request-scoped outcome collector.
func NewCaptureResponseWriter(logger *slog.Logger) *CaptureResponseWriter {
	return &CaptureResponseWriter{
		logger: logger,
		outcome: CapturedAuthOutcome{
			Decision: CapturedAuthDecisionUnset,
		},
	}
}

// NewDefaultCaptureResponseWriter creates a capture writer based on DI response dependencies.
func NewDefaultCaptureResponseWriter(deps ResponseDeps) *CaptureResponseWriter {
	w := NewCaptureResponseWriter(deps.Logger)
	w.responseSettings = newAuthResponseSettings(deps.Cfg)

	return w
}

// Outcome returns a copy of the last captured outcome.
func (w *CaptureResponseWriter) Outcome() CapturedAuthOutcome {
	if w == nil {
		return CapturedAuthOutcome{Decision: CapturedAuthDecisionUnset}
	}

	out := w.outcome
	out.Attributes = cloneAttributeMapping(out.Attributes)
	out.ResponseHeaders = out.ResponseHeaders.Clone()
	out.ResponseHeaderDeletes = append([]string(nil), out.ResponseHeaderDeletes...)
	out.FSMEventPath = append([]string(nil), out.FSMEventPath...)
	out.Groups = append([]string(nil), out.Groups...)
	out.GroupDistinguishedNames = append([]string(nil), out.GroupDistinguishedNames...)

	return out
}

// OK applies success side effects and captures the success outcome.
func (w *CaptureResponseWriter) OK(ctx *gin.Context, view *StateView) {
	if w == nil || view == nil || view.auth == nil {
		return
	}

	auth := view.auth
	auth.applyAuthSuccessSideEffects(ctx)
	w.captureOutcome(ctx, auth, authFSMStateAuthOK, CapturedAuthDecisionOK, "", auth.Runtime.StatusCodeOK)
}

// Fail applies failure side effects and captures the failure outcome.
func (w *CaptureResponseWriter) Fail(ctx *gin.Context, view *StateView) {
	if w == nil || view == nil || view.auth == nil {
		return
	}

	auth := view.auth
	auth.applyAuthFailureSideEffects(ctx)
	w.captureOutcome(ctx, auth, authFSMStateAuthFail, CapturedAuthDecisionFail, "", auth.Runtime.StatusCodeFail)
}

// TempFail applies temporary-failure side effects and captures the temporary failure outcome.
func (w *CaptureResponseWriter) TempFail(ctx *gin.Context, view *StateView, reason string) {
	if w == nil || view == nil || view.auth == nil {
		return
	}

	auth := view.auth
	auth.prepareAuthTempFail(reason)

	if auth.shouldLogAuthTempFail() {
		auth.logAuthTempFail(ctx, w.logger)
	}

	w.captureOutcome(ctx, auth, authFSMStateAuthTempFail, CapturedAuthDecisionTempFail, reason, auth.Runtime.StatusCodeInternalError)
}

func (w *CaptureResponseWriter) captureOutcome(
	ctx *gin.Context,
	auth *AuthState,
	terminalState authFSMState,
	decision CapturedAuthDecision,
	reason string,
	status int,
) {
	if auth == nil {
		return
	}

	projected := authOutcomeFromState(
		ctx,
		auth,
		authDecisionFromCaptured(decision),
		string(terminalState),
		reason,
		status,
		w.responseSettings,
	)
	w.outcome = capturedAuthOutcomeFromAuthOutcome(projected, decision)
}

// capturedResponseHeaders detaches response mutations selected before terminal rendering.
func capturedResponseHeaders(ctx *gin.Context) http.Header {
	if ctx == nil || ctx.Writer == nil {
		return nil
	}

	return ctx.Writer.Header().Clone()
}

// listAccountsSuccessOutcome captures response mutations and metadata without a terminal writer decision.
func listAccountsSuccessOutcome(
	auth *AuthState,
	ginCtx *gin.Context,
	accounts AccountList,
) *ListAccountsOutcome {
	if auth == nil {
		return nil
	}

	return &ListAccountsOutcome{
		ResponseHeaders:       capturedResponseHeaders(ginCtx),
		ResponseHeaderDeletes: capturedResponseHeaderDeletes(ginCtx),
		FSMEventPath:          append([]string(nil), auth.Runtime.AuthFSMEventPath...),
		Accounts:              append(AccountList(nil), accounts...),
		ResponseSettings:      newAuthResponseSettings(auth.Cfg()),
		Decision:              AuthDecisionOK,
		Session:               auth.Runtime.GUID,
		Protocol:              auth.GetProtocol().Get(),
		HTTPStatus:            http.StatusOK,
		LoginAttempts:         auth.GetFailCount(),
		MemoryCacheHit:        ginCtx != nil && ginCtx.GetBool(definitions.CtxLocalCacheAuthKey),
	}
}

// authOutcomeFromState detaches the complete terminal projection from AuthState.
// authOutcomeFromState projects one terminal compatibility host state into a detached application outcome.
func authOutcomeFromState(
	ctx *gin.Context,
	auth *AuthState,
	decision AuthDecision,
	terminalState string,
	reason string,
	status int,
	settings AuthResponseSettings,
) *AuthOutcome {
	if auth == nil {
		return nil
	}

	return &AuthOutcome{
		Attributes:              auth.GetAttributesCopy(),
		ResponseHeaders:         capturedResponseHeaders(ctx),
		ResponseHeaderDeletes:   capturedResponseHeaderDeletes(ctx),
		FSMEventPath:            append([]string(nil), auth.Runtime.AuthFSMEventPath...),
		ResponseSettings:        settings,
		Decision:                decision,
		TerminalState:           terminalState,
		Session:                 auth.Runtime.GUID,
		Account:                 auth.GetAccount(),
		AccountField:            auth.Runtime.AccountField,
		DisplayName:             auth.GetDisplayName(),
		UniqueUserID:            auth.GetUniqueUserID(),
		TOTPSecretField:         auth.Runtime.TOTPSecretField,
		TOTPRecoveryField:       auth.Runtime.TOTPRecoveryField,
		UniqueUserIDField:       auth.Runtime.UniqueUserIDField,
		DisplayNameField:        auth.Runtime.DisplayNameField,
		BackendName:             auth.Runtime.BackendName,
		StatusMessage:           auth.Runtime.StatusMessage,
		StatusMessageI18NKey:    auth.Runtime.StatusMessageI18NKey,
		ResponseLanguage:        auth.Runtime.ResponseLanguage,
		Error:                   reason,
		Groups:                  auth.GetGroups(),
		GroupDistinguishedNames: auth.GetGroupDistinguishedNames(),
		Protocol:                auth.GetProtocol().Get(),
		UsedBackendIP:           auth.Runtime.UsedBackendIP,
		RemoteBackendRef:        auth.Runtime.RemoteBackendRef,
		Backend:                 auth.Runtime.SourcePassDBBackend,
		UsedBackendPort:         auth.Runtime.UsedBackendPort,
		HTTPStatus:              status,
		LoginAttempts:           auth.GetFailCount(),
		MemoryCacheHit:          ctx != nil && ctx.GetBool(definitions.CtxLocalCacheAuthKey),
		DelayedResponseEligible: authOutcomeDelayedResponseEligible(auth, decision),
	}
}

// authOutcomeDelayedResponseEligible preserves the host's ordinary IdP password-failure boundary.
func authOutcomeDelayedResponseEligible(auth *AuthState, decision AuthDecision) bool {
	return authOutcomeIsIDPPasswordFailure(auth, decision)
}

// authOutcomeIsIDPPasswordFailure enforces the request invariant shared by ordinary and policy-selected delay.
func authOutcomeIsIDPPasswordFailure(auth *AuthState, decision AuthDecision) bool {
	return auth != nil && decision == AuthDecisionFail &&
		auth.Request.Service == definitions.ServIDP &&
		auth.Request.Method == definitions.AuthMethodPassword &&
		!auth.Request.NoAuth && !auth.Request.ListAccounts
}

// capturedAuthOutcomeFromAuthOutcome preserves the capture-specific decision vocabulary.
func capturedAuthOutcomeFromAuthOutcome(
	outcome *AuthOutcome,
	decision CapturedAuthDecision,
) CapturedAuthOutcome {
	if outcome == nil {
		return CapturedAuthOutcome{Decision: CapturedAuthDecisionUnset}
	}

	return convertAuthOutcomeProjection(*outcome, decision)
}

// newAuthResponseSettings detaches config-derived renderer inputs from one runtime generation.
func newAuthResponseSettings(cfg config.File) AuthResponseSettings {
	settings := AuthResponseSettings{Captured: true}
	if cfg == nil || cfg.GetServer() == nil {
		return settings
	}

	server := cfg.GetServer()
	settings.SMTPBackendAddress = server.GetSMTPBackendAddress()
	settings.IMAPBackendAddress = server.GetIMAPBackendAddress()
	settings.POP3BackendAddress = server.GetPOP3BackendAddress()
	settings.DefaultLanguage = server.Frontend.GetDefaultLanguage()
	settings.InstanceName = server.GetInstanceName()
	settings.SMTPBackendPort = server.GetSMTPBackendPort()
	settings.IMAPBackendPort = server.GetIMAPBackendPort()
	settings.POP3BackendPort = server.GetPOP3BackendPort()
	settings.NginxWaitDelay = uint(server.GetNginxWaitDelay())
	settings.BackendHealthChecks = cfg.HasRuntimeModule(definitions.ServiceBackendHealthChecks)

	return settings
}

func cloneAttributeMapping(source bktype.AttributeMapping) bktype.AttributeMapping {
	if source == nil {
		return nil
	}

	target := make(bktype.AttributeMapping, len(source))
	for key, values := range source {
		if values == nil {
			target[key] = nil

			continue
		}

		clonedValues := make([]any, len(values))
		copy(clonedValues, values)
		target[key] = clonedValues
	}

	return target
}
