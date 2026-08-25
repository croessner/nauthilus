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
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/encoding/cborcodec"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/stats"

	"github.com/gin-gonic/gin"
)

// StateView is a read-only snapshot wrapper around AuthState used by response and header layers.
// It keeps a private pointer to AuthState to avoid behavior changes.
type StateView struct {
	auth *AuthState
}

// Auth exposes the underlying AuthState for implementations in subpackages.
// It keeps write access internal to core by returning the pointer; callers must treat it as read-only.
func (v *StateView) Auth() *AuthState {
	return v.auth
}

// View creates a read-only view for the current auth state.
func (a *AuthState) View() *StateView {
	return &StateView{auth: a}
}

// ResponseWriter defines how to write authentication responses.
// It abstracts OK/Fail/TempFail without changing external API.
type ResponseWriter interface {
	// OK sends a success response to the client by setting appropriate headers and processing authentication logic.
	OK(ctx *gin.Context, view *StateView)

	// Fail sends a failure response to the client by setting appropriate headers and processing login attempt logic.
	Fail(ctx *gin.Context, view *StateView)

	// TempFail sends a temporary failure response with the specified reason and logs the error for debugging purposes.
	TempFail(ctx *gin.Context, view *StateView, reason string)
}

// ResponseDeps provides the dependencies required to write responses without using globals.
// Migrates request paths to use these injected dependencies.
type ResponseDeps struct {
	Cfg      config.File
	Env      config.Environment
	Logger   *slog.Logger
	Resolver localization.MessageResolver
}

// stateResponseWriter renders AuthState outcomes through the shared HTTP projector.
// A nil dependency pointer keeps package initialization free of config access.
type stateResponseWriter struct {
	deps *ResponseDeps
}

const responseBodyFieldError = "error"

type authResponse struct {
	OK           bool                    `json:"ok"`
	AccountField string                  `json:"account_field"`
	TOTPSecret   string                  `json:"totp_secret_field"`
	Backend      int                     `json:"backend"`
	Attributes   bktype.AttributeMapping `json:"attributes"`
}

type writerHolder struct {
	w ResponseWriter
}

var defaultResponseWriter atomic.Value

func init() {
	// Backward-compatible default: do not touch config/env/logging globals during init.
	// Many tests compile/run without having loaded the config singleton.
	// atomic.Value must never store values of different concrete types.
	defaultResponseWriter.Store(writerHolder{w: ResponseWriter(stateResponseWriter{})})
}

func getDefaultResponseWriter() ResponseWriter {
	if v := defaultResponseWriter.Load(); v != nil {
		if h, ok := v.(writerHolder); ok {
			if h.w != nil {
				return h.w
			}
		}
	}

	// Should not happen, but keep behavior safe.
	return stateResponseWriter{}
}

// SetDefaultResponseWriter configures the process-wide response writer.
// This is set at the HTTP boundary during startup so that request paths
// do not need to access global config/logger/environment.
func SetDefaultResponseWriter(w ResponseWriter) {
	if w == nil {
		return
	}

	defaultResponseWriter.Store(writerHolder{w: w})
}

// NewDefaultResponseWriter constructs the default response writer with injected dependencies.
func NewDefaultResponseWriter(deps ResponseDeps) ResponseWriter {
	return stateResponseWriter{deps: &deps}
}

func (a *AuthState) responseWriter() ResponseWriter {
	if a != nil && a.deps.Resp != nil {
		return a.deps.Resp
	}

	return getDefaultResponseWriter()
}

func (a *AuthState) applyAuthSuccessSideEffects(ctx *gin.Context) {
	a.ResetLoginAttemptsOnSuccess()
	a.finishAuthSuccessSideEffects(ctx)
}

func (a *AuthState) finishAuthSuccessSideEffects(ctx *gin.Context) {
	handleLogging(ctx, a)

	// Only authentication attempts
	if !a.Request.NoAuth && !a.Request.ListAccounts {
		stats.GetMetrics().GetAcceptedProtocols().WithLabelValues(a.Request.Protocol.Get()).Inc()
		stats.GetMetrics().GetLoginsCounter().WithLabelValues(definitions.LabelSuccess).Inc()
	}
}

func (a *AuthState) prepareAuthFailure() {
	if a.Runtime.StatusMessage == "" {
		a.Runtime.StatusMessage = definitions.PasswordFail
	}
}

func (a *AuthState) applyAuthFailureSideEffects(ctx *gin.Context) {
	a.prepareAuthFailure()
	a.loginAttemptProcessing(ctx)
}

func (a *AuthState) prepareAuthTempFail(reason string) {
	a.Runtime.StatusMessage = reason
}

func (a *AuthState) shouldLogAuthTempFail() bool {
	return a.Request.Service != definitions.ServJSON && a.Request.Service != definitions.ServCBOR
}

func (a *AuthState) logAuthTempFail(ctx *gin.Context, logger *slog.Logger) {
	keyvals := getLogSlice()

	defer putLogSlice(keyvals)

	keyvals = a.fillLogLineTemplate(keyvals, "tempfail", ctx.Request.URL.Path)
	keyvals = append(keyvals, definitions.LogKeyMsg, "Temporary server problem")

	_ = level.Warn(logger).WithContext(ctx).Log(keyvals...)
}

// OK renders success before applying the established logging and metric side effects.
func (w stateResponseWriter) OK(ctx *gin.Context, view *StateView) {
	a := view.auth
	deps := w.effectiveDeps(a)

	// On successful authentication, reset the internal fail counter to
	// ensure future logging reflects fresh attempts. Brute-force storage
	// remains authoritative for persistence.
	a.ResetLoginAttemptsOnSuccess()
	w.render(ctx, a, deps, AuthDecisionOK, "", a.Runtime.StatusCodeOK)

	a.finishAuthSuccessSideEffects(ctx)
}

// Fail renders denial before applying the established failure logging and metrics.
func (w stateResponseWriter) Fail(ctx *gin.Context, view *StateView) {
	a := view.auth
	deps := w.effectiveDeps(a)

	a.prepareAuthFailure()
	w.render(ctx, a, deps, AuthDecisionFail, "", a.Runtime.StatusCodeFail)
	a.loginAttemptProcessing(ctx)
}

// TempFail renders temporary failure before preserving legacy service-specific logging.
func (w stateResponseWriter) TempFail(ctx *gin.Context, view *StateView, reason string) {
	a := view.auth
	deps := w.effectiveDeps(a)

	a.prepareAuthTempFail(reason)
	w.render(ctx, a, deps, AuthDecisionTempFail, reason, a.Runtime.StatusCodeInternalError)

	if a.Request.Service != definitions.ServJSON && a.Request.Service != definitions.ServCBOR {
		a.logAuthTempFail(ctx, deps.Logger)
	}
}

// AuthOK is the general method to indicate authentication success.
func (a *AuthState) AuthOK(ctx *gin.Context) {
	a.responseWriter().OK(ctx, a.View())
	a.markAuthenticationMetric(ctx, AuthDecisionOK)
	a.observeConfiguredPolicyDecision(ctx)
}

// AuthFail handles the failure of authentication.
// It increases the login attempts, then delegates header/logging to the ResponseWriter.
func (a *AuthState) AuthFail(ctx *gin.Context) {
	a.increaseLoginAttempts()
	a.responseWriter().Fail(ctx, a.View())
	a.markAuthenticationMetric(ctx, AuthDecisionFail)
	a.observeConfiguredPolicyDecision(ctx)
}

// AuthTempFail sends a temporary failure response with the provided reason and logs the error.
func (a *AuthState) AuthTempFail(ctx *gin.Context, reason string) {
	a.responseWriter().TempFail(ctx, a.View(), reason)
	a.markAuthenticationMetric(ctx, AuthDecisionTempFail)
	a.observeConfiguredPolicyDecision(ctx)
}

// markAuthenticationMetric stores bounded terminal metadata for the outer transport observer.
func (a *AuthState) markAuthenticationMetric(ctx *gin.Context, outcome AuthDecision) {
	if a == nil || ctx == nil {
		return
	}

	ctx.Set(definitions.CtxAuthOutcomeKey, string(outcome))
	ctx.Set(definitions.CtxAuthProtocolKey, a.GetProtocol().Get())
}

// effectiveDeps selects immutable request config while preserving injected response services.
func (w stateResponseWriter) effectiveDeps(auth *AuthState) ResponseDeps {
	deps := ResponseDeps{}
	if w.deps != nil {
		deps = *w.deps
	}

	if auth != nil && auth.Cfg() != nil {
		deps.Cfg = auth.Cfg()
	}

	if deps.Logger == nil {
		deps.Logger = getDefaultLogger()
	}

	return deps
}

// render projects one AuthState terminal response through the shared renderer.
func (w stateResponseWriter) render(
	ctx *gin.Context,
	auth *AuthState,
	deps ResponseDeps,
	decision AuthDecision,
	reason string,
	status int,
) {
	if auth == nil {
		return
	}

	outcome := authOutcomeFromState(
		ctx,
		auth,
		decision,
		authTerminalState(decision),
		reason,
		status,
		newAuthResponseSettings(deps.Cfg),
	)
	input := AuthInput{
		Context: AuthContext{Protocol: auth.GetProtocol().Get()},
		Mode:    authModeFromState(auth),
		Service: auth.Request.Service,
	}

	NewHTTPAuthResponseRenderer(deps).RenderAuth(ctx, input, outcome)
}

// authModeFromState returns the transport-neutral operation represented by AuthState.
func authModeFromState(auth *AuthState) AuthMode {
	if auth == nil {
		return AuthModeAuthenticate
	}

	if auth.Request.ListAccounts {
		return AuthModeListAccounts
	}

	if auth.Request.NoAuth {
		return AuthModeLookupIdentity
	}

	return AuthModeAuthenticate
}

// authTerminalState maps a public terminal decision onto the established FSM state.
func authTerminalState(decision AuthDecision) string {
	switch decision {
	case AuthDecisionOK:
		return string(authFSMStateAuthOK)
	case AuthDecisionFail:
		return string(authFSMStateAuthFail)
	case AuthDecisionTempFail:
		return string(authFSMStateAuthTempFail)
	default:
		return ""
	}
}

func statusMessageContext(ctx *gin.Context) context.Context {
	if ctx == nil || ctx.Request == nil || ctx.Request.Context() == nil {
		return context.Background()
	}

	return ctx.Request.Context()
}

func acceptLanguageHeader(ctx *gin.Context) string {
	if ctx == nil {
		return ""
	}

	return ctx.GetHeader("Accept-Language")
}

func sendCBOR(ctx *gin.Context, status int, body any) {
	payload, err := cborcodec.Marshal(body)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	ctx.Data(status, "application/cbor", payload)
}
