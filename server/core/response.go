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
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/stats"

	"github.com/gin-gonic/gin"
	jsoniter "github.com/json-iterator/go"
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
	Cfg    config.File
	Env    config.Environment
	Logger *slog.Logger
}

// globalResponseWriter keeps legacy behavior without requiring config/env/logger to be loaded
// during package init.
//
// This type is used as the process default until the HTTP boundary overwrites it via
// `SetDefaultResponseWriter(...)` with a DI-configured writer.
type globalResponseWriter struct{}

type depResponseWriter struct {
	deps ResponseDeps
}

type writerHolder struct {
	w ResponseWriter
}

var defaultResponseWriter atomic.Value

func init() {
	// Backward-compatible default: do not touch config/env/logging globals during init.
	// Many tests compile/run without having loaded the config singleton.
	// atomic.Value must never store values of different concrete types.
	defaultResponseWriter.Store(writerHolder{w: ResponseWriter(globalResponseWriter{})})
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
	return globalResponseWriter{}
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
	return depResponseWriter{deps: deps}
}

func (globalResponseWriter) OK(ctx *gin.Context, view *StateView) {
	a := view.auth
	// On successful authentication, reset the internal fail counter to
	// ensure future logging reflects fresh attempts. Brute-force storage
	// remains authoritative for persistence.
	a.ResetLoginAttemptsOnSuccess()
	setCommonHeaders(ctx, a)

	switch a.Request.Service {
	case definitions.ServNginx:
		setNginxHeaders(ctx, a)
	case definitions.ServHeader:
		setHeaderHeaders(ctx, a)
	case definitions.ServJSON:
		sendAuthResponse(ctx, a)
	}

	handleLogging(ctx, a)

	// Only authentication attempts
	if !a.Request.NoAuth && !a.Request.ListAccounts {
		stats.GetMetrics().GetAcceptedProtocols().WithLabelValues(a.Request.Protocol.Get()).Inc()
		stats.GetMetrics().GetLoginsCounter().WithLabelValues(definitions.LabelSuccess).Inc()

		if !getDefaultConfigFile().HasFeature(definitions.FeatureBruteForce) {
			return
		}
	}
}

func (globalResponseWriter) Fail(ctx *gin.Context, view *StateView) {
	a := view.auth
	a.setFailureHeaders(ctx)
	a.loginAttemptProcessing(ctx)
}

func (globalResponseWriter) TempFail(ctx *gin.Context, view *StateView, reason string) {
	a := view.auth
	ctx.Header("Auth-Status", reason)
	ctx.Header("X-Nauthilus-Session", a.Runtime.GUID)
	a.setSMPTHeaders(ctx)

	a.Runtime.StatusMessage = reason

	if a.Request.Service == definitions.ServJSON {
		ctx.JSON(a.Runtime.StatusCodeInternalError, gin.H{"error": reason})

		return
	}

	ctx.String(a.Runtime.StatusCodeInternalError, a.Runtime.StatusMessage)

	keyvals := getLogSlice()

	defer putLogSlice(keyvals)

	keyvals = a.fillLogLineTemplate(keyvals, "tempfail", ctx.Request.URL.Path)
	keyvals = append(keyvals, definitions.LogKeyMsg, "Temporary server problem")

	level.Warn(getDefaultLogger()).WithContext(ctx).Log(keyvals...)
}

// AuthOK is the general method to indicate authentication success.
func (a *AuthState) AuthOK(ctx *gin.Context) {
	getDefaultResponseWriter().OK(ctx, a.View())
}

// AuthFail handles the failure of authentication.
// It increases the login attempts, then delegates header/logging to the ResponseWriter.
func (a *AuthState) AuthFail(ctx *gin.Context) {
	a.increaseLoginAttempts()
	getDefaultResponseWriter().Fail(ctx, a.View())
}

// AuthTempFail sends a temporary failure response with the provided reason and logs the error.
func (a *AuthState) AuthTempFail(ctx *gin.Context, reason string) {
	getDefaultResponseWriter().TempFail(ctx, a.View(), reason)
}

// OK implements the success response logic (unchanged behavior).
func (w depResponseWriter) OK(ctx *gin.Context, view *StateView) {
	a := view.auth
	// On successful authentication, reset the internal fail counter to
	// ensure future logging reflects fresh attempts. Brute-force storage
	// remains authoritative for persistence.
	a.ResetLoginAttemptsOnSuccess()
	setCommonHeaders(ctx, a)

	switch a.Request.Service {
	case definitions.ServNginx:
		setNginxHeadersWithDeps(w.deps.Cfg, w.deps.Logger, ctx, a)
	case definitions.ServHeader:
		setHeaderHeaders(ctx, a)
	case definitions.ServJSON:
		sendAuthResponse(ctx, a)
	}

	handleLogging(ctx, a)

	// Only authentication attempts
	if !a.Request.NoAuth && !a.Request.ListAccounts {
		stats.GetMetrics().GetAcceptedProtocols().WithLabelValues(a.Request.Protocol.Get()).Inc()
		stats.GetMetrics().GetLoginsCounter().WithLabelValues(definitions.LabelSuccess).Inc()

		if !w.deps.Cfg.HasFeature(definitions.FeatureBruteForce) {
			return
		}
	}
}

// Fail implements the failure response logic (unchanged behavior).
func (w depResponseWriter) Fail(ctx *gin.Context, view *StateView) {
	a := view.auth
	a.setFailureHeaders(ctx)
	a.loginAttemptProcessing(ctx)
}

// TempFail implements the temporary failure logic (unchanged behavior).
func (w depResponseWriter) TempFail(ctx *gin.Context, view *StateView, reason string) {
	a := view.auth
	ctx.Header("Auth-Status", reason)
	ctx.Header("X-Nauthilus-Session", a.Runtime.GUID)
	a.setSMPTHeaders(ctx)

	a.Runtime.StatusMessage = reason

	if a.Request.Service == definitions.ServJSON {
		ctx.JSON(a.Runtime.StatusCodeInternalError, gin.H{"error": reason})

		return
	}

	ctx.String(a.Runtime.StatusCodeInternalError, a.Runtime.StatusMessage)

	keyvals := getLogSlice()

	defer putLogSlice(keyvals)

	keyvals = a.fillLogLineTemplate(keyvals, "tempfail", ctx.Request.URL.Path)
	keyvals = append(keyvals, definitions.LogKeyMsg, "Temporary server problem")

	level.Warn(w.deps.Logger).WithContext(ctx).Log(keyvals...)
}

// sendAuthResponse sends a JSON response with the appropriate headers and content based on the AuthState.
// It now includes an explicit {"ok": true} field and emits only the fields required by clients and tests,
// in the exact order expected by the golden file.
func sendAuthResponse(ctx *gin.Context, auth *AuthState) {
	// Build a minimal response matching the golden expectations exactly.
	type response struct {
		OK           bool                    `json:"ok"`
		AccountField string                  `json:"account_field"`
		TOTPSecret   string                  `json:"totp_secret_field"`
		Backend      int                     `json:"backend"`
		Attributes   bktype.AttributeMapping `json:"attributes"`
	}

	resp := response{
		OK:           true,
		AccountField: auth.Runtime.AccountField,
		TOTPSecret:   auth.Runtime.TOTPSecretField,
		Backend:      int(auth.Runtime.SourcePassDBBackend),
		Attributes:   auth.Attributes.Attributes,
	}

	// Use stable JSON encoding to avoid parallel_mismatched in client tests
	// caused by non-deterministic map key ordering.
	b, err := jsoniter.ConfigCompatibleWithStandardLibrary.Marshal(resp)
	if err != nil {
		ctx.AbortWithStatus(http.StatusInternalServerError)

		return
	}

	ctx.Data(auth.Runtime.StatusCodeOK, "application/json; charset=utf-8", b)
}
