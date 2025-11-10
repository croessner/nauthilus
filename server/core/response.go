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
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/stats"

	"github.com/gin-gonic/gin"
)

// StateView is a read-only snapshot wrapper around AuthState used by response and header layers.
// It keeps a private pointer to AuthState to avoid behavior changes.
// Future phases may replace direct AuthState access with copied fields.
type StateView struct {
	auth *AuthState
}

// View creates a read-only view for the current auth state.
func (a *AuthState) View() *StateView { return &StateView{auth: a} }

// ResponseWriter defines how to write authentication responses.
// It abstracts OK/Fail/TempFail without changing external API.
type ResponseWriter interface {
	OK(ctx *gin.Context, view *StateView)
	Fail(ctx *gin.Context, view *StateView)
	TempFail(ctx *gin.Context, view *StateView, reason string)
}

// DefaultResponseWriter implements ResponseWriter with current behavior.
type DefaultResponseWriter struct{}

var defaultResponseWriter ResponseWriter = DefaultResponseWriter{}

// AuthOK is the general method to indicate authentication success.
func (a *AuthState) AuthOK(ctx *gin.Context) {
	defaultResponseWriter.OK(ctx, a.View())
}

// AuthFail handles the failure of authentication.
// It increases the login attempts, then delegates header/logging to the ResponseWriter.
func (a *AuthState) AuthFail(ctx *gin.Context) {
	a.increaseLoginAttempts()
	defaultResponseWriter.Fail(ctx, a.View())
}

// AuthTempFail sends a temporary failure response with the provided reason and logs the error.
func (a *AuthState) AuthTempFail(ctx *gin.Context, reason string) {
	defaultResponseWriter.TempFail(ctx, a.View(), reason)
}

// OK implements the success response logic (unchanged behavior).
func (DefaultResponseWriter) OK(ctx *gin.Context, view *StateView) {
	a := view.auth
	setCommonHeaders(ctx, a)

	switch a.Service {
	case definitions.ServNginx:
		setNginxHeaders(ctx, a)
	case definitions.ServHeader:
		setHeaderHeaders(ctx, a)
	case definitions.ServJSON:
		sendAuthResponse(ctx, a)
	}

	handleLogging(ctx, a)

	// Only authentication attempts
	if !(a.NoAuth || a.ListAccounts) {
		stats.GetMetrics().GetAcceptedProtocols().WithLabelValues(a.Protocol.Get()).Inc()
		stats.GetMetrics().GetLoginsCounter().WithLabelValues(definitions.LabelSuccess).Inc()

		if !config.GetFile().HasFeature(definitions.FeatureBruteForce) {
			return
		}
	}
}

// Fail implements the failure response logic (unchanged behavior).
func (DefaultResponseWriter) Fail(ctx *gin.Context, view *StateView) {
	a := view.auth
	a.setFailureHeaders(ctx)
	a.loginAttemptProcessing(ctx)
}

// TempFail implements the temporary failure logic (unchanged behavior).
func (DefaultResponseWriter) TempFail(ctx *gin.Context, view *StateView, reason string) {
	a := view.auth
	ctx.Header("Auth-Status", reason)
	ctx.Header("X-Nauthilus-Session", a.GUID)
	a.setSMPTHeaders(ctx)

	a.StatusMessage = reason

	if a.Service == definitions.ServJSON {
		ctx.JSON(a.StatusCodeInternalError, gin.H{"error": reason})
		return
	}

	ctx.String(a.StatusCodeInternalError, a.StatusMessage)

	keyvals := a.LogLineTemplate("tempfail", ctx.Request.URL.Path)
	keyvals = append(keyvals, definitions.LogKeyMsg, "Temporary server problem")

	level.Info(log.Logger).Log(keyvals...)
}

// sendAuthResponse sends a JSON response with the appropriate headers and content based on the AuthState.
// It now includes an explicit {"ok": true} field for clients that validate via a boolean flag.
func sendAuthResponse(ctx *gin.Context, auth *AuthState) {
	ppc := bktype.PositivePasswordCache{
		AccountField:    auth.AccountField,
		TOTPSecretField: auth.TOTPSecretField,
		Backend:         auth.SourcePassDBBackend,
		Attributes:      auth.Attributes,
	}

	// Wrap the original positive cache struct and add an explicit ok flag.
	resp := struct {
		OK bool `json:"ok"`
		bktype.PositivePasswordCache
	}{
		OK:                    true,
		PositivePasswordCache: ppc,
	}

	ctx.JSON(auth.StatusCodeOK, resp)
}
