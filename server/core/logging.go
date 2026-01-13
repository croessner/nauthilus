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
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
)

// handleLogging logs information about the authentication request if the verbosity level is greater than LogLevelWarn.
// It uses the log.Logger to log the information.
// The logged information includes the result of the a.LogLineTemplate() function, which returns either "ok" or an empty string depending on the value of a.NoAuth,
// and the path of the request URL obtained from ctx.Request.URL.Path.
func handleLogging(ctx *gin.Context, auth *AuthState) {
	keyvals := auth.LogLineTemplate(func() string {
		if !auth.NoAuth {
			return "ok"
		}

		return ""
	}(), ctx.Request.URL.Path)
	keyvals = append(keyvals, definitions.LogKeyMsg, "Authentication request was successful")

	level.Notice(auth.Logger()).Log(keyvals...)
}

// logProcessingRequest writes a prominent log line similar to the final one, but for the beginning of request processing.
// It logs all available request-related fields and explicitly sets msg="Processing request" while including the session GUID.
func logProcessingRequest(ctx *gin.Context, auth *AuthState) {
	if auth == nil || ctx == nil {
		return
	}

	keyvals := auth.LogLineProcessingTemplate(ctx.Request.URL.Path)

	// Add a human-readable message field as requested
	keyvals = append(keyvals, definitions.LogKeyMsg, "Processing incoming request")

	level.Notice(auth.Logger()).Log(keyvals...)
}

// LogLineTemplate constructs a key-value slice for logging authentication state and related metadata.
func (a *AuthState) LogLineTemplate(status string, endpoint string) []any {
	var keyvals []any

	if a.StatusMessage == "" {
		a.StatusMessage = "OK"
	}

	mode := "auth"
	if a.NoAuth {
		mode = "no-auth"
	}

	backendName := definitions.NotAvailable
	if a.BackendName != "" {
		backendName = a.BackendName
	}

	keyvals = []any{
		definitions.LogKeyGUID, util.WithNotAvailable(a.GUID),
		definitions.LogKeyMode, mode,
		definitions.LogKeyBackendName, backendName,
		definitions.LogKeyProtocol, util.WithNotAvailable(a.Protocol.String()),
		definitions.LogKeyOIDCCID, util.WithNotAvailable(a.OIDCCID),
		definitions.LogKeyLocalIP, util.WithNotAvailable(a.XLocalIP),
		definitions.LogKeyPort, util.WithNotAvailable(a.XPort),
		definitions.LogKeyClientIP, util.WithNotAvailable(a.ClientIP),
		definitions.LogKeyClientPort, util.WithNotAvailable(a.XClientPort),
		definitions.LogKeyClientHost, util.WithNotAvailable(a.ClientHost),
		definitions.LogKeyTLSSecure, util.WithNotAvailable(a.XSSLProtocol),
		definitions.LogKeyTLSCipher, util.WithNotAvailable(a.XSSLCipher),
		definitions.LogKeyAuthMethod, util.WithNotAvailable(a.Method),
		definitions.LogKeyUsername, util.WithNotAvailable(a.Username),
		definitions.LogKeyUsedPassdbBackend, util.WithNotAvailable(a.UsedPassDBBackend.String()),
		// current_password_retries should mean: number of failed attempts (FailCount semantics)
		definitions.LogKeyLoginAttempts, a.GetFailCount(),
		definitions.LogKeyPasswordsAccountSeen, a.PasswordsAccountSeen,
		definitions.LogKeyPasswordsTotalSeen, a.PasswordsTotalSeen,
		definitions.LogKeyUserAgent, util.WithNotAvailable(a.UserAgent),
		definitions.LogKeyClientID, util.WithNotAvailable(a.XClientID),
		definitions.LogKeyBruteForceName, util.WithNotAvailable(a.BruteForceName),
		definitions.LogKeyFeatureName, util.WithNotAvailable(a.FeatureName),
		definitions.LogKeyStatusMessage, util.WithNotAvailable(a.StatusMessage),
		definitions.LogKeyUriPath, endpoint,
		definitions.LogKeyStatus, util.WithNotAvailable(status),
		definitions.LogKeyAuthorized, a.Authorized,
		definitions.LogKeyAuthenticatedBool, a.Authenticated,
		definitions.LogKeyLatency, util.FormatDurationMs(time.Since(a.StartTime)),
	}

	if len(a.AdditionalLogs) > 0 && len(a.AdditionalLogs)%2 == 0 {
		// Pre-allocate the keyvals slice to avoid continuous reallocation
		keyvalsLen := len(keyvals)
		newKeyvals := make([]any, keyvalsLen+len(a.AdditionalLogs))
		copy(newKeyvals, keyvals)
		keyvals = newKeyvals[:keyvalsLen]

		for index := range a.AdditionalLogs {
			keyvals = append(keyvals, a.AdditionalLogs[index])
		}
	}

	return keyvals
}

// LogLineProcessingTemplate generates and returns a list of key-value pairs for logging session-related details.
func (a *AuthState) LogLineProcessingTemplate(endpoint string) []any {
	var keyvals []any

	mode := "auth"
	if a.NoAuth {
		mode = "no-auth"
	}

	keyvals = []any{
		definitions.LogKeyGUID, util.WithNotAvailable(a.GUID),
		definitions.LogKeyMode, mode,
		definitions.LogKeyProtocol, util.WithNotAvailable(a.Protocol.String()),
		definitions.LogKeyOIDCCID, util.WithNotAvailable(a.OIDCCID),
		definitions.LogKeyLocalIP, util.WithNotAvailable(a.XLocalIP),
		definitions.LogKeyPort, util.WithNotAvailable(a.XPort),
		definitions.LogKeyClientIP, util.WithNotAvailable(a.ClientIP),
		definitions.LogKeyClientPort, util.WithNotAvailable(a.XClientPort),
		definitions.LogKeyClientHost, util.WithNotAvailable(a.ClientHost),
		definitions.LogKeyTLSSecure, util.WithNotAvailable(a.XSSLProtocol),
		definitions.LogKeyTLSCipher, util.WithNotAvailable(a.XSSLCipher),
		definitions.LogKeyAuthMethod, util.WithNotAvailable(a.Method),
		definitions.LogKeyUsername, util.WithNotAvailable(a.Username),
		definitions.LogKeyUserAgent, util.WithNotAvailable(a.UserAgent),
		definitions.LogKeyClientID, util.WithNotAvailable(a.XClientID),
		definitions.LogKeyUriPath, endpoint,
	}

	return keyvals
}
