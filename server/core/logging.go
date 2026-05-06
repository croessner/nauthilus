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
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
)

var logSlicePool = sync.Pool{
	New: func() any {
		// Pre-allocate a slice with a reasonable capacity for the template fields plus extras.
		// LogLineTemplate uses ~30 pairs (60 elements).
		s := make([]any, 0, 128)

		return &s
	},
}

func getLogSlice() []any {
	p := logSlicePool.Get().(*[]any)

	return (*p)[:0]
}

func putLogSlice(s []any) {
	// Clear the slice to avoid keeping references to objects and allow GC.
	for i := range s {
		s[i] = nil
	}

	logSlicePool.Put(&s)
}

// handleLogging logs information about the authentication request if the verbosity level is greater than LogLevelWarn.
// It uses the log.Logger to log the information.
// The logged information includes the result of the a.LogLineTemplate() function, which returns either "ok" or an empty string depending on the value of a.NoAuth,
// and the path of the request URL obtained from ctx.Request.URL.Path.
func handleLogging(ctx *gin.Context, auth *AuthState) {
	keyvals := getLogSlice()

	defer putLogSlice(keyvals)

	status := func() string {
		if !auth.Request.NoAuth {
			return "ok"
		}

		return ""
	}()

	keyvals = auth.fillLogLineTemplate(keyvals, status, ctx.Request.URL.Path)
	keyvals = append(keyvals, definitions.LogKeyMsg, "Authentication request was successful")

	level.Notice(auth.Logger()).WithContext(ctx).Log(keyvals...)
}

// logProcessingRequest writes a prominent log line similar to the final one, but for the beginning of request processing.
// It logs all available request-related fields and explicitly sets msg="Processing request" while including the session GUID.
func logProcessingRequest(ctx *gin.Context, auth *AuthState) {
	if auth == nil || ctx == nil {
		return
	}

	keyvals := getLogSlice()

	defer putLogSlice(keyvals)

	keyvals = auth.fillLogLineProcessingTemplate(keyvals, ctx.Request.URL.Path)

	// Add a human-readable message field as requested
	keyvals = append(keyvals, definitions.LogKeyMsg, "Processing incoming request")

	level.Notice(auth.Logger()).WithContext(ctx).Log(keyvals...)
}

// LogLineTemplate constructs a key-value slice for logging authentication state and related metadata.
func (a *AuthState) LogLineTemplate(status string, endpoint string) []any {
	return a.fillLogLineTemplate(make([]any, 0, 64), status, endpoint)
}

func (a *AuthState) fillLogLineTemplate(keyvals []any, status string, endpoint string) []any {
	if a.Runtime.StatusMessage == "" {
		a.Runtime.StatusMessage = "OK"
	}

	mode := "auth"
	if a.Request.NoAuth {
		mode = "no-auth"
	}

	backendName := definitions.NotAvailable
	if a.Runtime.BackendName != "" {
		backendName = a.Runtime.BackendName
	}

	keyvals = append(keyvals,
		definitions.LogKeyGUID, util.WithNotAvailable(a.Runtime.GUID),
		definitions.LogKeyMode, mode,
		definitions.LogKeyBackendName, backendName,
		definitions.LogKeyProtocol, util.WithNotAvailable(a.Request.Protocol.String()),
		definitions.LogKeyOIDCCID, util.WithNotAvailable(a.Request.OIDCCID),
		definitions.LogKeySAMLEntityID, util.WithNotAvailable(a.Request.SAMLEntityID),
		definitions.LogKeyLocalIP, util.WithNotAvailable(a.Request.XLocalIP),
		definitions.LogKeyPort, util.WithNotAvailable(a.Request.XPort),
		definitions.LogKeyClientIP, util.WithNotAvailable(a.Request.ClientIP),
		definitions.LogKeyClientPort, util.WithNotAvailable(a.Request.XClientPort),
		definitions.LogKeyClientHost, util.WithNotAvailable(a.Request.ClientHost),
		definitions.LogKeyTLSSecure, util.WithNotAvailable(a.Request.XSSLProtocol),
		definitions.LogKeyTLSCipher, util.WithNotAvailable(a.Request.XSSLCipher),
		definitions.LogKeyAuthMethod, util.WithNotAvailable(a.Request.Method),
		definitions.LogKeyUsername, util.WithNotAvailable(a.Request.Username),
		definitions.LogKeyUsedPassdbBackend, util.WithNotAvailable(a.Runtime.UsedPassDBBackend.String()),
		// current_password_retries should mean: number of failed attempts (FailCount semantics)
		definitions.LogKeyLoginAttempts, a.GetFailCount(),
		definitions.LogKeyPasswordsAccountSeen, a.Security.PasswordsAccountSeen,
		definitions.LogKeyPasswordsTotalSeen, a.Security.PasswordsTotalSeen,
		definitions.LogKeyUserAgent, util.WithNotAvailable(a.Request.UserAgent),
		definitions.LogKeyClientID, util.WithNotAvailable(a.Request.XClientID),
		definitions.LogKeyBruteForceName, util.WithNotAvailable(a.Security.BruteForceName),
		definitions.LogKeyEnvironmentName, util.WithNotAvailable(a.Runtime.EnvironmentName),
		definitions.LogKeyStatusMessage, util.WithNotAvailable(a.Runtime.StatusMessage),
		definitions.LogKeyBFRWP, a.Runtime.BFRWP,
		definitions.LogKeyUriPath, endpoint,
		definitions.LogKeyStatus, util.WithNotAvailable(status),
		definitions.LogKeyAuthorized, a.Runtime.Authorized,
		definitions.LogKeyAuthenticatedBool, a.Runtime.Authenticated,
		definitions.LogKeyLatency, util.FormatDurationMs(time.Since(a.Runtime.StartTime)),
	)

	keyvals = appendExternalSessionLogValue(keyvals, a.Request.ExternalSessionID)
	keyvals = appendStructuredTLSLogValues(keyvals, a)
	keyvals = appendAuthLoginAttemptLogValue(keyvals, a.Request.AuthLoginAttempt)
	keyvals = appendHealthCheckLogValue(keyvals, a.IsBackendHealthCheckRequest())

	if len(a.Runtime.AdditionalLogs) > 0 && len(a.Runtime.AdditionalLogs)%2 == 0 {
		keyvals = append(keyvals, a.Runtime.AdditionalLogs...)
	}

	return keyvals
}

// LogLineProcessingTemplate generates and returns a list of key-value pairs for logging session-related details.
func (a *AuthState) LogLineProcessingTemplate(endpoint string) []any {
	return a.fillLogLineProcessingTemplate(make([]any, 0, 32), endpoint)
}

func (a *AuthState) fillLogLineProcessingTemplate(keyvals []any, endpoint string) []any {
	mode := "auth"
	if a.Request.NoAuth {
		mode = "no-auth"
	}

	keyvals = append(keyvals,
		definitions.LogKeyGUID, util.WithNotAvailable(a.Runtime.GUID),
		definitions.LogKeyMode, mode,
		definitions.LogKeyProtocol, util.WithNotAvailable(a.Request.Protocol.String()),
		definitions.LogKeyOIDCCID, util.WithNotAvailable(a.Request.OIDCCID),
		definitions.LogKeySAMLEntityID, util.WithNotAvailable(a.Request.SAMLEntityID),
		definitions.LogKeyLocalIP, util.WithNotAvailable(a.Request.XLocalIP),
		definitions.LogKeyPort, util.WithNotAvailable(a.Request.XPort),
		definitions.LogKeyClientIP, util.WithNotAvailable(a.Request.ClientIP),
		definitions.LogKeyClientPort, util.WithNotAvailable(a.Request.XClientPort),
		definitions.LogKeyClientHost, util.WithNotAvailable(a.Request.ClientHost),
		definitions.LogKeyTLSSecure, util.WithNotAvailable(a.Request.XSSLProtocol),
		definitions.LogKeyTLSCipher, util.WithNotAvailable(a.Request.XSSLCipher),
		definitions.LogKeyAuthMethod, util.WithNotAvailable(a.Request.Method),
		definitions.LogKeyUsername, util.WithNotAvailable(a.Request.Username),
		definitions.LogKeyUserAgent, util.WithNotAvailable(a.Request.UserAgent),
		definitions.LogKeyClientID, util.WithNotAvailable(a.Request.XClientID),
		definitions.LogKeyUriPath, endpoint,
	)

	keyvals = appendExternalSessionLogValue(keyvals, a.Request.ExternalSessionID)
	keyvals = appendStructuredTLSLogValues(keyvals, a)
	keyvals = appendAuthLoginAttemptLogValue(keyvals, a.Request.AuthLoginAttempt)
	keyvals = appendHealthCheckLogValue(keyvals, a.IsBackendHealthCheckRequest())

	return keyvals
}

func appendExternalSessionLogValue(keyvals []any, externalSessionID string) []any {
	if externalSessionID == "" {
		return keyvals
	}

	return append(keyvals, definitions.LogKeyExternalSession, externalSessionID)
}

func appendStructuredTLSLogValues(keyvals []any, auth *AuthState) []any {
	if auth == nil {
		return keyvals
	}

	request := auth.Request
	fields := []struct {
		key   string
		value string
	}{
		{definitions.LogKeySSL, request.XSSL},
		{definitions.LogKeySSLSessionID, request.XSSLSessionID},
		{definitions.LogKeySSLClientVerify, request.XSSLClientVerify},
		{definitions.LogKeySSLClientDN, request.XSSLClientDN},
		{definitions.LogKeySSLClientCN, request.XSSLClientCN},
		{definitions.LogKeySSLIssuer, request.XSSLIssuer},
		{definitions.LogKeySSLClientNotBefore, request.XSSLClientNotBefore},
		{definitions.LogKeySSLClientNotAfter, request.XSSLClientNotAfter},
		{definitions.LogKeySSLSubjectDN, request.XSSLSubjectDN},
		{definitions.LogKeySSLIssuerDN, request.XSSLIssuerDN},
		{definitions.LogKeySSLClientSubjectDN, request.XSSLClientSubjectDN},
		{definitions.LogKeySSLClientIssuerDN, request.XSSLClientIssuerDN},
		{definitions.LogKeySSLSerial, request.SSLSerial},
		{definitions.LogKeySSLFingerprint, request.SSLFingerprint},
	}

	for _, field := range fields {
		keyvals = append(keyvals, field.key, util.WithNotAvailable(field.value))
	}

	return keyvals
}

func appendAuthLoginAttemptLogValue(keyvals []any, attempt uint) []any {
	if attempt == 0 {
		return keyvals
	}

	return append(keyvals, definitions.LogKeyAuthLoginAttempt, attempt)
}

func appendHealthCheckLogValue(keyvals []any, healthCheck bool) []any {
	if !healthCheck {
		return keyvals
	}

	return append(keyvals, definitions.LogKeyHealthCheck, true)
}
