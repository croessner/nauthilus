// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"net/http"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
)

const (
	requestHeaderAuthorization      = "Authorization"
	requestHeaderCookie             = "Cookie"
	requestHeaderProxyAuthorization = "Proxy-Authorization"
	requestHeaderSetCookie          = "Set-Cookie"
)

var defaultSecretHeaderNames = []string{
	requestHeaderAuthorization,
	requestHeaderCookie,
	requestHeaderProxyAuthorization,
	requestHeaderSetCookie,
}

// SnapshotOption configures request snapshot construction.
type SnapshotOption func(*snapshotOptions)

type snapshotOptions struct {
	secretHeaders map[string]struct{}
}

// WithSnapshotSecretHeaders adds configured secret-bearing request headers to redact.
func WithSnapshotSecretHeaders(headers ...string) SnapshotOption {
	return func(options *snapshotOptions) {
		options.addSecretHeaders(headers...)
	}
}

// WithSnapshotConfig derives secret-bearing request headers from server configuration.
func WithSnapshotConfig(cfg config.File) SnapshotOption {
	return func(options *snapshotOptions) {
		options.addSecretHeaders(SecretBearingHeadersFromConfig(cfg)...)
	}
}

// SecretBearingHeadersFromConfig returns configured request headers that can carry passwords.
func SecretBearingHeadersFromConfig(cfg config.File) []string {
	if cfg == nil || cfg.GetServer() == nil {
		return nil
	}

	headers := cfg.GetServer().GetDefaultHTTPRequestHeader()

	return []string{
		headers.GetPassword(),
		headers.GetPasswordEncoded(),
	}
}

// NewRequestSnapshotFromAuthState copies safe request values out of AuthState for plugins.
func NewRequestSnapshotFromAuthState(auth *core.AuthState, options ...SnapshotOption) pluginapi.RequestSnapshot {
	opts := newSnapshotOptions(options...)

	if auth == nil {
		return pluginapi.RequestSnapshot{Headers: map[string][]string{}}
	}

	if cfg := auth.Cfg(); cfg != nil {
		opts.addSecretHeaders(SecretBearingHeadersFromConfig(cfg)...)
	}

	return pluginapi.RequestSnapshot{
		Headers:           redactedHeaders(headersFromAuthState(auth), opts.secretHeaders),
		Session:           auth.Runtime.GUID,
		ExternalSessionID: auth.Request.ExternalSessionID,
		HealthCheck:       auth.IsBackendHealthCheckRequest(),
		Service:           auth.Request.Service,
		Protocol:          protocolName(auth.Request.Protocol),
		Method:            auth.Request.Method,
		Username:          auth.Request.Username,
		Account:           auth.GetAccount(),
		AccountField:      auth.Runtime.AccountField,
		UniqueUserID:      auth.GetUniqueUserID(),
		DisplayName:       auth.GetDisplayName(),
		ClientIP:          auth.Request.ClientIP,
		ClientPort:        auth.Request.XClientPort,
		ClientNet:         auth.Runtime.BFClientNet,
		ClientHost:        auth.Request.ClientHost,
		ClientID:          auth.Request.XClientID,
		UserAgent:         auth.Request.UserAgent,
		LocalIP:           auth.Request.XLocalIP,
		LocalPort:         auth.Request.XPort,
		OIDCCID:           auth.Request.OIDCCID,
		SAMLEntityID:      auth.Request.SAMLEntityID,
		AuthLoginAttempt:  auth.Request.AuthLoginAttempt,
		IDP:               idPInfoFromAuthState(auth),
		TLS:               tlsInfoFromAuthState(auth),
		Diagnostics:       diagnosticsFromAuthState(auth),
		Runtime:           runtimeFlagsFromAuthState(auth),
	}
}

// newSnapshotOptions builds redaction options with mandatory defaults.
func newSnapshotOptions(options ...SnapshotOption) snapshotOptions {
	opts := snapshotOptions{secretHeaders: make(map[string]struct{}, len(defaultSecretHeaderNames))}
	opts.addSecretHeaders(defaultSecretHeaderNames...)

	for _, option := range options {
		if option != nil {
			option(&opts)
		}
	}

	return opts
}

// addSecretHeaders records canonicalized header names that must not reach plugins.
func (o *snapshotOptions) addSecretHeaders(headers ...string) {
	if o.secretHeaders == nil {
		o.secretHeaders = make(map[string]struct{}, len(headers))
	}

	for _, header := range headers {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(header))
		if canonical == "" {
			continue
		}

		o.secretHeaders[canonical] = struct{}{}
	}
}

// headersFromAuthState returns the best available incoming header source.
func headersFromAuthState(auth *core.AuthState) http.Header {
	if auth == nil {
		return nil
	}

	if auth.Request.HTTPClientRequest != nil {
		return auth.Request.HTTPClientRequest.Header
	}

	return http.Header(auth.Request.RequestMetadata)
}

// redactedHeaders returns canonical header copies without secret-bearing keys.
func redactedHeaders(headers http.Header, secretHeaders map[string]struct{}) map[string][]string {
	if len(headers) == 0 {
		return map[string][]string{}
	}

	output := make(map[string][]string, len(headers))
	for key, values := range headers {
		canonical := http.CanonicalHeaderKey(key)
		if _, secretHeader := secretHeaders[canonical]; secretHeader {
			continue
		}

		output[canonical] = append([]string(nil), values...)
	}

	return output
}

// protocolName returns the configured protocol name without exposing config internals.
func protocolName(protocol *config.Protocol) string {
	if protocol == nil {
		return ""
	}

	return protocol.Get()
}

// tlsInfoFromAuthState maps request TLS metadata to the public snapshot value.
func tlsInfoFromAuthState(auth *core.AuthState) pluginapi.TLSInfo {
	if auth == nil {
		return pluginapi.TLSInfo{}
	}

	verified := strings.EqualFold(auth.Request.XSSLClientVerify, "SUCCESS")

	return pluginapi.TLSInfo{
		Legacy: pluginapi.TLSLegacyInfo{
			State:            auth.Request.XSSL,
			SessionID:        auth.Request.XSSLSessionID,
			ClientVerify:     auth.Request.XSSLClientVerify,
			ClientDN:         auth.Request.XSSLClientDN,
			ClientCommonName: auth.Request.XSSLClientCN,
			Issuer:           auth.Request.XSSLIssuer,
			ClientNotBefore:  auth.Request.XSSLClientNotBefore,
			ClientNotAfter:   auth.Request.XSSLClientNotAfter,
			SubjectDN:        auth.Request.XSSLSubjectDN,
			IssuerDN:         auth.Request.XSSLIssuerDN,
			ClientSubjectDN:  auth.Request.XSSLClientSubjectDN,
			ClientIssuerDN:   auth.Request.XSSLClientIssuerDN,
			Protocol:         auth.Request.XSSLProtocol,
			CipherSuite:      auth.Request.XSSLCipher,
			Serial:           auth.Request.SSLSerial,
			Fingerprint:      auth.Request.SSLFingerprint,
		},
		ServerName:     auth.Request.XSSLSubjectDN,
		CipherSuite:    auth.Request.XSSLCipher,
		PeerCommonName: auth.Request.XSSLClientCN,
		PeerIssuer:     auth.Request.XSSLIssuer,
		Version:        auth.Request.XSSLProtocol,
		Enabled:        auth.Request.XSSL != "" || auth.Request.XSSLProtocol != "",
		Mutual:         verified,
		VerifiedChains: boolToCount(verified),
	}
}

// boolToCount maps a verified flag to a conservative chain count.
func boolToCount(ok bool) int {
	if ok {
		return 1
	}

	return 0
}

// runtimeFlagsFromAuthState maps core outcome flags into the public snapshot.
func runtimeFlagsFromAuthState(auth *core.AuthState) pluginapi.RuntimeFlags {
	if auth == nil {
		return pluginapi.RuntimeFlags{}
	}

	noAuth := auth.Request.NoAuth

	return pluginapi.RuntimeFlags{
		Debug:                    debugEnabled(auth),
		LocalRequest:             noAuth,
		NoAuth:                   noAuth,
		UserFound:                auth.Runtime.UserFound || auth.GetAccount() != "",
		Authenticated:            auth.Runtime.Authenticated,
		Authorized:               auth.Runtime.Authorized,
		Repeating:                auth.Runtime.BFRepeating,
		RWP:                      auth.Runtime.BFRWP,
		EnvironmentRejected:      environmentRejected(auth),
		EnvironmentStageExpected: stageExpected(auth, stageEnvironment),
		SubjectStageExpected:     stageExpected(auth, stageSubject),
	}
}

// diagnosticsFromAuthState copies bounded status and diagnostic values.
func diagnosticsFromAuthState(auth *core.AuthState) pluginapi.RequestDiagnostics {
	if auth == nil {
		return pluginapi.RequestDiagnostics{}
	}

	return pluginapi.RequestDiagnostics{
		StatusMessage:     snapshotStatusMessage(auth),
		BruteForceName:    auth.Security.BruteForceName,
		EnvironmentName:   auth.Runtime.EnvironmentName,
		LatencyMillis:     latencyMillis(auth.Runtime.StartTime),
		BruteForceCounter: bruteForceCounter(auth),
		HTTPStatus:        httpStatus(auth),
	}
}

// snapshotStatusMessage preserves selected policy text and fills terminal defaults for analytics rows.
func snapshotStatusMessage(auth *core.AuthState) string {
	if auth == nil {
		return ""
	}

	if message := strings.TrimSpace(auth.Runtime.StatusMessage); message != "" {
		return message
	}

	if auth.Runtime.Authenticated {
		return "OK"
	}

	if auth.Runtime.StatusCodeFail > 0 {
		return definitions.PasswordFail
	}

	return ""
}

// idPInfoFromAuthState reuses the core Lua IDP mapper when a config snapshot is available.
func idPInfoFromAuthState(auth *core.AuthState) pluginapi.IDPInfo {
	if auth == nil {
		return pluginapi.IDPInfo{}
	}

	info := pluginapi.IDPInfo{
		ClientID:   auth.Request.OIDCCID,
		UserGroups: cloneStrings(auth.GetGroups()),
	}

	if auth.Cfg() == nil {
		return info
	}

	request := lualib.GetCommonRequest()
	defer lualib.PutCommonRequest(request)

	auth.FillCommonRequest(request)

	info.RequestedScopes = cloneStrings(request.RequestedScopes)
	info.UserGroups = cloneStrings(request.UserGroups)
	info.AllowedClientScopes = cloneStrings(request.AllowedClientScopes)
	info.AllowedClientGrantTypes = cloneStrings(request.AllowedClientGrantTypes)
	info.GrantType = request.GrantType
	info.ClientID = request.OIDCCID
	info.ClientName = request.OIDCClientName
	info.RedirectURI = request.RedirectURI
	info.MFAMethod = request.MFAMethod
	info.MFACompleted = request.MFACompleted

	return info
}

// debugEnabled reports whether request diagnostics should include debug mode.
func debugEnabled(auth *core.AuthState) bool {
	if auth == nil || auth.Cfg() == nil || auth.Cfg().GetServer() == nil {
		return false
	}

	return auth.Cfg().GetServer().GetLog().GetLogLevel() == definitions.LogLevelDebug
}

// environmentRejected reports whether the request was rejected before subject analysis.
func environmentRejected(auth *core.AuthState) bool {
	if auth == nil || auth.Request.HTTPClientContext == nil {
		return false
	}

	return auth.Request.HTTPClientContext.GetBool(definitions.CtxEnvironmentRejectedKey)
}

type requestStage string

const (
	stageEnvironment requestStage = "environment"
	stageSubject     requestStage = "subject"
)

// stageExpected reports whether the configured request path includes a Lua stage.
func stageExpected(auth *core.AuthState, stage requestStage) bool {
	if auth == nil || auth.Cfg() == nil {
		return false
	}

	switch stage {
	case stageEnvironment:
		return auth.Cfg().HaveLuaEnvironmentSources()
	case stageSubject:
		return auth.Cfg().HaveLuaSubjectSources()
	default:
		return false
	}
}

// latencyMillis returns elapsed request time in milliseconds when the start time is known.
func latencyMillis(start time.Time) int64 {
	if start.IsZero() {
		return 0
	}

	elapsed := time.Since(start).Milliseconds()
	if elapsed < 0 {
		return 0
	}

	return elapsed
}

// bruteForceCounter returns the counter for the active brute-force bucket.
func bruteForceCounter(auth *core.AuthState) uint {
	if auth == nil || auth.Security.BruteForceName == "" {
		return 0
	}

	if val, ok := auth.Security.BruteForceCounter[auth.Security.BruteForceName]; ok {
		return val
	}

	parts := strings.Split(auth.Security.BruteForceName, ",")
	if len(parts) == 0 {
		return 0
	}

	return auth.Security.BruteForceCounter[parts[0]]
}

// httpStatus returns the host status code selected for the current outcome.
func httpStatus(auth *core.AuthState) int {
	if auth == nil {
		return 0
	}

	if auth.Runtime.Authenticated && auth.Runtime.StatusCodeOK > 0 {
		return auth.Runtime.StatusCodeOK
	}

	if !auth.Runtime.Authenticated && auth.Runtime.StatusCodeFail > 0 {
		return auth.Runtime.StatusCodeFail
	}

	return 0
}

// cloneStrings returns an immutable copy for public snapshot slices.
func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	return append([]string(nil), values...)
}
