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

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
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
		ClientIP:          auth.Request.ClientIP,
		ClientPort:        auth.Request.XClientPort,
		ClientHost:        auth.Request.ClientHost,
		UserAgent:         auth.Request.UserAgent,
		OIDCCID:           auth.Request.OIDCCID,
		SAMLEntityID:      auth.Request.SAMLEntityID,
		TLS:               tlsInfoFromAuthState(auth),
		Runtime: pluginapi.RuntimeFlags{
			LocalRequest:  auth.Request.NoAuth,
			Authenticated: auth.Runtime.Authenticated,
		},
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
