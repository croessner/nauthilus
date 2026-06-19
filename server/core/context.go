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
	"strings"

	"github.com/croessner/nauthilus/v3/server/secret"
)

// Credentials captures user-supplied credentials (username/password, optional MFA).
// It is intended to be immutable via options; apply them to AuthState via ApplyCredentials.
//
// Note: We intentionally keep MFA fields optional and currently unused to avoid
// behavior changes in existing flows. They are placeholders for future phases.
type Credentials struct {
	Username     string
	Password     secret.Value
	TOTP         string
	TOTPRecovery string
}

// CredentialOption mutates a Credentials value during construction.
type CredentialOption func(*Credentials)

// NewCredentials constructs a Credentials value using the provided options.
func NewCredentials(opts ...CredentialOption) Credentials {
	var c Credentials
	for _, o := range opts {
		o(&c)
	}

	return c
}

// WithUsername sets the username field.
func WithUsername(u string) CredentialOption { return func(c *Credentials) { c.Username = u } }

// WithPassword sets the password field.
func WithPassword(p secret.Value) CredentialOption { return func(c *Credentials) { c.Password = p } }

// AuthContext contains request/connection metadata that influences authentication.
// It is applied to AuthState via ApplyContextData.
//
// Only non-empty fields are applied to avoid altering existing precedence.
type AuthContext struct {
	RequestMetadata map[string][]string

	Method    string
	UserAgent string

	ClientIP          string
	ClientPort        string
	ClientHostname    string
	ClientID          string
	ExternalSessionID string

	LocalIP   string
	LocalPort string

	Protocol string

	XSSL                string
	XSSLSessionID       string
	XSSLClientVerify    string
	XSSLClientDN        string
	XSSLClientCN        string
	XSSLIssuer          string
	XSSLClientNotBefore string
	XSSLClientNotAfter  string
	XSSLSubjectDN       string
	XSSLIssuerDN        string
	XSSLClientSubjectDN string
	XSSLClientIssuerDN  string
	XSSLProtocol        string
	XSSLCipher          string

	SSLSerial      string
	SSLFingerprint string

	OIDCCID string
}

// AuthContextOption mutates an AuthContext during construction.
type AuthContextOption func(*AuthContext)

// NewAuthContext constructs an AuthContext value using the provided options.
func NewAuthContext(opts ...AuthContextOption) AuthContext {
	var c AuthContext

	for _, o := range opts {
		o(&c)
	}

	return c
}

// WithMethod provides the exported WithMethod function.
func WithMethod(m string) AuthContextOption {
	return func(c *AuthContext) { c.Method = m }
}

// WithUserAgent provides the exported WithUserAgent function.
func WithUserAgent(ua string) AuthContextOption {
	return func(c *AuthContext) { c.UserAgent = ua }
}

// WithClientIP provides the exported WithClientIP function.
func WithClientIP(ip string) AuthContextOption {
	return func(c *AuthContext) { c.ClientIP = ip }
}

// WithClientPort provides the exported WithClientPort function.
func WithClientPort(p string) AuthContextOption {
	return func(c *AuthContext) { c.ClientPort = p }
}

// WithClientHostname provides the exported WithClientHostname function.
func WithClientHostname(h string) AuthContextOption {
	return func(c *AuthContext) { c.ClientHostname = h }
}

// WithClientID provides the exported WithClientID function.
func WithClientID(id string) AuthContextOption {
	return func(c *AuthContext) { c.ClientID = id }
}

// WithExternalSessionID sets the optional upstream session identifier.
func WithExternalSessionID(id string) AuthContextOption {
	return func(c *AuthContext) { c.ExternalSessionID = normalizeExternalSessionID(id) }
}

// WithLocalIP provides the exported WithLocalIP function.
func WithLocalIP(ip string) AuthContextOption {
	return func(c *AuthContext) { c.LocalIP = ip }
}

// WithLocalPort provides the exported WithLocalPort function.
func WithLocalPort(p string) AuthContextOption {
	return func(c *AuthContext) { c.LocalPort = p }
}

// WithProtocol provides the exported WithProtocol function.
func WithProtocol(proto string) AuthContextOption {
	return func(c *AuthContext) { c.Protocol = proto }
}

// WithXSSL provides the exported WithXSSL function.
func WithXSSL(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSL = v }
}

// WithXSSLSessionID provides the exported WithXSSLSessionID function.
func WithXSSLSessionID(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLSessionID = v }
}

// WithXSSLClientVerify provides the exported WithXSSLClientVerify function.
func WithXSSLClientVerify(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientVerify = v }
}

// WithXSSLClientDN provides the exported WithXSSLClientDN function.
func WithXSSLClientDN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientDN = v }
}

// WithXSSLClientCN provides the exported WithXSSLClientCN function.
func WithXSSLClientCN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientCN = v }
}

// WithXSSLIssuer provides the exported WithXSSLIssuer function.
func WithXSSLIssuer(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLIssuer = v }
}

// WithXSSLClientNotBefore provides the exported WithXSSLClientNotBefore function.
func WithXSSLClientNotBefore(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientNotBefore = v }
}

// WithXSSLClientNotAfter provides the exported WithXSSLClientNotAfter function.
func WithXSSLClientNotAfter(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientNotAfter = v }
}

// WithXSSLSubjectDN provides the exported WithXSSLSubjectDN function.
func WithXSSLSubjectDN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLSubjectDN = v }
}

// WithXSSLIssuerDN provides the exported WithXSSLIssuerDN function.
func WithXSSLIssuerDN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLIssuerDN = v }
}

// WithXSSLClientSubjectDN provides the exported WithXSSLClientSubjectDN function.
func WithXSSLClientSubjectDN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientSubjectDN = v }
}

// WithXSSLClientIssuerDN provides the exported WithXSSLClientIssuerDN function.
func WithXSSLClientIssuerDN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientIssuerDN = v }
}

// WithXSSLProtocol provides the exported WithXSSLProtocol function.
func WithXSSLProtocol(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLProtocol = v }
}

// WithXSSLCipher provides the exported WithXSSLCipher function.
func WithXSSLCipher(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLCipher = v }
}

// WithSSLSerial provides the exported WithSSLSerial function.
func WithSSLSerial(v string) AuthContextOption {
	return func(c *AuthContext) { c.SSLSerial = v }
}

// WithSSLFingerprint provides the exported WithSSLFingerprint function.
func WithSSLFingerprint(v string) AuthContextOption {
	return func(c *AuthContext) { c.SSLFingerprint = v }
}

// WithOIDCCID provides the exported WithOIDCCID function.
func WithOIDCCID(v string) AuthContextOption {
	return func(c *AuthContext) { c.OIDCCID = v }
}

// WithRequestMetadata stores allowlisted transport metadata candidates for policy facts.
func WithRequestMetadata(values map[string][]string) AuthContextOption {
	return func(c *AuthContext) { c.RequestMetadata = cloneRequestMetadata(values) }
}

// FieldMapping groups configurable field names to reduce scattered getters.
// Currently unused to avoid behavior changes; reserved for next steps.
type FieldMapping struct {
	Account     string
	TOTPSecret  string
	UniqueID    string
	DisplayName string
}

func normalizeExternalSessionID(id string) string {
	return strings.TrimSpace(id)
}

func cloneRequestMetadata(input map[string][]string) map[string][]string {
	if input == nil {
		return nil
	}

	output := make(map[string][]string, len(input))
	for key, values := range input {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		if normalizedKey == "" {
			continue
		}

		output[normalizedKey] = append([]string(nil), values...)
	}

	return output
}
