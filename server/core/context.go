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

import "github.com/croessner/nauthilus/server/secret"

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
	Method    string
	UserAgent string

	ClientIP       string
	ClientPort     string
	ClientHostname string
	ClientID       string

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

func WithMethod(m string) AuthContextOption {
	return func(c *AuthContext) { c.Method = m }
}

func WithUserAgent(ua string) AuthContextOption {
	return func(c *AuthContext) { c.UserAgent = ua }
}

func WithClientIP(ip string) AuthContextOption {
	return func(c *AuthContext) { c.ClientIP = ip }
}

func WithClientPort(p string) AuthContextOption {
	return func(c *AuthContext) { c.ClientPort = p }
}

func WithClientHostname(h string) AuthContextOption {
	return func(c *AuthContext) { c.ClientHostname = h }
}

func WithClientID(id string) AuthContextOption {
	return func(c *AuthContext) { c.ClientID = id }
}

func WithLocalIP(ip string) AuthContextOption {
	return func(c *AuthContext) { c.LocalIP = ip }
}

func WithLocalPort(p string) AuthContextOption {
	return func(c *AuthContext) { c.LocalPort = p }
}

func WithProtocol(proto string) AuthContextOption {
	return func(c *AuthContext) { c.Protocol = proto }
}

func WithXSSL(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSL = v }
}

func WithXSSLSessionID(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLSessionID = v }
}

func WithXSSLClientVerify(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientVerify = v }
}

func WithXSSLClientDN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientDN = v }
}

func WithXSSLClientCN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientCN = v }
}

func WithXSSLIssuer(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLIssuer = v }
}

func WithXSSLClientNotBefore(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientNotBefore = v }
}

func WithXSSLClientNotAfter(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientNotAfter = v }
}

func WithXSSLSubjectDN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLSubjectDN = v }
}

func WithXSSLIssuerDN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLIssuerDN = v }
}

func WithXSSLClientSubjectDN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientSubjectDN = v }
}

func WithXSSLClientIssuerDN(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLClientIssuerDN = v }
}

func WithXSSLProtocol(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLProtocol = v }
}

func WithXSSLCipher(v string) AuthContextOption {
	return func(c *AuthContext) { c.XSSLCipher = v }
}

func WithSSLSerial(v string) AuthContextOption {
	return func(c *AuthContext) { c.SSLSerial = v }
}

func WithSSLFingerprint(v string) AuthContextOption {
	return func(c *AuthContext) { c.SSLFingerprint = v }
}

func WithOIDCCID(v string) AuthContextOption {
	return func(c *AuthContext) { c.OIDCCID = v }
}

// FieldMapping groups configurable field names to reduce scattered getters.
// Currently unused to avoid behavior changes; reserved for next steps.
type FieldMapping struct {
	Account     string
	TOTPSecret  string
	UniqueID    string
	DisplayName string
}
