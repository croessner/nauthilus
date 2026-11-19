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

// Package supportaccess holds the trust primitives shared by the read-only support services (historical
// authentication diagnosis and operational diagnostics) and their transport adapters.
//
// A transport adapter that verified a credential itself (the management HTTP bearer middleware, the MCP resource
// server) builds a VerifiedCredential from verified facts only; nothing in it comes from request bodies or
// caller-supplied headers. The services derive their permissions from it themselves, so every transport gets the same
// authorization, and they share one concurrency Gate per service.
package supportaccess

import (
	"slices"
	"strings"
)

// CredentialMethod names how a transport verified the caller.
type CredentialMethod string

const (
	// CredentialOIDCBearer is a backchannel OAuth service access token (client credentials) validated by the host.
	CredentialOIDCBearer CredentialMethod = "oidc_bearer"

	// CredentialBasic is a scoped HTTP Basic credential of the backchannel API validated by the host. It names
	// the configured username and holds exactly the scopes configured for it.
	CredentialBasic CredentialMethod = "basic_auth"

	// CredentialOAuthUser is a user access token issued by the own issuer for a hosted resource and validated by the
	// resource server of that resource (the MCP endpoint). It names a person acting through a client.
	CredentialOAuthUser CredentialMethod = "oauth_user"
)

// principalSeparator joins client and subject in the principal identity of a user credential.
const principalSeparator = "#"

// VerifiedCredential carries facts a transport adapter has already verified. Only an adapter that validated the
// credential itself may construct it.
type VerifiedCredential struct {
	Method   CredentialMethod
	ClientID string
	Subject  string
	Scopes   []string
}

// Verified reports whether the credential uses a known method and names a principal.
func (c VerifiedCredential) Verified() bool {
	return c.Identity() != ""
}

// Identity returns the stable principal identity used for audit records and per-principal limits.
//
// A service token is identified by its client (falling back to its subject) and a Basic credential by its
// username, which the adapter passes as the client. A user token is identified by client
// and subject together, so people sharing one client never share an audit identity or a concurrency share. Unknown
// methods and user tokens without both values have no identity and therefore no permission.
func (c VerifiedCredential) Identity() string {
	clientID, subject := strings.TrimSpace(c.ClientID), strings.TrimSpace(c.Subject)

	switch c.Method {
	case CredentialOIDCBearer, CredentialBasic:
		if clientID != "" {
			return clientID
		}

		return subject
	case CredentialOAuthUser:
		if clientID == "" || subject == "" {
			return ""
		}

		return clientID + principalSeparator + subject
	default:
		return ""
	}
}

// HasScope reports whether the verified scopes contain scope; an unverified credential holds no scope.
func (c VerifiedCredential) HasScope(scope string) bool {
	return scope != "" && c.Verified() && slices.Contains(c.Scopes, scope)
}
