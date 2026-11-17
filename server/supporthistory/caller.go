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

// Package supporthistory is the transport-independent application service for historical authentication diagnosis.
//
// It reads recorded ClickHouse evidence only (contrib/plugins/clickhouse/DIAGNOSTIC_CONTRACT.md), never current
// runtime state, and owns authorization, shared limits, correlation, interpretation, projection, coverage, and audit.
// Transport adapters (HTTP today, MCP later) authenticate their transport, pass verified credential facts, and
// serialize the returned DTOs; they contain no diagnosis logic.
package supporthistory

import (
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

// CredentialMethod names how a transport verified the caller.
type CredentialMethod string

// CredentialOIDCBearer is a backchannel OAuth access token validated by the host.
const CredentialOIDCBearer CredentialMethod = "oidc_bearer"

// VerifiedCredential carries facts a transport adapter has already verified. Only an adapter that validated the
// credential itself may construct it; nothing in it is taken from request bodies or caller-supplied headers.
type VerifiedCredential struct {
	Method   CredentialMethod
	ClientID string
	Subject  string
	Scopes   []string
}

// permission is the internal capability set derived from verified credential facts.
type permission uint8

const (
	// permissionAttemptsRead is the support projection: named subject, own data, counts.
	permissionAttemptsRead permission = 1 << iota

	// permissionDetailRead releases other identities behind shared addresses and operator-only factor results.
	permissionDetailRead
)

// Projection names the data projection a response was built with.
type Projection string

const (
	// ProjectionSupport is the support role projection.
	ProjectionSupport Projection = "support"

	// ProjectionDetail is the released detail role projection.
	ProjectionDetail Projection = "detail"
)

// Caller is an authorized principal of the history service. The zero value has no permission. Permissions are
// derived only here, from verified scopes; administrative scopes and Basic credentials grant nothing.
type Caller struct {
	identity    string
	method      CredentialMethod
	permissions permission
}

// NewCaller maps verified credential facts to history permissions.
func NewCaller(credential VerifiedCredential) Caller {
	caller := Caller{identity: callerIdentity(credential), method: credential.Method}
	if credential.Method != CredentialOIDCBearer || caller.identity == "" {
		return caller
	}

	if slices.Contains(credential.Scopes, definitions.ScopeHistoryRead) {
		caller.permissions |= permissionAttemptsRead
	}

	if slices.Contains(credential.Scopes, definitions.ScopeHistoryDetail) {
		caller.permissions |= permissionAttemptsRead | permissionDetailRead
	}

	return caller
}

// callerIdentity selects the stable audit identity of a verified credential.
func callerIdentity(credential VerifiedCredential) string {
	if identity := strings.TrimSpace(credential.ClientID); identity != "" {
		return identity
	}

	return strings.TrimSpace(credential.Subject)
}

// Identity returns the host-derived audit identity.
func (c Caller) Identity() string {
	return c.identity
}

// Method returns how the transport verified the caller.
func (c Caller) Method() CredentialMethod {
	return c.method
}

// has reports whether the caller holds every bit of the wanted permission.
func (c Caller) has(wanted permission) bool {
	return wanted != 0 && c.permissions&wanted == wanted
}

// projection returns the widest projection the caller may receive.
func (c Caller) projection() Projection {
	if c.has(permissionDetailRead) {
		return ProjectionDetail
	}

	return ProjectionSupport
}
