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

// Package supportops is the transport-independent application service for read-only operational diagnostics.
//
// It reads the current state of this instance (the nauthilus_runtime source) and, when configured, recorded log
// evidence from Loki through a fixed query profile. It owns authorization, request validation, limits, the merge of
// source results into findings, separate hypotheses, completeness statements, and audit. Transport adapters
// (management HTTP and MCP) authenticate their transport, pass verified credential facts, and serialize the returned
// DTOs; they contain no diagnosis logic. Nothing here changes runtime state.
package supportops

import (
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// Caller is an authorized principal of the diagnostics service. The zero value has no permission.
type Caller struct {
	identity string
	method   supportaccess.CredentialMethod
	allowed  bool
}

// NewCaller maps verified credential facts to the operations permission. Service tokens and user tokens of a
// hosted resource map through the same scope; a credential without a principal identity maps to nothing.
func NewCaller(credential supportaccess.VerifiedCredential) Caller {
	caller := Caller{identity: credential.Identity(), method: credential.Method}
	caller.allowed = caller.identity != "" && credential.HasScope(definitions.ScopeOperationsRead)

	return caller
}

// Identity returns the principal identity used for audit and per-principal limits.
func (c Caller) Identity() string {
	return c.identity
}

// Method returns how the transport verified the caller.
func (c Caller) Method() supportaccess.CredentialMethod {
	return c.method
}
