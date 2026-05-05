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

// Package policy contains shared vocabulary for the internal policy decision layer.
package policy

// BuiltinDefaultSet is the built-in policy set that preserves current auth behavior.
const BuiltinDefaultSet = "standard_auth"

// Stage identifies a policy evaluation checkpoint.
type Stage string

const (
	// StagePreAuth covers controls that run before backend authentication.
	StagePreAuth Stage = "pre_auth"

	// StageAuthBackend covers backend and password evaluation facts.
	StageAuthBackend Stage = "auth_backend"

	// StageAuthFilters covers request filters after backend evaluation.
	StageAuthFilters Stage = "auth_filters"

	// StageAccountProvider covers account-list provider facts.
	StageAccountProvider Stage = "account_provider"

	// StageAuthDecision covers final auth result selection.
	StageAuthDecision Stage = "auth_decision"
)

// Operation identifies the request operation evaluated by policy code.
type Operation string

const (
	// OperationAuthenticate is normal password authentication.
	OperationAuthenticate Operation = "authenticate"

	// OperationLookupIdentity is trusted identity lookup without password verification.
	OperationLookupIdentity Operation = "lookup_identity"

	// OperationListAccounts is account-list provider evaluation.
	OperationListAccounts Operation = "list_accounts"
)

// Decision is the transport-independent policy effect.
type Decision string

const (
	// DecisionNeutral allows the current stage to continue.
	DecisionNeutral Decision = "neutral"

	// DecisionDeny rejects the current operation.
	DecisionDeny Decision = "deny"

	// DecisionPermit permits the current operation where the stage allows it.
	DecisionPermit Decision = "permit"

	// DecisionTempFail reports a temporary failure for the current operation.
	DecisionTempFail Decision = "tempfail"
)

// CheckStatus is the normalized runtime status for a configured policy check.
type CheckStatus string

const (
	// CheckStatusOK means the check ran without a technical runtime error.
	CheckStatusOK CheckStatus = "ok"

	// CheckStatusSkipped means scheduling did not select the check.
	CheckStatusSkipped CheckStatus = "skipped"

	// CheckStatusError means the selected check hit a technical runtime error.
	CheckStatusError CheckStatus = "error"
)
