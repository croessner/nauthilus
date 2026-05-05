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
	// CheckTypeBruteForce identifies the built-in brute-force evaluator.
	CheckTypeBruteForce = "builtin.brute_force"

	// CheckTypeTLSEncryption identifies the built-in TLS evaluator.
	CheckTypeTLSEncryption = "builtin.tls_encryption"

	// CheckTypeRelayDomains identifies the built-in relay-domain evaluator.
	CheckTypeRelayDomains = "builtin.relay_domains"

	// CheckTypeRBL identifies the built-in RBL evaluator.
	CheckTypeRBL = "builtin.rbl"

	// CheckTypeLuaControl identifies one named Lua control evaluator.
	CheckTypeLuaControl = "lua.control"

	// CheckTypeLDAPBackend identifies LDAP backend evaluation.
	CheckTypeLDAPBackend = "backend.ldap"

	// CheckTypeLuaBackend identifies Lua backend evaluation.
	CheckTypeLuaBackend = "backend.lua"

	// CheckTypeLuaFilter identifies one named Lua filter evaluator.
	CheckTypeLuaFilter = "lua.filter"

	// CheckTypeAccountProvider identifies account-provider evaluation.
	CheckTypeAccountProvider = "backend.account_provider"
)

const (
	// RunIfAny selects a check regardless of authentication state.
	RunIfAny = "any"

	// RunIfAuthenticated selects a check only after authentication succeeded.
	RunIfAuthenticated = "authenticated"

	// RunIfUnauthenticated selects a check only before authentication succeeds.
	RunIfUnauthenticated = "unauthenticated"
)

const (
	// AttributeRequestOperation stores the active request operation.
	AttributeRequestOperation = "request.operation"

	// AttributeRequestTime stores the request evaluation timestamp.
	AttributeRequestTime = "request.time.now"

	// AttributeRequestClientIP stores the request client IP.
	AttributeRequestClientIP = "request.client.ip"

	// AttributeRequestProtocol stores the request protocol.
	AttributeRequestProtocol = "request.protocol"

	// AttributeBruteForceTriggered stores whether brute-force matched.
	AttributeBruteForceTriggered = "auth.brute_force.triggered"

	// AttributeBruteForceError stores a modeled brute-force error.
	AttributeBruteForceError = "auth.brute_force.error"

	// AttributeTLSSecure stores the accepted TLS state.
	AttributeTLSSecure = "auth.tls.secure"

	// AttributeRelayDomainPresent stores whether a relay domain was present.
	AttributeRelayDomainPresent = "auth.relay_domain.present"

	// AttributeRelayDomainKnown stores whether a relay domain is configured.
	AttributeRelayDomainKnown = "auth.relay_domain.known"

	// AttributeRelayDomainError stores a modeled relay-domain error.
	AttributeRelayDomainError = "auth.relay_domain.error"

	// AttributeRBLThresholdReached stores whether RBL threshold matched.
	AttributeRBLThresholdReached = "auth.rbl.threshold_reached"

	// AttributeRBLError stores a modeled RBL error.
	AttributeRBLError = "auth.rbl.error"

	// AttributeAuthenticated stores backend authentication success.
	AttributeAuthenticated = "auth.authenticated"

	// AttributeIdentityFound stores identity lookup success.
	AttributeIdentityFound = "auth.identity.found"

	// AttributeBackendTempFail stores a modeled backend temporary failure.
	AttributeBackendTempFail = "auth.backend.tempfail"

	// AttributeBackendEmptyUsername stores an empty username result.
	AttributeBackendEmptyUsername = "auth.backend.empty_username"

	// AttributeBackendEmptyPassword stores an empty password result.
	AttributeBackendEmptyPassword = "auth.backend.empty_password"

	// AttributeAccountProviderCompleted stores account-provider completion.
	AttributeAccountProviderCompleted = "auth.account_provider.completed"

	// AttributeAccountProviderTempFail stores account-provider temporary failure.
	AttributeAccountProviderTempFail = "auth.account_provider.tempfail"
)

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

const (
	// ResponseMarkerOK identifies a successful response class.
	ResponseMarkerOK = "auth.response.ok"

	// ResponseMarkerFail identifies a denial response class.
	ResponseMarkerFail = "auth.response.fail"

	// ResponseMarkerTempFail identifies a temporary-failure response class.
	ResponseMarkerTempFail = "auth.response.tempfail"

	// ResponseMarkerTempFailNoTLS identifies the TLS-required temporary-failure response class.
	ResponseMarkerTempFailNoTLS = "auth.response.tempfail.no_tls"

	// ResponseMarkerListAccountsOK identifies a successful account-list response class.
	ResponseMarkerListAccountsOK = "auth.response.list_accounts.ok"
)

const (
	// ObligationBruteForceUpdate identifies brute-force counter update enforcement.
	ObligationBruteForceUpdate = "auth.obligation.brute_force.update"

	// ObligationLuaPostActionEnqueue identifies Lua post-action enqueue enforcement.
	ObligationLuaPostActionEnqueue = "auth.obligation.lua_post_action.enqueue"
)

const (
	// FSMEventMarkerParseOK identifies a successful parser marker.
	FSMEventMarkerParseOK = "auth.fsm.event.parse_ok"

	// FSMEventMarkerParseFail identifies a parser failure marker.
	FSMEventMarkerParseFail = "auth.fsm.event.parse_fail"

	// FSMEventMarkerPreAuthOK identifies a successful pre-auth marker.
	FSMEventMarkerPreAuthOK = "auth.fsm.event.pre_auth_ok"

	// FSMEventMarkerPreAuthDeny identifies a pre-auth denial marker.
	FSMEventMarkerPreAuthDeny = "auth.fsm.event.pre_auth_deny"

	// FSMEventMarkerPreAuthTempFail identifies a pre-auth temporary failure marker.
	FSMEventMarkerPreAuthTempFail = "auth.fsm.event.pre_auth_tempfail"

	// FSMEventMarkerPreAuthAbort identifies a pre-auth abort marker.
	FSMEventMarkerPreAuthAbort = "auth.fsm.event.pre_auth_abort"

	// FSMEventMarkerAuthEvaluated identifies completed auth evaluation.
	FSMEventMarkerAuthEvaluated = "auth.fsm.event.auth_evaluated"

	// FSMEventMarkerAccountProviderEvaluated identifies completed account-provider evaluation.
	FSMEventMarkerAccountProviderEvaluated = "auth.fsm.event.account_provider_evaluated"

	// FSMEventMarkerAuthPermit identifies a final permit marker.
	FSMEventMarkerAuthPermit = "auth.fsm.event.auth_permit"

	// FSMEventMarkerAuthDeny identifies a final deny marker.
	FSMEventMarkerAuthDeny = "auth.fsm.event.auth_deny"

	// FSMEventMarkerAuthTempFail identifies a final temporary failure marker.
	FSMEventMarkerAuthTempFail = "auth.fsm.event.auth_tempfail"

	// FSMEventMarkerAuthEmptyUser identifies empty-user handling.
	FSMEventMarkerAuthEmptyUser = "auth.fsm.event.auth_empty_user"

	// FSMEventMarkerAuthEmptyPass identifies empty-password handling.
	FSMEventMarkerAuthEmptyPass = "auth.fsm.event.auth_empty_pass"

	// FSMEventMarkerBasicAuthOK identifies successful caller auth.
	FSMEventMarkerBasicAuthOK = "auth.fsm.event.basic_auth_ok"

	// FSMEventMarkerBasicAuthFail identifies failed caller auth.
	FSMEventMarkerBasicAuthFail = "auth.fsm.event.basic_auth_fail"

	// FSMEventMarkerAbort identifies a generic abort marker.
	FSMEventMarkerAbort = "auth.fsm.event.abort"
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
