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

const (
	// ResponseSourceDefault selects the response marker's default message.
	ResponseSourceDefault = "default"

	// ResponseSourceLiteral selects a configured literal response value.
	ResponseSourceLiteral = "literal"

	// ResponseSourceAttribute selects a configured attribute response value.
	ResponseSourceAttribute = "attribute"

	// ResponseSourceAttributeDetail selects a configured attribute detail response value.
	ResponseSourceAttributeDetail = "attribute_detail"

	// ResponseSourceI18N selects a configured localization key plus fallback.
	ResponseSourceI18N = "i18n"
)

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

	// CheckTypeLuaEnvironment identifies one named Lua environment attribute source.
	CheckTypeLuaEnvironment = "lua.environment"

	// CheckTypeLDAPBackend identifies LDAP backend evaluation.
	CheckTypeLDAPBackend = "backend.ldap"

	// CheckTypeLuaBackend identifies Lua backend evaluation.
	CheckTypeLuaBackend = "backend.lua"

	// CheckTypeLuaSubjectSource identifies one named Lua subject attribute source.
	CheckTypeLuaSubjectSource = "lua.subject"

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

	// AttributeRequestClientIPPresent stores whether the request client IP parsed successfully.
	AttributeRequestClientIPPresent = "request.client.ip.present"

	// AttributeRequestClientIPTrusted stores whether the selected client IP source is trusted.
	AttributeRequestClientIPTrusted = "request.client.ip.trusted"

	// AttributeRequestClientIPSource stores the selected client IP source.
	AttributeRequestClientIPSource = "request.client.ip.source"

	// AttributeRequestProtocol stores the request protocol.
	AttributeRequestProtocol = "request.protocol"

	// AttributeRequestTransportKind stores the server-derived transport kind.
	AttributeRequestTransportKind = "request.transport.kind"

	// AttributeRequestListenerName stores the configured listener identity when available.
	AttributeRequestListenerName = "request.listener.name"

	// AttributeRequestConnectionTLS stores whether the transport connection used TLS.
	AttributeRequestConnectionTLS = "request.connection.tls"

	// AttributeRequestInitiatorKind stores the server-derived request initiator kind.
	AttributeRequestInitiatorKind = "request.initiator.kind"

	// AttributeRequestHTTPRoute stores the normalized server route when available.
	AttributeRequestHTTPRoute = "request.http.route"

	// AttributeRequestGRPCMethod stores the normalized gRPC method when available.
	AttributeRequestGRPCMethod = "request.grpc.method"

	// AttributeRequestIDPClientID stores the IdP/OIDC client identifier when available before scheduling.
	AttributeRequestIDPClientID = "request.idp.client_id"

	// AttributeRequestSAMLServiceProviderID stores the SAML service-provider entity ID when available before scheduling.
	AttributeRequestSAMLServiceProviderID = "request.saml.sp_entity_id"

	// AttributeBruteForceTriggered stores whether brute-force matched.
	AttributeBruteForceTriggered = "auth.brute_force.triggered"

	// AttributeBruteForceRepeating stores whether brute-force matched a repeating state.
	AttributeBruteForceRepeating = "auth.brute_force.repeating"

	// AttributeBruteForceRWPActive stores whether repeating-wrong-password protection is active.
	AttributeBruteForceRWPActive = "auth.brute_force.rwp.active"

	// AttributeBruteForceRWPEnforceBucketUpdate stores whether the request should update bucket counters.
	AttributeBruteForceRWPEnforceBucketUpdate = "auth.brute_force.rwp.enforce_bucket_update"

	// AttributeBruteForceTolerationActive stores whether brute-force toleration currently applies.
	AttributeBruteForceTolerationActive = "auth.brute_force.toleration.active"

	// AttributeBruteForceTolerationMode stores the toleration calculation mode.
	AttributeBruteForceTolerationMode = "auth.brute_force.toleration.mode"

	// AttributeBruteForceTolerationCustom stores whether a custom toleration matched the request IP.
	AttributeBruteForceTolerationCustom = "auth.brute_force.toleration.custom"

	// AttributeBruteForceTolerationPositive stores the positive reputation counter.
	AttributeBruteForceTolerationPositive = "auth.brute_force.toleration.positive"

	// AttributeBruteForceTolerationNegative stores the negative reputation counter.
	AttributeBruteForceTolerationNegative = "auth.brute_force.toleration.negative"

	// AttributeBruteForceTolerationMaxNegative stores the tolerated negative counter limit.
	AttributeBruteForceTolerationMaxNegative = "auth.brute_force.toleration.max_negative"

	// AttributeBruteForceTolerationPercent stores the effective tolerated percentage.
	AttributeBruteForceTolerationPercent = "auth.brute_force.toleration.percent"

	// AttributeBruteForceTolerationTTLSeconds stores the effective toleration TTL in seconds.
	AttributeBruteForceTolerationTTLSeconds = "auth.brute_force.toleration.ttl_seconds"

	// AttributeBruteForceTolerationSuppressedBlock stores whether toleration suppressed a brute-force block.
	AttributeBruteForceTolerationSuppressedBlock = "auth.brute_force.toleration.suppressed_block"

	// AttributeBruteForceBucketMatchedCount stores the number of buckets matching the request context.
	AttributeBruteForceBucketMatchedCount = "auth.brute_force.bucket.matched_count"

	// AttributeBruteForceBucketTriggeredCount stores the number of buckets in a triggered state.
	AttributeBruteForceBucketTriggeredCount = "auth.brute_force.bucket.triggered_count"

	// AttributeBruteForceBucketMaxCount stores the highest observed bucket counter.
	AttributeBruteForceBucketMaxCount = "auth.brute_force.bucket.max_count"

	// AttributeBruteForceBucketMaxRatio stores the highest observed bucket fill ratio.
	AttributeBruteForceBucketMaxRatio = "auth.brute_force.bucket.max_ratio"

	// AttributeBruteForceError stores a modeled brute-force error.
	AttributeBruteForceError = "auth.brute_force.error"

	// AttributeTLSSecure stores the accepted TLS state.
	AttributeTLSSecure = "auth.tls.secure"

	// AttributeRelayDomainPresent stores whether a relay domain was present.
	AttributeRelayDomainPresent = "auth.relay_domain.present"

	// AttributeRelayDomainKnown stores whether a relay domain is configured.
	AttributeRelayDomainKnown = "auth.relay_domain.known"

	// AttributeRelayDomainValue stores the parsed relay-domain value.
	AttributeRelayDomainValue = "auth.relay_domain.value"

	// AttributeRelayDomainRejected stores whether relay-domain evaluation rejected the request.
	AttributeRelayDomainRejected = "auth.relay_domain.rejected"

	// AttributeRelayDomainStaticMatch stores whether a configured static relay domain matched.
	AttributeRelayDomainStaticMatch = "auth.relay_domain.static_match"

	// AttributeRelayDomainSoftAllowlisted stores whether relay-domain evaluation was soft-allowlisted.
	AttributeRelayDomainSoftAllowlisted = "auth.relay_domain.soft_allowlisted"

	// AttributeRelayDomainConfiguredCount stores the number of configured static relay domains.
	AttributeRelayDomainConfiguredCount = "auth.relay_domain.configured_count"

	// AttributeRelayDomainError stores a modeled relay-domain error.
	AttributeRelayDomainError = "auth.relay_domain.error"

	// AttributeRBLThresholdReached stores whether RBL threshold matched.
	AttributeRBLThresholdReached = "auth.rbl.threshold_reached"

	// AttributeRBLScore stores the aggregate RBL score.
	AttributeRBLScore = "auth.rbl.score"

	// AttributeRBLThreshold stores the configured RBL threshold.
	AttributeRBLThreshold = "auth.rbl.threshold"

	// AttributeRBLMatchedCount stores the number of RBL lists that matched.
	AttributeRBLMatchedCount = "auth.rbl.matched_count"

	// AttributeRBLMatchedLists stores the names of matched RBL lists.
	AttributeRBLMatchedLists = "auth.rbl.matched_lists"

	// AttributeRBLListCount stores the number of configured RBL lists.
	AttributeRBLListCount = "auth.rbl.list_count"

	// AttributeRBLAllowFailureErrorCount stores allowed RBL lookup error count.
	AttributeRBLAllowFailureErrorCount = "auth.rbl.allow_failure_error_count"

	// AttributeRBLEffectiveError stores whether an RBL error affects the decision.
	AttributeRBLEffectiveError = "auth.rbl.effective_error"

	// AttributeRBLSoftAllowlisted stores whether RBL evaluation was soft-allowlisted.
	AttributeRBLSoftAllowlisted = "auth.rbl.soft_allowlisted"

	// AttributeRBLIPAllowlisted stores whether the client IP was RBL-allowlisted.
	AttributeRBLIPAllowlisted = "auth.rbl.ip_allowlisted"

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
	// StagePreAuth covers checks that run before backend authentication.
	StagePreAuth Stage = "pre_auth"

	// StageAuthBackend covers backend and password evaluation facts.
	StageAuthBackend Stage = "auth_backend"

	// StageSubjectAnalysis covers subject analysis after backend evaluation.
	StageSubjectAnalysis Stage = "subject_analysis"

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

	// ObligationLuaActionDispatch identifies synchronous Lua action dispatch enforcement.
	ObligationLuaActionDispatch = "auth.obligation.lua_action.dispatch"

	// ObligationLuaPostActionEnqueue identifies Lua post-action enqueue enforcement.
	ObligationLuaPostActionEnqueue = "auth.obligation.lua_post_action.enqueue"
)

const (
	// ObligationArgAction names the bounded action argument for Lua action dispatch.
	ObligationArgAction = "action"

	// ObligationArgEnvironment names the optional environment source or control argument for Lua action dispatch.
	ObligationArgEnvironment = "environment"

	// ObligationArgWait names the optional wait argument for Lua action dispatch.
	ObligationArgWait = "wait"
)

const (
	// LuaActionDispatchBruteForce is the brute-force synchronous action name.
	LuaActionDispatchBruteForce = "brute_force"

	// LuaActionDispatchLua is the generic Lua-control synchronous action name.
	LuaActionDispatchLua = "lua"

	// LuaActionDispatchTLS is the TLS synchronous action name.
	LuaActionDispatchTLS = "tls_encryption"

	// LuaActionDispatchRelayDomains is the relay-domain synchronous action name.
	LuaActionDispatchRelayDomains = "relay_domains"

	// LuaActionDispatchRBL is the RBL synchronous action name.
	LuaActionDispatchRBL = "rbl"
)

// LuaActionDispatchActionAllowed reports whether name is a registered synchronous Lua action target.
func LuaActionDispatchActionAllowed(name string) bool {
	switch name {
	case LuaActionDispatchBruteForce,
		LuaActionDispatchLua,
		LuaActionDispatchTLS,
		LuaActionDispatchRelayDomains,
		LuaActionDispatchRBL:
		return true
	default:
		return false
	}
}

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
