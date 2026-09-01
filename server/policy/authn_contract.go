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

package policy

import "strings"

const (
	// AuthnNamespace owns the builtin authentication target family.
	AuthnNamespace = "authn"

	// AuthnProviderBruteForce owns the request-local brute-force check.
	AuthnProviderBruteForce = "authn/builtin/brute_force"
	// AuthnProviderEnvironment owns Lua and native environment collection.
	AuthnProviderEnvironment = "authn/environment"
	// AuthnProviderTLSEncryption owns transport-encryption checks.
	AuthnProviderTLSEncryption = "authn/builtin/tls_encryption"
	// AuthnProviderRelayDomains owns relay-domain checks.
	AuthnProviderRelayDomains = "authn/builtin/relay_domains"
	// AuthnProviderRBL owns realtime block-list checks.
	AuthnProviderRBL = "authn/builtin/rbl"
	// AuthnProviderBackend owns cache and authentication backend work.
	AuthnProviderBackend = "authn/auth_backend"
	// AuthnProviderSubject owns request-local post-backend subject work.
	AuthnProviderSubject = "authn/subject"
	// AuthnProviderLDAPBackend identifies the typed LDAP backend binding.
	AuthnProviderLDAPBackend = "authn/builtin/ldap_backend"
	// AuthnProviderLuaBackend identifies the configured Lua backend binding.
	AuthnProviderLuaBackend = "authn/builtin/lua_backend"
	// AuthnProviderPluginBackendOrder identifies the typed native backend order binding.
	AuthnProviderPluginBackendOrder = "authn/builtin/plugin_backend_order"
	// AuthnProviderAccount owns account-provider work.
	AuthnProviderAccount = "authn/builtin/account_provider"

	// AuthnFactOperation identifies the host-selected authentication operation.
	AuthnFactOperation = "nauthilus.auth.operation"
	// AuthnFactService identifies the host-selected authentication response surface.
	AuthnFactService = "nauthilus.auth.service"
	// AuthnFactCurrentDecision records the current pipeline outcome before candidate mapping.
	AuthnFactCurrentDecision = "nauthilus.auth.current_decision"
	// AuthnFactRequestClientIP records the host-normalized end-client address.
	AuthnFactRequestClientIP = "nauthilus.request.client.ip"
	// AuthnFactRequestClientIPPresent records whether a normalized end-client address exists.
	AuthnFactRequestClientIPPresent = "nauthilus.request.client.ip.present"
	// AuthnFactRequestClientIPTrusted records whether the normalized end-client path is trusted.
	AuthnFactRequestClientIPTrusted = "nauthilus.request.client.ip.trusted"
	// AuthnFactRequestCallerIP records the host-observed direct caller address.
	AuthnFactRequestCallerIP = "nauthilus.request.caller.ip"
	// AuthnFactRequestCallerIPPresent records whether a direct caller address exists.
	AuthnFactRequestCallerIPPresent = "nauthilus.request.caller.ip.present"
	// AuthnFactRequestLocalIP records the host-normalized local endpoint address.
	AuthnFactRequestLocalIP = "nauthilus.request.local.ip"
	// AuthnFactRequestLocalIPPresent records whether a normalized local endpoint address exists.
	AuthnFactRequestLocalIPPresent = "nauthilus.request.local.ip.present"

	// AuthnFactUsername identifies the caller-asserted authentication subject.
	AuthnFactUsername = "input.auth.username"
	// AuthnFactProtocol identifies the caller-asserted application protocol.
	AuthnFactProtocol = "environment.protocol"
	// AuthnFactMethod identifies the caller-asserted authentication method.
	AuthnFactMethod = "input.auth.method"
	// AuthnFactUserAgent identifies the caller-asserted user agent.
	AuthnFactUserAgent = "input.auth.user_agent"
	// AuthnFactClientIP identifies the caller-asserted end-client address.
	AuthnFactClientIP = "input.auth.client_ip"
	// AuthnFactClientPort identifies the caller-asserted end-client port.
	AuthnFactClientPort = "input.auth.client_port"
	// AuthnFactClientHostname identifies the caller-asserted end-client hostname.
	AuthnFactClientHostname = "input.auth.client_hostname"
	// AuthnFactClientID identifies the caller-asserted application client.
	AuthnFactClientID = "input.auth.client_id"
	// AuthnFactLocalIP identifies the caller-asserted local endpoint address.
	AuthnFactLocalIP = "input.auth.local_ip"
	// AuthnFactLocalPort identifies the caller-asserted local endpoint port.
	AuthnFactLocalPort = "input.auth.local_port"
	// AuthnFactIDPClientID identifies the request-bound OIDC client when present.
	AuthnFactIDPClientID = "input.auth.idp_client_id"
	// AuthnFactSAMLServiceProviderID identifies the request-bound SAML service provider.
	AuthnFactSAMLServiceProviderID = "input.auth.saml_service_provider_id"
	// AuthnFactLoginAttempt identifies the caller-supplied normalized login attempt ordinal.
	AuthnFactLoginAttempt = "input.auth.login_attempt"

	// AuthnFactBackend identifies the backend that produced the current result.
	AuthnFactBackend = "backend.kind"
	// AuthnFactAuthenticated records a successful password authentication result.
	AuthnFactAuthenticated = "backend.authenticated"
	// AuthnFactIdentityFound records a successful identity lookup result.
	AuthnFactIdentityFound = "backend.identity_found"
	// AuthnFactAccountField identifies the backend account attribute.
	AuthnFactAccountField = "backend.account_field"
	// AuthnFactGroups records backend-resolved group names.
	AuthnFactGroups = "backend.groups"
	// AuthnFactGroupDistinguishedNames records backend-resolved group distinguished names.
	AuthnFactGroupDistinguishedNames = "backend.group_distinguished_names"
	// AuthnFactAccountCount records the bounded account-provider result size.
	AuthnFactAccountCount = "backend.account_count"
	// AuthnFactAccountProviderCompleted records whether the account provider completed reliably.
	AuthnFactAccountProviderCompleted = "backend.account_provider_completed"
	// AuthnFactBruteForceError records a modeled brute-force provider failure.
	AuthnFactBruteForceError = "nauthilus.auth.brute_force.error"
	// AuthnFactBruteForceTriggered records a request-local brute-force match.
	AuthnFactBruteForceTriggered = "nauthilus.auth.brute_force.triggered"
	// AuthnFactTLSSecure records whether the accepted request path satisfies TLS policy.
	AuthnFactTLSSecure = "nauthilus.auth.tls.secure"
	// AuthnFactRelayDomainError records a relay-domain provider failure.
	AuthnFactRelayDomainError = "nauthilus.auth.relay_domain.error"
	// AuthnFactRelayDomainPresent records whether the request contains a relay domain.
	AuthnFactRelayDomainPresent = "nauthilus.auth.relay_domain.present"
	// AuthnFactRelayDomainKnown records whether the relay domain is configured.
	AuthnFactRelayDomainKnown = "nauthilus.auth.relay_domain.known"
	// AuthnFactRBLError records a modeled RBL provider failure.
	AuthnFactRBLError = "nauthilus.auth.rbl.error"
	// AuthnFactRBLThresholdReached records whether the configured RBL threshold matched.
	AuthnFactRBLThresholdReached = "nauthilus.auth.rbl.threshold_reached"
	// AuthnFactBackendTempFail records a modeled authentication backend failure.
	AuthnFactBackendTempFail = "nauthilus.auth.backend.tempfail"
	// AuthnFactBackendEmptyUsername records an empty authentication subject.
	AuthnFactBackendEmptyUsername = "nauthilus.auth.backend.empty_username"
	// AuthnFactBackendEmptyPassword records an empty authentication credential.
	AuthnFactBackendEmptyPassword = "nauthilus.auth.backend.empty_password"
	// AuthnFactMasterUserActive records host-validated master-user mode.
	AuthnFactMasterUserActive = "nauthilus.auth.master_user.active"
	// AuthnFactBruteForceTolerationCustom records whether custom toleration is active.
	AuthnFactBruteForceTolerationCustom = "nauthilus.auth.brute_force.toleration.custom"
	// AuthnFactBruteForceTolerationSuppressedBlock records a suppressed brute-force block.
	AuthnFactBruteForceTolerationSuppressedBlock = "nauthilus.auth.brute_force.toleration.suppressed_block"
	// AuthnFactAccountProviderTempFail records an unreliable account-provider result.
	AuthnFactAccountProviderTempFail = "nauthilus.auth.account_provider.tempfail"
)

var authnBuiltinProviderIdentities = map[string]string{
	"brute_force":          AuthnProviderBruteForce,
	"tls_encryption":       AuthnProviderTLSEncryption,
	"relay_domains":        AuthnProviderRelayDomains,
	"rbl":                  AuthnProviderRBL,
	"ldap_backend":         AuthnProviderLDAPBackend,
	"lua_backend":          AuthnProviderLuaBackend,
	"plugin_backend_order": AuthnProviderPluginBackendOrder,
	"account_provider":     AuthnProviderAccount,
}

// AuthnBuiltinProviderIdentity resolves one canonical builtin instance name to its exact provider use.
func AuthnBuiltinProviderIdentity(instance string) (string, bool) {
	identity, exists := authnBuiltinProviderIdentities[instance]

	return identity, exists
}

// IsAuthnBuiltinProviderIdentity reports whether an exact use belongs to the migrated builtin check vocabulary.
func IsAuthnBuiltinProviderIdentity(identity string) bool {
	for _, candidate := range authnBuiltinProviderIdentities {
		if candidate == identity {
			return true
		}
	}

	return false
}

// AuthnBuiltinCheckpointProviderIDs returns the immutable provider schedule for one exact authn checkpoint.
func AuthnBuiltinCheckpointProviderIDs(operation Operation, checkpoint Stage) []string {
	switch {
	case operation == OperationAuthenticate && checkpoint == StagePreAuth:
		return []string{AuthnProviderBruteForce}
	case operation == OperationAuthenticate && checkpoint == StageAuthDecision:
		return []string{
			AuthnProviderEnvironment,
			AuthnProviderTLSEncryption,
			AuthnProviderRelayDomains,
			AuthnProviderRBL,
			AuthnProviderBackend,
			AuthnProviderSubject,
		}
	case operation == OperationLookupIdentity && checkpoint == StagePreAuth:
		return []string{AuthnProviderEnvironment, AuthnProviderTLSEncryption, AuthnProviderRBL}
	case operation == OperationLookupIdentity && checkpoint == StageAuthDecision:
		return []string{AuthnProviderBackend, AuthnProviderSubject}
	case operation == OperationListAccounts && checkpoint == StageAuthDecision:
		return []string{AuthnProviderAccount}
	default:
		return nil
	}
}

// AuthnBuiltinProviderUse resolves an instance only when the immutable target checkpoint schedules it.
func AuthnBuiltinProviderUse(instance string, operation Operation, checkpoint Stage) (string, bool) {
	identity, exists := AuthnBuiltinProviderIdentity(instance)
	if !exists {
		return "", false
	}

	for _, scheduled := range AuthnBuiltinCheckpointProviderIDs(operation, checkpoint) {
		if scheduled == identity {
			return identity, true
		}
	}

	return "", false
}

// AuthnProviderObserveSafety returns the established default and assertion capability for one migrated provider use.
func AuthnProviderObserveSafety(use string) (defaultSafe bool, allowsAssertion bool, known bool) {
	switch use {
	case AuthnProviderTLSEncryption, AuthnProviderRelayDomains:
		return true, false, true
	case AuthnProviderBruteForce,
		AuthnProviderRBL,
		AuthnProviderLDAPBackend,
		AuthnProviderAccount:
		return false, false, true
	case AuthnProviderLuaBackend, AuthnProviderPluginBackendOrder:
		return false, true, true
	}

	switch {
	case strings.HasPrefix(use, AuthnNamespace+"/lua_environment_"),
		strings.HasPrefix(use, AuthnNamespace+"/lua_subject_"),
		strings.HasPrefix(use, AuthnNamespace+"/plugin."):
		return false, true, true
	default:
		return false, false, false
	}
}

var authnBuiltinAttributeFacts = map[string]string{
	AttributeBruteForceError:         AuthnFactBruteForceError,
	AttributeBruteForceTriggered:     AuthnFactBruteForceTriggered,
	AttributeTLSSecure:               AuthnFactTLSSecure,
	AttributeRelayDomainError:        AuthnFactRelayDomainError,
	AttributeRelayDomainPresent:      AuthnFactRelayDomainPresent,
	AttributeRelayDomainKnown:        AuthnFactRelayDomainKnown,
	AttributeRBLError:                AuthnFactRBLError,
	AttributeRBLThresholdReached:     AuthnFactRBLThresholdReached,
	AttributeBackendTempFail:         AuthnFactBackendTempFail,
	AttributeBackendEmptyUsername:    AuthnFactBackendEmptyUsername,
	AttributeBackendEmptyPassword:    AuthnFactBackendEmptyPassword,
	AttributeAccountProviderTempFail: AuthnFactAccountProviderTempFail,
}

var authnHostOwnedAttributeFacts = map[string]string{
	AttributeRequestClientIP:                     AuthnFactRequestClientIP,
	AttributeRequestClientIPPresent:              AuthnFactRequestClientIPPresent,
	AttributeRequestClientIPTrusted:              AuthnFactRequestClientIPTrusted,
	AttributeRequestCallerIP:                     AuthnFactRequestCallerIP,
	AttributeRequestCallerIPPresent:              AuthnFactRequestCallerIPPresent,
	AttributeRequestLocalIP:                      AuthnFactRequestLocalIP,
	AttributeRequestLocalIPPresent:               AuthnFactRequestLocalIPPresent,
	AttributeMasterUserActive:                    AuthnFactMasterUserActive,
	AttributeBruteForceTolerationCustom:          AuthnFactBruteForceTolerationCustom,
	AttributeBruteForceTolerationSuppressedBlock: AuthnFactBruteForceTolerationSuppressedBlock,
}

const authnAuthorityNauthilus = "nauthilus"

// AuthnCanonicalFactIdentity maps one established auth attribute to its strict fact owner.
func AuthnCanonicalFactIdentity(attributeID string, source string) (string, string, bool) {
	switch source {
	case "builtin":
		if factID, exists := authnBuiltinAttributeFacts[attributeID]; exists {
			return factID, authnAuthorityNauthilus, true
		}

		return authnGeneratedExecutionFact(attributeID)
	case "lua":
		return authnProviderFact(attributeID, "lua")
	case "plugin":
		return authnProviderFact(attributeID, "plugin")
	default:
		return "", "", false
	}
}

// AuthnResponseDetailFactID returns the canonical public response-detail fact identity.
func AuthnResponseDetailFactID(factID string, detail string) string {
	if factID == "" || detail == "" {
		return ""
	}

	return factID + "." + detail
}

// AuthnResponseDetailTruncatedFactID identifies host-side response-detail sanitation state.
func AuthnResponseDetailTruncatedFactID(factID string, detail string) string {
	detailFactID := AuthnResponseDetailFactID(factID, detail)
	if detailFactID == "" {
		return ""
	}

	return detailFactID + ".truncated"
}

// AuthnResponseDetailSelectedFactID identifies whether the raw public detail was nonblank.
func AuthnResponseDetailSelectedFactID(factID string, detail string) string {
	detailFactID := AuthnResponseDetailFactID(factID, detail)
	if detailFactID == "" {
		return ""
	}

	return detailFactID + ".selected"
}

// AuthnLuaEnvironmentFactID returns one catalog-owned Lua environment execution fact.
func AuthnLuaEnvironmentFactID(name string, suffix string) string {
	return "nauthilus.auth.lua.environment." + name + "." + suffix
}

// AuthnLuaSubjectFactID returns one catalog-owned Lua subject execution fact.
func AuthnLuaSubjectFactID(name string, suffix string) string {
	return "nauthilus.auth.lua.subject." + name + "." + suffix
}

// authnGeneratedExecutionFact maps selected host-owned and generated execution attributes.
func authnGeneratedExecutionFact(attributeID string) (string, string, bool) {
	if factID, exists := authnHostOwnedAttributeFacts[attributeID]; exists {
		return factID, authnAuthorityNauthilus, true
	}

	for _, prefix := range []string{
		"auth.lua.environment.",
		"auth.lua.subject.",
		"auth.plugin.environment.",
		"auth.plugin.subject.",
	} {
		if strings.HasPrefix(attributeID, prefix) {
			return "nauthilus." + attributeID, authnAuthorityNauthilus, true
		}
	}

	if strings.HasPrefix(attributeID, "nauthilus.") {
		return attributeID, authnAuthorityNauthilus, true
	}

	return "", "", false
}

// authnProviderFact retains canonical provider facts and derives their exact owner segment.
func authnProviderFact(attributeID string, source string) (string, string, bool) {
	if !strings.HasPrefix(attributeID, source+".") {
		return "", "", false
	}

	parts := strings.Split(attributeID, ".")
	if len(parts) < 3 || parts[1] == "" {
		return "", "", false
	}

	return attributeID, parts[1], true
}
