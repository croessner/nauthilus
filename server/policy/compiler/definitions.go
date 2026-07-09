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

package compiler

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	checkTypeBruteForce        = policy.CheckTypeBruteForce
	checkTypeTLSEncryption     = policy.CheckTypeTLSEncryption
	checkTypeRelayDomains      = policy.CheckTypeRelayDomains
	checkTypeRBL               = policy.CheckTypeRBL
	checkTypeLuaEnvironment    = policy.CheckTypeLuaEnvironment
	checkTypePluginEnvironment = policy.CheckTypePluginEnvironment
	checkTypeLDAPBackend       = policy.CheckTypeLDAPBackend
	checkTypeLuaBackend        = policy.CheckTypeLuaBackend
	checkTypePluginBackend     = policy.CheckTypePluginBackend
	checkTypeLuaSubjectSource  = policy.CheckTypeLuaSubjectSource
	checkTypePluginSubject     = policy.CheckTypePluginSubjectSource
	checkTypeAccountProvider   = policy.CheckTypeAccountProvider

	runIfAny             = policy.RunIfAny
	runIfAuthenticated   = policy.RunIfAuthenticated
	runIfUnauthenticated = policy.RunIfUnauthenticated

	effectKindObligation = "obligation"
	effectKindPostAction = "post_action"
	effectKindAdvice     = "advice"

	detailReasonCode          = "reason_code"
	detailStatusMessage       = "status_message"
	policyProfileGRPCList     = "grpc_list_accounts"
	policyProfileHTTPList     = "http_list_accounts"
	policyAdviceAuditReason   = "auth.advice.audit_reason"
	pluginModuleConfigRefRoot = "plugins.modules."
)

var simpleIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func configPathError(path string, message string) error {
	return config.NewValidationProblem(path, message)
}

func indexedPath(parent string, index int) string {
	return fmt.Sprintf("%s[%d]", parent, index)
}

func childPath(parent string, child string) string {
	if parent == "" {
		return child
	}

	return parent + "." + child
}

func builtinCheckTypeRegistry() map[string]policyruntime.CheckTypeDefinition {
	registry := make(map[string]policyruntime.CheckTypeDefinition)
	addCheckTypes(registry, preAuthCheckTypes())
	addCheckTypes(registry, backendCheckTypes())

	return registry
}

func addCheckTypes(
	registry map[string]policyruntime.CheckTypeDefinition,
	definitions map[string]policyruntime.CheckTypeDefinition,
) {
	maps.Copy(registry, definitions)
}

func preAuthCheckTypes() map[string]policyruntime.CheckTypeDefinition {
	return map[string]policyruntime.CheckTypeDefinition{
		checkTypeBruteForce: {
			Stage:              policy.StagePreAuth,
			Operations:         []policy.Operation{policy.OperationAuthenticate},
			ConfigRefPrefix:    "auth.controls.brute_force",
			MinimumAttributes:  []string{"auth.brute_force.triggered", "auth.brute_force.error"},
			ObserveSafeDefault: false,
		},
		checkTypeTLSEncryption: {
			Stage:              policy.StagePreAuth,
			Operations:         []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity},
			ConfigRefPrefix:    "auth.controls.tls_encryption",
			MinimumAttributes:  []string{"auth.tls.secure"},
			ObserveSafeDefault: true,
		},
		checkTypeRelayDomains: {
			Stage:              policy.StagePreAuth,
			Operations:         []policy.Operation{policy.OperationAuthenticate},
			ConfigRefPrefix:    "auth.controls.relay_domains",
			MinimumAttributes:  []string{"auth.relay_domain.present", "auth.relay_domain.known", "auth.relay_domain.error"},
			ObserveSafeDefault: true,
		},
		checkTypeRBL: {
			Stage:              policy.StagePreAuth,
			Operations:         []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity},
			ConfigRefPrefix:    "auth.controls.rbl",
			MinimumAttributes:  []string{"auth.rbl.threshold_reached", "auth.rbl.error"},
			ObserveSafeDefault: false,
		},
		checkTypeLuaEnvironment: {
			Stage:                      policy.StagePreAuth,
			Operations:                 []policy.Operation{policy.OperationAuthenticate},
			ConfigRefPrefix:            "auth.policy.attribute_sources.lua.environment.",
			ObserveSafeDefault:         false,
			AllowsObserveSafeAssertion: true,
		},
		checkTypePluginEnvironment: {
			Stage:                      policy.StagePreAuth,
			Operations:                 []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity},
			ConfigRefPrefix:            pluginModuleConfigRefRoot,
			ObserveSafeDefault:         false,
			AllowsObserveSafeAssertion: true,
		},
	}
}

func backendCheckTypes() map[string]policyruntime.CheckTypeDefinition {
	return map[string]policyruntime.CheckTypeDefinition{
		checkTypeLDAPBackend: {
			Stage:              policy.StageAuthBackend,
			Operations:         []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity},
			ConfigRefPrefix:    "auth.backends.ldap",
			MinimumAttributes:  backendMinimumAttributes(),
			ObserveSafeDefault: false,
		},
		checkTypeLuaBackend: {
			Stage:                      policy.StageAuthBackend,
			Operations:                 []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity},
			ConfigRefPrefix:            "auth.backends.lua.backend",
			MinimumAttributes:          backendMinimumAttributes(),
			ObserveSafeDefault:         false,
			AllowsObserveSafeAssertion: true,
		},
		checkTypePluginBackend: {
			Stage:                      policy.StageAuthBackend,
			Operations:                 []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity},
			ConfigRefPrefix:            "auth.backends.order",
			MinimumAttributes:          backendMinimumAttributes(),
			ObserveSafeDefault:         false,
			AllowsObserveSafeAssertion: true,
		},
		checkTypeLuaSubjectSource: {
			Stage:                      policy.StageSubjectAnalysis,
			Operations:                 []policy.Operation{policy.OperationAuthenticate},
			ConfigRefPrefix:            "auth.policy.attribute_sources.lua.subject.",
			ObserveSafeDefault:         false,
			AllowsObserveSafeAssertion: true,
		},
		checkTypePluginSubject: {
			Stage:                      policy.StageSubjectAnalysis,
			Operations:                 []policy.Operation{policy.OperationAuthenticate},
			ConfigRefPrefix:            pluginModuleConfigRefRoot,
			ObserveSafeDefault:         false,
			AllowsObserveSafeAssertion: true,
		},
		checkTypeAccountProvider: {
			Stage:              policy.StageAccountProvider,
			Operations:         []policy.Operation{policy.OperationListAccounts},
			ConfigRefPrefix:    "auth.backends",
			MinimumAttributes:  []string{"auth.account_provider.completed", "auth.account_provider.tempfail"},
			ObserveSafeDefault: false,
		},
	}
}

func builtinFSMEventRegistry() map[string]policyruntime.FSMEventDefinition {
	return map[string]policyruntime.FSMEventDefinition{
		policy.FSMEventMarkerParseOK:                  {ID: policy.FSMEventMarkerParseOK},
		policy.FSMEventMarkerParseFail:                {ID: policy.FSMEventMarkerParseFail},
		policy.FSMEventMarkerPreAuthOK:                {ID: policy.FSMEventMarkerPreAuthOK, AllowedStage: policy.StagePreAuth, PolicyVisible: true},
		policy.FSMEventMarkerPreAuthDeny:              {ID: policy.FSMEventMarkerPreAuthDeny, AllowedStage: policy.StagePreAuth, PolicyVisible: true},
		policy.FSMEventMarkerPreAuthTempFail:          {ID: policy.FSMEventMarkerPreAuthTempFail, AllowedStage: policy.StagePreAuth, PolicyVisible: true},
		policy.FSMEventMarkerPreAuthAbort:             {ID: policy.FSMEventMarkerPreAuthAbort, AllowedStage: policy.StagePreAuth, PolicyVisible: true},
		policy.FSMEventMarkerAuthEvaluated:            {ID: policy.FSMEventMarkerAuthEvaluated},
		policy.FSMEventMarkerAccountProviderEvaluated: {ID: policy.FSMEventMarkerAccountProviderEvaluated},
		policy.FSMEventMarkerAuthPermit:               {ID: policy.FSMEventMarkerAuthPermit, AllowedStage: policy.StageAuthDecision, PolicyVisible: true},
		policy.FSMEventMarkerAuthDeny:                 {ID: policy.FSMEventMarkerAuthDeny, AllowedStage: policy.StageAuthDecision, PolicyVisible: true},
		policy.FSMEventMarkerAuthTempFail:             {ID: policy.FSMEventMarkerAuthTempFail, AllowedStage: policy.StageAuthDecision, PolicyVisible: true},
		policy.FSMEventMarkerAuthEmptyUser:            {ID: policy.FSMEventMarkerAuthEmptyUser, AllowedStage: policy.StageAuthDecision, PolicyVisible: true},
		policy.FSMEventMarkerAuthEmptyPass:            {ID: policy.FSMEventMarkerAuthEmptyPass, AllowedStage: policy.StageAuthDecision, PolicyVisible: true},
		policy.FSMEventMarkerBasicAuthOK:              {ID: policy.FSMEventMarkerBasicAuthOK},
		policy.FSMEventMarkerBasicAuthFail:            {ID: policy.FSMEventMarkerBasicAuthFail},
		policy.FSMEventMarkerAbort:                    {ID: policy.FSMEventMarkerAbort},
	}
}

func builtinResponseRegistry() map[string]policyruntime.ResponseDefinition {
	commonProfiles := []string{
		"http_json",
		"http_cbor",
		"nginx_auth_request",
		"http_header",
		"http_plain",
		policyProfileHTTPList,
		"grpc_auth_service",
		"grpc_lookup_identity",
		policyProfileGRPCList,
		"idp_browser",
		"idp_oidc",
		"idp_saml",
		"idp_device",
	}

	return map[string]policyruntime.ResponseDefinition{
		policy.ResponseMarkerOK: {
			ID:       policy.ResponseMarkerOK,
			Effect:   policy.DecisionPermit,
			Profiles: append([]string(nil), commonProfiles...),
		},
		policy.ResponseMarkerFail: {
			ID:       policy.ResponseMarkerFail,
			Effect:   policy.DecisionDeny,
			Profiles: append([]string(nil), commonProfiles...),
		},
		policy.ResponseMarkerTempFail: {
			ID:       policy.ResponseMarkerTempFail,
			Effect:   policy.DecisionTempFail,
			Profiles: append([]string(nil), commonProfiles...),
		},
		policy.ResponseMarkerTempFailNoTLS: {
			ID:       policy.ResponseMarkerTempFailNoTLS,
			Effect:   policy.DecisionTempFail,
			Profiles: append([]string(nil), commonProfiles...),
		},
		policy.ResponseMarkerListAccountsOK: {
			ID:       policy.ResponseMarkerListAccountsOK,
			Effect:   policy.DecisionPermit,
			Profiles: []string{policyProfileHTTPList, policyProfileGRPCList},
		},
	}
}

func builtinObligationRegistry() map[string]policyruntime.EffectDefinition {
	return map[string]policyruntime.EffectDefinition{
		policy.ObligationBruteForceUpdate:     {ID: policy.ObligationBruteForceUpdate, Kind: effectKindObligation},
		policy.ObligationLuaActionDispatch:    {ID: policy.ObligationLuaActionDispatch, Kind: effectKindObligation},
		policy.ObligationLuaPostActionEnqueue: {ID: policy.ObligationLuaPostActionEnqueue, Kind: effectKindObligation},
		policy.ObligationClickHousePostAction: {ID: policy.ObligationClickHousePostAction, Kind: effectKindObligation},
	}
}

func builtinAdviceRegistry() map[string]policyruntime.EffectDefinition {
	return map[string]policyruntime.EffectDefinition{
		policyAdviceAuditReason: {ID: policyAdviceAuditReason, Kind: effectKindAdvice},
	}
}

// backendMinimumAttributes returns the required backend fact IDs for backend-stage checks.
func backendMinimumAttributes() []string {
	return []string{
		policy.AttributeAuthenticated,
		policy.AttributeIdentityFound,
		policy.AttributeBackendTempFail,
		policy.AttributeBackendEmptyUsername,
		policy.AttributeBackendEmptyPassword,
	}
}

func stageValid(stage policy.Stage) bool {
	switch stage {
	case policy.StagePreAuth,
		policy.StageAuthBackend,
		policy.StageSubjectAnalysis,
		policy.StageAccountProvider,
		policy.StageAuthDecision:
		return true
	default:
		return false
	}
}

func operationValid(operation policy.Operation) bool {
	switch operation {
	case policy.OperationAuthenticate,
		policy.OperationLookupIdentity,
		policy.OperationListAccounts:
		return true
	default:
		return false
	}
}

func stageOrder(stage policy.Stage) int {
	switch stage {
	case policy.StagePreAuth:
		return 0
	case policy.StageAuthBackend:
		return 1
	case policy.StageSubjectAnalysis, policy.StageAccountProvider:
		return 2
	case policy.StageAuthDecision:
		return 3
	default:
		return 99
	}
}

func stringsContain(values []string, value string) bool {
	return slices.Contains(values, value)
}

func operationsContain(values []policy.Operation, value policy.Operation) bool {
	return slices.Contains(values, value)
}

func operationsIntersect(left []policy.Operation, right []policy.Operation) bool {
	for _, operation := range left {
		if operationsContain(right, operation) {
			return true
		}
	}

	return false
}

func normalizeIdentifierFromConfigRef(prefix string, configRef string, fallback string) string {
	if after, ok := strings.CutPrefix(configRef, prefix); ok {
		return strings.TrimSpace(after)
	}

	return strings.TrimSpace(fallback)
}
