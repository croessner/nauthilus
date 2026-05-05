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
	"regexp"
	"strings"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/policy"
	policyruntime "github.com/croessner/nauthilus/server/policy/runtime"
)

const (
	checkTypeBruteForce      = policy.CheckTypeBruteForce
	checkTypeTLSEncryption   = policy.CheckTypeTLSEncryption
	checkTypeRelayDomains    = policy.CheckTypeRelayDomains
	checkTypeRBL             = policy.CheckTypeRBL
	checkTypeLuaControl      = policy.CheckTypeLuaControl
	checkTypeLDAPBackend     = policy.CheckTypeLDAPBackend
	checkTypeLuaBackend      = policy.CheckTypeLuaBackend
	checkTypeLuaFilter       = policy.CheckTypeLuaFilter
	checkTypeAccountProvider = policy.CheckTypeAccountProvider

	runIfAny             = policy.RunIfAny
	runIfAuthenticated   = policy.RunIfAuthenticated
	runIfUnauthenticated = policy.RunIfUnauthenticated
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
	for checkType, definition := range definitions {
		registry[checkType] = definition
	}
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
		checkTypeLuaControl: {
			Stage:                      policy.StagePreAuth,
			Operations:                 []policy.Operation{policy.OperationAuthenticate},
			ConfigRefPrefix:            "auth.controls.lua.controls.",
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
			MinimumAttributes:  []string{"auth.authenticated", "auth.identity.found", "auth.backend.tempfail", "auth.backend.empty_username", "auth.backend.empty_password"},
			ObserveSafeDefault: false,
		},
		checkTypeLuaBackend: {
			Stage:                      policy.StageAuthBackend,
			Operations:                 []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity},
			ConfigRefPrefix:            "auth.backends.lua.backend",
			MinimumAttributes:          []string{"auth.authenticated", "auth.identity.found", "auth.backend.tempfail", "auth.backend.empty_username", "auth.backend.empty_password"},
			ObserveSafeDefault:         false,
			AllowsObserveSafeAssertion: true,
		},
		checkTypeLuaFilter: {
			Stage:                      policy.StageAuthFilters,
			Operations:                 []policy.Operation{policy.OperationAuthenticate},
			ConfigRefPrefix:            "auth.controls.lua.filters.",
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
		"http_list_accounts",
		"grpc_auth_service",
		"grpc_lookup_identity",
		"grpc_list_accounts",
		"idp_browser",
		"idp_oidc",
		"idp_saml",
		"idp_device",
	}

	return map[string]policyruntime.ResponseDefinition{
		"auth.response.ok": {
			ID:       "auth.response.ok",
			Effect:   policy.DecisionPermit,
			Profiles: append([]string(nil), commonProfiles...),
		},
		"auth.response.fail": {
			ID:       "auth.response.fail",
			Effect:   policy.DecisionDeny,
			Profiles: append([]string(nil), commonProfiles...),
		},
		"auth.response.tempfail": {
			ID:       "auth.response.tempfail",
			Effect:   policy.DecisionTempFail,
			Profiles: append([]string(nil), commonProfiles...),
		},
		"auth.response.tempfail.no_tls": {
			ID:       "auth.response.tempfail.no_tls",
			Effect:   policy.DecisionTempFail,
			Profiles: append([]string(nil), commonProfiles...),
		},
		"auth.response.list_accounts.ok": {
			ID:       "auth.response.list_accounts.ok",
			Effect:   policy.DecisionPermit,
			Profiles: []string{"http_list_accounts", "grpc_list_accounts"},
		},
	}
}

func builtinObligationRegistry() map[string]policyruntime.EffectDefinition {
	return map[string]policyruntime.EffectDefinition{
		"auth.obligation.brute_force.update":      {ID: "auth.obligation.brute_force.update", Kind: "obligation"},
		"auth.obligation.lua_post_action.enqueue": {ID: "auth.obligation.lua_post_action.enqueue", Kind: "obligation"},
	}
}

func builtinAdviceRegistry() map[string]policyruntime.EffectDefinition {
	return map[string]policyruntime.EffectDefinition{
		"auth.advice.audit_reason": {ID: "auth.advice.audit_reason", Kind: "advice"},
	}
}

func stageValid(stage policy.Stage) bool {
	switch stage {
	case policy.StagePreAuth,
		policy.StageAuthBackend,
		policy.StageAuthFilters,
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
	case policy.StageAuthFilters, policy.StageAccountProvider:
		return 2
	case policy.StageAuthDecision:
		return 3
	default:
		return 99
	}
}

func stringsContain(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}

	return false
}

func operationsContain(values []policy.Operation, value policy.Operation) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}

	return false
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
	if strings.HasPrefix(configRef, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(configRef, prefix))
	}

	return strings.TrimSpace(fallback)
}
