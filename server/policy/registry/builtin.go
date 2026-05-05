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

package registry

import "github.com/croessner/nauthilus/server/policy"

const (
	producerBruteForce      = "builtin.brute_force"
	producerTLSEncryption   = "builtin.tls_encryption"
	producerRelayDomains    = "builtin.relay_domains"
	producerRBL             = "builtin.rbl"
	producerLDAPBackend     = "backend.ldap"
	producerLuaBackend      = "backend.lua"
	producerAccountProvider = "backend.account_provider"
)

// NewBuiltinAttributeRegistry returns the minimum Go-owned attribute registry.
func NewBuiltinAttributeRegistry() (*AttributeRegistry, error) {
	registry := NewAttributeRegistry()
	for _, definition := range builtinAttributeDefinitions() {
		if err := registry.Register(definition); err != nil {
			return nil, err
		}
	}

	return registry, nil
}

func builtinAttributeDefinitions() []AttributeDefinition {
	operations := newOperationSets()
	definitions := requestAttributes(operations.all)
	definitions = append(definitions, preAuthAttributes(operations.authOnly, operations.authLookup)...)
	definitions = append(definitions, backendAttributes(operations.authOnly, operations.authLookup)...)
	definitions = append(definitions, accountProviderAttributes(operations.listOnly)...)

	return definitions
}

type operationSets struct {
	all        []policy.Operation
	authOnly   []policy.Operation
	authLookup []policy.Operation
	listOnly   []policy.Operation
}

func newOperationSets() operationSets {
	return operationSets{
		all: []policy.Operation{
			policy.OperationAuthenticate,
			policy.OperationLookupIdentity,
			policy.OperationListAccounts,
		},
		authOnly:   []policy.Operation{policy.OperationAuthenticate},
		authLookup: []policy.Operation{policy.OperationAuthenticate, policy.OperationLookupIdentity},
		listOnly:   []policy.Operation{policy.OperationListAccounts},
	}
}

func requestAttributes(allOperations []policy.Operation) []AttributeDefinition {
	return []AttributeDefinition{
		requestAttribute("request.operation", AttributeTypeString, allOperations),
		requestAttribute("request.time.now", AttributeTypeDateTime, allOperations),
		requestAttribute("request.client.ip", AttributeTypeIP, allOperations),
		requestAttribute("request.protocol", AttributeTypeString, allOperations),
	}
}

func preAuthAttributes(authOnly []policy.Operation, authLookup []policy.Operation) []AttributeDefinition {
	return []AttributeDefinition{
		{
			ID:            "auth.brute_force.triggered",
			Description:   "Brute-force protection matched the current request.",
			Stage:         policy.StagePreAuth,
			Operations:    authOnly,
			ProducerTypes: []string{producerBruteForce},
			Category:      AttributeCategoryEnvironment,
			Type:          AttributeTypeBool,
			Source:        SourceBuiltin,
			Details: map[string]DetailDefinition{
				"rule":       {Type: AttributeTypeString, Sensitivity: "internal"},
				"client_net": {Type: AttributeTypeCIDR, Sensitivity: "internal"},
				"repeating":  {Type: AttributeTypeBool, Sensitivity: "internal"},
			},
		},
		{
			ID:            "auth.brute_force.error",
			Description:   "Brute-force evaluation failed due to a technical runtime error.",
			Stage:         policy.StagePreAuth,
			Operations:    authOnly,
			ProducerTypes: []string{producerBruteForce},
			Category:      AttributeCategoryEnvironment,
			Type:          AttributeTypeBool,
			Source:        SourceBuiltin,
			Details:       errorDetails(true),
		},
		{
			ID:            "auth.tls.secure",
			Description:   "The request arrived over an accepted TLS path.",
			Stage:         policy.StagePreAuth,
			Operations:    authLookup,
			ProducerTypes: []string{producerTLSEncryption},
			Category:      AttributeCategoryEnvironment,
			Type:          AttributeTypeBool,
			Source:        SourceBuiltin,
		},
	}
}

func backendAttributes(authOnly []policy.Operation, authLookup []policy.Operation) []AttributeDefinition {
	return []AttributeDefinition{
		relayDomainAttribute("auth.relay_domain.present", "A relay domain was present in the request.", authOnly),
		relayDomainAttribute("auth.relay_domain.known", "The relay domain is known to the configured control.", authOnly),
		relayDomainErrorAttribute(authOnly),
		rblThresholdAttribute(authLookup),
		rblErrorAttribute(authLookup),
		backendAttribute("auth.authenticated", "Backend authentication succeeded.", policy.StageAuthBackend, authOnly, AttributeCategorySubject, AttributeTypeBool, "backend"),
		backendAttribute("auth.identity.found", "Backend identity lookup found the requested user.", policy.StageAuthBackend, []policy.Operation{policy.OperationLookupIdentity}, AttributeCategorySubject, AttributeTypeBool, "backend"),
		backendTempfailAttribute(authLookup),
		backendAttribute("auth.backend.empty_username", "The request has no username.", policy.StageAuthBackend, authLookup, AttributeCategorySubject, AttributeTypeBool),
		backendAttribute("auth.backend.empty_password", "The request has no password.", policy.StageAuthBackend, authOnly, AttributeCategorySubject, AttributeTypeBool),
	}
}

func accountProviderAttributes(listOnly []policy.Operation) []AttributeDefinition {
	return []AttributeDefinition{
		{
			ID:            "auth.account_provider.completed",
			Description:   "Account-provider evaluation completed.",
			Stage:         policy.StageAccountProvider,
			Operations:    listOnly,
			ProducerTypes: []string{producerAccountProvider},
			Category:      AttributeCategoryResource,
			Type:          AttributeTypeBool,
			Source:        SourceBuiltin,
			Details: map[string]DetailDefinition{
				"count": {Type: AttributeTypeNumber, Sensitivity: "internal"},
			},
		},
		{
			ID:            "auth.account_provider.tempfail",
			Description:   "Account-provider evaluation failed temporarily.",
			Stage:         policy.StageAccountProvider,
			Operations:    listOnly,
			ProducerTypes: []string{producerAccountProvider},
			Category:      AttributeCategoryResource,
			Type:          AttributeTypeBool,
			Source:        SourceBuiltin,
			Details:       errorDetails(true),
		},
	}
}

func relayDomainAttribute(id string, description string, operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            id,
		Description:   description,
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerRelayDomains},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
		Details:       domainDetails(),
	}
}

func relayDomainErrorAttribute(operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            "auth.relay_domain.error",
		Description:   "Relay-domain evaluation failed due to a technical runtime error.",
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerRelayDomains},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
		Details:       errorDetails(true),
	}
}

func rblThresholdAttribute(operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            "auth.rbl.threshold_reached",
		Description:   "RBL evaluation reached the configured rejection threshold.",
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerRBL},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
		Details: map[string]DetailDefinition{
			"lists": {Type: AttributeTypeStringList, Sensitivity: "internal"},
		},
	}
}

func rblErrorAttribute(operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            "auth.rbl.error",
		Description:   "RBL evaluation failed due to a technical runtime error.",
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerRBL},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
		Details:       errorDetails(true),
	}
}

func backendTempfailAttribute(operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            "auth.backend.tempfail",
		Description:   "Backend evaluation failed due to a temporary technical runtime error.",
		Stage:         policy.StageAuthBackend,
		Operations:    operations,
		ProducerTypes: []string{producerLDAPBackend, producerLuaBackend},
		Category:      AttributeCategoryResource,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
		Details: map[string]DetailDefinition{
			"backend":     {Type: AttributeTypeString, Sensitivity: "internal"},
			"reason_code": {Type: AttributeTypeString, Sensitivity: "internal"},
			"retryable":   {Type: AttributeTypeBool, Sensitivity: "internal"},
		},
	}
}

func requestAttribute(id string, valueType AttributeType, operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:          id,
		Description: id,
		Stage:       policy.StagePreAuth,
		Operations:  operations,
		Category:    AttributeCategoryEnvironment,
		Type:        valueType,
		Source:      SourceBuiltin,
	}
}

func backendAttribute(
	id string,
	description string,
	stage policy.Stage,
	operations []policy.Operation,
	category AttributeCategory,
	valueType AttributeType,
	details ...string,
) AttributeDefinition {
	definition := AttributeDefinition{
		ID:            id,
		Description:   description,
		Stage:         stage,
		Operations:    operations,
		ProducerTypes: []string{producerLDAPBackend, producerLuaBackend},
		Category:      category,
		Type:          valueType,
		Source:        SourceBuiltin,
	}

	if len(details) > 0 {
		definition.Details = make(map[string]DetailDefinition, len(details))
		for _, name := range details {
			definition.Details[name] = DetailDefinition{Type: AttributeTypeString, Sensitivity: "internal"}
		}
	}

	return definition
}

func errorDetails(includeRetryable bool) map[string]DetailDefinition {
	details := map[string]DetailDefinition{
		"reason_code": {Type: AttributeTypeString, Sensitivity: "internal"},
	}

	if includeRetryable {
		details["retryable"] = DetailDefinition{Type: AttributeTypeBool, Sensitivity: "internal"}
	}

	return details
}

func domainDetails() map[string]DetailDefinition {
	return map[string]DetailDefinition{
		"domain": {Type: AttributeTypeString, Sensitivity: "internal"},
	}
}
