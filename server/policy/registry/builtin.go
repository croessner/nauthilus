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

import "github.com/croessner/nauthilus/v3/server/policy"

const (
	detailBackend             = "backend"
	detailBruteBucketCount    = "bucket_count"
	detailBruteBucketID       = "bucket_id"
	detailBruteBucketRatio    = "bucket_ratio"
	detailBruteClientNet      = "client_net"
	detailBruteEffectiveLimit = "effective_limit"
	detailBruteRepeating      = "repeating"
	detailBruteRule           = "rule"
	detailBruteRWPActive      = "rwp_active"
	detailReasonCode          = "reason_code"
	detailRetryable           = "retryable"
	detailSoftAllowlisted     = "soft_allowlisted"
	producerBruteForce        = policy.CheckTypeBruteForce
	producerTLSEncryption     = policy.CheckTypeTLSEncryption
	producerRelayDomains      = policy.CheckTypeRelayDomains
	producerRBL               = policy.CheckTypeRBL
	producerLDAPBackend       = policy.CheckTypeLDAPBackend
	producerLuaBackend        = policy.CheckTypeLuaBackend
	producerAccountProvider   = policy.CheckTypeAccountProvider
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
		requestAttribute(policy.AttributeRequestOperation, AttributeTypeString, allOperations),
		requestAttribute(policy.AttributeRequestTime, AttributeTypeDateTime, allOperations),
		requestAttribute(policy.AttributeRequestClientIP, AttributeTypeIP, allOperations),
		requestAttribute(policy.AttributeRequestClientIPPresent, AttributeTypeBool, allOperations),
		requestAttribute(policy.AttributeRequestClientIPTrusted, AttributeTypeBool, allOperations),
		requestAttribute(policy.AttributeRequestClientIPSource, AttributeTypeString, allOperations),
		requestAttribute(policy.AttributeRequestCallerIP, AttributeTypeIP, allOperations),
		requestAttribute(policy.AttributeRequestCallerIPPresent, AttributeTypeBool, allOperations),
		requestAttribute(policy.AttributeRequestCallerIPSource, AttributeTypeString, allOperations),
		requestAttribute(policy.AttributeRequestLocalIP, AttributeTypeIP, allOperations),
		requestAttribute(policy.AttributeRequestLocalIPPresent, AttributeTypeBool, allOperations),
		requestAttribute(policy.AttributeRequestLocalPort, AttributeTypeString, allOperations),
		requestAttribute(policy.AttributeRequestLocalPortPresent, AttributeTypeBool, allOperations),
		requestAttribute(policy.AttributeRequestProtocol, AttributeTypeString, allOperations),
		requestAttribute(policy.AttributeRequestTransportKind, AttributeTypeString, allOperations),
		requestAttribute(policy.AttributeRequestListenerName, AttributeTypeString, allOperations),
		requestAttribute(policy.AttributeRequestConnectionTLS, AttributeTypeBool, allOperations),
		requestAttribute(policy.AttributeRequestInitiatorKind, AttributeTypeString, allOperations),
		requestAttribute(policy.AttributeRequestHTTPRoute, AttributeTypeString, allOperations),
		requestAttribute(policy.AttributeRequestGRPCMethod, AttributeTypeString, allOperations),
		requestAttribute(policy.AttributeRequestIDPClientID, AttributeTypeString, allOperations),
		requestAttribute(policy.AttributeRequestSAMLServiceProviderID, AttributeTypeString, allOperations),
	}
}

func preAuthAttributes(authOnly []policy.Operation, authLookup []policy.Operation) []AttributeDefinition {
	attributes := []AttributeDefinition{bruteForceTriggeredAttribute(authOnly)}
	attributes = append(attributes, bruteForceStateAttributes(authOnly)...)
	attributes = append(attributes, bruteForceTolerationAttributes(authOnly)...)
	attributes = append(attributes, bruteForceBucketAttributes(authOnly)...)
	attributes = append(attributes, bruteForceErrorAttribute(authOnly))
	attributes = append(attributes, tlsSecureAttribute(authLookup))

	return attributes
}

// bruteForceTriggeredAttribute describes the primary pre-auth brute-force match fact.
func bruteForceTriggeredAttribute(authOnly []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            policy.AttributeBruteForceTriggered,
		Description:   "Brute-force protection matched the current request.",
		Stage:         policy.StagePreAuth,
		Operations:    authOnly,
		ProducerTypes: []string{producerBruteForce},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
		Details: map[string]DetailDefinition{
			detailBruteRule:           {Type: AttributeTypeString, Sensitivity: DetailSensitivityInternal},
			detailBruteBucketID:       {Type: AttributeTypeString, Sensitivity: DetailSensitivityInternal},
			detailBruteClientNet:      {Type: AttributeTypeCIDR, Sensitivity: DetailSensitivityInternal},
			detailBruteRepeating:      {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
			detailBruteRWPActive:      {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
			detailBruteBucketCount:    {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
			detailBruteBucketRatio:    {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
			detailBruteEffectiveLimit: {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		},
	}
}

// bruteForceStateAttributes returns pre-auth brute-force state attributes.
func bruteForceStateAttributes(authOnly []policy.Operation) []AttributeDefinition {
	return []AttributeDefinition{
		bruteForceBoolAttribute(
			policy.AttributeBruteForceRepeating,
			"Brute-force protection matched a repeating state for the current request.",
			authOnly,
		),
		bruteForceBoolAttribute(
			policy.AttributeBruteForceRWPActive,
			"Repeating-wrong-password protection is active for the current request.",
			authOnly,
		),
		bruteForceBoolAttribute(
			policy.AttributeBruteForceRWPEnforceBucketUpdate,
			"Bucket counters should be updated for the current request.",
			authOnly,
		),
	}
}

// bruteForceTolerationAttributes returns pre-auth brute-force toleration attributes.
func bruteForceTolerationAttributes(authOnly []policy.Operation) []AttributeDefinition {
	return []AttributeDefinition{
		bruteForceBoolAttribute(
			policy.AttributeBruteForceTolerationActive,
			"Brute-force toleration currently applies to the request client IP.",
			authOnly,
		),
		bruteForceStringAttribute(
			policy.AttributeBruteForceTolerationMode,
			"Brute-force toleration calculation mode for the request client IP.",
			authOnly,
		),
		bruteForceBoolAttribute(
			policy.AttributeBruteForceTolerationCustom,
			"A custom brute-force toleration matched the request client IP.",
			authOnly,
		),
		bruteForceNumberAttribute(
			policy.AttributeBruteForceTolerationPositive,
			"Positive reputation counter used by brute-force toleration.",
			authOnly,
		),
		bruteForceNumberAttribute(
			policy.AttributeBruteForceTolerationNegative,
			"Negative reputation counter used by brute-force toleration.",
			authOnly,
		),
		bruteForceNumberAttribute(
			policy.AttributeBruteForceTolerationMaxNegative,
			"Maximum negative reputation counter tolerated by brute-force toleration.",
			authOnly,
		),
		bruteForceNumberAttribute(
			policy.AttributeBruteForceTolerationPercent,
			"Effective tolerated percentage used by brute-force toleration.",
			authOnly,
		),
		bruteForceNumberAttribute(
			policy.AttributeBruteForceTolerationTTLSeconds,
			"Effective brute-force toleration TTL in seconds.",
			authOnly,
		),
		bruteForceBoolAttribute(
			policy.AttributeBruteForceTolerationSuppressedBlock,
			"Brute-force toleration suppressed a block that would otherwise have been applied.",
			authOnly,
		),
	}
}

// bruteForceBucketAttributes returns pre-auth brute-force bucket summary attributes.
func bruteForceBucketAttributes(authOnly []policy.Operation) []AttributeDefinition {
	return []AttributeDefinition{
		bruteForceNumberAttribute(
			policy.AttributeBruteForceBucketMatchedCount,
			"Number of brute-force buckets matching the current request context.",
			authOnly,
		),
		bruteForceNumberAttribute(
			policy.AttributeBruteForceBucketTriggeredCount,
			"Number of brute-force buckets in a triggered state for the current request.",
			authOnly,
		),
		bruteForceNumberAttribute(
			policy.AttributeBruteForceBucketMaxCount,
			"Highest observed brute-force bucket counter for the current request.",
			authOnly,
		),
		bruteForceNumberAttribute(
			policy.AttributeBruteForceBucketMaxRatio,
			"Highest observed brute-force bucket fill ratio for the current request.",
			authOnly,
		),
	}
}

// bruteForceErrorAttribute returns the pre-auth brute-force runtime error attribute.
func bruteForceErrorAttribute(authOnly []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            policy.AttributeBruteForceError,
		Description:   "Brute-force evaluation failed due to a technical runtime error.",
		Stage:         policy.StagePreAuth,
		Operations:    authOnly,
		ProducerTypes: []string{producerBruteForce},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
		Details:       errorDetails(true),
	}
}

// tlsSecureAttribute returns the pre-auth TLS security attribute.
func tlsSecureAttribute(authLookup []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            policy.AttributeTLSSecure,
		Description:   "The request arrived over an accepted TLS path.",
		Stage:         policy.StagePreAuth,
		Operations:    authLookup,
		ProducerTypes: []string{producerTLSEncryption},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
	}
}

func bruteForceBoolAttribute(id string, description string, operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            id,
		Description:   description,
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerBruteForce},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
		Details:       bruteForceSummaryDetails(),
	}
}

func bruteForceNumberAttribute(id string, description string, operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            id,
		Description:   description,
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerBruteForce},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeNumber,
		Source:        SourceBuiltin,
		Details:       bruteForceSummaryDetails(),
	}
}

func bruteForceStringAttribute(id string, description string, operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            id,
		Description:   description,
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerBruteForce},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeString,
		Source:        SourceBuiltin,
		Details:       bruteForceSummaryDetails(),
	}
}

func bruteForceSummaryDetails() map[string]DetailDefinition {
	return map[string]DetailDefinition{
		"rule":             {Type: AttributeTypeString, Sensitivity: DetailSensitivityInternal},
		"bucket_id":        {Type: AttributeTypeString, Sensitivity: DetailSensitivityInternal},
		"client_net":       {Type: AttributeTypeCIDR, Sensitivity: DetailSensitivityInternal},
		"matched":          {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		"repeating":        {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		"rwp_active":       {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		"toleration_mode":  {Type: AttributeTypeString, Sensitivity: DetailSensitivityInternal},
		"custom":           {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		"active":           {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		"suppressed_block": {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		"positive":         {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"negative":         {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"max_negative":     {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"percent":          {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"ttl_seconds":      {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"bucket_count":     {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"bucket_ratio":     {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"effective_limit":  {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
	}
}

func backendAttributes(authOnly []policy.Operation, authLookup []policy.Operation) []AttributeDefinition {
	return []AttributeDefinition{
		relayDomainAttribute(policy.AttributeRelayDomainPresent, "A relay domain was present in the request.", authOnly),
		relayDomainAttribute(policy.AttributeRelayDomainKnown, "The relay domain is known to the configured control.", authOnly),
		relayDomainStringAttribute(policy.AttributeRelayDomainValue, "The parsed relay domain value from the request.", authOnly),
		relayDomainAttribute(policy.AttributeRelayDomainRejected, "Relay-domain evaluation rejected the request.", authOnly),
		relayDomainAttribute(policy.AttributeRelayDomainStaticMatch, "The relay domain matched a configured static domain.", authOnly),
		relayDomainAttribute(policy.AttributeRelayDomainSoftAllowlisted, "Relay-domain evaluation was soft-allowlisted.", authOnly),
		relayDomainNumberAttribute(policy.AttributeRelayDomainConfiguredCount, "Number of configured static relay domains.", authOnly),
		relayDomainErrorAttribute(authOnly),
		rblThresholdAttribute(authLookup),
		rblNumberAttribute(policy.AttributeRBLScore, "Aggregate RBL score for the current request.", authLookup),
		rblNumberAttribute(policy.AttributeRBLThreshold, "Configured RBL threshold for the current request.", authLookup),
		rblNumberAttribute(policy.AttributeRBLMatchedCount, "Number of RBL lists that matched the current request.", authLookup),
		rblStringListAttribute(policy.AttributeRBLMatchedLists, "Names of RBL lists that matched the current request.", authLookup),
		rblNumberAttribute(policy.AttributeRBLListCount, "Number of configured RBL lists.", authLookup),
		rblNumberAttribute(policy.AttributeRBLAllowFailureErrorCount, "Number of RBL errors ignored by allow_failure.", authLookup),
		rblBoolAttribute(policy.AttributeRBLEffectiveError, "An RBL lookup error affects the decision.", authLookup),
		rblBoolAttribute(policy.AttributeRBLSoftAllowlisted, "RBL evaluation was soft-allowlisted.", authLookup),
		rblBoolAttribute(policy.AttributeRBLIPAllowlisted, "The client IP was allowlisted for RBL evaluation.", authLookup),
		rblErrorAttribute(authLookup),
		backendAttribute(policy.AttributeAuthenticated, "Backend authentication succeeded.", policy.StageAuthBackend, authOnly, AttributeCategorySubject, AttributeTypeBool, "backend"),
		backendAttribute(policy.AttributeIdentityFound, "Backend identity lookup found the requested user.", policy.StageAuthBackend, []policy.Operation{policy.OperationLookupIdentity}, AttributeCategorySubject, AttributeTypeBool, "backend"),
		backendAttribute(policy.AttributeMasterUserActive, "Authentication used configured master-user mode.", policy.StageAuthBackend, authOnly, AttributeCategorySubject, AttributeTypeBool, "backend", "master_user", "target_user"),
		backendTempfailAttribute(authLookup),
		backendAttribute(policy.AttributeBackendEmptyUsername, "The request has no username.", policy.StageAuthBackend, authLookup, AttributeCategorySubject, AttributeTypeBool),
		backendAttribute(policy.AttributeBackendEmptyPassword, "The request has no password.", policy.StageAuthBackend, authOnly, AttributeCategorySubject, AttributeTypeBool),
	}
}

func accountProviderAttributes(listOnly []policy.Operation) []AttributeDefinition {
	return []AttributeDefinition{
		{
			ID:            policy.AttributeAccountProviderCompleted,
			Description:   "Account-provider evaluation completed.",
			Stage:         policy.StageAccountProvider,
			Operations:    listOnly,
			ProducerTypes: []string{producerAccountProvider},
			Category:      AttributeCategoryResource,
			Type:          AttributeTypeBool,
			Source:        SourceBuiltin,
			Details: map[string]DetailDefinition{
				"count": {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
			},
		},
		{
			ID:            policy.AttributeAccountProviderTempFail,
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

func relayDomainStringAttribute(id string, description string, operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            id,
		Description:   description,
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerRelayDomains},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeString,
		Source:        SourceBuiltin,
		Details:       domainDetails(),
	}
}

func relayDomainNumberAttribute(id string, description string, operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            id,
		Description:   description,
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerRelayDomains},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeNumber,
		Source:        SourceBuiltin,
		Details:       domainDetails(),
	}
}

func relayDomainErrorAttribute(operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            policy.AttributeRelayDomainError,
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

func rblNumberAttribute(id string, description string, operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            id,
		Description:   description,
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerRBL},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeNumber,
		Source:        SourceBuiltin,
		Details:       rblSummaryDetails(),
	}
}

func rblBoolAttribute(id string, description string, operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            id,
		Description:   description,
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerRBL},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
		Details:       rblSummaryDetails(),
	}
}

func rblStringListAttribute(id string, description string, operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            id,
		Description:   description,
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerRBL},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeStringList,
		Source:        SourceBuiltin,
		Details:       rblSummaryDetails(),
	}
}

func rblThresholdAttribute(operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            policy.AttributeRBLThresholdReached,
		Description:   "RBL evaluation reached the configured rejection threshold.",
		Stage:         policy.StagePreAuth,
		Operations:    operations,
		ProducerTypes: []string{producerRBL},
		Category:      AttributeCategoryEnvironment,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
		Details:       rblSummaryDetails(),
	}
}

func rblErrorAttribute(operations []policy.Operation) AttributeDefinition {
	return AttributeDefinition{
		ID:            policy.AttributeRBLError,
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
		ID:            policy.AttributeBackendTempFail,
		Description:   "Backend evaluation failed due to a temporary technical runtime error.",
		Stage:         policy.StageAuthBackend,
		Operations:    operations,
		ProducerTypes: []string{producerLDAPBackend, producerLuaBackend},
		Category:      AttributeCategoryResource,
		Type:          AttributeTypeBool,
		Source:        SourceBuiltin,
		Details: map[string]DetailDefinition{
			detailBackend:    {Type: AttributeTypeString, Sensitivity: DetailSensitivityInternal},
			detailReasonCode: {Type: AttributeTypeString, Sensitivity: DetailSensitivityInternal},
			detailRetryable:  {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
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
			definition.Details[name] = DetailDefinition{Type: AttributeTypeString, Sensitivity: DetailSensitivityInternal}
		}
	}

	return definition
}

func errorDetails(includeRetryable bool) map[string]DetailDefinition {
	details := map[string]DetailDefinition{
		detailReasonCode: {Type: AttributeTypeString, Sensitivity: DetailSensitivityInternal},
	}

	if includeRetryable {
		details[detailRetryable] = DetailDefinition{Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal}
	}

	return details
}

func domainDetails() map[string]DetailDefinition {
	return map[string]DetailDefinition{
		"domain":              {Type: AttributeTypeString, Sensitivity: DetailSensitivityInternal},
		"matched_domain":      {Type: AttributeTypeString, Sensitivity: DetailSensitivityInternal},
		"configured_count":    {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"present":             {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		"known":               {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		"rejected":            {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		"static_match":        {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		detailSoftAllowlisted: {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
	}
}

func rblSummaryDetails() map[string]DetailDefinition {
	return map[string]DetailDefinition{
		"lists":                     {Type: AttributeTypeStringList, Sensitivity: DetailSensitivityInternal},
		"score":                     {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"threshold":                 {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"matched_count":             {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"list_count":                {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"allow_failure_error_count": {Type: AttributeTypeNumber, Sensitivity: DetailSensitivityInternal},
		"effective_error":           {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		detailSoftAllowlisted:       {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
		"ip_allowlisted":            {Type: AttributeTypeBool, Sensitivity: DetailSensitivityInternal},
	}
}
