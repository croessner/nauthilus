// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyconfig

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/text/language"
)

var (
	// ErrValidation identifies a semantic unified policy contract violation.
	ErrValidation = errors.New("invalid standalone policy configuration")

	exactSchemaPattern       = regexp.MustCompile(`^([a-z0-9_]+(?:\.[a-z0-9_]+)*)/([a-z0-9]+(?:[-_][a-z0-9]+)*)/v([1-9][0-9]*)$`)
	metadataKeyPattern       = regexp.MustCompile(`^[0-9a-z_.-]+$`)
	policyConditionSetName   = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	unsafeRequestSourceNames = map[string]struct{}{
		"authorization":       {},
		"proxy-authorization": {},
		"cookie":              {},
		"set-cookie":          {},
	}
)

const (
	authnNamespace               = "authn"
	providerFailureIndeterminate = "indeterminate"
	providerFailureContinue      = "continue"
	executionReturnOnly          = "return_only"
	executionHostSync            = "host_sync"
	executionHostPostAction      = "host_post_action"
	effectKindAdvice             = "advice"
	keywordAny                   = "any"
	keywordPlugin                = "plugin"
	decisionDeny                 = "deny"
	decisionNotApplicable        = "not_applicable"
	requestHeaderFactPrefix      = "request.header."
	requestMetadataFactPrefix    = "request.metadata."
	requestFactVisibility        = "public"
	providerKindLuaEnvironment   = "lua_environment"
	providerKindLuaSubject       = "lua_subject"
	effectKindLuaAction          = "lua_action"
	luaActionTypeLua             = "lua"
	luaActionTypePost            = "post"
	pluginBindingEnvironment     = "environment"
	pluginBindingSubject         = "subject"
	valueTypeString              = "string"
	luaEnvironmentPrefix         = "lua_environment_"
	luaSubjectPrefix             = "lua_subject_"
	luaActionPrefix              = "lua_action_"
)

// Validate enforces path-aware semantic invariants on an isolated document.
func Validate(document Document) error {
	document = Normalize(document)

	if err := validateAPI(document.Policy.API); err != nil {
		return err
	}

	if err := validateNamespaces(document.Policy.Namespaces); err != nil {
		return err
	}

	if err := validateTargets(document.Policy.Targets); err != nil {
		return err
	}

	if err := validateConfiguredReferences(document); err != nil {
		return err
	}

	if err := validateProviderBudgets(document); err != nil {
		return err
	}

	return validateDiagnosticAliases(document)
}

// validateAPI validates global bounds and dedicated client profiles.
func validateAPI(api APIConfig) error {
	if api.GRPC.RequireMTLS && !api.GRPC.Enabled {
		return invalid("policy.api.grpc.require_mtls", "requires the gRPC transport to be enabled")
	}

	if err := validateAPILimits(api.Limits); err != nil {
		return err
	}

	principals := make(map[string]struct{}, len(api.Clients))
	usernames := make(map[string]struct{}, len(api.Clients))

	for index, client := range api.Clients {
		path := fmt.Sprintf("policy.api.clients[%d]", index)
		if err := validateClientProfile(client, api.Limits, path); err != nil {
			return err
		}

		if _, exists := principals[client.Principal]; exists {
			return invalid(path+".principal", "must be unique")
		}

		principals[client.Principal] = struct{}{}
		if client.Authentication.Basic == nil {
			continue
		}

		username := client.Authentication.Basic.Username
		if _, exists := usernames[username]; exists {
			return invalid(path+".authentication.basic.username", "must be unique across Policy-Basic profiles")
		}

		usernames[username] = struct{}{}
	}

	return nil
}

// validateAPILimits rejects negative or incomplete configured server bounds.
func validateAPILimits(limits APILimitsConfig) error {
	integerLimits := []struct {
		path  string
		value int
	}{
		{"max_request_bytes", limits.MaxRequestBytes},
		{"max_facts", limits.MaxFacts},
		{"max_string_bytes", limits.MaxStringBytes},
		{"max_list_items", limits.MaxListItems},
		{"max_value_bytes", limits.MaxValueBytes},
		{"per_client_concurrency", limits.PerClientConcurrency},
		{"per_client_requests_per_second", limits.PerClientRequestsPerSecond},
		{"max_obligations", limits.MaxObligations},
		{"max_advice", limits.MaxAdvice},
		{"max_parameter_bytes", limits.MaxParameterBytes},
	}

	for _, limit := range integerLimits {
		if limit.value < 0 {
			return invalid("policy.api.limits."+limit.path, "must not be negative")
		}
	}

	if limits.ProviderTimeout < 0 {
		return invalid("policy.api.limits.provider_timeout", "must not be negative")
	}

	if limits.EvaluationTimeout < 0 {
		return invalid("policy.api.limits.evaluation_timeout", "must not be negative")
	}

	return nil
}

// validateClientProfile validates one principal-owned admission boundary.
func validateClientProfile(client ClientProfileConfig, limits APILimitsConfig, path string) error {
	if strings.TrimSpace(client.Principal) == "" {
		return invalid(path+".principal", "must be non-empty")
	}

	authenticationKinds, err := validateClientAuthenticationKinds(client.AuthenticationKinds, path+".authentication_kinds")
	if err != nil {
		return err
	}

	if err := validateClientAuthentication(client.Authentication, authenticationKinds, path+".authentication"); err != nil {
		return err
	}

	if err := validateClientTargets(client.Targets, path+".targets"); err != nil {
		return err
	}

	if err := validateClientAttributeAllowlists(client, path); err != nil {
		return err
	}

	if err := validateClientAllowedSchemas(client.AllowedSchemas, path+".allowed_schemas"); err != nil {
		return err
	}

	return validateClientLimits(client, limits, path)
}

// validateClientAuthenticationKinds validates one non-empty set of supported authentication kinds.
func validateClientAuthenticationKinds(kinds []string, path string) (map[string]struct{}, error) {
	if len(kinds) == 0 {
		return nil, invalid(path, "must contain at least one authentication kind")
	}

	uniqueKinds := make(map[string]struct{}, len(kinds))
	for index, kind := range kinds {
		kindPath := fmt.Sprintf("%s[%d]", path, index)
		if kind != policy.CallerAuthenticationKindBearer && kind != policy.CallerAuthenticationKindBasic {
			return nil, invalid(kindPath, "must be oidc_bearer or basic")
		}

		if _, exists := uniqueKinds[kind]; exists {
			return nil, invalid(kindPath, "must not duplicate an authentication kind")
		}

		uniqueKinds[kind] = struct{}{}
	}

	return uniqueKinds, nil
}

// validateClientAuthentication enforces profile ownership of dedicated Policy-Basic material.
func validateClientAuthentication(authentication ClientAuthenticationConfig, kinds map[string]struct{}, path string) error {
	_, basicEnabled := kinds[policy.CallerAuthenticationKindBasic]
	if basicEnabled && authentication.Basic == nil {
		return invalid(path+".basic", "must be configured for the basic authentication kind")
	}

	if !basicEnabled && authentication.Basic != nil {
		return invalid(path+".basic", "requires the basic authentication kind")
	}

	if authentication.Basic == nil {
		return nil
	}

	if strings.TrimSpace(authentication.Basic.Username) == "" {
		return invalid(path+".basic.username", "must be non-empty")
	}

	if authentication.Basic.Password.IsZero() {
		return invalid(path+".basic.password", "must be non-empty")
	}

	return nil
}

// validateClientTargets validates namespace/action admission references.
func validateClientTargets(targets []ClientTargetConfig, path string) error {
	seenTargets := make(map[string]struct{}, len(targets))
	seenActions := make(map[string]struct{})

	for index, target := range targets {
		targetPath := fmt.Sprintf("%s[%d]", path, index)

		if !validNamespace(target.Namespace) {
			return invalid(targetPath+".namespace", "must be a canonical namespace")
		}

		if len(target.Actions) == 0 {
			return invalid(targetPath+".actions", "must contain at least one exact action")
		}

		for actionIndex, action := range target.Actions {
			actionPath := fmt.Sprintf("%s.actions[%d]", targetPath, actionIndex)

			if !validAction(action) {
				return invalid(actionPath, "must be a canonical action")
			}

			qualifiedAction := target.Namespace + "/" + action

			if _, exists := seenActions[qualifiedAction]; exists {
				return invalid(actionPath, "must not duplicate an action grant")
			}

			seenActions[qualifiedAction] = struct{}{}
		}

		if _, exists := seenTargets[target.Namespace]; exists {
			return invalid(targetPath+".namespace", "must not duplicate a target grant")
		}

		seenTargets[target.Namespace] = struct{}{}
	}

	return nil
}

// validateClientAttributeAllowlists validates category-relative caller fact identities.
func validateClientAttributeAllowlists(client ClientProfileConfig, path string) error {
	allowlists := []struct {
		attributes []string
		category   string
		path       string
	}{
		{client.AllowedSubjectAttributes, string(decision.FactCategorySubject), path + ".allowed_subject_attributes"},
		{client.AllowedResourceAttributes, string(decision.FactCategoryResource), path + ".allowed_resource_attributes"},
		{client.AllowedEnvironmentAttributes, string(decision.FactCategoryEnvironment), path + ".allowed_environment_attributes"},
		{client.AllowedInputAttributes, "input", path + ".allowed_input_attributes"},
	}

	for _, allowlist := range allowlists {
		if err := validateClientAttributeAllowlist(allowlist.attributes, allowlist.category, allowlist.path); err != nil {
			return err
		}
	}

	return nil
}

// validateClientAttributeAllowlist rejects non-canonical, trusted, and duplicate relative attributes.
func validateClientAttributeAllowlist(attributes []string, category string, path string) error {
	seen := make(map[string]struct{}, len(attributes))

	for index, attribute := range attributes {
		attributePath := fmt.Sprintf("%s[%d]", path, index)
		prefix, _, _ := strings.Cut(attribute, ".")

		if decision.FactSource(prefix).IsValid() {
			return invalid(attributePath, "trusted fact families cannot be caller supplied")
		}

		canonical := category + "." + attribute
		if !validFact(canonical) {
			return invalid(attributePath, "must form a canonical caller fact under its category")
		}

		if _, exists := seen[canonical]; exists {
			return invalid(attributePath, "must not duplicate an allowed attribute")
		}

		seen[canonical] = struct{}{}
	}

	return nil
}

// validateClientAllowedSchemas validates unique exact schema references.
func validateClientAllowedSchemas(schemas []string, path string) error {
	seen := make(map[string]struct{}, len(schemas))

	for index, schema := range schemas {
		schemaPath := fmt.Sprintf("%s[%d]", path, index)

		if _, _, err := parseExactSchemaReference(schema, schemaPath); err != nil {
			return err
		}

		if _, exists := seen[schema]; exists {
			return invalid(schemaPath, "must not duplicate an allowed schema")
		}

		seen[schema] = struct{}{}
	}

	return nil
}

// validateClientLimits checks every profile override against its global bound.
func validateClientLimits(client ClientProfileConfig, limits APILimitsConfig, path string) error {
	clientLimits := []struct {
		path        string
		serverValue int
		value       int
	}{
		{path + ".max_request_bytes", limits.MaxRequestBytes, client.MaxRequestBytes},
		{path + ".max_facts", limits.MaxFacts, client.MaxFacts},
		{path + ".max_concurrency", limits.PerClientConcurrency, client.MaxConcurrency},
		{path + ".requests_per_second", limits.PerClientRequestsPerSecond, client.RequestsPerSecond},
	}

	for _, limit := range clientLimits {
		if err := validateClientLimit(limit.value, limit.serverValue, limit.path); err != nil {
			return err
		}
	}

	return nil
}

// validateClientLimit keeps a per-client limit non-negative and no broader than a configured server limit.
func validateClientLimit(value int, serverValue int, path string) error {
	if value < 0 {
		return invalid(path, "must not be negative")
	}

	if serverValue > 0 && value > serverValue {
		return invalid(path, "must not exceed the server limit")
	}

	return nil
}

// validateNamespaces validates namespace-owned definitions in stable path order.
func validateNamespaces(namespaces map[string]NamespaceConfig) error {
	for _, namespaceName := range sortedNamespaceNames(namespaces) {
		path := "policy.namespaces." + namespaceName
		if !validNamespace(namespaceName) {
			return invalid(path, "must be a canonical namespace")
		}

		if err := validateNamespace(namespaceName, namespaces[namespaceName], path); err != nil {
			return err
		}
	}

	return nil
}

// validateNamespace delegates every namespace-owned definition family.
func validateNamespace(namespaceName string, namespace NamespaceConfig, path string) error {
	validators := []func() error{
		func() error { return validateLocalization(namespace.Localization, path+".localization") },
		func() error { return validateConditionSets(namespace.ConditionSets, path+".condition_sets") },
		func() error {
			return validateSchemaContributions(namespace.SchemaContributions, path+".schema_contributions")
		},
		func() error {
			return validateStaticSchemas(namespaceName, namespace.SchemaContributions.Static, path+".schema_contributions.static")
		},
		func() error { return validateFactSources(namespace.FactSources, path+".fact_sources") },
		func() error { return validateProviders(namespaceName, namespace.Providers, path+".providers") },
		func() error { return validateEffects(namespaceName, namespace.Effects, path+".effects") },
		func() error { return validateDomainPlans(namespaceName, namespace, path+".domain_plans") },
		func() error { return validatePolicySets(namespaceName, namespace.PolicySets, path+".policy_sets") },
	}

	for _, validator := range validators {
		if err := validator(); err != nil {
			return err
		}
	}

	return nil
}

// validateLocalization preserves unique, bounded translation catalog semantics.
func validateLocalization(localization LocalizationConfig, path string) error {
	seen := make(map[string]struct{}, len(localization.Catalogs))

	for index, catalog := range localization.Catalogs {
		catalogPath := fmt.Sprintf("%s.catalogs[%d]", path, index)
		if err := validateLocalizationCatalog(catalog, catalogPath); err != nil {
			return err
		}

		identity := catalog.Namespace + "\x00" + catalog.Language
		if _, exists := seen[identity]; exists {
			return invalid(catalogPath, "duplicates an existing namespace and language catalog")
		}

		seen[identity] = struct{}{}

		if err := validateLocalizationEntries(catalog.Entries, catalogPath+".entries"); err != nil {
			return err
		}
	}

	return nil
}

// validateLocalizationCatalog checks one bounded catalog before duplicate detection.
func validateLocalizationCatalog(catalog TranslationCatalogConfig, path string) error {
	if strings.TrimSpace(catalog.Namespace) == "" || len(catalog.Namespace) > 64 || !printableASCII(catalog.Namespace) {
		return invalid(path+".namespace", "must be non-empty bounded printable ASCII")
	}

	if strings.TrimSpace(catalog.Language) == "" || len(catalog.Language) > 35 || !printableASCII(catalog.Language) {
		return invalid(path+".language", "must be a bounded BCP 47 language tag")
	}

	if _, err := language.Parse(catalog.Language); err != nil {
		return invalid(path+".language", "must be a valid BCP 47 language tag")
	}

	if catalog.Entries == nil {
		return invalid(path+".entries", "must be present")
	}

	if len(catalog.Entries) > 1024 {
		return invalid(path+".entries", "must not contain more than 1024 messages")
	}

	return nil
}

// validateLocalizationEntries checks stable non-empty message keys and bounded values.
func validateLocalizationEntries(entries map[string]string, path string) error {
	for _, key := range sortedMapKeys(entries) {
		if strings.TrimSpace(key) == "" {
			return invalid(path, "message key must not be blank")
		}

		entryPath := path + "." + key
		if len(key) > 256 {
			return invalid(entryPath, "message key must not exceed 256 bytes")
		}

		message := entries[key]
		if strings.TrimSpace(message) == "" {
			return invalid(entryPath, "message must not be blank")
		}

		if len(message) > 4096 {
			return invalid(entryPath, "message must not exceed 4096 bytes")
		}
	}

	return nil
}

// validateConditionSets preserves typed network, string, and local-time operands.
func validateConditionSets(sets ConditionSetsConfig, path string) error {
	if err := validateNetworkConditionSets(sets.Networks, path+".networks"); err != nil {
		return err
	}

	if err := validateStringConditionSets(sets.Strings, path+".strings"); err != nil {
		return err
	}

	for _, name := range sortedTimeWindowNames(sets.TimeWindows) {
		window := sets.TimeWindows[name]

		windowPath := path + ".time_windows." + name
		if !validConditionSetName(name) {
			return invalid(windowPath, "must use a canonical local name")
		}

		if _, err := time.LoadLocation(window.Timezone); err != nil {
			return invalid(windowPath+".timezone", "must be an IANA timezone name")
		}

		for index, day := range window.Days {
			if !validWeekday(day) {
				return invalid(fmt.Sprintf("%s.days[%d]", windowPath, index), "must be one of mon, tue, wed, thu, fri, sat, or sun")
			}
		}

		for index, interval := range window.Intervals {
			intervalPath := fmt.Sprintf("%s.intervals[%d]", windowPath, index)

			start, err := parseClockMinute(interval.Start)
			if err != nil {
				return invalid(intervalPath+".start", "must use HH:MM")
			}

			end, err := parseClockMinute(interval.End)
			if err != nil {
				return invalid(intervalPath+".end", "must use HH:MM")
			}

			if end <= start {
				return invalid(intervalPath, "must not cross midnight")
			}
		}
	}

	return nil
}

// validateNetworkConditionSets checks canonical names and every IP or CIDR operand.
func validateNetworkConditionSets(sets map[string][]string, path string) error {
	for _, name := range sortedMapKeys(sets) {
		setPath := path + "." + name
		if !validConditionSetName(name) {
			return invalid(setPath, "must use lowercase letters, digits, and underscores")
		}

		for index, entry := range sets[name] {
			if !validNetworkOperand(entry) {
				return invalid(fmt.Sprintf("%s[%d]", setPath, index), "must be an IP address or CIDR")
			}
		}
	}

	return nil
}

// validateStringConditionSets checks non-empty exact values without duplicates.
func validateStringConditionSets(sets map[string][]string, path string) error {
	for _, name := range sortedMapKeys(sets) {
		setPath := path + "." + name
		if !validConditionSetName(name) {
			return invalid(setPath, "must use lowercase letters, digits, and underscores")
		}

		entries := sets[name]
		if len(entries) == 0 {
			return invalid(setPath, "must not be empty")
		}

		seen := make(map[string]struct{}, len(entries))
		for index, entry := range entries {
			entryPath := fmt.Sprintf("%s[%d]", setPath, index)
			if strings.TrimSpace(entry) == "" {
				return invalid(entryPath, "must not be empty")
			}

			if _, exists := seen[entry]; exists {
				return invalid(entryPath, "duplicates an earlier value")
			}

			seen[entry] = struct{}{}
		}
	}

	return nil
}

// validNetworkOperand reports whether a value is one parseable address or prefix.
func validNetworkOperand(value string) bool {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		_, err := netip.ParsePrefix(value)

		return err == nil
	}

	_, err := netip.ParseAddr(value)

	return err == nil
}

// validConditionSetName preserves the old simple local-name contract.
func validConditionSetName(value string) bool {
	return policyConditionSetName.MatchString(value)
}

// validWeekday recognizes the retained case-insensitive weekday abbreviations.
func validWeekday(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "mon", "tue", "wed", "thu", "fri", "sat", "sun":
		return true
	default:
		return false
	}
}

// parseClockMinute parses one retained local-time HH:MM value.
func parseClockMinute(value string) (int, error) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid time")
	}

	hour, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}

	minute, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, err
	}

	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, fmt.Errorf("invalid time")
	}

	return hour*60 + minute, nil
}

// validateSchemaContributions rejects empty registry-script identities.
func validateSchemaContributions(contributions SchemaContributionsConfig, path string) error {
	for index, script := range contributions.Lua.RegistryScripts {
		if strings.TrimSpace(script) == "" {
			return invalid(fmt.Sprintf("%s.lua.registry_scripts[%d]", path, index), "must be non-empty")
		}
	}

	return nil
}

// validateFactSources validates bounded source-to-fact projections.
func validateFactSources(sources FactSourcesConfig, path string) error {
	seen := make(map[string]string, len(sources.HTTPHeaders)+len(sources.GRPCMetadata)+len(sources.BackendAttributes))

	for index, source := range sources.HTTPHeaders {
		sourcePath := fmt.Sprintf("%s.http_headers[%d]", path, index)
		if err := validateHTTPHeaderFactSource(source, sourcePath, seen); err != nil {
			return err
		}
	}

	for index, source := range sources.GRPCMetadata {
		sourcePath := fmt.Sprintf("%s.grpc_metadata[%d]", path, index)
		if err := validateGRPCMetadataFactSource(source, sourcePath, seen); err != nil {
			return err
		}
	}

	return validateBackendFactSources(sources.BackendAttributes, path+".backend_attributes", seen)
}

// validateHTTPHeaderFactSource validates one safe header projection and its destination.
func validateHTTPHeaderFactSource(
	source HTTPHeaderFactSourceConfig,
	path string,
	seen map[string]string,
) error {
	header := strings.TrimSpace(source.Header)
	if header == "" || !httpguts.ValidHeaderFieldName(header) {
		return invalid(path+".header", "must be a valid HTTP header name")
	}

	if unsafeRequestSourceName(header) {
		return invalid(path+".header", "must not expose credential or session headers")
	}

	if err := validateRequestFact(source.Attribute, requestHeaderFactPrefix, path+".attribute", seen, path); err != nil {
		return err
	}

	if err := validateFactSourceNormalization(source.Normalize, path+".normalize"); err != nil {
		return err
	}

	return validateFactSourceVisibility(source.Visibility, path+".visibility")
}

// validateGRPCMetadataFactSource validates one safe metadata projection and its destination.
func validateGRPCMetadataFactSource(
	source GRPCMetadataFactSourceConfig,
	path string,
	seen map[string]string,
) error {
	key := strings.TrimSpace(source.Key)
	if key == "" || key != strings.ToLower(key) || !metadataKeyPattern.MatchString(key) {
		return invalid(path+".key", "must be a lowercase gRPC metadata key")
	}

	if unsafeRequestSourceName(key) {
		return invalid(path+".key", "must not expose credential or session metadata")
	}

	if err := validateRequestFact(source.Attribute, requestMetadataFactPrefix, path+".attribute", seen, path); err != nil {
		return err
	}

	if err := validateFactSourceNormalization(source.Normalize, path+".normalize"); err != nil {
		return err
	}

	return validateFactSourceVisibility(source.Visibility, path+".visibility")
}

// validateRequestFact enforces a source-specific identity and namespace-wide uniqueness.
func validateRequestFact(value string, prefix string, path string, seen map[string]string, ownerPath string) error {
	if !strings.HasPrefix(value, prefix) || !validFact(value) {
		return invalid(path, "must be a canonical request fact with the correct source prefix")
	}

	return recordFactSource(value, path, ownerPath, seen)
}

// validateFactSourceNormalization preserves the retained lower/upper and non-negative bound contract.
func validateFactSourceNormalization(normalize NormalizeConfig, path string) error {
	caseMode := strings.TrimSpace(normalize.Case)
	if caseMode != "" && caseMode != "lower" && caseMode != "upper" {
		return invalid(path+".case", "must be lower or upper")
	}

	if normalize.MaxLength < 0 {
		return invalid(path+".max_length", "must not be negative")
	}

	return nil
}

// validateFactSourceVisibility preserves public-only request projection behavior.
func validateFactSourceVisibility(value string, path string) error {
	if value != "" && value != requestFactVisibility {
		return invalid(path, "must be public")
	}

	return nil
}

// unsafeRequestSourceName reports whether a request source can carry credentials or sessions.
func unsafeRequestSourceName(value string) bool {
	_, unsafe := unsafeRequestSourceNames[strings.ToLower(strings.TrimSpace(value))]

	return unsafe
}

// recordFactSource rejects duplicate destinations across every namespace-owned fact source family.
func recordFactSource(value string, path string, ownerPath string, seen map[string]string) error {
	if previous, exists := seen[value]; exists {
		return invalid(path, "duplicates fact source from "+previous)
	}

	seen[value] = ownerPath

	return nil
}

// validateBackendFactSources validates backend attribute export contracts.
func validateBackendFactSources(
	sources []BackendAttributeFactSourceConfig,
	path string,
	seen map[string]string,
) error {
	for index, source := range sources {
		sourcePath := fmt.Sprintf("%s[%d]", path, index)
		if strings.TrimSpace(source.Name) == "" {
			return invalid(sourcePath+".name", "must be non-empty")
		}

		if !validFact(source.Attribute) {
			return invalid(sourcePath+".attribute", "must be a canonical fact identity")
		}

		if err := recordFactSource(source.Attribute, sourcePath+".attribute", sourcePath, seen); err != nil {
			return err
		}

		if !validBackendFactType(source.Type) {
			return invalid(sourcePath+".type", "must be bool, string, string_list, or number")
		}

		if source.Sensitivity != "" && source.Sensitivity != "public" && source.Sensitivity != "internal" && source.Sensitivity != "secret" {
			return invalid(sourcePath+".sensitivity", "must be public, internal, or secret")
		}
	}

	return nil
}

// validateProviders validates configured provider ownership and failure semantics.
func validateProviders(namespace string, providers map[string]ProviderConfig, path string) error {
	for _, name := range sortedProviderNames(providers) {
		provider := providers[name]

		providerPath := path + "." + name
		if !validProviderLocalName(namespace, name, provider.Kind) {
			return invalid(providerPath, "must use a canonical local name or exact authn plugin identity")
		}

		if !validProviderKind(provider.Kind) {
			return invalid(providerPath+".kind", "must be lua_environment, lua_subject, native, or plugin")
		}

		if err := validateProviderSchedule(namespace, provider, providerPath); err != nil {
			return err
		}

		if err := validateProviderBinding(namespace, name, provider, providerPath); err != nil {
			return err
		}

		if err := validateTargetReferences(provider.Targets, providerPath+".targets"); err != nil {
			return err
		}

		if err := validateExecutions(provider.Executions, providerPath+".executions"); err != nil {
			return err
		}

		if err := validateDiagnosticID(provider.Diagnostics.PublicID, providerPath+".diagnostics.public_id"); err != nil {
			return err
		}
	}

	return nil
}

// validateProviderBinding delegates each provider kind to its binding boundary.
func validateProviderBinding(namespace string, name string, provider ProviderConfig, path string) error {
	if err := validateReservedAuthnProviderKind(namespace, name, provider.Kind, path); err != nil {
		return err
	}

	switch provider.Kind {
	case providerKindLuaEnvironment:
		return validateLuaProviderBinding(
			namespace,
			name,
			provider.ScriptPath,
			luaEnvironmentPrefix,
			pluginBindingEnvironment,
			path,
		)
	case providerKindLuaSubject:
		return validateLuaProviderBinding(
			namespace,
			name,
			provider.ScriptPath,
			luaSubjectPrefix,
			pluginBindingSubject,
			path,
		)
	case keywordPlugin:
		return validatePluginProviderBinding(namespace, name, provider.Module, path)
	}

	return nil
}

// validateReservedAuthnProviderKind protects the two qualified Lua identity families from kind spoofing.
func validateReservedAuthnProviderKind(namespace string, name string, kind string, path string) error {
	if namespace != authnNamespace {
		return nil
	}

	if strings.HasPrefix(name, luaEnvironmentPrefix) && kind != providerKindLuaEnvironment {
		return invalid(path+".kind", "the lua_environment_ prefix is reserved for Lua environment providers")
	}

	if strings.HasPrefix(name, luaSubjectPrefix) && kind != providerKindLuaSubject {
		return invalid(path+".kind", "the lua_subject_ prefix is reserved for Lua subject providers")
	}

	return nil
}

// validateLuaProviderBinding enforces a source-specific authn prefix and non-empty script path.
func validateLuaProviderBinding(
	namespace string,
	name string,
	scriptPath string,
	prefix string,
	source string,
	path string,
) error {
	if namespace == authnNamespace && !strings.HasPrefix(name, prefix) {
		return invalid(path, "authn Lua "+source+" providers require the "+prefix+" prefix")
	}

	if strings.TrimSpace(scriptPath) == "" {
		return invalid(path+".script_path", "Lua "+source+" providers require a script path")
	}

	return nil
}

// validatePluginProviderBinding matches one authn plugin definition to its embedded module identity.
func validatePluginProviderBinding(namespace string, name string, module string, path string) error {
	if namespace != authnNamespace {
		return nil
	}

	identityModule, _, ok := parseAuthnPluginProviderLocal(name)
	if !ok {
		return invalid(path, "authn plugin providers require an exact plugin.<module>.environment or plugin.<module>.subject.<local> identity")
	}

	if !validNamespace(module) {
		return invalid(path+".module", "must name one canonical plugin module")
	}

	if module != identityModule {
		return invalid(path+".module", "must match the module embedded in the provider identity")
	}

	return nil
}

// validateProviderSchedule requires explicit generic failure and bounded timeout behavior.
func validateProviderSchedule(namespace string, provider ProviderConfig, path string) error {
	if namespace != authnNamespace && provider.Failure == "" {
		return invalid(path+".failure", "generic providers require indeterminate or continue")
	}

	if provider.Failure != "" && provider.Failure != providerFailureIndeterminate && provider.Failure != providerFailureContinue {
		return invalid(path+".failure", "must be indeterminate or continue")
	}

	if provider.Timeout < 0 {
		return invalid(path+".timeout", "must not be negative")
	}

	return nil
}

// validateTargetReferences validates namespace-local action allowlists.
func validateTargetReferences(targets []TargetReferenceConfig, path string) error {
	for index, target := range targets {
		if !validAction(target.Action) {
			return invalid(fmt.Sprintf("%s[%d].action", path, index), "must be a canonical action")
		}
	}

	return nil
}

// validateExecutions checks provider host execution allowlists.
func validateExecutions(executions []string, path string) error {
	for index, execution := range executions {
		if execution != executionHostSync && execution != executionHostPostAction {
			return invalid(fmt.Sprintf("%s[%d]", path, index), "must be host_sync or host_post_action")
		}
	}

	return nil
}

// validateEffects validates execution ownership, providers, parameters, and diagnostics.
func validateEffects(namespace string, effects map[string]EffectConfig, path string) error {
	for _, name := range sortedEffectNames(effects) {
		effect := effects[name]

		effectPath := path + "." + name
		if !validAction(name) {
			return invalid(effectPath, "must use a canonical local name")
		}

		if err := validateEffect(namespace, name, effect, effectPath); err != nil {
			return err
		}
	}

	return nil
}

// validateEffect enforces exactly one effect execution owner.
func validateEffect(namespace string, name string, effect EffectConfig, path string) error {
	if namespace == authnNamespace && strings.HasPrefix(name, luaActionPrefix) && effect.Kind != effectKindLuaAction {
		return invalid(path+".kind", "the lua_action_ prefix is reserved for Lua action effects")
	}

	if effect.Kind != defaultEffectKind && effect.Kind != effectKindAdvice && effect.Kind != effectKindLuaAction {
		return invalid(path+".kind", "must be obligation, advice, or lua_action")
	}

	if effect.Kind == effectKindLuaAction {
		if err := validateLuaActionEffect(namespace, name, effect, path); err != nil {
			return err
		}
	} else if err := validateEffectOwnership(effect, path); err != nil {
		return err
	}

	if err := validateTargetReferences(effect.Targets, path+".targets"); err != nil {
		return err
	}

	if err := validateEffectParameters(effect.Parameters, path+".parameters"); err != nil {
		return err
	}

	return validateDiagnosticID(effect.Diagnostics.PublicID, path+".diagnostics.public_id")
}

// validateEffectOwnership enforces one closed execution class and compatible provider binding.
func validateEffectOwnership(effect EffectConfig, path string) error {
	if effect.Execution != executionReturnOnly && effect.Execution != executionHostSync && effect.Execution != executionHostPostAction {
		return invalid(path+".execution", "must be return_only, host_sync, or host_post_action")
	}

	if effect.Execution == executionReturnOnly && effect.Provider != "" {
		return invalid(path+".provider", "return_only effects cannot bind a provider")
	}

	if effect.Execution != executionReturnOnly && !validQualified(effect.Provider) {
		return invalid(path+".provider", "host effects require one exact qualified provider")
	}

	if effect.Kind == effectKindAdvice && effect.Execution != executionReturnOnly {
		return invalid(path+".execution", "advice must be return_only")
	}

	return nil
}

// validateLuaActionEffect preserves reserved identity, script, and exact host ownership.
func validateLuaActionEffect(namespace string, name string, effect EffectConfig, path string) error {
	if !validLuaActionType(effect.ActionType) {
		return invalid(path+".action_type", "must be brute_force, rbl, tls_encryption, relay_domains, lua, or post")
	}

	want := executionHostSync
	if effect.ActionType == luaActionTypePost {
		want = executionHostPostAction
	}

	if effect.Execution != want {
		return invalid(path+".execution", "does not match action_type host ownership")
	}

	if strings.TrimSpace(effect.ScriptPath) == "" {
		return invalid(path+".script_path", "Lua actions require a script path")
	}

	if namespace != authnNamespace {
		return invalid(path+".kind", "Lua actions are restricted to the authn namespace")
	}

	if !strings.HasPrefix(name, luaActionPrefix) {
		return invalid(path, "authn Lua action effects require the lua_action_ prefix")
	}

	if effect.Provider != "" {
		return invalid(path+".provider", "Lua action execution is bound internally and forbids an operator provider")
	}

	return nil
}

// validLuaActionType reports whether value belongs to the retained Lua action vocabulary.
func validLuaActionType(value string) bool {
	switch value {
	case "brute_force", "rbl", "tls_encryption", "relay_domains", luaActionTypeLua, luaActionTypePost:
		return true
	default:
		return false
	}
}

// validateEffectParameters validates typed parameter declarations.
func validateEffectParameters(parameters map[string]EffectParameterConfig, path string) error {
	for _, name := range sortedEffectParameterNames(parameters) {
		parameter := parameters[name]

		parameterPath := path + "." + name
		if !validAction(name) {
			return invalid(parameterPath, "must use a canonical parameter name")
		}

		if !validValueKind(parameter.Type) {
			return invalid(parameterPath+".type", "must be an exact value kind")
		}

		if parameter.MaxLength < 0 || parameter.MaxItems < 0 || parameter.MaxBytes < 0 {
			return invalid(parameterPath, "bounds must not be negative")
		}
	}

	return nil
}

// validateDomainPlans validates checkpoint ownership and provider instances.
func validateDomainPlans(namespaceName string, namespace NamespaceConfig, path string) error {
	for _, name := range sortedDomainPlanNames(namespace.DomainPlans) {
		plan := namespace.DomainPlans[name]

		planPath := path + "." + name
		if !validAction(name) {
			return invalid(planPath, "must use a canonical local name")
		}

		if err := validateSchedulerGuards(plan.SchedulerGuards, planPath+".scheduler_guards"); err != nil {
			return err
		}

		if err := validateCheckpoints(namespaceName, namespace.Providers, plan, planPath+".checkpoints"); err != nil {
			return err
		}
	}

	return nil
}

// validateSchedulerGuards validates exact missing-fact behavior.
func validateSchedulerGuards(guards map[string]SchedulerGuardConfig, path string) error {
	for _, name := range sortedSchedulerGuardNames(guards) {
		guard := guards[name]

		guardPath := path + "." + name
		if !validAction(name) {
			return invalid(guardPath, "must use a canonical local name")
		}

		if guard.OnMissingAttribute != "" && guard.OnMissingAttribute != "run" {
			return invalid(guardPath+".on_missing_attribute", "must be run")
		}

		if err := validateCondition(guard.If, guardPath+".if"); err != nil {
			return err
		}
	}

	return nil
}

// validateCheckpoints validates provider instances, local references, and dependency order.
func validateCheckpoints(
	namespace string,
	providers map[string]ProviderConfig,
	plan DomainPlanConfig,
	path string,
) error {
	seenOutputs := make(map[string]string)

	for _, name := range sortedCheckpointNames(plan.Checkpoints) {
		checkpoint := plan.Checkpoints[name]

		checkpointPath := path + "." + name
		if !validAction(name) {
			return invalid(checkpointPath, "must use a canonical checkpoint name")
		}

		instances := make(map[string]int, len(checkpoint.Providers))
		for index, provider := range checkpoint.Providers {
			providerPath := fmt.Sprintf("%s.providers[%d]", checkpointPath, index)
			if err := validateProviderInstance(namespace, provider, providerPath); err != nil {
				return err
			}

			if previous, exists := instances[provider.Name]; exists {
				return invalid(providerPath+".name", fmt.Sprintf("duplicates provider instance at index %d", previous))
			}

			instances[provider.Name] = index

			if !providerUseResolvable(namespace, provider.Use, providers) {
				return invalid(providerPath+".use", "does not resolve to a provider owned by this namespace")
			}

			if provider.Output != "" {
				if !validFact(provider.Output) {
					return invalid(providerPath+".output", "must be a canonical fact identity")
				}

				if previous, exists := seenOutputs[provider.Output]; exists {
					return invalid(providerPath+".output", "duplicates provider output from "+previous)
				}

				seenOutputs[provider.Output] = providerPath
			}
		}

		if err := validateCheckpointReferences(checkpoint, plan.SchedulerGuards, instances, checkpointPath); err != nil {
			return err
		}
	}

	return nil
}

// validateProviderInstance validates one checkpoint-local provider binding.
func validateProviderInstance(namespace string, provider ProviderInstanceConfig, path string) error {
	if !validAction(provider.Name) {
		return invalid(path+".name", "must be a canonical instance name")
	}

	if !validProviderUse(provider.Use) {
		return invalid(path+".use", "must be an exact qualified provider identity")
	}

	if err := validateProviderObserveSafety(namespace, provider, path); err != nil {
		return err
	}

	if err := validateProviderAuthState(namespace, provider.RunIf.AuthState, path+".run_if.auth_state"); err != nil {
		return err
	}

	if err := validateUniqueLocalNames(provider.Actions, path+".actions", "action"); err != nil {
		return err
	}

	return nil
}

// validateProviderObserveSafety rejects assertions unsupported by immutable authn provider semantics.
func validateProviderObserveSafety(namespace string, provider ProviderInstanceConfig, path string) error {
	if provider.ObserveSafe == nil || !*provider.ObserveSafe || namespace != authnNamespace {
		return nil
	}

	defaultSafe, allowsAssertion, known := policy.AuthnProviderObserveSafety(provider.Use)
	if known && !defaultSafe && !allowsAssertion {
		return invalid(path+".observe_safe", "cannot be asserted for this authn provider")
	}

	return nil
}

// validateProviderAuthState restricts auth-state predicates to authn and the closed state vocabulary.
func validateProviderAuthState(namespace string, authState string, path string) error {
	if authState == "" {
		return nil
	}

	if namespace != authnNamespace {
		return invalid(path, "is restricted to authn domain plans")
	}

	if authState != "authenticated" && authState != "unauthenticated" && authState != keywordAny {
		return invalid(path, "must be authenticated, unauthenticated, or any")
	}

	return nil
}

// validateCheckpointReferences resolves dependencies and exact plan-local scheduler guards.
func validateCheckpointReferences(
	checkpoint CheckpointConfig,
	guards map[string]SchedulerGuardConfig,
	instances map[string]int,
	path string,
) error {
	for index, provider := range checkpoint.Providers {
		providerPath := fmt.Sprintf("%s.providers[%d]", path, index)

		if err := validateProviderDependencies(provider, instances, providerPath); err != nil {
			return err
		}

		seenGuards := make(map[string]struct{}, len(provider.SkipIf))
		for guardIndex, guard := range provider.SkipIf {
			guardPath := fmt.Sprintf("%s.skip_if[%d]", providerPath, guardIndex)
			if !validAction(guard) {
				return invalid(guardPath, "must be a canonical scheduler guard name")
			}

			if _, exists := seenGuards[guard]; exists {
				return invalid(guardPath, "must be unique")
			}

			seenGuards[guard] = struct{}{}
			if _, exists := guards[guard]; !exists {
				return invalid(guardPath, "references an unknown scheduler guard in this domain plan")
			}
		}
	}

	return validateProviderDependencyCycles(checkpoint, instances, path)
}

// validateProviderDependencies resolves checkpoint-local or immutable builtin prerequisites.
func validateProviderDependencies(
	provider ProviderInstanceConfig,
	instances map[string]int,
	path string,
) error {
	seen := make(map[string]struct{}, len(provider.After))
	for index, dependency := range provider.After {
		dependencyPath := fmt.Sprintf("%s.after[%d]", path, index)
		if !validAction(dependency) {
			return invalid(dependencyPath, "must be a canonical provider instance name")
		}

		if _, exists := seen[dependency]; exists {
			return invalid(dependencyPath, "must be unique")
		}

		seen[dependency] = struct{}{}
		if _, exists := instances[dependency]; exists {
			continue
		}

		return invalid(dependencyPath, "references an unknown provider instance in this checkpoint")
	}

	return nil
}

// validateProviderDependencyCycles rejects checkpoint-local scheduling cycles at the closing edge.
func validateProviderDependencyCycles(
	checkpoint CheckpointConfig,
	instances map[string]int,
	path string,
) error {
	visiting := make(map[string]bool, len(instances))
	visited := make(map[string]bool, len(instances))

	var visit func(string) error

	visit = func(name string) error {
		if visited[name] {
			return nil
		}

		visiting[name] = true
		providerIndex := instances[name]
		provider := checkpoint.Providers[providerIndex]

		for dependencyIndex, dependency := range provider.After {
			if _, local := instances[dependency]; !local {
				continue
			}

			if visiting[dependency] {
				return invalid(
					fmt.Sprintf("%s.providers[%d].after[%d]", path, providerIndex, dependencyIndex),
					"creates a provider dependency cycle",
				)
			}

			if err := visit(dependency); err != nil {
				return err
			}
		}

		visiting[name] = false
		visited[name] = true

		return nil
	}

	for _, provider := range checkpoint.Providers {
		if err := visit(provider.Name); err != nil {
			return err
		}
	}

	return nil
}

// validateUniqueLocalNames checks canonical non-duplicated names in source order.
func validateUniqueLocalNames(values []string, path string, description string) error {
	seen := make(map[string]struct{}, len(values))
	for index, value := range values {
		valuePath := fmt.Sprintf("%s[%d]", path, index)
		if !validAction(value) {
			return invalid(valuePath, "must be a canonical "+description)
		}

		if _, exists := seen[value]; exists {
			return invalid(valuePath, "must be unique")
		}

		seen[value] = struct{}{}
	}

	return nil
}

// validatePolicySets validates visibility, exports, rules, and diagnostics.
func validatePolicySets(namespace string, policySets map[string]PolicySetConfig, path string) error {
	for _, name := range sortedPolicySetNames(policySets) {
		policySet := policySets[name]

		setPath := path + "." + name
		if !validAction(name) {
			return invalid(setPath, "must use a canonical local name")
		}

		if namespace == authnNamespace && name == "standard_auth" {
			return invalid(setPath, "authn/standard_auth is supplied only by the builtin contribution")
		}

		if err := validatePolicySet(policySet, setPath); err != nil {
			return err
		}
	}

	return nil
}

// validatePolicySet enforces private/exported ownership and validates ordered rules.
func validatePolicySet(policySet PolicySetConfig, path string) error {
	if policySet.Visibility != VisibilityPrivate && policySet.Visibility != VisibilityExported {
		return invalid(path+".visibility", "must be private or exported")
	}

	if policySet.Visibility == VisibilityPrivate && policySet.ExportContract != nil {
		return invalid(path+".export_contract", "private policy sets cannot declare an export contract")
	}

	if policySet.Visibility == VisibilityExported {
		if policySet.ExportContract == nil {
			return invalid(path+".export_contract", "exported policy sets require a complete contract")
		}

		if err := validateExportContract(*policySet.ExportContract, path+".export_contract"); err != nil {
			return err
		}
	}

	if err := validateDiagnosticID(policySet.Diagnostics.PublicID, path+".diagnostics.public_id"); err != nil {
		return err
	}

	for index, rule := range policySet.Rules {
		if err := validatePolicyRule(rule, fmt.Sprintf("%s.rules[%d]", path, index)); err != nil {
			return err
		}
	}

	return nil
}

// validateExportContract requires every explicit capability field.
func validateExportContract(contract ExportContractConfig, path string) error {
	if contract.RequiredFacts == nil {
		return invalid(path+".required_facts", "must be present, including when empty")
	}

	if len(contract.CompatibleCheckpoints) == 0 {
		return invalid(path+".compatible_checkpoints", "must contain at least one checkpoint")
	}

	if len(contract.AllowedDecisions) == 0 {
		return invalid(path+".allowed_decisions", "must contain at least one decision")
	}

	if contract.AllowedEffects == nil {
		return invalid(path+".allowed_effects", "must be present, including when empty")
	}

	for index, fact := range contract.RequiredFacts {
		factPath := fmt.Sprintf("%s.required_facts[%d]", path, index)
		if !validFact(fact.Attribute) {
			return invalid(factPath+".attribute", "must be a canonical fact identity")
		}

		if !validValueKind(fact.Type) {
			return invalid(factPath+".type", "must be an exact value kind")
		}
	}

	return nil
}

// validatePolicyRule validates exact checkpoint selection and qualified effects.
func validatePolicyRule(rule PolicyRuleConfig, path string) error {
	if !validAction(rule.Name) {
		return invalid(path+".name", "must be a canonical rule name")
	}

	if !validAction(rule.Checkpoint) {
		return invalid(path+".checkpoint", "must be a canonical checkpoint selector")
	}

	if err := validateUniqueLocalNames(rule.Actions, path+".actions", "action"); err != nil {
		return err
	}

	if err := validateUniqueLocalNames(rule.RequireProviders, path+".require_providers", "provider instance name"); err != nil {
		return err
	}

	if err := validateCondition(rule.If, path+".if"); err != nil {
		return err
	}

	return validateThen(rule.Then, path+".then")
}

// validateCondition requires one unambiguous logical or attribute expression.
func validateCondition(condition ConditionConfig, path string) error {
	logicalForms := presentLogicalForms(condition)
	operators := presentAttributeOperators(condition)

	if len(logicalForms) > 0 {
		return validateLogicalCondition(condition, path, logicalForms, operators)
	}

	return validateAttributeCondition(condition, path, operators)
}

// validateLogicalCondition rejects mixed forms and validates the selected logical children.
func validateLogicalCondition(
	condition ConditionConfig,
	path string,
	forms []string,
	operators []string,
) error {
	if len(forms) > 1 {
		return invalid(path+"."+forms[1], "condition must declare exactly one logical form")
	}

	if condition.Attribute != "" {
		return invalid(path+".attribute", "cannot be combined with a logical condition")
	}

	if condition.Detail != "" {
		return invalid(path+".detail", "cannot be combined with a logical condition")
	}

	if len(operators) > 0 {
		return invalid(path+"."+operators[0], "cannot be combined with a logical condition")
	}

	switch forms[0] {
	case "always":
		if condition.Always == nil || !*condition.Always {
			return invalid(path+".always", "must be true")
		}

		return nil
	case "not":
		return validateCondition(*condition.Not, path+".not")
	case "all":
		return validateConditionChildren(condition.All, path+".all")
	case keywordAny:
		return validateConditionChildren(condition.Any, path+".any")
	default:
		return invalid(path, "condition requires exactly one expression")
	}
}

// validateAttributeCondition requires one fact identity and exactly one operator.
func validateAttributeCondition(condition ConditionConfig, path string, operators []string) error {
	if condition.Attribute == "" {
		if len(operators) == 0 && condition.Detail == "" {
			return invalid(path, "condition requires exactly one expression")
		}

		return invalid(path+".attribute", "attribute operators require a canonical fact identity")
	}

	if !validFact(condition.Attribute) {
		return invalid(path+".attribute", "must be a canonical fact identity")
	}

	if len(operators) == 0 {
		return invalid(path, "attribute condition requires exactly one operator")
	}

	if len(operators) > 1 {
		return invalid(path+"."+operators[1], "attribute condition must declare exactly one operator")
	}

	return nil
}

// validateConditionChildren requires a non-empty logical child list and validates every child.
func validateConditionChildren(children []ConditionConfig, path string) error {
	if len(children) == 0 {
		return invalid(path, "logical conditions require at least one child")
	}

	for index, child := range children {
		if err := validateCondition(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
			return err
		}
	}

	return nil
}

// presentLogicalForms returns configured logical fields in canonical model order.
func presentLogicalForms(condition ConditionConfig) []string {
	forms := make([]string, 0, 4)
	if condition.Not != nil {
		forms = append(forms, "not")
	}

	if condition.Always != nil {
		forms = append(forms, "always")
	}

	if condition.All != nil {
		forms = append(forms, "all")
	}

	if condition.Any != nil {
		forms = append(forms, keywordAny)
	}

	return forms
}

// presentAttributeOperators returns configured attribute operators in canonical model order.
func presentAttributeOperators(condition ConditionConfig) []string {
	operators := make([]string, 0, 17)
	appendConditionOperator(&operators, "matches", condition.Matches != "")
	appendConditionOperator(&operators, "cidr_contains", condition.CIDRContains != "")
	appendConditionOperator(&operators, "within_time_window", condition.WithinTimeWindow != "")
	appendConditionOperator(&operators, "is", condition.Is != nil)
	appendConditionOperator(&operators, "eq", condition.Eq != nil)
	appendConditionOperator(&operators, "ne", condition.Ne != nil)
	appendConditionOperator(&operators, "in", condition.In != nil)
	appendConditionOperator(&operators, "not_in", condition.NotIn != nil)
	appendConditionOperator(&operators, "exists", condition.Exists != nil)
	appendConditionOperator(&operators, "contains", condition.Contains != nil)
	appendConditionOperator(&operators, "contains_any", condition.ContainsAny != nil)
	appendConditionOperator(&operators, "contains_all", condition.ContainsAll != nil)
	appendConditionOperator(&operators, "contains_none", condition.ContainsNone != nil)
	appendConditionOperator(&operators, "gt", condition.GT != nil)
	appendConditionOperator(&operators, "gte", condition.GTE != nil)
	appendConditionOperator(&operators, "lt", condition.LT != nil)
	appendConditionOperator(&operators, "lte", condition.LTE != nil)

	return operators
}

// appendConditionOperator records one present operator without duplicating selection logic.
func appendConditionOperator(operators *[]string, name string, present bool) {
	if present {
		*operators = append(*operators, name)
	}
}

// validateThen checks closed decisions and exact effect references.
func validateThen(then ThenConfig, path string) error {
	if then.Decision != "" && then.Decision != "permit" && then.Decision != decisionDeny && then.Decision != providerFailureIndeterminate && then.Decision != decisionNotApplicable {
		return invalid(path+".decision", "must be a registered decision")
	}

	if err := validateEffectSelections(then.Obligations, path+".obligations"); err != nil {
		return err
	}

	return validateEffectSelections(then.Advice, path+".advice")
}

// validateEffectSelections checks exact qualified selected effect identities.
func validateEffectSelections(selections []EffectSelectionConfig, path string) error {
	for index, selection := range selections {
		if !validQualified(selection.ID) {
			return invalid(fmt.Sprintf("%s[%d].id", path, index), "must be an exact qualified effect identity")
		}
	}

	return nil
}

// validateTargets validates every explicit activation in source order.
func validateTargets(targets []TargetConfig) error {
	seen := make(map[string]struct{}, len(targets))

	for index, target := range targets {
		path := fmt.Sprintf("policy.targets[%d]", index)
		if err := validateTarget(target, path); err != nil {
			return err
		}

		identity := target.Namespace + "/" + target.Action
		if _, exists := seen[identity]; exists {
			return invalid(path+".action", "target activation must be unique")
		}

		seen[identity] = struct{}{}
	}

	return nil
}

// validateTarget enforces exact schema, activation, fallback, and timeout semantics.
func validateTarget(target TargetConfig, path string) error {
	if !validNamespace(target.Namespace) {
		return invalid(path+".namespace", "must be a canonical namespace")
	}

	if !validAction(target.Action) {
		return invalid(path+".action", "must be a canonical action")
	}

	if err := validateTargetSchema(target, path+".schema"); err != nil {
		return err
	}

	if err := validateTargetMode(target, path+".mode"); err != nil {
		return err
	}

	if target.DefaultPolicy != "" && !validQualified(target.DefaultPolicy) {
		return invalid(path+".default_policy", "must be an exact qualified policy-set identity")
	}

	if target.DomainPlan != "" && !validQualified(target.DomainPlan) {
		return invalid(path+".domain_plan", "must be an exact qualified domain-plan identity")
	}

	if err := validateTargetFallback(target, path); err != nil {
		return err
	}

	if err := validateTargetPlans(target.Plans, path+".plans"); err != nil {
		return err
	}

	return validateTargetReport(target, path+".report")
}

// validateTargetMode keeps observe authority restricted to authn targets.
func validateTargetMode(target TargetConfig, path string) error {
	if target.Mode != defaultAuthorityMode && target.Mode != "observe" {
		return invalid(path, "must be enforce or observe")
	}

	if target.Namespace != authnNamespace && target.Mode != defaultAuthorityMode {
		return invalid(path, "generic targets support enforce mode only")
	}

	return nil
}

// validateTargetSchema requires one exact version matching the activated target.
func validateTargetSchema(target TargetConfig, path string) error {
	namespace, action, err := parseExactSchemaReference(target.Schema, path)
	if err != nil {
		return err
	}

	if namespace != target.Namespace || action != target.Action {
		return invalid(path, "must match the activated namespace and action")
	}

	return nil
}

// parseExactSchemaReference validates and splits one namespace/action/vN reference.
func parseExactSchemaReference(value string, path string) (string, string, error) {
	matches := exactSchemaPattern.FindStringSubmatch(value)
	if len(matches) != 4 {
		return "", "", invalid(path, "must be an exact namespace/action/vN schema reference")
	}

	if _, err := strconv.ParseUint(matches[3], 10, 32); err != nil {
		return "", "", invalid(path, "schema version is out of range")
	}

	return matches[1], matches[2], nil
}

// validateTargetFallback separates authn-owned and generic fallback contracts.
func validateTargetFallback(target TargetConfig, path string) error {
	if target.Namespace == authnNamespace {
		if target.NoMatch != "" {
			return invalid(path+".no_match", "authn targets forbid generic no-match configuration")
		}

		if target.Timeouts.Evaluation != 0 {
			return invalid(path+".timeouts.evaluation", "authn preserves its host-owned timeout")
		}

		if target.Timeouts.ProviderDefault != 0 {
			return invalid(path+".timeouts.provider_default", "authn preserves its host-owned timeout")
		}

		if target.DefaultPolicy != standardAuthPolicy {
			return invalid(path+".default_policy", "authn builtin fallback is exactly authn/standard_auth")
		}

		return nil
	}

	if target.NoMatch != decisionNotApplicable && target.NoMatch != decisionDeny {
		return invalid(path+".no_match", "generic targets require not_applicable or deny")
	}

	if target.Timeouts.Evaluation <= 0 {
		return invalid(path+".timeouts.evaluation", "generic targets require a positive evaluation timeout")
	}

	if target.Timeouts.ProviderDefault <= 0 {
		return invalid(path+".timeouts.provider_default", "generic targets require a positive provider timeout")
	}

	if target.Timeouts.ProviderDefault > target.Timeouts.Evaluation {
		return invalid(path+".timeouts.provider_default", "must not exceed the target evaluation timeout")
	}

	return nil
}

// validateTargetPlans checks exact checkpoint and qualified set references.
func validateTargetPlans(plans map[string]TargetPlanConfig, path string) error {
	for _, checkpoint := range sortedTargetPlanNames(plans) {
		plan := plans[checkpoint]

		checkpointPath := path + "." + checkpoint
		if !validAction(checkpoint) {
			return invalid(checkpointPath, "must use a canonical checkpoint name")
		}

		for index, policySet := range plan.PolicySets {
			if !validQualified(policySet) {
				return invalid(fmt.Sprintf("%s.policy_sets[%d]", checkpointPath, index), "must be an exact qualified policy-set identity")
			}
		}
	}

	return nil
}

// validateTargetReport restricts authn-specific detail toggles to authn targets.
func validateTargetReport(target TargetConfig, path string) error {
	if target.Namespace == authnNamespace {
		return nil
	}

	if target.Report.IncludeFSM {
		return invalid(path+".include_fsm", "is restricted to authn targets")
	}

	if target.Report.IncludeChecks {
		return invalid(path+".include_checks", "is restricted to authn targets")
	}

	if target.Report.IncludeAttributes {
		return invalid(path+".include_attributes", "is restricted to authn targets")
	}

	return nil
}

// validateConfiguredReferences resolves explicit target-owned plans and required provider instances.
func validateConfiguredReferences(document Document) error {
	for targetIndex, target := range document.Policy.Targets {
		targetPath := fmt.Sprintf("policy.targets[%d]", targetIndex)

		plan, hasPlan, err := resolveTargetDomainPlan(document.Policy.Namespaces, target, targetPath+".domain_plan")
		if err != nil {
			return err
		}

		for _, checkpoint := range sortedTargetPlanNames(target.Plans) {
			if err := validateTargetCheckpointReferences(
				document.Policy.Namespaces,
				target,
				target.Plans[checkpoint],
				plan,
				hasPlan,
				checkpoint,
				targetPath+".plans."+checkpoint,
			); err != nil {
				return err
			}
		}
	}

	return nil
}

// resolveTargetDomainPlan resolves one private namespace-owned plan selected by an activation.
func resolveTargetDomainPlan(
	namespaces map[string]NamespaceConfig,
	target TargetConfig,
	path string,
) (DomainPlanConfig, bool, error) {
	if target.DomainPlan == "" {
		return DomainPlanConfig{}, false, nil
	}

	owner, name, ok := strings.Cut(target.DomainPlan, "/")
	if !ok || owner != target.Namespace {
		return DomainPlanConfig{}, false, invalid(path, "must reference a domain plan owned by the target namespace")
	}

	namespace, exists := namespaces[owner]
	if !exists {
		return DomainPlanConfig{}, false, invalid(path, "references an unknown namespace")
	}

	plan, exists := namespace.DomainPlans[name]
	if !exists {
		return DomainPlanConfig{}, false, invalid(path, "references an unknown domain plan")
	}

	return plan, true, nil
}

// validateTargetCheckpointReferences validates set imports and target-aware provider requirements.
func validateTargetCheckpointReferences(
	namespaces map[string]NamespaceConfig,
	target TargetConfig,
	binding TargetPlanConfig,
	domainPlan DomainPlanConfig,
	hasDomainPlan bool,
	checkpoint string,
	path string,
) error {
	instances, err := resolveTargetCheckpointInstances(domainPlan, hasDomainPlan, checkpoint, path)
	if err != nil {
		return err
	}

	for referenceIndex, reference := range binding.PolicySets {
		referencePath := fmt.Sprintf("%s.policy_sets[%d]", path, referenceIndex)
		if err := validateTargetPolicySetReference(
			namespaces,
			target,
			reference,
			checkpoint,
			instances,
			hasDomainPlan,
			referencePath,
		); err != nil {
			return err
		}
	}

	return nil
}

// resolveTargetCheckpointInstances indexes one selected checkpoint's provider instances by local name.
func resolveTargetCheckpointInstances(
	domainPlan DomainPlanConfig,
	hasDomainPlan bool,
	checkpoint string,
	path string,
) (map[string]ProviderInstanceConfig, error) {
	instances := make(map[string]ProviderInstanceConfig)
	if !hasDomainPlan {
		return instances, nil
	}

	configuredCheckpoint, exists := domainPlan.Checkpoints[checkpoint]
	if !exists {
		return nil, invalid(path, "is not declared by the selected domain plan")
	}

	for _, provider := range configuredCheckpoint.Providers {
		instances[provider.Name] = provider
	}

	return instances, nil
}

// validateTargetPolicySetReference resolves one import and its target-specific provider requirements.
func validateTargetPolicySetReference(
	namespaces map[string]NamespaceConfig,
	target TargetConfig,
	reference string,
	checkpoint string,
	instances map[string]ProviderInstanceConfig,
	hasDomainPlan bool,
	path string,
) error {
	owner, name, ok := strings.Cut(reference, "/")
	if !ok {
		return invalid(path, "must use an exact qualified policy-set identity")
	}

	if target.Namespace == authnNamespace && reference == standardAuthPolicy {
		return nil
	}

	namespace, exists := namespaces[owner]
	if !exists {
		return invalid(path, "references an unknown policy-set namespace")
	}

	policySet, exists := namespace.PolicySets[name]
	if !exists {
		return invalid(path, "references an unknown policy set")
	}

	if owner != target.Namespace && policySet.Visibility != VisibilityExported {
		return invalid(path, "cross-namespace policy sets must be exported")
	}

	return validateRequiredProvidersForTarget(
		policySet,
		owner,
		name,
		target,
		checkpoint,
		instances,
		hasDomainPlan,
	)
}

// validateRequiredProvidersForTarget resolves rule requirements by instance name and checkpoint action.
func validateRequiredProvidersForTarget(
	policySet PolicySetConfig,
	setNamespace string,
	setName string,
	target TargetConfig,
	checkpoint string,
	instances map[string]ProviderInstanceConfig,
	hasDomainPlan bool,
) error {
	for ruleIndex, rule := range policySet.Rules {
		if rule.Checkpoint != checkpoint || !ruleAppliesToAction(rule, target.Action) {
			continue
		}

		for requirementIndex, requirement := range rule.RequireProviders {
			path := fmt.Sprintf(
				"policy.namespaces.%s.policy_sets.%s.rules[%d].require_providers[%d]",
				setNamespace,
				setName,
				ruleIndex,
				requirementIndex,
			)

			provider, exists := instances[requirement]
			if exists && providerAppliesToAction(provider, target.Action) {
				continue
			}

			if !hasDomainPlan && target.Namespace == authnNamespace {
				_, available := policy.AuthnBuiltinProviderUse(
					requirement,
					policy.Operation(target.Action),
					policy.Stage(checkpoint),
				)
				if available {
					continue
				}
			}

			if !hasDomainPlan {
				return invalid(path, "requires an explicit domain plan provider instance")
			}

			return invalid(path, "references an unavailable provider instance for this checkpoint and action")
		}
	}

	return nil
}

// ruleAppliesToAction reports whether a rule participates in one target action.
func ruleAppliesToAction(rule PolicyRuleConfig, action string) bool {
	return len(rule.Actions) == 0 || slicesContain(rule.Actions, action)
}

// providerAppliesToAction reports whether a provider instance participates in one target action.
func providerAppliesToAction(provider ProviderInstanceConfig, action string) bool {
	return len(provider.Actions) == 0 || slicesContain(provider.Actions, action)
}

// slicesContain reports exact membership without importing target-specific policy packages.
func slicesContain(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}

	return false
}

// validateProviderBudgets keeps explicit provider timeouts inside every matching target budget.
func validateProviderBudgets(document Document) error {
	for _, namespaceName := range sortedNamespaceNames(document.Policy.Namespaces) {
		namespace := document.Policy.Namespaces[namespaceName]

		for _, providerName := range sortedProviderNames(namespace.Providers) {
			provider := namespace.Providers[providerName]
			if provider.Timeout <= 0 {
				continue
			}

			for _, target := range document.Policy.Targets {
				if target.Namespace != namespaceName || !targetReferencesAction(provider.Targets, target.Action) {
					continue
				}

				if target.Timeouts.ProviderDefault > 0 && provider.Timeout > target.Timeouts.ProviderDefault {
					return invalid(
						"policy.namespaces."+namespaceName+".providers."+providerName+".timeout",
						"must not exceed the matching target provider-default timeout",
					)
				}

				if target.Timeouts.Evaluation > 0 && provider.Timeout > target.Timeouts.Evaluation {
					return invalid(
						"policy.namespaces."+namespaceName+".providers."+providerName+".timeout",
						"must not exceed the matching target evaluation timeout",
					)
				}
			}
		}
	}

	return nil
}

// validateDiagnosticID enforces one bounded lowercase alias without path syntax.
func validateDiagnosticID(value string, path string) error {
	if value == "" {
		return nil
	}

	if !validAction(value) {
		return invalid(path, "must be one bounded lowercase target-local alias without a path")
	}

	return nil
}

// validateDiagnosticAliases rejects aliases that collide in one activated target projection.
func validateDiagnosticAliases(document Document) error {
	for targetIndex, target := range document.Policy.Targets {
		aliases := make(map[string]string)
		if err := collectTargetDefinitionAliases(document, target, aliases); err != nil {
			return err
		}

		if err := collectTargetPolicySetAliases(document, targetIndex, target, aliases); err != nil {
			return err
		}
	}

	return nil
}

// collectTargetDefinitionAliases indexes provider and effect aliases available to one target.
func collectTargetDefinitionAliases(document Document, target TargetConfig, aliases map[string]string) error {
	namespace, exists := document.Policy.Namespaces[target.Namespace]
	if !exists {
		return nil
	}

	base := "policy.namespaces." + target.Namespace

	for _, name := range sortedProviderNames(namespace.Providers) {
		provider := namespace.Providers[name]
		if targetReferencesAction(provider.Targets, target.Action) {
			path := base + ".providers." + name + ".diagnostics.public_id"
			if err := addDiagnosticAlias(aliases, provider.Diagnostics.PublicID, path); err != nil {
				return err
			}
		}
	}

	for _, name := range sortedEffectNames(namespace.Effects) {
		effect := namespace.Effects[name]
		if targetReferencesAction(effect.Targets, target.Action) {
			path := base + ".effects." + name + ".diagnostics.public_id"
			if err := addDiagnosticAlias(aliases, effect.Diagnostics.PublicID, path); err != nil {
				return err
			}
		}
	}

	return nil
}

// collectTargetPolicySetAliases indexes the exact policy sets bound into one target plan.
func collectTargetPolicySetAliases(document Document, targetIndex int, target TargetConfig, aliases map[string]string) error {
	references := make([]string, 0)
	if target.DefaultPolicy != "" {
		references = append(references, target.DefaultPolicy)
	}

	for _, checkpoint := range sortedTargetPlanNames(target.Plans) {
		references = append(references, target.Plans[checkpoint].PolicySets...)
	}

	for _, reference := range references {
		parts := strings.SplitN(reference, "/", 2)
		if len(parts) != 2 {
			continue
		}

		namespace, exists := document.Policy.Namespaces[parts[0]]
		if !exists {
			continue
		}

		policySet, exists := namespace.PolicySets[parts[1]]
		if !exists {
			continue
		}

		path := "policy.namespaces." + parts[0] + ".policy_sets." + parts[1] + ".diagnostics.public_id"
		if err := addDiagnosticAlias(aliases, policySet.Diagnostics.PublicID, path); err != nil {
			return newPathError(path, ErrValidation, fmt.Sprintf("duplicates a diagnostic alias in policy.targets[%d]", targetIndex))
		}
	}

	return nil
}

// targetReferencesAction reports whether an empty or explicit allowlist includes the target action.
func targetReferencesAction(targets []TargetReferenceConfig, action string) bool {
	if len(targets) == 0 {
		return true
	}

	for _, target := range targets {
		if target.Action == action {
			return true
		}
	}

	return false
}

// addDiagnosticAlias adds one alias and returns the colliding path on duplication.
func addDiagnosticAlias(aliases map[string]string, alias string, path string) error {
	if alias == "" {
		return nil
	}

	if existingPath, exists := aliases[alias]; exists {
		if existingPath == path {
			return nil
		}

		return invalid(path, "duplicates another public alias in this target")
	}

	aliases[alias] = path

	return nil
}

// invalid creates one semantic path error.
func invalid(path string, message string) *PathError {
	return newPathError(path, ErrValidation, message)
}

// validNamespace reports whether value uses bounded lowercase dotted segments.
func validNamespace(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}

	for _, segment := range strings.Split(value, ".") {
		if !validIdentifierSegment(segment, false) {
			return false
		}
	}

	return true
}

// validAction reports whether value uses bounded lowercase words and separators.
func validAction(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}

	separator := false

	for index := range len(value) {
		current := value[index]
		switch {
		case lowerWordByte(current):
			separator = false
		case current == '-' || current == '_':
			if index == 0 || index == len(value)-1 || separator {
				return false
			}

			separator = true
		default:
			return false
		}
	}

	return true
}

// validIdentifierSegment validates one lowercase namespace or fact segment.
func validIdentifierSegment(value string, allowHyphen bool) bool {
	if value == "" {
		return false
	}

	for index := range len(value) {
		current := value[index]
		if lowerWordByte(current) || current == '_' || allowHyphen && current == '-' {
			continue
		}

		return false
	}

	return true
}

// lowerWordByte reports whether value is one lowercase ASCII word byte.
func lowerWordByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// validFact reports whether value is one bounded dotted fact identity.
func validFact(value string) bool {
	if len(value) == 0 || len(value) > 192 {
		return false
	}

	segments := strings.Split(value, ".")
	if len(segments) < 2 {
		return false
	}

	for _, segment := range segments {
		if !validIdentifierSegment(segment, true) {
			return false
		}
	}

	return true
}

// validProviderUse accepts configured provider IDs and exact immutable authn provider families.
func validProviderUse(value string) bool {
	if validQualified(value) {
		return true
	}

	if policy.IsAuthnBuiltinProviderIdentity(value) {
		return true
	}

	return validAuthnPluginProviderUse(value)
}

// validAuthnPluginProviderUse validates the two host-owned native plugin provider forms.
func validAuthnPluginProviderUse(value string) bool {
	owner, local, ok := strings.Cut(value, "/")
	if !ok || owner != authnNamespace {
		return false
	}

	_, _, ok = parseAuthnPluginProviderLocal(local)

	return ok
}

// validProviderLocalName accepts dotted local identities only for exact authn plugin definitions.
func validProviderLocalName(namespace string, name string, kind string) bool {
	if validAction(name) {
		return true
	}

	if namespace != authnNamespace || kind != keywordPlugin {
		return false
	}

	_, _, ok := parseAuthnPluginProviderLocal(name)

	return ok
}

// parseAuthnPluginProviderLocal extracts the module and binding family from one exact local identity.
func parseAuthnPluginProviderLocal(value string) (string, string, bool) {
	const prefix = "plugin."
	if !strings.HasPrefix(value, prefix) {
		return "", "", false
	}

	local := strings.TrimPrefix(value, prefix)
	if module, ok := strings.CutSuffix(local, "."+pluginBindingEnvironment); ok && validNamespace(module) {
		return module, pluginBindingEnvironment, true
	}

	subjectSeparator := "." + pluginBindingSubject + "."
	subject := strings.LastIndex(local, subjectSeparator)

	if subject <= 0 {
		return "", "", false
	}

	module := local[:subject]
	name := local[subject+len(subjectSeparator):]

	if !validNamespace(module) || !validAction(name) {
		return "", "", false
	}

	return module, pluginBindingSubject, true
}

// providerUseResolvable enforces namespace-private configured providers and immutable host bindings.
func providerUseResolvable(namespace string, use string, providers map[string]ProviderConfig) bool {
	if policy.IsAuthnBuiltinProviderIdentity(use) {
		return namespace == authnNamespace
	}

	owner, name, ok := strings.Cut(use, "/")
	if !ok || owner != namespace {
		return false
	}

	if namespace == authnNamespace {
		if module, _, plugin := parseAuthnPluginProviderLocal(name); plugin {
			provider, exists := providers[name]

			return exists && provider.Kind == keywordPlugin && provider.Module == module
		}
	}

	_, exists := providers[name]

	return exists
}

// validQualified reports whether value is one exact namespace/local identity.
func validQualified(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.Count(value, "/") != 1 {
		return false
	}

	parts := strings.SplitN(value, "/", 2)

	return validNamespace(parts[0]) && validAction(parts[1])
}

// validBackendFactType preserves the old backend-export value vocabulary.
func validBackendFactType(value string) bool {
	switch value {
	case "bool", valueTypeString, "string_list", "number":
		return true
	default:
		return false
	}
}

// printableASCII reports whether every byte belongs to the retained printable ASCII set.
func printableASCII(value string) bool {
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}

	return true
}

// validValueKind reports whether value belongs to the compiler's closed kind set.
func validValueKind(value string) bool {
	switch value {
	case valueTypeString, "boolean", "integer", "double", "strings", "bytes", "timestamp":
		return true
	default:
		return false
	}
}

// validProviderKind reports whether one configured provider uses a registered binding family.
func validProviderKind(value string) bool {
	switch value {
	case providerKindLuaEnvironment, providerKindLuaSubject, "native", keywordPlugin:
		return true
	default:
		return false
	}
}

// sortedNamespaceNames returns deterministic namespace keys.
func sortedNamespaceNames(values map[string]NamespaceConfig) []string {
	return sortedMapKeys(values)
}

// sortedTimeWindowNames returns deterministic time-window keys.
func sortedTimeWindowNames(values map[string]TimeWindowConfig) []string {
	return sortedMapKeys(values)
}

// sortedProviderNames returns deterministic provider keys.
func sortedProviderNames(values map[string]ProviderConfig) []string {
	return sortedMapKeys(values)
}

// sortedEffectNames returns deterministic effect keys.
func sortedEffectNames(values map[string]EffectConfig) []string {
	return sortedMapKeys(values)
}

// sortedEffectParameterNames returns deterministic parameter keys.
func sortedEffectParameterNames(values map[string]EffectParameterConfig) []string {
	return sortedMapKeys(values)
}

// sortedDomainPlanNames returns deterministic domain-plan keys.
func sortedDomainPlanNames(values map[string]DomainPlanConfig) []string {
	return sortedMapKeys(values)
}

// sortedSchedulerGuardNames returns deterministic scheduler-guard keys.
func sortedSchedulerGuardNames(values map[string]SchedulerGuardConfig) []string {
	return sortedMapKeys(values)
}

// sortedCheckpointNames returns deterministic checkpoint keys.
func sortedCheckpointNames(values map[string]CheckpointConfig) []string {
	return sortedMapKeys(values)
}

// sortedPolicySetNames returns deterministic policy-set keys.
func sortedPolicySetNames(values map[string]PolicySetConfig) []string {
	return sortedMapKeys(values)
}

// sortedTargetPlanNames returns deterministic target plan keys.
func sortedTargetPlanNames(values map[string]TargetPlanConfig) []string {
	return sortedMapKeys(values)
}

// sortedMapKeys returns deterministic string keys for any configured definition map.
func sortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}
