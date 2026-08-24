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

package admission

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/internal/identifier"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"golang.org/x/time/rate"
)

const (
	maximumAdmissionPrincipalLength = 512
	subjectFactPrefix               = "subject"
	resourceFactPrefix              = "resource"
	environmentFactPrefix           = "environment"
	inputFactPrefix                 = "input"
)

type compiledGrant struct {
	schema policyruntime.CompiledSchema
}

type compiledFieldLists struct {
	subject     map[string]struct{}
	resource    map[string]struct{}
	environment map[string]struct{}
	input       map[string]struct{}
}

type compiledProfile struct {
	grants      map[string]compiledGrant
	kinds       map[string]struct{}
	fields      compiledFieldLists
	limiter     *rate.Limiter
	concurrency chan struct{}
	principal   string
	limits      Limits
	diagnostics bool
	internal    bool
}

type authority struct {
	profiles map[string]*compiledProfile
}

type fieldListInput struct {
	values   []string
	prefix   string
	category decision.FactCategory
}

// Prepare validates, detaches, and compiles one immutable generation-owned authority.
func Prepare(
	configuration Configuration,
	catalog *policyruntime.TargetCatalog,
	credentials policyruntime.CredentialProfiles,
) (policyruntime.AdmissionPreparation, error) {
	if catalog == nil {
		return policyruntime.AdmissionPreparation{}, configurationError("target catalog is required")
	}

	if err := validateGlobalLimits(configuration.GlobalLimits); err != nil {
		return policyruntime.AdmissionPreparation{}, err
	}

	profiles := make(map[string]*compiledProfile, len(configuration.Profiles))
	profileIDs := make([]string, 0, len(configuration.Profiles))

	for index, profile := range configuration.Profiles {
		compiled, err := compileProfile(profile, configuration.GlobalLimits, catalog)
		if err != nil {
			return policyruntime.AdmissionPreparation{}, configurationError(
				fmt.Sprintf("profile %d is invalid", index),
			)
		}

		if _, duplicate := profiles[compiled.principal]; duplicate {
			return policyruntime.AdmissionPreparation{}, configurationError("profile principal is duplicated")
		}

		profiles[compiled.principal] = compiled
		profileIDs = append(profileIDs, compiled.principal)
	}

	metadata, err := policyruntime.NewAdmissionProfiles(profileIDs)
	if err != nil {
		return policyruntime.AdmissionPreparation{}, configurationError("profile identities are invalid")
	}

	if err := metadata.ValidateCredentials(credentials); err != nil {
		return policyruntime.AdmissionPreparation{}, configurationError("profile credentials do not match admission metadata")
	}

	return policyruntime.AdmissionPreparation{
		Authority: &authority{profiles: profiles},
		Profiles:  metadata,
	}, nil
}

// compileProfile validates one exact profile and constructs its stateful limit controls.
func compileProfile(
	profile Profile,
	global Limits,
	catalog *policyruntime.TargetCatalog,
) (*compiledProfile, error) {
	if !validPrincipal(profile.Principal) {
		return nil, configurationError("profile principal is invalid")
	}

	kinds, err := compileAuthenticationKinds(profile.AuthenticationKinds, profile.Internal)
	if err != nil {
		return nil, err
	}

	grants, err := compileGrants(profile.References, catalog)
	if err != nil {
		return nil, err
	}

	fields, err := compileFieldLists(profile, grants)
	if err != nil {
		return nil, err
	}

	limits, err := effectiveLimits(profile.Limits, global)
	if err != nil {
		return nil, err
	}

	return &compiledProfile{
		grants:      grants,
		kinds:       kinds,
		fields:      fields,
		limiter:     rate.NewLimiter(rate.Limit(limits.RequestsPerSecond), limits.RequestsPerSecond),
		concurrency: make(chan struct{}, limits.MaxConcurrency),
		principal:   profile.Principal,
		limits:      limits,
		diagnostics: profile.Diagnostics,
		internal:    profile.Internal,
	}, nil
}

// compileAuthenticationKinds validates explicit external or named-internal credential kinds.
func compileAuthenticationKinds(input []string, internal bool) (map[string]struct{}, error) {
	if len(input) == 0 {
		return nil, configurationError("profile authentication kinds are required")
	}

	result := make(map[string]struct{}, len(input))
	for _, kind := range input {
		if _, duplicate := result[kind]; duplicate {
			return nil, configurationError("profile authentication kind is duplicated")
		}

		if !validAuthenticationKind(kind, internal) {
			return nil, configurationError("profile authentication kind is incompatible with its internal status")
		}

		result[kind] = struct{}{}
	}

	if internal && (len(result) != 1 || !containsKey(result, policy.CallerAuthenticationKindInternal)) {
		return nil, configurationError("internal profile must use only the internal authentication kind")
	}

	return result, nil
}

// validAuthenticationKind reports whether one kind belongs to the selected profile class.
func validAuthenticationKind(kind string, internal bool) bool {
	if internal {
		return kind == policy.CallerAuthenticationKindInternal
	}

	return kind == policy.CallerAuthenticationKindBearer || kind == policy.CallerAuthenticationKindBasic
}

// compileGrants resolves every exact profile reference against the activated catalog.
func compileGrants(
	references []registry.ClientAdmissionReference,
	catalog *policyruntime.TargetCatalog,
) (map[string]compiledGrant, error) {
	if len(references) == 0 {
		return nil, configurationError("profile target references are required")
	}

	grants := make(map[string]compiledGrant, len(references))
	seen := make(map[string]struct{}, len(references))

	for _, reference := range references {
		target := reference.Target()
		identity := target.String() + "@" + reference.Schema().String()

		if _, duplicate := seen[identity]; duplicate {
			return nil, configurationError("profile target reference is duplicated")
		}

		seen[identity] = struct{}{}

		compiled, exists := catalog.Lookup(target)
		if !exists {
			return nil, configurationError("profile references an unavailable target")
		}

		if compiled.Schema().Identity().String() != reference.Schema().String() {
			return nil, configurationError("profile reference does not match the activated exact schema")
		}

		grants[target.String()] = compiledGrant{schema: compiled.Schema()}
	}

	return grants, nil
}

// compileFieldLists validates relative allowlists against the union of granted exact schemas.
func compileFieldLists(profile Profile, grants map[string]compiledGrant) (compiledFieldLists, error) {
	inputs := []fieldListInput{
		{values: profile.AllowedSubjectAttributes, prefix: subjectFactPrefix, category: decision.FactCategorySubject},
		{values: profile.AllowedResourceAttributes, prefix: resourceFactPrefix, category: decision.FactCategoryResource},
		{values: profile.AllowedEnvironmentAttributes, prefix: environmentFactPrefix, category: decision.FactCategoryEnvironment},
		{values: profile.AllowedInputAttributes, prefix: inputFactPrefix, category: decision.FactCategoryEnvironment},
	}
	compiled := make([]map[string]struct{}, 0, len(inputs))

	for _, input := range inputs {
		fields, err := compileFieldList(input, grants)
		if err != nil {
			return compiledFieldLists{}, err
		}

		compiled = append(compiled, fields)
	}

	return compiledFieldLists{
		subject:     compiled[0],
		resource:    compiled[1],
		environment: compiled[2],
		input:       compiled[3],
	}, nil
}

// compileFieldList validates one relative category allowlist without broadening any schema.
func compileFieldList(
	input fieldListInput,
	grants map[string]compiledGrant,
) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(input.values))

	for _, field := range input.values {
		if !validRelativeField(input.prefix, field) || reservedSubmittedKey(field) {
			return nil, configurationError("profile contains an invalid relative field")
		}

		if _, duplicate := result[field]; duplicate {
			return nil, configurationError("profile relative field is duplicated")
		}

		if !schemaUnionAllowsField(grants, input.prefix+"."+field, input.category) {
			return nil, configurationError("profile relative field is not a caller-owned schema field")
		}

		result[field] = struct{}{}
	}

	return result, nil
}

// schemaUnionAllowsField reports whether any granted schema owns the field for the expected caller category.
func schemaUnionAllowsField(
	grants map[string]compiledGrant,
	id string,
	category decision.FactCategory,
) bool {
	found := false

	for _, grant := range grants {
		for _, definition := range grant.schema.Facts() {
			if definition.ID() != id {
				continue
			}

			found = true

			if definition.Category() != category ||
				!slices.Contains(definition.AllowedSources(), decision.FactSourceCaller) {
				return false
			}
		}
	}

	return found
}

// validRelativeField validates a field through its canonical category-qualified identity.
func validRelativeField(prefix string, field string) bool {
	return field != "" && !strings.HasPrefix(field, ".") && !strings.HasSuffix(field, ".") &&
		identifier.Fact(prefix+"."+field)
}

// reservedSubmittedKey rejects relative keys shaped like any trusted fact family.
func reservedSubmittedKey(field string) bool {
	family := strings.SplitN(field, ".", 2)[0]

	return decision.FactSource(family).IsValid()
}

// validateGlobalLimits requires every generation default to establish a finite bound.
func validateGlobalLimits(limits Limits) error {
	if limits.MaxRequestBytes <= 0 || limits.MaxFacts <= 0 || limits.MaxConcurrency <= 0 ||
		limits.RequestsPerSecond <= 0 {
		return configurationError("global admission limits must be positive")
	}

	return nil
}

// effectiveLimits inherits zero profile values and rejects broader profile overrides.
func effectiveLimits(profile Limits, global Limits) (Limits, error) {
	requestBytes, err := effectiveLimit(profile.MaxRequestBytes, global.MaxRequestBytes)
	if err != nil {
		return Limits{}, err
	}

	facts, err := effectiveLimit(profile.MaxFacts, global.MaxFacts)
	if err != nil {
		return Limits{}, err
	}

	concurrency, err := effectiveLimit(profile.MaxConcurrency, global.MaxConcurrency)
	if err != nil {
		return Limits{}, err
	}

	requestRate, err := effectiveLimit(profile.RequestsPerSecond, global.RequestsPerSecond)
	if err != nil {
		return Limits{}, err
	}

	return Limits{
		MaxRequestBytes:   requestBytes,
		MaxFacts:          facts,
		MaxConcurrency:    concurrency,
		RequestsPerSecond: requestRate,
	}, nil
}

// effectiveLimit returns one inherited finite bound.
func effectiveLimit(profile int, global int) (int, error) {
	if profile < 0 || profile > global {
		return 0, configurationError("profile admission limit is invalid or broader than its global limit")
	}

	if profile == 0 {
		return global, nil
	}

	return profile, nil
}

// validPrincipal preserves exact bounded UTF-8 OAuth and internal principal identities.
func validPrincipal(principal string) bool {
	return principal != "" && len(principal) <= maximumAdmissionPrincipalLength &&
		strings.TrimSpace(principal) == principal && utf8.ValidString(principal)
}

// containsKey reports exact membership in one immutable string set.
func containsKey(values map[string]struct{}, key string) bool {
	_, exists := values[key]

	return exists
}
