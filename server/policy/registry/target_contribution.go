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

import (
	"context"
	"fmt"
	"slices"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/internal/identifier"
)

const (
	maximumContributionDefinitions = 256
	maximumOwnedNamespaces         = 16
	maximumTargetSchemaVersions    = 16
	factBoundsNonNegativeReason    = "bounds must not be negative"
)

// FactSchemaInput carries one fact declaration into its immutable constructor.
type FactSchemaInput struct {
	ID             string
	AllowedSources []decision.FactSource
	Category       decision.FactCategory
	Kind           decision.ValueKind
	MaxLength      int
	MaxItems       int
	MaxBytes       int
	Required       bool
}

// FactSchema is one immutable exact schema fact definition.
type FactSchema struct {
	id             string
	allowedSources []decision.FactSource
	category       decision.FactCategory
	kind           decision.ValueKind
	maxLength      int
	maxItems       int
	maxBytes       int
	required       bool
}

// NewFactSchema validates and deeply owns one exact fact definition.
func NewFactSchema(input FactSchemaInput) (FactSchema, error) {
	if !identifier.Fact(input.ID) {
		return FactSchema{}, newValidationError(
			ErrInvalidFactSchema,
			"schema.facts",
			input.ID,
			"must be a bounded canonical fact identity",
		)
	}

	if !input.Category.IsValid() || !input.Kind.IsValid() {
		return FactSchema{}, newValidationError(
			ErrInvalidFactSchema,
			"schema.facts."+input.ID,
			input.ID,
			"must use registered category and value kind",
		)
	}

	if err := validateFactSources(input.ID, input.AllowedSources); err != nil {
		return FactSchema{}, err
	}

	if err := validateFactBounds(input); err != nil {
		return FactSchema{}, err
	}

	return FactSchema{
		id:             input.ID,
		allowedSources: append([]decision.FactSource(nil), input.AllowedSources...),
		category:       input.Category,
		kind:           input.Kind,
		maxLength:      input.MaxLength,
		maxItems:       input.MaxItems,
		maxBytes:       input.MaxBytes,
		required:       input.Required,
	}, nil
}

// ID returns the exact canonical fact identity.
func (f FactSchema) ID() string {
	return f.id
}

// AllowedSources returns a detached source allowlist.
func (f FactSchema) AllowedSources() []decision.FactSource {
	return append([]decision.FactSource(nil), f.allowedSources...)
}

// Category returns the required fact category.
func (f FactSchema) Category() decision.FactCategory {
	return f.category
}

// Kind returns the required strict value kind.
func (f FactSchema) Kind() decision.ValueKind {
	return f.kind
}

// MaxLength returns the configured text or text-member limit.
func (f FactSchema) MaxLength() int {
	return f.maxLength
}

// MaxItems returns the configured list item limit.
func (f FactSchema) MaxItems() int {
	return f.maxItems
}

// MaxBytes returns the configured byte limit.
func (f FactSchema) MaxBytes() int {
	return f.maxBytes
}

// Required reports whether the selected schema requires the fact.
func (f FactSchema) Required() bool {
	return f.required
}

// clone returns a detached immutable fact schema value.
func (f FactSchema) clone() FactSchema {
	f.allowedSources = append([]decision.FactSource(nil), f.allowedSources...)

	return f
}

// valid reports whether the fact schema satisfies its constructor invariant.
func (f FactSchema) valid() bool {
	if !identifier.Fact(f.id) || !f.category.IsValid() || !f.kind.IsValid() || len(f.allowedSources) == 0 {
		return false
	}

	for _, source := range f.allowedSources {
		if !source.IsValid() {
			return false
		}
	}

	return f.maxLength >= 0 && f.maxItems >= 0 && f.maxBytes >= 0
}

// SchemaDefinition is one immutable contributed exact schema version.
type SchemaDefinition struct {
	identity    SchemaIdentity
	facts       []FactSchema
	builtinAuth bool
}

// NewSchemaDefinition validates and deeply owns one schema definition.
func NewSchemaDefinition(identity SchemaIdentity, facts []FactSchema) (SchemaDefinition, error) {
	if !identity.valid() {
		return SchemaDefinition{}, newValidationError(
			ErrInvalidSchemaIdentity,
			"schema",
			identity.String(),
			"must be constructor validated",
		)
	}

	if len(facts) > maximumContributionDefinitions {
		return SchemaDefinition{}, newValidationError(
			ErrInvalidFactSchema,
			identity.String()+".facts",
			identity.String(),
			"contains too many fact definitions",
		)
	}

	cloned := make([]FactSchema, 0, len(facts))
	seen := make(map[string]struct{}, len(facts))

	for _, fact := range facts {
		if !fact.valid() {
			return SchemaDefinition{}, newValidationError(
				ErrInvalidFactSchema,
				identity.String()+".facts",
				fact.ID(),
				"must be constructor validated",
			)
		}

		if _, exists := seen[fact.ID()]; exists {
			return SchemaDefinition{}, newValidationError(
				ErrDuplicateDefinition,
				identity.String()+".facts",
				fact.ID(),
				"fact definition occurs more than once",
			)
		}

		seen[fact.ID()] = struct{}{}
		cloned = append(cloned, fact.clone())
	}

	return SchemaDefinition{identity: identity, facts: cloned}, nil
}

// Identity returns the exact qualified schema identity.
func (s SchemaDefinition) Identity() SchemaIdentity {
	return s.identity
}

// Facts returns detached immutable fact definitions.
func (s SchemaDefinition) Facts() []FactSchema {
	return cloneFactSchemas(s.facts)
}

// IsBuiltinAuth reports immutable builtin provenance for an authn schema.
func (s SchemaDefinition) IsBuiltinAuth() bool {
	return s.builtinAuth
}

// clone returns a detached schema definition.
func (s SchemaDefinition) clone() SchemaDefinition {
	s.facts = cloneFactSchemas(s.facts)

	return s
}

// valid reports whether the schema definition satisfies its constructor invariant.
func (s SchemaDefinition) valid() bool {
	if !s.identity.valid() {
		return false
	}

	for _, fact := range s.facts {
		if !fact.valid() {
			return false
		}
	}

	return true
}

// TargetDefinition is one immutable contributed target with supported exact schemas.
type TargetDefinition struct {
	target  decision.Target
	schemas []SchemaIdentity
}

// NewTargetDefinition validates and owns one contributed target definition.
func NewTargetDefinition(target decision.Target, schemas []SchemaIdentity) (TargetDefinition, error) {
	validatedTarget, err := decision.NewTarget(target.Namespace(), target.Action())
	if err != nil {
		return TargetDefinition{}, newValidationError(
			ErrInvalidAction,
			"target",
			target.String(),
			"must be constructor validated",
		)
	}

	if len(schemas) == 0 || len(schemas) > maximumTargetSchemaVersions {
		return TargetDefinition{}, newValidationError(
			ErrInvalidSchemaIdentity,
			validatedTarget.String()+".schemas",
			validatedTarget.String(),
			"must declare a bounded non-empty exact schema set",
		)
	}

	cloned := append([]SchemaIdentity(nil), schemas...)
	seen := make(map[string]struct{}, len(cloned))

	for _, schema := range cloned {
		if !schema.valid() || schema.Namespace() != target.Namespace() || schema.Name() != target.Action() {
			return TargetDefinition{}, newValidationError(
				ErrTargetSchemaMismatch,
				validatedTarget.String()+".schemas",
				schema.String(),
				"schema must belong to the exact target",
			)
		}

		if _, exists := seen[schema.String()]; exists {
			return TargetDefinition{}, newValidationError(
				ErrDuplicateDefinition,
				validatedTarget.String()+".schemas",
				schema.String(),
				"schema identity occurs more than once",
			)
		}

		seen[schema.String()] = struct{}{}
	}

	return TargetDefinition{target: validatedTarget, schemas: cloned}, nil
}

// Target returns the exact contributed target.
func (d TargetDefinition) Target() decision.Target {
	return d.target
}

// Schemas returns a detached exact schema identity list.
func (d TargetDefinition) Schemas() []SchemaIdentity {
	return append([]SchemaIdentity(nil), d.schemas...)
}

// Supports reports whether the target contributed the exact schema version.
func (d TargetDefinition) Supports(schema SchemaIdentity) bool {
	return slices.ContainsFunc(d.schemas, func(candidate SchemaIdentity) bool {
		return candidate.String() == schema.String()
	})
}

// valid reports whether the target definition satisfies its constructor invariant.
func (d TargetDefinition) valid() bool {
	_, err := decision.NewTarget(d.target.Namespace(), d.target.Action())

	return err == nil && len(d.schemas) > 0
}

// NamespaceOwnership bounds one contributor to explicitly assigned namespaces.
type NamespaceOwnership struct {
	owner      string
	namespaces []string
}

// NewNamespaceOwnership validates one contributor and its bounded namespace allowlist.
func NewNamespaceOwnership(owner string, namespaces []string) (NamespaceOwnership, error) {
	if !identifier.Namespace(owner) {
		return NamespaceOwnership{}, newValidationError(
			ErrNamespaceOwnership,
			"contributor.owner",
			owner,
			"must be a canonical bounded identity",
		)
	}

	if len(namespaces) == 0 || len(namespaces) > maximumOwnedNamespaces {
		return NamespaceOwnership{}, newValidationError(
			ErrNamespaceOwnership,
			"contributor.namespaces",
			owner,
			"must contain a bounded non-empty namespace allowlist",
		)
	}

	cloned := append([]string(nil), namespaces...)
	seen := make(map[string]struct{}, len(cloned))

	for _, namespace := range cloned {
		if !identifier.Namespace(namespace) {
			return NamespaceOwnership{}, newValidationError(
				ErrInvalidNamespace,
				"contributor.namespaces",
				namespace,
				"must contain lowercase ASCII segments separated by dots",
			)
		}

		if _, exists := seen[namespace]; exists {
			return NamespaceOwnership{}, newValidationError(
				ErrDuplicateNamespace,
				"contributor.namespaces",
				namespace,
				"namespace occurs more than once",
			)
		}

		seen[namespace] = struct{}{}
	}

	return NamespaceOwnership{owner: owner, namespaces: cloned}, nil
}

// Owner returns the exact contributor identity.
func (o NamespaceOwnership) Owner() string {
	return o.owner
}

// Namespaces returns a detached namespace allowlist.
func (o NamespaceOwnership) Namespaces() []string {
	return append([]string(nil), o.namespaces...)
}

// Owns reports whether the contributor owns the exact namespace.
func (o NamespaceOwnership) Owns(namespace string) bool {
	return slices.Contains(o.namespaces, namespace)
}

// valid reports whether ownership satisfies its constructor invariant.
func (o NamespaceOwnership) valid() bool {
	return identifier.Namespace(o.owner) && len(o.namespaces) > 0
}

// DefinitionContribution is the sole immutable internal definition contribution DTO.
type DefinitionContribution struct {
	ownership  NamespaceOwnership
	targets    []TargetDefinition
	schemas    []SchemaDefinition
	policySets []PolicySetDefinition
	plans      []DomainPlanDefinition
	providers  []ProviderDefinition
	effects    []EffectDefinition
}

// DefinitionContributionInput carries every catalog definition kind through one DTO.
type DefinitionContributionInput struct {
	Ownership  NamespaceOwnership
	Targets    []TargetDefinition
	Schemas    []SchemaDefinition
	PolicySets []PolicySetDefinition
	Plans      []DomainPlanDefinition
	Providers  []ProviderDefinition
	Effects    []EffectDefinition
}

// NewDefinitionContribution validates namespace ownership and deeply owns all definitions.
func NewDefinitionContribution(
	ownership NamespaceOwnership,
	targets []TargetDefinition,
	schemas []SchemaDefinition,
) (DefinitionContribution, error) {
	return NewCompleteDefinitionContribution(DefinitionContributionInput{
		Ownership: ownership,
		Targets:   targets,
		Schemas:   schemas,
	})
}

// NewCompleteDefinitionContribution validates and owns every catalog definition kind.
func NewCompleteDefinitionContribution(input DefinitionContributionInput) (DefinitionContribution, error) {
	ownership := input.Ownership
	if !ownership.valid() {
		return DefinitionContribution{}, newValidationError(
			ErrNamespaceOwnership,
			"contributor",
			ownership.Owner(),
			"must be constructor validated",
		)
	}

	definitionCount := len(input.Targets) + len(input.Schemas) + len(input.PolicySets) +
		len(input.Plans) + len(input.Providers) + len(input.Effects)
	if definitionCount == 0 || definitionCount > maximumContributionDefinitions {
		return DefinitionContribution{}, newValidationError(
			ErrDuplicateDefinition,
			"contributor.definitions",
			ownership.Owner(),
			"must contain a bounded non-empty definition set",
		)
	}

	clonedTargets, err := cloneContributionTargets(ownership, input.Targets)
	if err != nil {
		return DefinitionContribution{}, err
	}

	clonedSchemas, err := cloneContributionSchemas(ownership, input.Schemas)
	if err != nil {
		return DefinitionContribution{}, err
	}

	clonedSets, err := cloneContributionPolicySets(ownership, input.PolicySets)
	if err != nil {
		return DefinitionContribution{}, err
	}

	clonedPlans, err := cloneContributionPlans(ownership, input.Plans)
	if err != nil {
		return DefinitionContribution{}, err
	}

	clonedProviders, err := cloneContributionProviders(ownership, input.Providers)
	if err != nil {
		return DefinitionContribution{}, err
	}

	clonedEffects, err := cloneContributionEffects(ownership, input.Effects)
	if err != nil {
		return DefinitionContribution{}, err
	}

	return DefinitionContribution{
		ownership:  ownership,
		targets:    clonedTargets,
		schemas:    clonedSchemas,
		policySets: clonedSets,
		plans:      clonedPlans,
		providers:  clonedProviders,
		effects:    clonedEffects,
	}, nil
}

// Ownership returns the immutable contributor namespace bounds.
func (c DefinitionContribution) Ownership() NamespaceOwnership {
	return NamespaceOwnership{owner: c.ownership.owner, namespaces: c.ownership.Namespaces()}
}

// Targets returns detached contributed target definitions.
func (c DefinitionContribution) Targets() []TargetDefinition {
	targets := append([]TargetDefinition(nil), c.targets...)
	for index := range targets {
		targets[index].schemas = append([]SchemaIdentity(nil), targets[index].schemas...)
	}

	return targets
}

// Schemas returns detached contributed schema definitions.
func (c DefinitionContribution) Schemas() []SchemaDefinition {
	schemas := append([]SchemaDefinition(nil), c.schemas...)
	for index := range schemas {
		schemas[index] = schemas[index].clone()
	}

	return schemas
}

// PolicySets returns detached contributed namespace-nested sets.
func (c DefinitionContribution) PolicySets() []PolicySetDefinition {
	result := make([]PolicySetDefinition, 0, len(c.policySets))
	for _, set := range c.policySets {
		result = append(result, set.clone())
	}

	return result
}

// Plans returns detached target-owned domain plans.
func (c DefinitionContribution) Plans() []DomainPlanDefinition {
	result := make([]DomainPlanDefinition, 0, len(c.plans))
	for _, plan := range c.plans {
		result = append(result, plan.clone())
	}

	return result
}

// Providers returns detached provider descriptors.
func (c DefinitionContribution) Providers() []ProviderDefinition {
	result := append([]ProviderDefinition(nil), c.providers...)
	for index := range result {
		result[index] = result[index].clone()
	}

	return result
}

// Effects returns detached effect descriptors.
func (c DefinitionContribution) Effects() []EffectDefinition {
	result := append([]EffectDefinition(nil), c.effects...)
	for index := range result {
		result[index] = result[index].clone()
	}

	return result
}

// Validate rejects a contribution that did not pass through its immutable constructor.
func (c DefinitionContribution) Validate() error {
	if !c.ownership.valid() {
		return newValidationError(
			ErrInvalidContribution,
			"contributor",
			c.ownership.Owner(),
			"ownership must be constructor validated",
		)
	}

	if len(c.targets)+len(c.schemas)+len(c.policySets)+len(c.plans)+len(c.providers)+len(c.effects) == 0 {
		return newValidationError(
			ErrInvalidContribution,
			"contributor.definitions",
			c.ownership.Owner(),
			"definition set must not be empty",
		)
	}

	_, err := NewCompleteDefinitionContribution(DefinitionContributionInput{
		Ownership:  c.ownership,
		Targets:    c.targets,
		Schemas:    c.schemas,
		PolicySets: c.policySets,
		Plans:      c.plans,
		Providers:  c.providers,
		Effects:    c.effects,
	})

	return err
}

// Contributor supplies one immutable bounded definition batch during candidate compilation.
type Contributor interface {
	Contribute(context.Context) (DefinitionContribution, error)
}

// validateFactSources validates the exact bounded source allowlist.
func validateFactSources(id string, sources []decision.FactSource) error {
	if len(sources) == 0 || len(sources) > len([]decision.FactSource{
		decision.FactSourceCaller,
		decision.FactSourceToken,
		decision.FactSourceTransport,
		decision.FactSourceNauthilus,
		decision.FactSourceBackend,
		decision.FactSourceLua,
		decision.FactSourcePlugin,
	}) {
		return newValidationError(ErrInvalidFactSchema, "schema.facts."+id, id, "must declare a bounded source allowlist")
	}

	seen := make(map[decision.FactSource]struct{}, len(sources))
	for _, source := range sources {
		if !source.IsValid() {
			return newValidationError(ErrInvalidFactSchema, "schema.facts."+id, id, "contains an unknown fact source")
		}

		if _, exists := seen[source]; exists {
			return newValidationError(ErrDuplicateDefinition, "schema.facts."+id, string(source), "source occurs more than once")
		}

		seen[source] = struct{}{}
	}

	return nil
}

// validateFactBounds enforces non-negative and value-kind-specific schema bounds.
func validateFactBounds(input FactSchemaInput) error {
	if input.MaxLength < 0 {
		return newValidationError(ErrInvalidFactSchema, "schema.facts."+input.ID, input.ID, factBoundsNonNegativeReason)
	}

	if input.MaxItems < 0 {
		return newValidationError(ErrInvalidFactSchema, "schema.facts."+input.ID, input.ID, factBoundsNonNegativeReason)
	}

	if input.MaxBytes < 0 {
		return newValidationError(ErrInvalidFactSchema, "schema.facts."+input.ID, input.ID, factBoundsNonNegativeReason)
	}

	switch input.Kind {
	case decision.ValueKindString:
		return requireFactBounds(input, validStringFactBounds(input))
	case decision.ValueKindStrings:
		return requireFactBounds(input, validStringListFactBounds(input))
	case decision.ValueKindBytes:
		return requireFactBounds(input, validBytesFactBounds(input))
	default:
		return requireFactBounds(input, validScalarFactBounds(input))
	}
}

// validStringFactBounds reports whether only a positive text bound is present.
func validStringFactBounds(input FactSchemaInput) bool {
	if input.MaxLength <= 0 || input.MaxItems != 0 {
		return false
	}

	return input.MaxBytes == 0
}

// validStringListFactBounds reports whether list count and member text are bounded.
func validStringListFactBounds(input FactSchemaInput) bool {
	if input.MaxLength <= 0 || input.MaxItems <= 0 {
		return false
	}

	return input.MaxBytes == 0
}

// validBytesFactBounds reports whether only a positive byte bound is present.
func validBytesFactBounds(input FactSchemaInput) bool {
	if input.MaxLength != 0 || input.MaxItems != 0 {
		return false
	}

	return input.MaxBytes > 0
}

// validScalarFactBounds reports whether scalar kinds declare no size bounds.
func validScalarFactBounds(input FactSchemaInput) bool {
	if input.MaxLength != 0 || input.MaxItems != 0 {
		return false
	}

	return input.MaxBytes == 0
}

// requireFactBounds returns one stable error when kind-specific bounds do not match.
func requireFactBounds(input FactSchemaInput, valid bool) error {
	if valid {
		return nil
	}

	return newValidationError(
		ErrInvalidFactSchema,
		"schema.facts."+input.ID,
		input.ID,
		"bounds must match the exact value kind",
	)
}

// cloneContributionTargets validates namespace ownership and target collisions.
func cloneContributionTargets(ownership NamespaceOwnership, targets []TargetDefinition) ([]TargetDefinition, error) {
	cloned := append([]TargetDefinition(nil), targets...)
	seen := make(map[string]struct{}, len(cloned))

	for index := range cloned {
		target := cloned[index]
		identityValue := target.Target().String()

		if !target.valid() {
			return nil, newValidationError(ErrInvalidAction, "contributor.targets", identityValue, "must be constructor validated")
		}

		if !ownership.Owns(target.Target().Namespace()) {
			return nil, newValidationError(ErrNamespaceOwnership, "contributor.targets", identityValue, ownershipReason(ownership))
		}

		if _, exists := seen[identityValue]; exists {
			return nil, newValidationError(ErrDuplicateDefinition, "contributor.targets", identityValue, "target occurs more than once")
		}

		seen[identityValue] = struct{}{}

		cloned[index].schemas = append([]SchemaIdentity(nil), target.schemas...)
	}

	return cloned, nil
}

// cloneContributionSchemas validates namespace ownership and schema collisions.
func cloneContributionSchemas(ownership NamespaceOwnership, schemas []SchemaDefinition) ([]SchemaDefinition, error) {
	cloned := append([]SchemaDefinition(nil), schemas...)
	seen := make(map[string]struct{}, len(cloned))

	for index := range cloned {
		schema := cloned[index]
		identityValue := schema.Identity().String()

		if !schema.valid() {
			return nil, newValidationError(ErrInvalidSchemaIdentity, "contributor.schemas", identityValue, "must be constructor validated")
		}

		if !ownership.Owns(schema.Identity().Namespace()) {
			return nil, newValidationError(ErrNamespaceOwnership, "contributor.schemas", identityValue, ownershipReason(ownership))
		}

		if _, exists := seen[identityValue]; exists {
			return nil, newValidationError(ErrDuplicateDefinition, "contributor.schemas", identityValue, "schema occurs more than once")
		}

		seen[identityValue] = struct{}{}
		cloned[index] = schema.clone()
	}

	return cloned, nil
}

// cloneContributionPolicySets validates set namespace ownership and collisions.
func cloneContributionPolicySets(ownership NamespaceOwnership, sets []PolicySetDefinition) ([]PolicySetDefinition, error) {
	result := make([]PolicySetDefinition, 0, len(sets))
	seen := make(map[string]struct{}, len(sets))

	for _, set := range sets {
		identityValue := set.ID().String()
		if !set.ID().valid() || !ownership.Owns(set.ID().Namespace()) {
			return nil, newValidationError(ErrNamespaceOwnership, "contributor.policy_sets", identityValue, ownershipReason(ownership))
		}

		if _, exists := seen[identityValue]; exists {
			return nil, newValidationError(ErrDuplicateDefinition, "contributor.policy_sets", identityValue, "policy set occurs more than once")
		}

		seen[identityValue] = struct{}{}

		result = append(result, set.clone())
	}

	return result, nil
}

// cloneContributionPlans validates target namespace ownership and collisions.
func cloneContributionPlans(ownership NamespaceOwnership, plans []DomainPlanDefinition) ([]DomainPlanDefinition, error) {
	result := make([]DomainPlanDefinition, 0, len(plans))
	seen := make(map[string]struct{}, len(plans))

	for _, plan := range plans {
		identityValue := plan.Target().String()
		if !plan.valid() || !ownership.Owns(plan.Target().Namespace()) {
			return nil, newValidationError(ErrNamespaceOwnership, "contributor.plans", identityValue, ownershipReason(ownership))
		}

		if _, exists := seen[identityValue]; exists {
			return nil, newValidationError(ErrDuplicateDefinition, "contributor.plans", identityValue, "domain plan occurs more than once")
		}

		seen[identityValue] = struct{}{}

		result = append(result, plan.clone())
	}

	return result, nil
}

// cloneContributionProviders validates provider namespace ownership and collisions.
func cloneContributionProviders(ownership NamespaceOwnership, providers []ProviderDefinition) ([]ProviderDefinition, error) {
	return cloneQualifiedDefinitions(
		ownership,
		providers,
		"providers",
		"provider",
		identifier.ProviderIdentity,
		func(provider ProviderDefinition) string { return provider.ID() },
		func(provider ProviderDefinition) (ProviderDefinition, error) { return provider.validatedClone() },
	)
}

// cloneContributionEffects validates effect namespace ownership and collisions.
func cloneContributionEffects(ownership NamespaceOwnership, effects []EffectDefinition) ([]EffectDefinition, error) {
	return cloneQualifiedDefinitions(
		ownership,
		effects,
		"effects",
		"effect",
		validEffectID,
		func(effect EffectDefinition) string { return effect.ID() },
		func(effect EffectDefinition) (EffectDefinition, error) { return effect.validatedClone() },
	)
}

// cloneQualifiedDefinitions shares namespace ownership, collision, and copy rules.
func cloneQualifiedDefinitions[T any](
	ownership NamespaceOwnership,
	values []T,
	pathKind string,
	identityKind string,
	validIdentity func(string) bool,
	identityOf func(T) string,
	validatedClone func(T) (T, error),
) ([]T, error) {
	result := make([]T, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	path := "contributor." + pathKind

	for _, value := range values {
		identityValue := identityOf(value)
		if !validIdentity(identityValue) || !ownership.Owns(qualifiedNamespace(identityValue)) {
			return nil, newValidationError(ErrNamespaceOwnership, path, identityValue, ownershipReason(ownership))
		}

		if _, exists := seen[identityValue]; exists {
			return nil, newValidationError(ErrDuplicateDefinition, path, identityValue, identityKind+" occurs more than once")
		}

		seen[identityValue] = struct{}{}

		cloned, err := validatedClone(value)
		if err != nil {
			return nil, err
		}

		result = append(result, cloned)
	}

	return result, nil
}

// qualifiedNamespace extracts a constructor-validated qualified identity namespace.
func qualifiedNamespace(value string) string {
	for index := range len(value) {
		if value[index] == '/' {
			return value[:index]
		}
	}

	return ""
}

// cloneFactSchemas returns detached immutable fact schemas.
func cloneFactSchemas(facts []FactSchema) []FactSchema {
	cloned := append([]FactSchema(nil), facts...)
	for index := range cloned {
		cloned[index] = cloned[index].clone()
	}

	return cloned
}

// ownershipReason describes the exact namespace bound without precedence language.
func ownershipReason(ownership NamespaceOwnership) string {
	return fmt.Sprintf("contributor %q owns only %v", ownership.Owner(), ownership.Namespaces())
}
