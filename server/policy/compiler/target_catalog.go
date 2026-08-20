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
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const authnNamespace = "authn"

var (
	// ErrDefinitionCollision identifies equal contributed identities without precedence.
	ErrDefinitionCollision = errors.New("policy catalog definition collision")

	// ErrDuplicateContributor identifies repeated contributor identities.
	ErrDuplicateContributor = errors.New("duplicate policy catalog contributor")

	// ErrUnknownTargetDefinition identifies activation of an uncontributed target.
	ErrUnknownTargetDefinition = errors.New("unknown policy target definition")

	// ErrUnknownSchemaDefinition identifies activation of an uncontributed exact schema.
	ErrUnknownSchemaDefinition = errors.New("unknown policy schema definition")

	// ErrDuplicateTargetActivation identifies repeated activation of one exact target.
	ErrDuplicateTargetActivation = errors.New("duplicate policy target activation")

	// ErrUnknownActivatedTarget identifies an admission reference to an inactive target.
	ErrUnknownActivatedTarget = errors.New("unknown activated policy target")

	// ErrAdmissionSchemaMismatch identifies an admission reference to a different schema version.
	ErrAdmissionSchemaMismatch = errors.New("policy admission schema does not match activated schema")

	// ErrUnknownPolicySet identifies an exact set reference without a definition.
	ErrUnknownPolicySet = errors.New("unknown policy set")

	// ErrPrivatePolicySetImport identifies a cross-namespace reference to a private set.
	ErrPrivatePolicySetImport = errors.New("private policy set cannot be imported across namespaces")

	// ErrIncompletePolicySetImport identifies a cross-namespace reference without a full typed contract.
	ErrIncompletePolicySetImport = errors.New("incomplete cross-namespace policy set import")

	// ErrIncompatiblePolicySetImport identifies unequal exact export/import capabilities.
	ErrIncompatiblePolicySetImport = errors.New("incompatible policy set import contract")

	// ErrPolicySetImportCycle identifies cyclic explicit set imports.
	ErrPolicySetImportCycle = errors.New("cyclic policy set import")

	// ErrPolicyRuleTargetMismatch identifies a rule bound to a different exact target.
	ErrPolicyRuleTargetMismatch = errors.New("policy rule target mismatch")

	// ErrPolicyRuleCheckpointMismatch identifies a rule bound to a different exact checkpoint.
	ErrPolicyRuleCheckpointMismatch = errors.New("policy rule checkpoint mismatch")

	// ErrPolicyRuleFactMismatch identifies an expression fact outside the selected exact schema.
	ErrPolicyRuleFactMismatch = errors.New("policy rule fact mismatch")

	// ErrPolicyEffectTargetMismatch identifies an effect outside the exact target allowlist.
	ErrPolicyEffectTargetMismatch = errors.New("policy effect target mismatch")

	// ErrPolicyEffectParameterMismatch identifies typed effect arguments outside the schema.
	ErrPolicyEffectParameterMismatch = errors.New("policy effect parameter mismatch")

	// ErrUnknownEffectProvider identifies an unresolved host-effect provider binding.
	ErrUnknownEffectProvider = errors.New("unknown policy effect provider")

	// ErrIncompatibleEffectProvider identifies a target/class mismatch in a provider binding.
	ErrIncompatibleEffectProvider = errors.New("incompatible policy effect provider")

	// ErrMissingPostActionAcceptanceCapability identifies a post-action provider without supervisor ownership.
	ErrMissingPostActionAcceptanceCapability = errors.New("missing host post-action acceptance capability")

	// ErrDuplicateDiagnosticPublicID identifies target-local public alias collisions.
	ErrDuplicateDiagnosticPublicID = errors.New("duplicate target diagnostic public id")

	// ErrMissingNoMatchBehavior identifies a generic activation without an explicit fallback.
	ErrMissingNoMatchBehavior = errors.New("missing generic no-match behavior")

	// ErrInvalidNoMatchBehavior identifies a generic fallback outside deny/not-applicable.
	ErrInvalidNoMatchBehavior = errors.New("invalid generic no-match behavior")

	// ErrAuthnNoMatchBehavior identifies forbidden generic fallback configuration on authn.
	ErrAuthnNoMatchBehavior = errors.New("authn target cannot configure generic no-match")

	// ErrStandardAuthTargetMismatch identifies assignment of standard_auth outside authn.
	ErrStandardAuthTargetMismatch = errors.New("standard_auth is restricted to authn targets")

	// ErrStandardAuthCrossNamespaceImport identifies cross-domain use of the builtin auth set.
	ErrStandardAuthCrossNamespaceImport = errors.New("standard_auth cannot be imported across namespaces")

	// ErrUnknownDomainPlan identifies activation without one exact contributed plan.
	ErrUnknownDomainPlan = errors.New("unknown policy domain plan")

	// ErrDefaultPolicySetUnbound identifies a default absent from every exact checkpoint.
	ErrDefaultPolicySetUnbound = errors.New("default policy set is not bound to a target checkpoint")

	// ErrDefaultPolicySetNamespaceMismatch identifies a cross-namespace default without an import.
	ErrDefaultPolicySetNamespaceMismatch = errors.New("default policy set belongs to another namespace")
)

// TargetCatalogCompiler builds immutable target/schema candidates without publishing them.
type TargetCatalogCompiler struct {
	contributors []registry.Contributor
}

type collectedCatalogDefinitions struct {
	targets    map[string]ownedTargetDefinition
	schemas    map[string]ownedSchemaDefinition
	policySets map[string]registry.PolicySetDefinition
	plans      map[string]registry.DomainPlanDefinition
	providers  map[string]registry.ProviderDefinition
	effects    map[string]registry.EffectDefinition
	claims     map[string]string
}

type ownedTargetDefinition struct {
	definition registry.TargetDefinition
}

type ownedSchemaDefinition struct {
	definition registry.SchemaDefinition
}

// NewTargetCatalogCompiler owns the ordered contributor adapters for one candidate build.
func NewTargetCatalogCompiler(contributors ...registry.Contributor) *TargetCatalogCompiler {
	return &TargetCatalogCompiler{contributors: append([]registry.Contributor(nil), contributors...)}
}

// Compile collects definitions and compiles only explicitly activated target/schema records.
func (c *TargetCatalogCompiler) Compile(
	ctx context.Context,
	activations []registry.TargetActivation,
) (*policyruntime.TargetCatalog, error) {
	definitions, err := c.collectDefinitions(ctx)
	if err != nil {
		return nil, err
	}

	if err := validateCatalogDefinitions(definitions); err != nil {
		return nil, err
	}

	records, err := compileActivatedRecords(definitions, activations)
	if err != nil {
		return nil, err
	}

	catalog, err := policyruntime.NewTargetCatalog(records, collectedPolicySets(definitions))
	if err != nil {
		return nil, fmt.Errorf("compile target catalog candidate: %w", err)
	}

	return catalog, nil
}

// ValidateAdmissionReferences validates future client references without mutating or activating the catalog.
func ValidateAdmissionReferences(
	catalog *policyruntime.TargetCatalog,
	references []registry.ClientAdmissionReference,
) error {
	seen := make(map[string]struct{}, len(references))

	for _, reference := range references {
		identity := reference.Target().String() + "@" + reference.Schema().String()
		if _, exists := seen[identity]; exists {
			return fmt.Errorf("%s: duplicate client admission reference %s", reference.Path(), identity)
		}

		seen[identity] = struct{}{}

		compiled, ok := catalog.Lookup(reference.Target())
		if !ok {
			return fmt.Errorf("%w: %s: %s", ErrUnknownActivatedTarget, reference.Path(), reference.Target().String())
		}

		if compiled.Schema().Identity().String() != reference.Schema().String() {
			return fmt.Errorf(
				"%w: %s: activated %s, referenced %s",
				ErrAdmissionSchemaMismatch,
				reference.Path(),
				compiled.Schema().Identity().String(),
				reference.Schema().String(),
			)
		}
	}

	return nil
}

// collectDefinitions obtains one immutable batch per contributor and rejects all collisions.
func (c *TargetCatalogCompiler) collectDefinitions(ctx context.Context) (collectedCatalogDefinitions, error) {
	definitions := collectedCatalogDefinitions{
		targets:    make(map[string]ownedTargetDefinition),
		schemas:    make(map[string]ownedSchemaDefinition),
		policySets: make(map[string]registry.PolicySetDefinition),
		plans:      make(map[string]registry.DomainPlanDefinition),
		providers:  make(map[string]registry.ProviderDefinition),
		effects:    make(map[string]registry.EffectDefinition),
		claims:     make(map[string]string),
	}

	if c == nil {
		return definitions, nil
	}

	owners := make(map[string]struct{}, len(c.contributors))

	for index, contributor := range c.contributors {
		if contributor == nil {
			return collectedCatalogDefinitions{}, fmt.Errorf("catalog.contributors[%d]: contributor is nil", index)
		}

		if err := ctx.Err(); err != nil {
			return collectedCatalogDefinitions{}, err
		}

		contribution, err := contributor.Contribute(ctx)
		if err != nil {
			return collectedCatalogDefinitions{}, fmt.Errorf("catalog.contributors[%d]: %w", index, err)
		}

		if err := contribution.Validate(); err != nil {
			return collectedCatalogDefinitions{}, fmt.Errorf("catalog.contributors[%d]: %w", index, err)
		}

		owner := contribution.Ownership().Owner()
		if _, exists := owners[owner]; exists {
			return collectedCatalogDefinitions{}, fmt.Errorf("%w: %s", ErrDuplicateContributor, owner)
		}

		owners[owner] = struct{}{}

		if err := collectContributionDefinitions(&definitions, contribution); err != nil {
			return collectedCatalogDefinitions{}, err
		}
	}

	return definitions, nil
}

// collectContributionDefinitions inserts all contribution kinds through one collision path.
func collectContributionDefinitions(
	definitions *collectedCatalogDefinitions,
	contribution registry.DefinitionContribution,
) error {
	owner := contribution.Ownership().Owner()
	if err := collectTargetSchemaDefinitions(definitions, contribution, owner); err != nil {
		return err
	}

	return collectPolicyExecutionDefinitions(definitions, contribution, owner)
}

// collectTargetSchemaDefinitions inserts foundation definition kinds.
func collectTargetSchemaDefinitions(
	definitions *collectedCatalogDefinitions,
	contribution registry.DefinitionContribution,
	owner string,
) error {
	err := collectDefinitionKind(
		definitions,
		"target",
		owner,
		contribution.Targets(),
		func(target registry.TargetDefinition) string { return target.Target().String() },
		func(identity string, target registry.TargetDefinition) {
			definitions.targets[identity] = ownedTargetDefinition{definition: target}
		},
	)
	if err != nil {
		return err
	}

	return collectDefinitionKind(
		definitions,
		"schema",
		owner,
		contribution.Schemas(),
		func(schema registry.SchemaDefinition) string { return schema.Identity().String() },
		func(identity string, schema registry.SchemaDefinition) {
			definitions.schemas[identity] = ownedSchemaDefinition{definition: schema}
		},
	)
}

// collectPolicyExecutionDefinitions inserts policy, plan, provider, and effect kinds.
func collectPolicyExecutionDefinitions(
	definitions *collectedCatalogDefinitions,
	contribution registry.DefinitionContribution,
	owner string,
) error {
	err := collectDefinitionKind(
		definitions,
		"policy_set",
		owner,
		contribution.PolicySets(),
		func(set registry.PolicySetDefinition) string { return set.ID().String() },
		func(identity string, set registry.PolicySetDefinition) { definitions.policySets[identity] = set },
	)
	if err != nil {
		return err
	}

	err = collectDefinitionKind(
		definitions,
		"domain_plan",
		owner,
		contribution.Plans(),
		func(plan registry.DomainPlanDefinition) string { return plan.Target().String() },
		func(identity string, plan registry.DomainPlanDefinition) { definitions.plans[identity] = plan },
	)
	if err != nil {
		return err
	}

	err = collectDefinitionKind(
		definitions,
		"provider",
		owner,
		contribution.Providers(),
		func(provider registry.ProviderDefinition) string { return provider.ID() },
		func(identity string, provider registry.ProviderDefinition) {
			definitions.providers[identity] = provider
		},
	)
	if err != nil {
		return err
	}

	return collectDefinitionKind(
		definitions,
		"effect",
		owner,
		contribution.Effects(),
		func(effect registry.EffectDefinition) string { return effect.ID() },
		func(identity string, effect registry.EffectDefinition) { definitions.effects[identity] = effect },
	)
}

// collectDefinitionKind inserts one definition kind without replacement or precedence.
func collectDefinitionKind[T any](
	definitions *collectedCatalogDefinitions,
	kind string,
	owner string,
	values []T,
	identityOf func(T) string,
	store func(string, T),
) error {
	for _, value := range values {
		identity := identityOf(value)
		if err := definitions.claim(kind, identity, owner); err != nil {
			return err
		}

		store(identity, value)
	}

	return nil
}

// compileActivatedRecords resolves exact contributed identities into runtime-owned records.
func compileActivatedRecords(
	definitions collectedCatalogDefinitions,
	activations []registry.TargetActivation,
) ([]policyruntime.TargetCatalogRecord, error) {
	records := make([]policyruntime.TargetCatalogRecord, 0, len(activations))
	activated := make(map[string]struct{}, len(activations))

	for _, activation := range activations {
		targetIdentity := activation.Target().String()
		if _, exists := activated[targetIdentity]; exists {
			return nil, fmt.Errorf("%w: %s: %s", ErrDuplicateTargetActivation, activation.Path(), targetIdentity)
		}

		activated[targetIdentity] = struct{}{}
	}

	for _, activation := range activations {
		targetIdentity := activation.Target().String()

		target, ok := definitions.targets[targetIdentity]
		if !ok {
			return nil, fmt.Errorf("%w: %s: %s", ErrUnknownTargetDefinition, activation.Path(), targetIdentity)
		}

		schemaIdentity := activation.Schema().String()

		schema, ok := definitions.schemas[schemaIdentity]
		if !ok || !target.definition.Supports(activation.Schema()) {
			return nil, fmt.Errorf("%w: %s.schema: %s", ErrUnknownSchemaDefinition, activation.Path(), schemaIdentity)
		}

		record, err := compileActivatedRecord(definitions, activation, schema.definition)
		if err != nil {
			return nil, err
		}

		records = append(records, record)
	}

	return records, nil
}

// validateCatalogDefinitions cross-validates global imports, exports, and effect bindings.
func validateCatalogDefinitions(definitions collectedCatalogDefinitions) error {
	if err := validatePolicySetImportGraph(definitions.policySets); err != nil {
		return err
	}

	if err := validatePolicySetExports(definitions.policySets); err != nil {
		return err
	}

	return validateEffectProviderBindings(definitions.providers, definitions.effects)
}

// validatePolicySetExports proves every exported capability matches its own rules exactly.
func validatePolicySetExports(sets map[string]registry.PolicySetDefinition) error {
	for _, identity := range sortedMapKeys(sets) {
		set := sets[identity]

		contract, exported := set.ExportContract()
		if !exported {
			continue
		}

		actual, err := registry.DerivePolicySetCapability(sets, set.ID().String())
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrIncompatiblePolicySetImport, set.ID().String(), err)
		}

		if !contract.Equal(actual) {
			return fmt.Errorf("%w: %s export contract does not match its rules", ErrIncompatiblePolicySetImport, set.ID().String())
		}
	}

	return nil
}

// validatePolicySetImportGraph rejects unknown references and cycles before activation.
func validatePolicySetImportGraph(sets map[string]registry.PolicySetDefinition) error {
	temporary := make(map[string]bool, len(sets))
	permanent := make(map[string]bool, len(sets))

	var visit func(string) error

	visit = func(identity string) error {
		if permanent[identity] {
			return nil
		}

		if temporary[identity] {
			return fmt.Errorf("%w: %s", ErrPolicySetImportCycle, identity)
		}

		set, exists := sets[identity]
		if !exists {
			return fmt.Errorf("%w: %s", ErrUnknownPolicySet, identity)
		}

		temporary[identity] = true

		for _, imported := range set.Imports() {
			if err := validatePolicySetImport(set.ID().Namespace(), imported, sets, false); err != nil {
				return err
			}

			if err := visit(imported.Set().String()); err != nil {
				return err
			}
		}

		temporary[identity] = false
		permanent[identity] = true

		return nil
	}

	for _, identity := range sortedMapKeys(sets) {
		if err := visit(identity); err != nil {
			return err
		}
	}

	return nil
}

// validatePolicySetImport enforces exact cross-namespace typed capabilities.
func validatePolicySetImport(
	ownerNamespace string,
	imported registry.PolicySetImport,
	sets map[string]registry.PolicySetDefinition,
	allowBuiltinRoot bool,
) error {
	set, exists := sets[imported.Set().String()]
	if !exists {
		return fmt.Errorf("%w: %s: %s", ErrUnknownPolicySet, imported.Path(), imported.Set().String())
	}

	if imported.Set().String() == registry.BuiltinStandardAuthPolicySet && !allowBuiltinRoot {
		return fmt.Errorf("%w: %s", ErrStandardAuthCrossNamespaceImport, imported.Path())
	}

	if ownerNamespace == imported.Set().Namespace() {
		return nil
	}

	if set.Visibility() != registry.PolicySetVisibilityExported {
		return fmt.Errorf("%w: %s: %s", ErrPrivatePolicySetImport, imported.Path(), imported.Set().String())
	}

	requested := imported.Contract()
	if !requested.Complete() {
		return fmt.Errorf("%w: %s: %s", ErrIncompletePolicySetImport, imported.Path(), imported.Set().String())
	}

	exported, ok := set.ExportContract()
	if !ok || !exported.Equal(requested) || !exported.SupportsCheckpoint(imported.Checkpoint()) {
		return fmt.Errorf("%w: %s: %s", ErrIncompatiblePolicySetImport, imported.Path(), imported.Set().String())
	}

	return nil
}

// validateEffectProviderBindings proves every host effect has one compatible owner.
func validateEffectProviderBindings(
	providers map[string]registry.ProviderDefinition,
	effects map[string]registry.EffectDefinition,
) error {
	for _, identity := range sortedMapKeys(effects) {
		effect := effects[identity]
		if effect.Execution() == registry.ExecutionReturnOnly {
			continue
		}

		provider, exists := providers[effect.Provider()]
		if !exists {
			return fmt.Errorf("%w: effect %s provider %s", ErrUnknownEffectProvider, effect.ID(), effect.Provider())
		}

		for _, target := range effect.Targets() {
			if !provider.Supports(target, effect.Execution()) {
				return fmt.Errorf("%w: effect %s target %s provider %s", ErrIncompatibleEffectProvider, effect.ID(), target.String(), provider.ID())
			}
		}

		if effect.Execution() == registry.ExecutionHostPostAction && !provider.HasPostActionAcceptance() {
			return fmt.Errorf("%w: effect %s provider %s", ErrMissingPostActionAcceptanceCapability, effect.ID(), provider.ID())
		}
	}

	return nil
}

// compileActivatedRecord resolves one complete target schema, plan, defaults, and registries.
func compileActivatedRecord(
	definitions collectedCatalogDefinitions,
	activation registry.TargetActivation,
	schema registry.SchemaDefinition,
) (policyruntime.TargetCatalogRecord, error) {
	plan, exists := definitions.plans[activation.Target().String()]
	if !exists {
		return policyruntime.TargetCatalogRecord{}, fmt.Errorf("%w: %s: %s", ErrUnknownDomainPlan, activation.Path(), activation.Target().String())
	}

	if !activation.PolicyConfigured() {
		return policyruntime.TargetCatalogRecord{}, fmt.Errorf("%w: %s.no_match", ErrMissingNoMatchBehavior, activation.Path())
	}

	if err := validateTargetDefaults(activation, definitions.policySets); err != nil {
		return policyruntime.TargetCatalogRecord{}, err
	}

	checkpoints, usedSets, usedProviders, _, err := compileDomainPlan(definitions, activation, schema, plan)
	if err != nil {
		return policyruntime.TargetCatalogRecord{}, err
	}

	effects := selectTargetEffects(definitions.effects, activation.Target())
	for _, effect := range effects {
		if effect.Provider() != "" {
			usedProviders[effect.Provider()] = struct{}{}
		}
	}

	providers := selectProviders(definitions.providers, usedProviders, activation.Target())

	if err := validateDiagnosticAliases(activation.Target(), definitions.policySets, usedSets, providers, effects); err != nil {
		return policyruntime.TargetCatalogRecord{}, err
	}

	return policyruntime.TargetCatalogRecord{
		Target:                      activation.Target(),
		Schema:                      schema,
		SourcePlan:                  plan,
		ActivationPolicySetBindings: activation.PolicySetBindings(),
		Checkpoints:                 checkpoints,
		Providers:                   providers,
		Effects:                     effects,
		DefaultPolicySet:            activation.DefaultPolicySet(),
		NoMatch:                     activation.NoMatch(),
		AuthorityMode:               activation.AuthorityMode(),
		Report:                      activation.Report(),
	}, nil
}

// validateTargetDefaults enforces generic no-match and authn standard-auth isolation.
func validateTargetDefaults(
	activation registry.TargetActivation,
	sets map[string]registry.PolicySetDefinition,
) error {
	isAuthn := activation.Target().Namespace() == authnNamespace
	defaultSet := activation.DefaultPolicySet()
	mode := activation.AuthorityMode()

	if !mode.Valid() || (!isAuthn && mode != registry.AuthorityModeEnforce) {
		return fmt.Errorf("%w: %s.mode: %s", registry.ErrInvalidAuthorityMode, activation.Path(), mode)
	}

	if err := validateTargetFallback(activation, isAuthn, defaultSet); err != nil {
		return err
	}

	if !defaultSet.IsZero() {
		set, exists := sets[defaultSet.String()]
		if !exists {
			return fmt.Errorf("%w: %s.default_policy: %s", ErrUnknownPolicySet, activation.Path(), defaultSet.String())
		}

		if set.ID().Namespace() != activation.Target().Namespace() {
			return fmt.Errorf("%w: %s.default_policy: %s", ErrDefaultPolicySetNamespaceMismatch, activation.Path(), defaultSet.String())
		}
	}

	return nil
}

// validateTargetFallback separates authn standard authority from generic no-match handling.
func validateTargetFallback(
	activation registry.TargetActivation,
	isAuthn bool,
	defaultSet registry.PolicySetID,
) error {
	if defaultSet.String() == registry.BuiltinStandardAuthPolicySet && !isAuthn {
		return fmt.Errorf("%w: %s.default_policy", ErrStandardAuthTargetMismatch, activation.Path())
	}

	if isAuthn {
		return validateAuthnFallback(activation, defaultSet)
	}

	if activation.NoMatch() == registry.NoMatchUnset {
		return fmt.Errorf("%w: %s.no_match", ErrMissingNoMatchBehavior, activation.Path())
	}

	if !activation.NoMatch().ValidGeneric() {
		return fmt.Errorf("%w: %s.no_match: %s", ErrInvalidNoMatchBehavior, activation.Path(), activation.NoMatch())
	}

	return nil
}

// validateAuthnFallback requires standard_auth and forbids generic no-match.
func validateAuthnFallback(activation registry.TargetActivation, defaultSet registry.PolicySetID) error {
	if activation.NoMatch() != registry.NoMatchUnset {
		return fmt.Errorf("%w: %s.no_match", ErrAuthnNoMatchBehavior, activation.Path())
	}

	if defaultSet.String() != registry.BuiltinStandardAuthPolicySet {
		return fmt.Errorf("%w: %s.default_policy", ErrStandardAuthTargetMismatch, activation.Path())
	}

	return nil
}

// compileDomainPlan resolves exact checkpoint roots and their explicit import closure.
func compileDomainPlan(
	definitions collectedCatalogDefinitions,
	activation registry.TargetActivation,
	schema registry.SchemaDefinition,
	plan registry.DomainPlanDefinition,
) ([]policyruntime.CheckpointRecord, map[string]struct{}, map[string]struct{}, map[string]struct{}, error) {
	checkpoints := plan.Checkpoints()
	if activation.Target().Namespace() != authnNamespace && !containsCheckpoint(checkpoints, "final_decision") {
		return nil, nil, nil, nil, fmt.Errorf("%w: %s requires final decision checkpoint", registry.ErrInvalidDomainPlan, activation.Target().String())
	}

	usedSets := make(map[string]struct{})
	usedProviders := make(map[string]struct{})
	usedEffects := make(map[string]struct{})
	records := make([]policyruntime.CheckpointRecord, 0, len(checkpoints))

	bindings, err := activationBindingsByCheckpoint(activation, checkpoints)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for _, checkpoint := range checkpoints {
		checkpoint, err = mergeCheckpointBindings(checkpoint, bindings[checkpoint.Name()])
		if err != nil {
			return nil, nil, nil, nil, err
		}

		record, err := compileCheckpoint(
			definitions,
			activation.Target(),
			schema,
			checkpoint,
			plan.IsBuiltinAuth(),
			usedSets,
			usedProviders,
			usedEffects,
		)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		records = append(records, record)
	}

	for effectID := range usedEffects {
		effect := definitions.effects[effectID]
		if effect.Provider() != "" {
			usedProviders[effect.Provider()] = struct{}{}
		}
	}

	defaultSet := activation.DefaultPolicySet()
	if !defaultSet.IsZero() {
		if _, bound := usedSets[defaultSet.String()]; !bound {
			return nil, nil, nil, nil, fmt.Errorf("%w: %s.default_policy: %s", ErrDefaultPolicySetUnbound, activation.Path(), defaultSet.String())
		}
	}

	return records, usedSets, usedProviders, usedEffects, nil
}

// activationBindingsByCheckpoint validates every explicit activation reference against the plan topology.
func activationBindingsByCheckpoint(
	activation registry.TargetActivation,
	checkpoints []registry.CheckpointDefinition,
) (map[string][]registry.PolicySetImport, error) {
	known := make(map[string]struct{}, len(checkpoints))
	for _, checkpoint := range checkpoints {
		known[checkpoint.Name()] = struct{}{}
	}

	result := make(map[string][]registry.PolicySetImport)

	for _, binding := range activation.PolicySetBindings() {
		if _, exists := known[binding.Checkpoint()]; !exists {
			return nil, fmt.Errorf("%w: %s: %s", ErrPolicyRuleCheckpointMismatch, binding.Path(), binding.Checkpoint())
		}

		if binding.Set().String() == registry.BuiltinStandardAuthPolicySet {
			return nil, fmt.Errorf("%w: %s", ErrStandardAuthCrossNamespaceImport, binding.Path())
		}

		result[binding.Checkpoint()] = append(result[binding.Checkpoint()], binding)
	}

	return result, nil
}

// mergeCheckpointBindings places explicit configured authority before contributed fallback bindings.
func mergeCheckpointBindings(
	checkpoint registry.CheckpointDefinition,
	bindings []registry.PolicySetImport,
) (registry.CheckpointDefinition, error) {
	if len(bindings) == 0 {
		return checkpoint, nil
	}

	sets := append([]registry.PolicySetImport(nil), bindings...)
	sets = append(sets, checkpoint.PolicySets()...)

	return registry.NewCheckpointDefinitionWithProviderInstances(
		checkpoint.Name(),
		sets,
		checkpoint.ProviderInstances(),
	)
}

// compileCheckpoint validates and resolves one exact target plan checkpoint.
func compileCheckpoint(
	definitions collectedCatalogDefinitions,
	target decision.Target,
	schema registry.SchemaDefinition,
	checkpoint registry.CheckpointDefinition,
	allowBuiltinRoot bool,
	usedSets map[string]struct{},
	usedProviders map[string]struct{},
	usedEffects map[string]struct{},
) (policyruntime.CheckpointRecord, error) {
	setIDs, err := resolveCheckpointPolicySets(
		definitions.policySets,
		definitions.effects,
		target,
		schema,
		checkpoint,
		allowBuiltinRoot,
	)
	if err != nil {
		return policyruntime.CheckpointRecord{}, err
	}

	compiledRules := make([]policyruntime.CompiledRuleRecord, 0)

	for _, setID := range setIDs {
		usedSets[setID.String()] = struct{}{}

		set := definitions.policySets[setID.String()]

		rules, err := validatePolicySetRules(
			set,
			target,
			checkpoint.Name(),
			checkpointProviderReferences(checkpoint),
			schema,
			definitions.effects,
			usedEffects,
		)
		if err != nil {
			return policyruntime.CheckpointRecord{}, err
		}

		compiledRules = append(compiledRules, rules...)
	}

	if err := validateCheckpointProviders(definitions.providers, target, checkpoint, usedProviders); err != nil {
		return policyruntime.CheckpointRecord{}, err
	}

	return policyruntime.CheckpointRecord{
		Name:              checkpoint.Name(),
		PolicySetBindings: checkpoint.PolicySets(),
		PolicySetIDs:      setIDs,
		ProviderIDs:       checkpoint.Providers(),
		ProviderInstances: checkpoint.ProviderInstances(),
		Rules:             compiledRules,
	}, nil
}

// checkpointProviderReferences exposes instance names and exact uses for rule compatibility validation.
func checkpointProviderReferences(checkpoint registry.CheckpointDefinition) []string {
	instances := checkpoint.ProviderInstances()
	references := make([]string, 0, len(instances)*2)
	seen := make(map[string]struct{}, len(instances)*2)

	for _, instance := range instances {
		for _, reference := range []string{instance.Name(), instance.Use()} {
			if _, exists := seen[reference]; exists {
				continue
			}

			seen[reference] = struct{}{}
			references = append(references, reference)
		}
	}

	return references
}

// validateCheckpointProviders resolves exact target-aware scheduled providers.
func validateCheckpointProviders(
	providers map[string]registry.ProviderDefinition,
	target decision.Target,
	checkpoint registry.CheckpointDefinition,
	used map[string]struct{},
) error {
	for _, instance := range checkpoint.ProviderInstances() {
		providerID := instance.Use()

		provider, exists := providers[providerID]
		if !exists {
			return fmt.Errorf("%w: checkpoint %s provider %s", ErrUnknownEffectProvider, checkpoint.Name(), providerID)
		}

		if !provider.AllowsTarget(target) {
			return fmt.Errorf("%w: checkpoint %s provider %s target %s", ErrIncompatibleEffectProvider, checkpoint.Name(), providerID, target.String())
		}

		used[providerID] = struct{}{}
	}

	return nil
}

// resolveCheckpointPolicySets expands explicit imports in deterministic depth-first order.
func resolveCheckpointPolicySets(
	sets map[string]registry.PolicySetDefinition,
	effects map[string]registry.EffectDefinition,
	target decision.Target,
	schema registry.SchemaDefinition,
	checkpoint registry.CheckpointDefinition,
	allowBuiltinRoot bool,
) ([]registry.PolicySetID, error) {
	resolver := checkpointPolicySetResolver{
		sets:       sets,
		effects:    effects,
		result:     make([]registry.PolicySetID, 0),
		visited:    make(map[string]bool),
		schema:     schema,
		target:     target,
		checkpoint: checkpoint,
	}

	for _, root := range checkpoint.PolicySets() {
		if err := resolver.resolve(target.Namespace(), root, allowBuiltinRoot); err != nil {
			return nil, err
		}
	}

	return resolver.result, nil
}

// checkpointPolicySetResolver owns deterministic expansion for one exact target checkpoint.
type checkpointPolicySetResolver struct {
	sets       map[string]registry.PolicySetDefinition
	effects    map[string]registry.EffectDefinition
	result     []registry.PolicySetID
	visited    map[string]bool
	schema     registry.SchemaDefinition
	target     decision.Target
	checkpoint registry.CheckpointDefinition
}

// resolve validates and appends one explicit import and its matching nested closure.
func (r *checkpointPolicySetResolver) resolve(
	ownerNamespace string,
	imported registry.PolicySetImport,
	allowBuiltinRoot bool,
) error {
	if imported.Target().String() != r.target.String() {
		return fmt.Errorf("%w: %s: %s", ErrPolicyRuleTargetMismatch, imported.Path(), imported.Target().String())
	}

	if imported.Checkpoint() != r.checkpoint.Name() {
		return fmt.Errorf("%w: %s: %s", ErrPolicyRuleCheckpointMismatch, imported.Path(), imported.Checkpoint())
	}

	if err := validatePolicySetImport(ownerNamespace, imported, r.sets, allowBuiltinRoot); err != nil {
		return err
	}

	if ownerNamespace != imported.Set().Namespace() {
		if err := validateImportedCapability(imported, r.target, r.schema, r.effects); err != nil {
			return err
		}
	}

	identity := imported.Set().String()
	if r.visited[identity] {
		return nil
	}

	r.visited[identity] = true
	r.result = append(r.result, imported.Set())

	set := r.sets[identity]
	for _, nested := range set.Imports() {
		if nested.Target().String() != r.target.String() || nested.Checkpoint() != r.checkpoint.Name() {
			continue
		}

		if err := r.resolve(set.ID().Namespace(), nested, false); err != nil {
			return err
		}
	}

	return nil
}

// validateImportedCapability proves the complete cross-namespace surface against one exact target schema.
func validateImportedCapability(
	imported registry.PolicySetImport,
	target decision.Target,
	schema registry.SchemaDefinition,
	effects map[string]registry.EffectDefinition,
) error {
	contract := imported.Contract()
	facts := make(map[string]registry.FactSchema, len(schema.Facts()))

	for _, fact := range schema.Facts() {
		facts[fact.ID()] = fact
	}

	for _, required := range contract.Facts() {
		fact, exists := facts[required.ID()]
		if !exists || fact.Kind() != required.Kind() {
			return fmt.Errorf(
				"%w: import %s fact %s",
				ErrPolicyRuleFactMismatch,
				imported.Set().String(),
				required.ID(),
			)
		}
	}

	for _, effectID := range contract.Effects() {
		effect, exists := effects[effectID]
		if !exists || !effect.AllowsTarget(target) {
			return fmt.Errorf(
				"%w: import %s effect %s",
				ErrPolicyEffectTargetMismatch,
				imported.Set().String(),
				effectID,
			)
		}
	}

	return nil
}

// validatePolicySetRules validates target/checkpoint, facts, and selected effects.
func validatePolicySetRules(
	set registry.PolicySetDefinition,
	target decision.Target,
	checkpoint string,
	checkpointProviders []string,
	schema registry.SchemaDefinition,
	effects map[string]registry.EffectDefinition,
	usedEffects map[string]struct{},
) ([]policyruntime.CompiledRuleRecord, error) {
	facts := make(map[string]registry.FactSchema)
	for _, fact := range schema.Facts() {
		facts[fact.ID()] = fact
	}

	compiled := make([]policyruntime.CompiledRuleRecord, 0)

	for _, rule := range set.Rules() {
		if rule.Checkpoint() != checkpoint || !rule.AllowsAction(target.Action()) {
			continue
		}

		if err := validatePolicyRuleTarget(
			set, rule, target, checkpointProviders, facts, effects, usedEffects,
		); err != nil {
			return nil, err
		}

		compiled = append(compiled, policyruntime.ProjectPolicyRule(target, set.ID(), checkpoint, rule))
	}

	return compiled, nil
}

// validatePolicyRuleTarget validates all target-local fact, provider, and effect contracts.
func validatePolicyRuleTarget(
	set registry.PolicySetDefinition,
	rule registry.PolicyRule,
	target decision.Target,
	checkpointProviders []string,
	facts map[string]registry.FactSchema,
	effects map[string]registry.EffectDefinition,
	usedEffects map[string]struct{},
) error {
	for _, fact := range rule.FactContracts() {
		definition, exists := facts[fact.ID()]
		if !exists || definition.Kind() != fact.Kind() {
			return fmt.Errorf("%w: set %s rule %s fact %s", ErrPolicyRuleFactMismatch, set.ID().String(), rule.Name(), fact.ID())
		}
	}

	for _, providerID := range rule.RequiredProviders() {
		if !slices.Contains(checkpointProviders, providerID) {
			return fmt.Errorf(
				"%w: set %s rule %s requires unscheduled provider %s",
				ErrPolicyRuleCheckpointMismatch,
				set.ID().String(),
				rule.Name(),
				providerID,
			)
		}
	}

	if err := validateRuleEffectUses(set, rule, target, rule.Effects(), registry.EffectKindObligation, effects, usedEffects); err != nil {
		return err
	}

	return validateRuleEffectUses(set, rule, target, rule.Advice(), registry.EffectKindAdvice, effects, usedEffects)
}

// validateRuleEffectUses resolves one ordered obligation or advice selection class.
func validateRuleEffectUses(
	set registry.PolicySetDefinition,
	rule registry.PolicyRule,
	target decision.Target,
	uses []registry.EffectUse,
	wantKind registry.EffectKind,
	effects map[string]registry.EffectDefinition,
	usedEffects map[string]struct{},
) error {
	for _, use := range uses {
		definition, exists := effects[use.ID()]
		if !exists {
			return fmt.Errorf("unknown policy effect: set %s rule %s effect %s", set.ID().String(), rule.Name(), use.ID())
		}

		if definition.Kind() != wantKind {
			return fmt.Errorf(
				"%w: set %s rule %s effect %s has class %s, want %s",
				ErrPolicyEffectParameterMismatch,
				set.ID().String(),
				rule.Name(),
				use.ID(),
				definition.Kind(),
				wantKind,
			)
		}

		if !definition.AllowsTarget(target) {
			return fmt.Errorf("%w: set %s rule %s effect %s", ErrPolicyEffectTargetMismatch, set.ID().String(), rule.Name(), use.ID())
		}

		if err := definition.ValidateUse(use); err != nil {
			return fmt.Errorf("%w: set %s rule %s: %v", ErrPolicyEffectParameterMismatch, set.ID().String(), rule.Name(), err)
		}

		usedEffects[use.ID()] = struct{}{}
	}

	return nil
}

// validateDiagnosticAliases enforces one bounded alias namespace per target projection.
func validateDiagnosticAliases(
	target decision.Target,
	sets map[string]registry.PolicySetDefinition,
	usedSets map[string]struct{},
	providers []registry.ProviderDefinition,
	effects []registry.EffectDefinition,
) error {
	aliases := make(map[string]string)
	claim := func(alias string, component string) error {
		if alias == "" {
			return nil
		}

		if existing, exists := aliases[alias]; exists {
			return fmt.Errorf("%w: target %s alias %s used by %s and %s", ErrDuplicateDiagnosticPublicID, target.String(), alias, existing, component)
		}

		aliases[alias] = component

		return nil
	}

	for _, identity := range sortedMapKeys(usedSets) {
		if err := claim(sets[identity].DiagnosticID(), "policy_set "+identity); err != nil {
			return err
		}
	}

	for _, provider := range providers {
		if err := claim(provider.DiagnosticID(), "provider "+provider.ID()); err != nil {
			return err
		}
	}

	for _, effect := range effects {
		if err := claim(effect.DiagnosticID(), "effect "+effect.ID()); err != nil {
			return err
		}
	}

	return nil
}

// selectProviders keeps the target-local provider registry small and authoritative.
func selectProviders(
	definitions map[string]registry.ProviderDefinition,
	used map[string]struct{},
	target decision.Target,
) []registry.ProviderDefinition {
	result := make([]registry.ProviderDefinition, 0, len(used))
	for identity := range used {
		provider := definitions[identity]
		if provider.AllowsTarget(target) {
			result = append(result, provider)
		}
	}

	sort.Slice(result, func(left int, right int) bool {
		return result[left].ID() < result[right].ID()
	})

	return result
}

// selectTargetEffects keeps the exact target-aware effect registry deterministic.
func selectTargetEffects(
	definitions map[string]registry.EffectDefinition,
	target decision.Target,
) []registry.EffectDefinition {
	result := make([]registry.EffectDefinition, 0)

	for _, effect := range definitions {
		if effect.AllowsTarget(target) {
			result = append(result, effect)
		}
	}

	sort.Slice(result, func(left int, right int) bool {
		return result[left].ID() < result[right].ID()
	})

	return result
}

// containsCheckpoint reports whether a plan declares one exact checkpoint.
func containsCheckpoint(values []registry.CheckpointDefinition, name string) bool {
	for _, value := range values {
		if value.Name() == name {
			return true
		}
	}

	return false
}

// sortedMapKeys returns deterministic identity order for validation and diagnostics.
func sortedMapKeys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for identity := range values {
		result = append(result, identity)
	}

	sort.Strings(result)

	return result
}

// collectedPolicySets returns deterministic immutable global set definitions.
func collectedPolicySets(definitions collectedCatalogDefinitions) []registry.PolicySetDefinition {
	result := make([]registry.PolicySetDefinition, 0, len(definitions.policySets))
	for _, set := range definitions.policySets {
		result = append(result, set)
	}

	sort.Slice(result, func(left int, right int) bool {
		return result[left].ID().String() < result[right].ID().String()
	})

	return result
}

// claim rejects an exact definition collision without choosing an owner.
func (d *collectedCatalogDefinitions) claim(kind string, identity string, owner string) error {
	claimIdentity := kind + ":" + identity
	if existingOwner, exists := d.claims[claimIdentity]; exists {
		return definitionCollision(kind, identity, existingOwner, owner)
	}

	d.claims[claimIdentity] = owner

	return nil
}

// definitionCollision reports both owners and never chooses a precedence winner.
func definitionCollision(kind string, identity string, firstOwner string, secondOwner string) error {
	return fmt.Errorf(
		"%w: %s %s contributed by both %s and %s",
		ErrDefinitionCollision,
		kind,
		identity,
		firstOwner,
		secondOwner,
	)
}
