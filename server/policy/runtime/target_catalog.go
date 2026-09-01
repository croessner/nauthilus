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

package runtime

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/internal/identifier"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

const authnNamespace = "authn"

var (
	// ErrDuplicateCompiledTarget identifies repeated target records in one candidate.
	ErrDuplicateCompiledTarget = errors.New("duplicate compiled policy target")

	// ErrUnknownCompiledTarget identifies fact validation for an inactive target.
	ErrUnknownCompiledTarget = errors.New("unknown compiled policy target")

	// ErrInvalidCompiledTarget identifies a direct runtime record that bypasses compiler invariants.
	ErrInvalidCompiledTarget = errors.New("invalid compiled policy target")

	// ErrDuplicateCompiledCheckpoint identifies a silently ambiguous checkpoint key.
	ErrDuplicateCompiledCheckpoint = errors.New("duplicate compiled policy checkpoint")

	// ErrDuplicateCompiledProvider identifies a silently ambiguous provider key.
	ErrDuplicateCompiledProvider = errors.New("duplicate compiled policy provider")

	// ErrDuplicateCompiledEffect identifies a silently ambiguous effect key.
	ErrDuplicateCompiledEffect = errors.New("duplicate compiled policy effect")
)

// TargetCatalogRecord carries one activated exact target/schema pair into the runtime candidate.
type TargetCatalogRecord struct {
	Target                      decision.Target
	Schema                      registry.SchemaDefinition
	SourcePlan                  registry.DomainPlanDefinition
	Report                      registry.TargetReportSettings
	ActivationPolicySetBindings []registry.PolicySetImport
	Checkpoints                 []CheckpointRecord
	Providers                   []registry.ProviderDefinition
	Effects                     []registry.EffectDefinition
	DefaultPolicySet            registry.PolicySetID
	NoMatch                     registry.NoMatchBehavior
	AuthorityMode               registry.AuthorityMode
}

// CheckpointRecord carries one resolved exact plan checkpoint into the runtime candidate.
type CheckpointRecord struct {
	Name              string
	PolicySetBindings []registry.PolicySetImport
	PolicySetIDs      []registry.PolicySetID
	ProviderIDs       []string
	ProviderInstances []registry.ProviderInstanceDefinition
	Rules             []CompiledRuleRecord
}

// CompiledProviderInstance is one immutable resolved checkpoint-local provider binding.
type CompiledProviderInstance struct {
	dependencies []string
	definition   registry.ProviderInstanceDefinition
}

// Path returns the configuration-owned provider source path.
func (i CompiledProviderInstance) Path() string {
	return i.definition.Path()
}

// Name returns the exact checkpoint-local instance identity.
func (i CompiledProviderInstance) Name() string {
	return i.definition.Name()
}

// Use returns the qualified provider definition identity.
func (i CompiledProviderInstance) Use() string {
	return i.definition.Use()
}

// Actions returns detached target-action restrictions.
func (i CompiledProviderInstance) Actions() []string {
	return i.definition.Actions()
}

// After returns detached authored instance dependencies.
func (i CompiledProviderInstance) After() []string {
	return i.definition.After()
}

// Dependencies returns the resolved union of authored and definition-owned dependencies.
func (i CompiledProviderInstance) Dependencies() []string {
	return append([]string(nil), i.dependencies...)
}

// RunIfAuthState returns the effective authn structural scheduling state.
func (i CompiledProviderInstance) RunIfAuthState() string {
	return i.definition.RunIfAuthState()
}

// SkipIf returns detached plan-local scheduler guard references.
func (i CompiledProviderInstance) SkipIf() []string {
	return i.definition.SkipIf()
}

// ObserveSafe returns the effective provider observation safety value.
func (i CompiledProviderInstance) ObserveSafe() bool {
	return i.definition.ObserveSafe()
}

// ObserveSafeAuthored reports whether observation safety was explicitly configured.
func (i CompiledProviderInstance) ObserveSafeAuthored() bool {
	return i.definition.ObserveSafeAuthored()
}

// Output returns the optional canonical fact output identity.
func (i CompiledProviderInstance) Output() string {
	return i.definition.Output()
}

// clone returns one deeply detached compiled provider instance.
func (i CompiledProviderInstance) clone() CompiledProviderInstance {
	i.dependencies = i.Dependencies()

	return i
}

// CompiledRuleRecord carries one exact target-instantiated rule into the runtime boundary.
type CompiledRuleRecord struct {
	Target                           decision.Target
	PolicySetID                      registry.PolicySetID
	Name                             string
	Checkpoint                       string
	PresentationStage                string
	RequiredProviders                []string
	Expression                       registry.PolicyExpression
	Effects                          []registry.EffectUse
	Advice                           []registry.EffectUse
	Decision                         decision.Effect
	Reason                           string
	OutcomeMarker                    string
	FSMEventMarker                   string
	ResponseMarker                   string
	ResponseMessage                  registry.PolicyResponseMessage
	ResponseLanguage                 registry.PolicyResponseLanguage
	SkipRemainingCheckpointProviders bool
}

// ProjectPolicyRule maps one source rule to its sole complete executable record representation.
func ProjectPolicyRule(
	target decision.Target,
	setID registry.PolicySetID,
	checkpoint string,
	rule registry.PolicyRule,
) CompiledRuleRecord {
	return CompiledRuleRecord{
		Target: target, PolicySetID: setID, Name: rule.Name(), Checkpoint: checkpoint,
		PresentationStage: rule.PresentationStage(),
		RequiredProviders: rule.RequiredProviders(), Expression: rule.Expression(), Effects: rule.Effects(), Advice: rule.Advice(),
		Decision: rule.Decision(), Reason: rule.Reason(), OutcomeMarker: rule.OutcomeMarker(),
		FSMEventMarker: rule.FSMEventMarker(), ResponseMarker: rule.ResponseMarker(),
		ResponseMessage: rule.ResponseMessage(), ResponseLanguage: rule.ResponseLanguage(),
		SkipRemainingCheckpointProviders: rule.SkipRemainingCheckpointProviders(),
	}
}

// CompiledCheckpoint is one immutable exact target plan checkpoint.
type CompiledCheckpoint struct {
	providerInstancesByName map[string]CompiledProviderInstance
	policySetIDs            []string
	providerIDs             []string
	providerInstances       []CompiledProviderInstance
	providerLevels          [][]string
	productionPolicySetIDs  []string
	comparisonPolicySetIDs  []string
	name                    string
}

// Name returns the exact checkpoint identity.
func (c CompiledCheckpoint) Name() string {
	return c.name
}

// PolicySetIDs returns the exact reachable set order.
func (c CompiledCheckpoint) PolicySetIDs() []string {
	return append([]string(nil), c.policySetIDs...)
}

// ProviderIDs returns the exact scheduled provider order.
func (c CompiledCheckpoint) ProviderIDs() []string {
	return append([]string(nil), c.providerIDs...)
}

// ProviderInstances returns detached ordered checkpoint-local provider bindings.
func (c CompiledCheckpoint) ProviderInstances() []CompiledProviderInstance {
	result := make([]CompiledProviderInstance, 0, len(c.providerInstances))
	for _, instance := range c.providerInstances {
		result = append(result, instance.clone())
	}

	return result
}

// LookupProviderInstance resolves one exact checkpoint-local instance identity.
func (c CompiledCheckpoint) LookupProviderInstance(name string) (CompiledProviderInstance, bool) {
	instance, ok := c.providerInstancesByName[name]

	return instance.clone(), ok
}

// ProviderLevels returns deterministic dependency levels for concurrent execution.
func (c CompiledCheckpoint) ProviderLevels() [][]string {
	result := make([][]string, 0, len(c.providerLevels))
	for _, level := range c.providerLevels {
		result = append(result, append([]string(nil), level...))
	}

	return result
}

// ProductionPolicySetIDs returns the exact ordered production authority for this checkpoint.
func (c CompiledCheckpoint) ProductionPolicySetIDs() []string {
	return append([]string(nil), c.productionPolicySetIDs...)
}

// ComparisonPolicySetIDs returns configured rules evaluated without production authority.
func (c CompiledCheckpoint) ComparisonPolicySetIDs() []string {
	return append([]string(nil), c.comparisonPolicySetIDs...)
}

// ContainsPolicySet reports whether this checkpoint can execute an exact set.
func (c CompiledCheckpoint) ContainsPolicySet(identity string) bool {
	return slices.Contains(c.policySetIDs, identity)
}

// CompiledDomainPlan is one immutable ordered checkpoint topology.
type CompiledDomainPlan struct {
	byName                map[string]CompiledCheckpoint
	schedulerGuardsByName map[string]registry.SchedulerGuardDefinition
	checkpoints           []CompiledCheckpoint
	schedulerGuards       []registry.SchedulerGuardDefinition
}

// Checkpoints returns detached ordered checkpoint descriptors.
func (p CompiledDomainPlan) Checkpoints() []CompiledCheckpoint {
	result := make([]CompiledCheckpoint, 0, len(p.checkpoints))
	for _, checkpoint := range p.checkpoints {
		result = append(result, cloneCompiledCheckpoint(checkpoint))
	}

	return result
}

// Checkpoint resolves one exact checkpoint identity.
func (p CompiledDomainPlan) Checkpoint(name string) (CompiledCheckpoint, bool) {
	checkpoint, ok := p.byName[name]

	return cloneCompiledCheckpoint(checkpoint), ok
}

// SchedulerGuards returns detached ordered plan-local scheduling predicates.
func (p CompiledDomainPlan) SchedulerGuards() []registry.SchedulerGuardDefinition {
	return append([]registry.SchedulerGuardDefinition(nil), p.schedulerGuards...)
}

// SchedulerGuard resolves one exact plan-local scheduling predicate.
func (p CompiledDomainPlan) SchedulerGuard(name string) (registry.SchedulerGuardDefinition, bool) {
	guard, ok := p.schedulerGuardsByName[name]

	return guard, ok
}

// clone returns one deeply detached plan.
func (p CompiledDomainPlan) clone() CompiledDomainPlan {
	checkpoints := p.Checkpoints()

	byName := make(map[string]CompiledCheckpoint, len(checkpoints))
	for _, checkpoint := range checkpoints {
		byName[checkpoint.Name()] = cloneCompiledCheckpoint(checkpoint)
	}

	guards := p.SchedulerGuards()

	guardsByName := make(map[string]registry.SchedulerGuardDefinition, len(guards))
	for _, guard := range guards {
		guardsByName[guard.Name()] = guard
	}

	return CompiledDomainPlan{
		checkpoints: checkpoints, byName: byName,
		schedulerGuards: guards, schedulerGuardsByName: guardsByName,
	}
}

// CompiledRule is one immutable target/checkpoint-instantiated executable rule.
type CompiledRule struct {
	record CompiledRuleRecord
}

// Target returns the exact instantiated rule target.
func (r CompiledRule) Target() decision.Target {
	return r.record.Target
}

// PolicySetID returns the exact owning set identity.
func (r CompiledRule) PolicySetID() registry.PolicySetID {
	return r.record.PolicySetID
}

// Name returns the namespace-local source rule name.
func (r CompiledRule) Name() string {
	return r.record.Name
}

// Checkpoint returns the exact instantiated checkpoint.
func (r CompiledRule) Checkpoint() string {
	return r.record.Checkpoint
}

// RequiredProviders returns exact provider dependencies in the same checkpoint.
func (r CompiledRule) RequiredProviders() []string {
	return append([]string(nil), r.record.RequiredProviders...)
}

// Expression returns the executable immutable source predicate.
func (r CompiledRule) Expression() registry.PolicyExpression {
	return r.record.Expression
}

// Effects returns detached typed effect selections.
func (r CompiledRule) Effects() []registry.EffectUse {
	return append([]registry.EffectUse(nil), r.record.Effects...)
}

// Advice returns detached selected non-authoritative effect requests.
func (r CompiledRule) Advice() []registry.EffectUse {
	return append([]registry.EffectUse(nil), r.record.Advice...)
}

// Decision returns the configured authoritative result.
func (r CompiledRule) Decision() decision.Effect {
	return r.record.Decision
}

// PresentationStage returns the optional builtin authn semantic stage.
func (r CompiledRule) PresentationStage() string {
	return r.record.PresentationStage
}

// Reason returns the retained stable decision reason.
func (r CompiledRule) Reason() string {
	return r.record.Reason
}

// OutcomeMarker returns the retained outcome adapter marker.
func (r CompiledRule) OutcomeMarker() string {
	return r.record.OutcomeMarker
}

// FSMEventMarker returns the retained authentication-state marker.
func (r CompiledRule) FSMEventMarker() string {
	return r.record.FSMEventMarker
}

// ResponseMarker returns the retained response-profile marker.
func (r CompiledRule) ResponseMarker() string {
	return r.record.ResponseMarker
}

// ResponseMessage returns the retained immutable response-message source.
func (r CompiledRule) ResponseMessage() registry.PolicyResponseMessage {
	return r.record.ResponseMessage
}

// ResponseLanguage returns the retained immutable response-language source.
func (r CompiledRule) ResponseLanguage() registry.PolicyResponseLanguage {
	return r.record.ResponseLanguage
}

// SkipRemainingCheckpointProviders returns the checkpoint-local control marker.
func (r CompiledRule) SkipRemainingCheckpointProviders() bool {
	return r.record.SkipRemainingCheckpointProviders
}

// clone returns one deeply detached immutable runtime rule.
func (r CompiledRule) clone() CompiledRule {
	r.record.RequiredProviders = r.RequiredProviders()
	r.record.Effects = r.Effects()
	r.record.Advice = r.Advice()

	return r
}

// CompiledPolicySet is one immutable catalog-owned set descriptor.
type CompiledPolicySet struct {
	definition registry.PolicySetDefinition
	rules      []CompiledRule
}

// ID returns the canonical qualified set identity.
func (s CompiledPolicySet) ID() registry.PolicySetID {
	return s.definition.ID()
}

// Visibility returns the exact private/exported setting.
func (s CompiledPolicySet) Visibility() registry.PolicySetVisibility {
	return s.definition.Visibility()
}

// IsBuiltinStandardAuth reports whether the existing auth evaluator owns this set.
func (s CompiledPolicySet) IsBuiltinStandardAuth() bool {
	return s.definition.IsBuiltinStandardAuth()
}

// HasFinalDefaultDeny reports the immutable builtin final fallback contract.
func (s CompiledPolicySet) HasFinalDefaultDeny() bool {
	return s.definition.HasFinalDefaultDeny()
}

// DiagnosticID returns the optional target-local public alias.
func (s CompiledPolicySet) DiagnosticID() string {
	return s.definition.DiagnosticID()
}

// Rules returns detached exact target/checkpoint-instantiated rules.
func (s CompiledPolicySet) Rules() []CompiledRule {
	result := append([]CompiledRule(nil), s.rules...)
	for index := range result {
		result[index] = result[index].clone()
	}

	return result
}

// CompiledSchema is an immutable request-time exact fact schema.
type CompiledSchema struct {
	identity registry.SchemaIdentity
	facts    map[string]registry.FactSchema
	ordered  []string
}

// Identity returns the exact compiled schema identity.
func (s CompiledSchema) Identity() registry.SchemaIdentity {
	return s.identity
}

// Facts returns detached fact definitions in deterministic declaration order.
func (s CompiledSchema) Facts() []registry.FactSchema {
	result := make([]registry.FactSchema, 0, len(s.ordered))
	for _, id := range s.ordered {
		result = append(result, s.facts[id])
	}

	return result
}

// ValidateFacts verifies one immutable fact set against this exact schema version.
func (s CompiledSchema) ValidateFacts(facts decision.FactSet) error {
	if err := s.ValidatePresentFacts(facts); err != nil {
		return err
	}

	for _, id := range s.ordered {
		definition := s.facts[id]
		if !definition.Required() {
			continue
		}

		if _, ok := facts.Get(id); !ok {
			return schemaFactError(s.identity, id, "required fact is missing")
		}
	}

	return nil
}

// ValidatePresentFacts verifies supplied facts without requiring provider-produced values yet.
func (s CompiledSchema) ValidatePresentFacts(facts decision.FactSet) error {
	for _, fact := range facts.Facts() {
		definition, ok := s.facts[fact.ID()]
		if !ok {
			return schemaFactError(s.identity, fact.ID(), "fact is not declared by the selected exact schema")
		}

		if err := validateCompiledFact(definition, fact); err != nil {
			return schemaFactError(s.identity, fact.ID(), err.Error())
		}
	}

	return nil
}

// clone returns a detached compiled schema.
func (s CompiledSchema) clone() CompiledSchema {
	return newCompiledSchema(s.identity, s.Facts())
}

// CompiledTarget is one immutable activated target and selected exact schema.
type CompiledTarget struct {
	target           decision.Target
	schema           CompiledSchema
	domainPlan       CompiledDomainPlan
	providers        map[string]registry.ProviderDefinition
	effects          map[string]registry.EffectDefinition
	policySets       map[string]CompiledPolicySet
	defaultPolicySet registry.PolicySetID
	report           registry.TargetReportSettings
	noMatch          registry.NoMatchBehavior
	authorityMode    registry.AuthorityMode
}

// Target returns the exact activated namespace/action pair.
func (t CompiledTarget) Target() decision.Target {
	return t.target
}

// Schema returns a detached immutable selected schema.
func (t CompiledTarget) Schema() CompiledSchema {
	return t.schema.clone()
}

// DomainPlan returns the detached authoritative checkpoint topology.
func (t CompiledTarget) DomainPlan() CompiledDomainPlan {
	return t.domainPlan.clone()
}

// DefaultPolicySet returns the target-specific qualified fallback set.
func (t CompiledTarget) DefaultPolicySet() registry.PolicySetID {
	return t.defaultPolicySet
}

// NoMatch returns the explicit generic fallback or unset authn value.
func (t CompiledTarget) NoMatch() registry.NoMatchBehavior {
	return t.noMatch
}

// AuthorityMode returns the exact enforce or observe target mode.
func (t CompiledTarget) AuthorityMode() registry.AuthorityMode {
	return t.authorityMode
}

// Report returns the exact target-local diagnostic report selection.
func (t CompiledTarget) Report() registry.TargetReportSettings {
	return t.report
}

// LookupPolicySet resolves one exact target-local instantiated policy set.
func (t CompiledTarget) LookupPolicySet(id registry.PolicySetID) (CompiledPolicySet, bool) {
	set, ok := t.policySets[id.String()]
	if !ok {
		return CompiledPolicySet{}, false
	}

	set.rules = set.Rules()

	return set, true
}

// LookupProvider resolves one exact target-local provider descriptor.
func (t CompiledTarget) LookupProvider(id string) (registry.ProviderDefinition, bool) {
	provider, ok := t.providers[id]

	return provider, ok
}

// HostPreparesProvider reports whether authn host orchestration owns a scheduled provider before evaluation.
func (t CompiledTarget) HostPreparesProvider(id string) bool {
	if t.target.Namespace() != authnNamespace {
		return false
	}

	provider, ok := t.providers[id]
	if !ok {
		return false
	}

	if provider.IsBuiltin() {
		return true
	}

	return strings.HasPrefix(id, authnNamespace+"/lua_environment_") ||
		strings.HasPrefix(id, authnNamespace+"/lua_subject_") ||
		authnNativeSourceProvider(id)
}

// authnNativeSourceProvider recognizes only the two configured public auth source identity families.
func authnNativeSourceProvider(id string) bool {
	const prefix = authnNamespace + "/plugin."
	if !strings.HasPrefix(id, prefix) {
		return false
	}

	local := strings.TrimPrefix(id, prefix)

	return strings.HasSuffix(local, ".environment") || strings.Contains(local, ".subject.")
}

// ProviderIDs returns deterministic target-local provider identities.
func (t CompiledTarget) ProviderIDs() []string {
	result := make([]string, 0, len(t.providers))
	for identity := range t.providers {
		result = append(result, identity)
	}

	sort.Strings(result)

	return result
}

// LookupEffect resolves one canonical target-local effect identity.
func (t CompiledTarget) LookupEffect(id string) (registry.EffectDefinition, bool) {
	effect, ok := t.effects[id]

	return effect, ok
}

// EffectIDs returns deterministic target-local canonical effect identities.
func (t CompiledTarget) EffectIDs() []string {
	result := make([]string, 0, len(t.effects))
	for identity := range t.effects {
		result = append(result, identity)
	}

	sort.Strings(result)

	return result
}

// clone returns a detached compiled target.
func (t CompiledTarget) clone() CompiledTarget {
	providers := make(map[string]registry.ProviderDefinition, len(t.providers))
	for identity, provider := range t.providers {
		providers[identity] = provider
	}

	effects := make(map[string]registry.EffectDefinition, len(t.effects))
	for identity, effect := range t.effects {
		effects[identity] = effect
	}

	sets := make(map[string]CompiledPolicySet, len(t.policySets))
	for identity, set := range t.policySets {
		set.rules = set.Rules()
		sets[identity] = set
	}

	return CompiledTarget{
		target:           t.target,
		schema:           t.schema.clone(),
		domainPlan:       t.domainPlan.clone(),
		providers:        providers,
		effects:          effects,
		policySets:       sets,
		defaultPolicySet: t.defaultPolicySet,
		report:           t.report,
		noMatch:          t.noMatch,
		authorityMode:    t.authorityMode,
	}
}

// TargetCatalog is an immutable off-side candidate of explicitly activated targets.
type TargetCatalog struct {
	targets    map[string]CompiledTarget
	policySets map[string]CompiledPolicySet
}

// NewTargetCatalog validates and deeply owns activated target records.
func NewTargetCatalog(records []TargetCatalogRecord, policySetGroups ...[]registry.PolicySetDefinition) (*TargetCatalog, error) {
	targets := make(map[string]CompiledTarget, len(records))
	schemaDefinitions := make([]registry.SchemaDefinition, 0, len(records))

	for _, record := range records {
		schemaDefinitions = append(schemaDefinitions, record.Schema)
	}

	if err := registry.ValidateRecordSchemaIdentities(schemaDefinitions); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCompiledTarget, err)
	}

	policySets, err := policySetIndex(policySetGroups)
	if err != nil {
		return nil, err
	}

	for _, record := range records {
		compiled, err := compileTargetRecord(record, policySets)
		if err != nil {
			return nil, err
		}

		if _, exists := targets[compiled.Target().String()]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateCompiledTarget, compiled.Target().String())
		}

		targets[compiled.Target().String()] = compiled
	}

	return &TargetCatalog{targets: targets, policySets: policySets}, nil
}

// policySetIndex validates and owns global immutable set definitions.
func policySetIndex(groups [][]registry.PolicySetDefinition) (map[string]CompiledPolicySet, error) {
	result := make(map[string]CompiledPolicySet)

	for _, group := range groups {
		for _, definition := range group {
			identity := definition.ID().String()
			if _, err := registry.ParsePolicySetID("runtime.policy_sets", identity); err != nil {
				return nil, fmt.Errorf("%w: %s", ErrInvalidCompiledTarget, identity)
			}

			if _, exists := result[identity]; exists {
				return nil, fmt.Errorf("duplicate compiled policy set: %s", identity)
			}

			result[identity] = CompiledPolicySet{definition: definition}
		}
	}

	if err := validateRuntimePolicySetGraph(result); err != nil {
		return nil, err
	}

	return result, nil
}

// validateRuntimePolicySetGraph revalidates all source imports, cycles, and exported actual capabilities.
func validateRuntimePolicySetGraph(sets map[string]CompiledPolicySet) error {
	temporary := make(map[string]bool, len(sets))
	permanent := make(map[string]bool, len(sets))

	var visit func(string) error

	visit = func(identity string) error {
		if permanent[identity] {
			return nil
		}

		if temporary[identity] {
			return fmt.Errorf("%w: cyclic policy-set import at %s", ErrInvalidCompiledTarget, identity)
		}

		set, exists := sets[identity]
		if !exists {
			return fmt.Errorf("%w: unknown policy set %s", ErrInvalidCompiledTarget, identity)
		}

		temporary[identity] = true

		for _, imported := range set.definition.Imports() {
			child, childExists := sets[imported.Set().String()]
			if !childExists {
				return fmt.Errorf("%w: set %s imports unknown set %s", ErrInvalidCompiledTarget, identity, imported.Set().String())
			}

			if err := validateRuntimeSourceImport(set.definition, imported, child.definition); err != nil {
				return err
			}

			if err := visit(imported.Set().String()); err != nil {
				return err
			}
		}

		delete(temporary, identity)
		permanent[identity] = true

		return nil
	}

	for _, identity := range sortedRuntimeKeys(sets) {
		if err := visit(identity); err != nil {
			return err
		}
	}

	return validateRuntimePolicySetExports(sets)
}

// validateRuntimePolicySetExports proves declared and actual transitive capabilities are equal.
func validateRuntimePolicySetExports(sets map[string]CompiledPolicySet) error {
	definitions := compiledPolicySetDefinitions(sets)

	for _, identity := range sortedRuntimeKeys(sets) {
		set := sets[identity].definition

		declared, exported := set.ExportContract()
		if !exported {
			continue
		}

		actual, err := registry.DerivePolicySetCapability(definitions, identity)
		if err != nil {
			return fmt.Errorf("%w: set %s capability derivation failed: %v", ErrInvalidCompiledTarget, identity, err)
		}

		if !declared.Equal(actual) {
			return fmt.Errorf("%w: set %s export contract does not match its actual source capability", ErrInvalidCompiledTarget, identity)
		}
	}

	return nil
}

// validateRuntimeSourceImport enforces exact source-owned cross-namespace edges.
func validateRuntimeSourceImport(
	owner registry.PolicySetDefinition,
	imported registry.PolicySetImport,
	child registry.PolicySetDefinition,
) error {
	if child.ID().String() == registry.BuiltinStandardAuthPolicySet {
		return fmt.Errorf("%w: standard_auth cannot be imported by %s", ErrInvalidCompiledTarget, owner.ID().String())
	}

	if owner.ID().Namespace() == child.ID().Namespace() {
		return nil
	}

	declared, exported := child.ExportContract()
	requested := imported.Contract()

	if child.Visibility() != registry.PolicySetVisibilityExported ||
		!exported ||
		!requested.Complete() ||
		!requested.Equal(declared) ||
		!declared.SupportsCheckpoint(imported.Checkpoint()) {
		return fmt.Errorf("%w: set %s has an invalid import of %s", ErrInvalidCompiledTarget, owner.ID().String(), child.ID().String())
	}

	return nil
}

// compiledPolicySetDefinitions projects runtime wrappers to shared immutable source definitions.
func compiledPolicySetDefinitions(sets map[string]CompiledPolicySet) map[string]registry.PolicySetDefinition {
	result := make(map[string]registry.PolicySetDefinition, len(sets))
	for identity, set := range sets {
		result[identity] = set.definition
	}

	return result
}

// compileTargetRecord validates and owns one complete target runtime record.
func compileTargetRecord(
	record TargetCatalogRecord,
	policySets map[string]CompiledPolicySet,
) (CompiledTarget, error) {
	target, identity, err := validateTargetRecordIdentity(record)
	if err != nil {
		return CompiledTarget{}, err
	}

	providers, err := providerIndex(record.Providers, target)
	if err != nil {
		return CompiledTarget{}, err
	}

	effects, err := effectIndex(record.Effects, target, providers)
	if err != nil {
		return CompiledTarget{}, err
	}

	if err := validateBuiltinAuthDescriptors(target, record.Schema, record.SourcePlan, providers, effects); err != nil {
		return CompiledTarget{}, err
	}

	plan, rules, err := compileDomainPlanRecord(target, record, policySets, providers, effects)
	if err != nil {
		return CompiledTarget{}, err
	}

	if err := validateCompiledRules(rules, effects); err != nil {
		return CompiledTarget{}, err
	}

	if err := validateCompiledDefaults(target, record, plan, policySets); err != nil {
		return CompiledTarget{}, err
	}

	targetPolicySets := compileTargetPolicySets(policySets, record.Checkpoints, rules)
	if err := validateRuntimeDiagnosticAliases(target, targetPolicySets, providers, effects); err != nil {
		return CompiledTarget{}, err
	}

	return CompiledTarget{
		target:           target,
		schema:           newCompiledSchema(identity, record.Schema.Facts()),
		domainPlan:       plan,
		providers:        providers,
		effects:          effects,
		policySets:       targetPolicySets,
		defaultPolicySet: record.DefaultPolicySet,
		report:           record.Report,
		noMatch:          record.NoMatch,
		authorityMode:    record.AuthorityMode,
	}, nil
}

// validateTargetRecordIdentity validates one exact target/schema identity pair.
func validateTargetRecordIdentity(record TargetCatalogRecord) (decision.Target, registry.SchemaIdentity, error) {
	target, err := decision.NewTarget(record.Target.Namespace(), record.Target.Action())
	if err != nil {
		return decision.Target{}, registry.SchemaIdentity{}, err
	}

	identity := record.Schema.Identity()
	if identity.Namespace() != target.Namespace() || identity.Name() != target.Action() {
		return decision.Target{}, registry.SchemaIdentity{}, fmt.Errorf(
			"%w: target %s cannot select schema %s",
			registry.ErrTargetSchemaMismatch,
			target.String(),
			identity.String(),
		)
	}

	return target, identity, nil
}

// validateBuiltinAuthDescriptors prevents direct callers from omitting or replacing host contracts.
func validateBuiltinAuthDescriptors(
	target decision.Target,
	schema registry.SchemaDefinition,
	plan registry.DomainPlanDefinition,
	providers map[string]registry.ProviderDefinition,
	effects map[string]registry.EffectDefinition,
) error {
	if target.Namespace() != authnNamespace {
		return nil
	}

	if !schema.IsBuiltinAuth() {
		return fmt.Errorf("%w: target %s must use an immutable builtin auth schema", ErrInvalidCompiledTarget, target.String())
	}

	if err := validateBuiltinAuthPlanProviders(target, plan, providers); err != nil {
		return err
	}

	return validateBuiltinAuthEffects(target, providers, effects)
}

// validateBuiltinAuthPlanProviders resolves configured bindings without allowing host identity replacement.
func validateBuiltinAuthPlanProviders(
	target decision.Target,
	plan registry.DomainPlanDefinition,
	providers map[string]registry.ProviderDefinition,
) error {
	for _, checkpoint := range plan.Checkpoints() {
		for _, providerID := range checkpoint.Providers() {
			provider, exists := providers[providerID]
			if !exists || registry.IsBuiltinAuthProviderID(providerID) && !provider.IsBuiltin() {
				return fmt.Errorf("%w: target %s has invalid builtin checkpoint provider %s", ErrInvalidCompiledTarget, target.String(), providerID)
			}
		}
	}

	return nil
}

// validateBuiltinAuthEffects protects every required canonical effect binding.
func validateBuiltinAuthEffects(
	target decision.Target,
	providers map[string]registry.ProviderDefinition,
	effects map[string]registry.EffectDefinition,
) error {
	expected := registry.BuiltinAuthEffectIDs(target.Action())
	for _, effectID := range expected {
		effect, exists := effects[effectID]

		if !exists || !effect.IsBuiltin() || effect.ID() != effectID {
			return fmt.Errorf("%w: target %s has invalid builtin effect %s", ErrInvalidCompiledTarget, target.String(), effectID)
		}

		provider, providerExists := providers[effect.Provider()]
		if effect.Execution() != registry.ExecutionReturnOnly && (!providerExists || !provider.IsBuiltin()) {
			return fmt.Errorf("%w: target %s has invalid builtin provider for %s", ErrInvalidCompiledTarget, target.String(), effectID)
		}
	}

	return nil
}

// validateRuntimeDiagnosticAliases rejects direct target-local public alias collisions.
func validateRuntimeDiagnosticAliases(
	target decision.Target,
	sets map[string]CompiledPolicySet,
	providers map[string]registry.ProviderDefinition,
	effects map[string]registry.EffectDefinition,
) error {
	aliases := make(map[string]string)
	claim := func(alias string, component string) error {
		if alias == "" {
			return nil
		}

		if existing, exists := aliases[alias]; exists {
			return fmt.Errorf(
				"%w: target %s diagnostic alias %s used by %s and %s",
				ErrInvalidCompiledTarget,
				target.String(),
				alias,
				existing,
				component,
			)
		}

		aliases[alias] = component

		return nil
	}

	for _, identity := range sortedRuntimeKeys(sets) {
		if err := claim(sets[identity].DiagnosticID(), "policy_set "+identity); err != nil {
			return err
		}
	}

	for _, identity := range sortedRuntimeKeys(providers) {
		if err := claim(providers[identity].DiagnosticID(), "provider "+identity); err != nil {
			return err
		}
	}

	for _, identity := range sortedRuntimeKeys(effects) {
		if err := claim(effects[identity].DiagnosticID(), "effect "+identity); err != nil {
			return err
		}
	}

	return nil
}

// sortedRuntimeKeys returns deterministic target-local descriptor order.
func sortedRuntimeKeys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))

	for identity := range values {
		result = append(result, identity)
	}

	sort.Strings(result)

	return result
}

// LookupPolicySet returns one detached immutable global policy-set descriptor.
func (c *TargetCatalog) LookupPolicySet(id registry.PolicySetID) (CompiledPolicySet, bool) {
	if c == nil {
		return CompiledPolicySet{}, false
	}

	set, ok := c.policySets[id.String()]

	return set, ok
}

// AdmissionCount reports the separately owned client admission entries in this candidate.
func (c *TargetCatalog) AdmissionCount() int {
	return 0
}

// Len returns the number of explicitly activated targets.
func (c *TargetCatalog) Len() int {
	if c == nil {
		return 0
	}

	return len(c.targets)
}

// Targets returns detached activated targets in deterministic identity order.
func (c *TargetCatalog) Targets() []CompiledTarget {
	if c == nil {
		return nil
	}

	identities := sortedRuntimeKeys(c.targets)

	result := make([]CompiledTarget, 0, len(identities))
	for _, identity := range identities {
		result = append(result, c.targets[identity].clone())
	}

	return result
}

// Lookup returns a detached compiled target by exact identity.
func (c *TargetCatalog) Lookup(target decision.Target) (CompiledTarget, bool) {
	if c == nil {
		return CompiledTarget{}, false
	}

	compiled, ok := c.targets[target.String()]
	if !ok {
		return CompiledTarget{}, false
	}

	return compiled.clone(), true
}

// ValidateFacts resolves one activated target and validates only its selected exact schema.
func (c *TargetCatalog) ValidateFacts(target decision.Target, facts decision.FactSet) error {
	compiled, ok := c.Lookup(target)
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownCompiledTarget, target.String())
	}

	return compiled.schema.ValidateFacts(facts)
}

// Clone returns a deeply detached immutable catalog candidate.
func (c *TargetCatalog) Clone() *TargetCatalog {
	if c == nil {
		return nil
	}

	targets := make(map[string]CompiledTarget, len(c.targets))
	for identity, target := range c.targets {
		targets[identity] = target.clone()
	}

	policySets := make(map[string]CompiledPolicySet, len(c.policySets))
	for identity, set := range c.policySets {
		policySets[identity] = set
	}

	return &TargetCatalog{targets: targets, policySets: policySets}
}

// newCompiledDomainPlan indexes one ordered checkpoint record set and its authority projection.
func newCompiledDomainPlan(
	target decision.Target,
	mode registry.AuthorityMode,
	records []CheckpointRecord,
	rules []CompiledRule,
	providers map[string]registry.ProviderDefinition,
) (CompiledDomainPlan, error) {
	checkpoints := make([]CompiledCheckpoint, 0, len(records))
	byName := make(map[string]CompiledCheckpoint, len(records))

	for _, record := range records {
		instances, err := checkpointProviderInstances(record)
		if err != nil {
			return CompiledDomainPlan{}, err
		}

		compiledInstances, err := compileProviderInstances(instances, providers)
		if err != nil {
			return CompiledDomainPlan{}, err
		}

		instancesByName := make(map[string]CompiledProviderInstance, len(compiledInstances))
		for _, instance := range compiledInstances {
			instancesByName[instance.Name()] = instance.clone()
		}

		setIDs := make([]string, 0, len(record.PolicySetIDs))
		for _, setID := range record.PolicySetIDs {
			setIDs = append(setIDs, setID.String())
		}

		checkpoint := CompiledCheckpoint{
			name:                    record.Name,
			policySetIDs:            setIDs,
			providerIDs:             providerInstanceUses(instances),
			providerInstances:       compiledInstances,
			providerInstancesByName: instancesByName,
			providerLevels:          compileProviderLevels(compiledInstances),
		}
		checkpoint.productionPolicySetIDs, checkpoint.comparisonPolicySetIDs = checkpointAuthority(
			target,
			mode,
			checkpoint,
			rules,
		)
		checkpoints = append(checkpoints, checkpoint)
		byName[record.Name] = checkpoint
	}

	return CompiledDomainPlan{checkpoints: checkpoints, byName: byName}, nil
}

// checkpointAuthority separates configured authn comparison from production ownership.
func checkpointAuthority(
	target decision.Target,
	mode registry.AuthorityMode,
	checkpoint CompiledCheckpoint,
	rules []CompiledRule,
) ([]string, []string) {
	if target.Namespace() != authnNamespace {
		return checkpoint.PolicySetIDs(), nil
	}

	configured := activeConfiguredPolicySets(checkpoint, rules)
	if mode == registry.AuthorityModeObserve {
		return []string{registry.BuiltinStandardAuthPolicySet}, configured
	}

	if len(configured) > 0 {
		return configured, nil
	}

	return []string{registry.BuiltinStandardAuthPolicySet}, nil
}

// activeConfiguredPolicySets returns ordered non-builtin sets with executable rules.
func activeConfiguredPolicySets(checkpoint CompiledCheckpoint, rules []CompiledRule) []string {
	active := make(map[string]struct{})

	for _, rule := range rules {
		if rule.Checkpoint() == checkpoint.Name() {
			active[rule.PolicySetID().String()] = struct{}{}
		}
	}

	result := make([]string, 0, len(active))

	for _, identity := range checkpoint.PolicySetIDs() {
		if identity == registry.BuiltinStandardAuthPolicySet {
			continue
		}

		if _, exists := active[identity]; exists {
			result = append(result, identity)
		}
	}

	return result
}

// compileDomainPlanRecord rejects malformed direct records and instantiates exact rules.
func compileDomainPlanRecord(
	target decision.Target,
	record TargetCatalogRecord,
	policySets map[string]CompiledPolicySet,
	providers map[string]registry.ProviderDefinition,
	effects map[string]registry.EffectDefinition,
) (CompiledDomainPlan, []CompiledRule, error) {
	if len(record.Checkpoints) == 0 {
		return CompiledDomainPlan{}, nil, fmt.Errorf("%w: target %s has no checkpoints", ErrInvalidCompiledTarget, target.String())
	}

	seen := make(map[string]struct{}, len(record.Checkpoints))
	for _, checkpoint := range record.Checkpoints {
		if !identifier.Action(checkpoint.Name) {
			return CompiledDomainPlan{}, nil, fmt.Errorf("%w: invalid checkpoint %s", ErrInvalidCompiledTarget, checkpoint.Name)
		}

		if _, exists := seen[checkpoint.Name]; exists {
			return CompiledDomainPlan{}, nil, fmt.Errorf("%w: %s", ErrDuplicateCompiledCheckpoint, checkpoint.Name)
		}

		seen[checkpoint.Name] = struct{}{}
	}

	if err := validateSourcePlanRecord(target, record); err != nil {
		return CompiledDomainPlan{}, nil, err
	}

	rules := make([]CompiledRule, 0)

	for _, checkpoint := range record.Checkpoints {
		if err := validateCheckpointRecord(target, record.Schema, checkpoint, policySets, providers, effects); err != nil {
			return CompiledDomainPlan{}, nil, err
		}

		compiled, err := compileRuleRecords(target, record.Schema, checkpoint, policySets)
		if err != nil {
			return CompiledDomainPlan{}, nil, err
		}

		rules = append(rules, compiled...)
	}

	if err := validateProviderContinuationSafety(record.Schema, record.Checkpoints, rules, providers); err != nil {
		return CompiledDomainPlan{}, nil, err
	}

	plan, err := newCompiledDomainPlan(target, record.AuthorityMode, record.Checkpoints, rules, providers)
	if err != nil {
		return CompiledDomainPlan{}, nil, err
	}

	plan.schedulerGuards = record.SourcePlan.SchedulerGuards()

	plan.schedulerGuardsByName = make(map[string]registry.SchedulerGuardDefinition, len(plan.schedulerGuards))
	for _, guard := range plan.schedulerGuards {
		plan.schedulerGuardsByName[guard.Name()] = guard
	}

	return plan, rules, nil
}

// validateSourcePlanRecord proves checkpoint order, schedules, and merged roots came from one source plan.
func validateSourcePlanRecord(target decision.Target, record TargetCatalogRecord) error {
	sourceCheckpoints := record.SourcePlan.Checkpoints()
	if record.SourcePlan.Target().String() != target.String() || len(sourceCheckpoints) == 0 {
		return fmt.Errorf("%w: target %s has no matching source domain plan", ErrInvalidCompiledTarget, target.String())
	}

	if target.Namespace() == authnNamespace && !record.SourcePlan.IsBuiltinAuth() {
		return fmt.Errorf("%w: target %s must use immutable builtin auth topology", ErrInvalidCompiledTarget, target.String())
	}

	if len(sourceCheckpoints) != len(record.Checkpoints) {
		return fmt.Errorf("%w: target %s checkpoint count does not match its source plan", ErrInvalidCompiledTarget, target.String())
	}

	activationBindings, err := runtimeActivationBindingsByCheckpoint(record.ActivationPolicySetBindings, sourceCheckpoints)
	if err != nil {
		return err
	}

	for index, source := range sourceCheckpoints {
		compiled := record.Checkpoints[index]

		instances, instanceErr := checkpointProviderInstances(compiled)
		if instanceErr != nil {
			return instanceErr
		}

		if compiled.Name != source.Name() || !equalProviderInstanceDefinitions(instances, source.ProviderInstances()) {
			return fmt.Errorf("%w: target %s checkpoint %d does not match its source schedule", ErrInvalidCompiledTarget, target.String(), index)
		}

		expectedBindings := append([]registry.PolicySetImport(nil), activationBindings[source.Name()]...)
		expectedBindings = append(expectedBindings, source.PolicySets()...)

		if !equalPolicySetImports(compiled.PolicySetBindings, expectedBindings) {
			return fmt.Errorf("%w: target %s checkpoint %s roots do not match its source plan", ErrInvalidCompiledTarget, target.String(), source.Name())
		}
	}

	return nil
}

// runtimeActivationBindingsByCheckpoint validates target-level roots against source topology.
func runtimeActivationBindingsByCheckpoint(
	bindings []registry.PolicySetImport,
	checkpoints []registry.CheckpointDefinition,
) (map[string][]registry.PolicySetImport, error) {
	known := make(map[string]struct{}, len(checkpoints))
	for _, checkpoint := range checkpoints {
		known[checkpoint.Name()] = struct{}{}
	}

	result := make(map[string][]registry.PolicySetImport)

	for _, binding := range bindings {
		if _, exists := known[binding.Checkpoint()]; !exists {
			return nil, fmt.Errorf("%w: activation binding %s references unknown checkpoint %s", ErrInvalidCompiledTarget, binding.Set().String(), binding.Checkpoint())
		}

		result[binding.Checkpoint()] = append(result[binding.Checkpoint()], binding)
	}

	return result, nil
}

// equalPolicySetImports compares exact ordered root binding descriptors.
func equalPolicySetImports(left []registry.PolicySetImport, right []registry.PolicySetImport) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if !left[index].Equal(right[index]) {
			return false
		}
	}

	return true
}

// checkpointProviderInstances returns exact source-owned provider metadata.
func checkpointProviderInstances(checkpoint CheckpointRecord) ([]registry.ProviderInstanceDefinition, error) {
	if len(checkpoint.ProviderInstances) == 0 {
		if len(checkpoint.ProviderIDs) == 0 {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"%w: checkpoint %s requires exact provider instances",
			ErrInvalidCompiledTarget,
			checkpoint.Name,
		)
	}

	if !slices.Equal(checkpoint.ProviderIDs, providerInstanceUses(checkpoint.ProviderInstances)) {
		return nil, fmt.Errorf("%w: checkpoint %s provider identities do not match its instance projection", ErrInvalidCompiledTarget, checkpoint.Name)
	}

	return append([]registry.ProviderInstanceDefinition(nil), checkpoint.ProviderInstances...), nil
}

// providerInstanceUses projects the exact ordered uses for record integrity checks.
func providerInstanceUses(instances []registry.ProviderInstanceDefinition) []string {
	result := make([]string, 0, len(instances))
	for _, instance := range instances {
		result = append(result, instance.Use())
	}

	return result
}

// equalProviderInstanceDefinitions compares every exact source-owned provider field.
func equalProviderInstanceDefinitions(
	left []registry.ProviderInstanceDefinition,
	right []registry.ProviderInstanceDefinition,
) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if !left[index].Equal(right[index]) {
			return false
		}
	}

	return true
}

// validateCheckpointRecord resolves every exact set and provider reference.
func validateCheckpointRecord(
	target decision.Target,
	schema registry.SchemaDefinition,
	checkpoint CheckpointRecord,
	policySets map[string]CompiledPolicySet,
	providers map[string]registry.ProviderDefinition,
	effects map[string]registry.EffectDefinition,
) error {
	instances, err := checkpointProviderInstances(checkpoint)
	if err != nil {
		return err
	}

	resolved, err := resolveRuntimeCheckpointPolicySets(target, schema, checkpoint, policySets, effects)
	if err != nil {
		return err
	}

	if !equalPolicySetIDs(resolved, checkpoint.PolicySetIDs) {
		return fmt.Errorf("%w: checkpoint %s policy-set closure does not match its exact bindings", ErrInvalidCompiledTarget, checkpoint.Name)
	}

	seenProviders := make(map[string]struct{}, len(instances))
	outputOwners := make(map[string]string)
	declaredFacts := schemaFactIDs(schema)

	for _, instance := range instances {
		if err := validateScheduledProvider(
			target,
			checkpoint.Name,
			instance,
			providers,
			seenProviders,
			declaredFacts,
			outputOwners,
		); err != nil {
			return err
		}
	}

	if err := validateCheckpointProviderGraph(checkpoint.Name, instances, providers); err != nil {
		return err
	}

	return nil
}

// schemaFactIDs returns the exact fact identifiers declared by one target schema.
func schemaFactIDs(schema registry.SchemaDefinition) map[string]struct{} {
	result := make(map[string]struct{}, len(schema.Facts()))

	for _, fact := range schema.Facts() {
		result[fact.ID()] = struct{}{}
	}

	return result
}

// validateScheduledProvider validates one checkpoint member and reserves its fact outputs.
func validateScheduledProvider(
	target decision.Target,
	checkpointName string,
	instance registry.ProviderInstanceDefinition,
	providers map[string]registry.ProviderDefinition,
	seenProviders map[string]struct{},
	declaredFacts map[string]struct{},
	outputOwners map[string]string,
) error {
	providerID := instance.Use()
	provider, exists := providers[providerID]
	if !exists {
		return fmt.Errorf("%w: checkpoint %s references unknown provider %s", ErrInvalidCompiledTarget, checkpointName, providerID)
	}

	if _, exists = seenProviders[instance.Name()]; exists {
		return fmt.Errorf("%w: checkpoint %s repeats provider instance %s", ErrInvalidCompiledTarget, checkpointName, instance.Name())
	}

	seenProviders[instance.Name()] = struct{}{}

	if target.Namespace() != authnNamespace && !provider.Scheduled() {
		return fmt.Errorf("%w: generic provider %s requires explicit failure and timeout", ErrInvalidCompiledTarget, providerID)
	}

	for _, factID := range provider.ProducedFacts() {
		if _, exists = declaredFacts[factID]; !exists {
			return fmt.Errorf("%w: provider %s produces undeclared fact %s", ErrInvalidCompiledTarget, providerID, factID)
		}

		if owner, owned := outputOwners[factID]; owned {
			return fmt.Errorf("%w: providers %s and %s both produce fact %s", ErrInvalidCompiledTarget, owner, instance.Name(), factID)
		}

		outputOwners[factID] = instance.Name()
	}

	if instance.Output() != "" {
		if _, exists = declaredFacts[instance.Output()]; !exists {
			return fmt.Errorf("%w: provider instance %s produces undeclared fact %s", ErrInvalidCompiledTarget, instance.Name(), instance.Output())
		}

		if owner, owned := outputOwners[instance.Output()]; owned {
			return fmt.Errorf("%w: providers %s and %s both produce fact %s", ErrInvalidCompiledTarget, owner, instance.Name(), instance.Output())
		}

		outputOwners[instance.Output()] = instance.Name()
	}

	return nil
}

// validateCheckpointProviderGraph rejects foreign dependencies and cycles before activation.
func validateCheckpointProviderGraph(
	checkpointName string,
	instances []registry.ProviderInstanceDefinition,
	providers map[string]registry.ProviderDefinition,
) error {
	compiled, err := compileProviderInstances(instances, providers)
	if err != nil {
		return err
	}

	if levels := compileProviderLevels(compiled); len(levels) == 0 && len(compiled) > 0 {
		return fmt.Errorf("%w: checkpoint %s provider dependency cycle", ErrInvalidCompiledTarget, checkpointName)
	}

	return nil
}

// compileProviderInstances resolves authored and definition-owned dependency edges by instance name.
func compileProviderInstances(
	instances []registry.ProviderInstanceDefinition,
	providers map[string]registry.ProviderDefinition,
) ([]CompiledProviderInstance, error) {
	names := make(map[string]struct{}, len(instances))
	namesByUse := make(map[string][]string, len(instances))

	for _, instance := range instances {
		if _, exists := names[instance.Name()]; exists {
			return nil, fmt.Errorf("%w: duplicate provider instance %s", ErrInvalidCompiledTarget, instance.Name())
		}

		names[instance.Name()] = struct{}{}
		namesByUse[instance.Use()] = append(namesByUse[instance.Use()], instance.Name())
	}

	result := make([]CompiledProviderInstance, 0, len(instances))
	for _, instance := range instances {
		provider, exists := providers[instance.Use()]
		if !exists {
			return nil, fmt.Errorf("%w: provider instance %s references unknown provider %s", ErrInvalidCompiledTarget, instance.Name(), instance.Use())
		}

		dependencies, err := resolveProviderInstanceDependencies(instance, provider, names, namesByUse)
		if err != nil {
			return nil, err
		}

		result = append(result, CompiledProviderInstance{
			definition:   instance,
			dependencies: dependencies,
		})
	}

	return result, nil
}

// resolveProviderInstanceDependencies merges local after edges with exact provider-definition requirements.
func resolveProviderInstanceDependencies(
	instance registry.ProviderInstanceDefinition,
	provider registry.ProviderDefinition,
	names map[string]struct{},
	namesByUse map[string][]string,
) ([]string, error) {
	dependencies := append([]string(nil), instance.After()...)
	seen := make(map[string]struct{}, len(dependencies)+len(provider.Requires()))

	for _, dependency := range dependencies {
		if _, exists := names[dependency]; !exists {
			return nil, fmt.Errorf("%w: provider instance %s follows unknown instance %s", ErrInvalidCompiledTarget, instance.Name(), dependency)
		}

		seen[dependency] = struct{}{}
	}

	for _, requiredUse := range provider.Requires() {
		candidates := namesByUse[requiredUse]
		if len(candidates) == 0 {
			return nil, fmt.Errorf("%w: provider %s requires unscheduled provider %s", ErrInvalidCompiledTarget, instance.Use(), requiredUse)
		}

		if len(candidates) > 1 {
			return nil, fmt.Errorf("%w: provider %s has ambiguous required use %s across instances %s", ErrInvalidCompiledTarget, instance.Use(), requiredUse, strings.Join(candidates, ","))
		}

		dependency := candidates[0]
		if _, exists := seen[dependency]; exists {
			continue
		}

		seen[dependency] = struct{}{}
		dependencies = append(dependencies, dependency)
	}

	return dependencies, nil
}

// compileProviderLevels projects one acyclic provider graph into deterministic dependency levels.
func compileProviderLevels(
	instances []CompiledProviderInstance,
) [][]string {
	remaining := make(map[string]int, len(instances))
	dependants := make(map[string][]string, len(instances))

	for _, instance := range instances {
		dependencies := instance.Dependencies()
		remaining[instance.Name()] = len(dependencies)

		for _, dependency := range dependencies {
			dependants[dependency] = append(dependants[dependency], instance.Name())
		}
	}

	levels := make([][]string, 0)
	processed := 0

	for processed < len(instances) {
		level := make([]string, 0)

		for providerID, count := range remaining {
			if count == 0 {
				level = append(level, providerID)
			}
		}

		if len(level) == 0 {
			return nil
		}

		sort.Strings(level)
		levels = append(levels, level)

		for _, providerID := range level {
			delete(remaining, providerID)

			processed++

			for _, dependant := range dependants[providerID] {
				remaining[dependant]--
			}
		}
	}

	return levels
}

// validateProviderContinuationSafety proves omitted output cannot satisfy an unconditional requirement.
func validateProviderContinuationSafety(
	schema registry.SchemaDefinition,
	checkpoints []CheckpointRecord,
	rules []CompiledRule,
	providers map[string]registry.ProviderDefinition,
) error {
	requiredFacts := make(map[string]struct{})

	for _, fact := range schema.Facts() {
		if fact.Required() {
			requiredFacts[fact.ID()] = struct{}{}
		}
	}

	rulesByCheckpoint := make(map[string][]CompiledRule)
	for _, rule := range rules {
		rulesByCheckpoint[rule.Checkpoint()] = append(rulesByCheckpoint[rule.Checkpoint()], rule)
	}

	for _, checkpoint := range checkpoints {
		instances, err := checkpointProviderInstances(checkpoint)
		if err != nil {
			return err
		}

		for _, instance := range instances {
			provider := providers[instance.Use()]
			if provider.Failure() != registry.ProviderFailureContinue {
				continue
			}

			producedFacts := append([]string(nil), provider.ProducedFacts()...)
			if instance.Output() != "" && !slices.Contains(producedFacts, instance.Output()) {
				producedFacts = append(producedFacts, instance.Output())
			}

			for _, factID := range producedFacts {
				if _, required := requiredFacts[factID]; required {
					return fmt.Errorf("%w: provider %s continue cannot omit required fact %s", ErrInvalidCompiledTarget, instance.Name(), factID)
				}

				for _, rule := range rulesByCheckpoint[checkpoint.Name] {
					if ruleUsesFact(rule, factID) &&
						!requiredProvidersContainInstance(rule.RequiredProviders(), instance) {
						return fmt.Errorf("%w: provider %s continue requires rule %s to declare the provider", ErrInvalidCompiledTarget, instance.Name(), rule.Name())
					}
				}
			}
		}
	}

	return nil
}

// ruleUsesFact reports whether one rule expression or response projection reads a fact.
func ruleUsesFact(rule CompiledRule, factID string) bool {
	for _, contract := range rule.Expression().FactContracts() {
		if contract.ID() == factID {
			return true
		}
	}

	return rule.ResponseMessage().FactID() == factID || rule.ResponseLanguage().FactID() == factID
}

// requiredProvidersContainInstance accepts only exact checkpoint-local instance names.
func requiredProvidersContainInstance(
	required []string,
	instance registry.ProviderInstanceDefinition,
) bool {
	return slices.Contains(required, instance.Name())
}

// resolveRequiredProviderReferences validates exact source instance names.
func resolveRequiredProviderReferences(
	references []string,
	instances []registry.ProviderInstanceDefinition,
) ([]string, error) {
	result := make([]string, 0, len(references))

	for _, reference := range references {
		if slices.ContainsFunc(instances, func(instance registry.ProviderInstanceDefinition) bool {
			return instance.Name() == reference
		}) {
			result = append(result, reference)

			continue
		}

		return nil, fmt.Errorf("requires unscheduled provider instance %s", reference)
	}

	return result, nil
}

// runtimeCheckpointResolver revalidates exact root authority and its ordered import closure.
type runtimeCheckpointResolver struct {
	policySets map[string]CompiledPolicySet
	effects    map[string]registry.EffectDefinition
	schema     registry.SchemaDefinition
	target     decision.Target
	checkpoint string
	result     []registry.PolicySetID
	visited    map[string]bool
	active     map[string]bool
}

// resolveRuntimeCheckpointPolicySets expands direct-runtime bindings without trusting compiler output.
func resolveRuntimeCheckpointPolicySets(
	target decision.Target,
	schema registry.SchemaDefinition,
	checkpoint CheckpointRecord,
	policySets map[string]CompiledPolicySet,
	effects map[string]registry.EffectDefinition,
) ([]registry.PolicySetID, error) {
	resolver := runtimeCheckpointResolver{
		policySets: policySets,
		effects:    effects,
		schema:     schema,
		target:     target,
		checkpoint: checkpoint.Name,
		result:     make([]registry.PolicySetID, 0, len(checkpoint.PolicySetIDs)),
		visited:    make(map[string]bool),
		active:     make(map[string]bool),
	}
	seenRoots := make(map[string]struct{}, len(checkpoint.PolicySetBindings))

	for _, binding := range checkpoint.PolicySetBindings {
		identity := binding.Set().String()
		if _, exists := seenRoots[identity]; exists {
			return nil, fmt.Errorf("%w: checkpoint %s repeats root binding %s", ErrInvalidCompiledTarget, checkpoint.Name, identity)
		}

		seenRoots[identity] = struct{}{}

		if err := resolver.resolve(target.Namespace(), binding); err != nil {
			return nil, err
		}
	}

	return resolver.result, nil
}

// resolve validates one exact import edge before appending its source-owned closure.
func (r *runtimeCheckpointResolver) resolve(ownerNamespace string, imported registry.PolicySetImport) error {
	if imported.Target().String() != r.target.String() || imported.Checkpoint() != r.checkpoint {
		return fmt.Errorf(
			"%w: binding %s does not match target %s checkpoint %s",
			ErrInvalidCompiledTarget,
			imported.Set().String(),
			r.target.String(),
			r.checkpoint,
		)
	}

	identity := imported.Set().String()
	set, exists := r.policySets[identity]

	if !exists {
		return fmt.Errorf("%w: checkpoint %s references unknown set %s", ErrInvalidCompiledTarget, r.checkpoint, identity)
	}

	if err := r.validateImport(ownerNamespace, imported, set.definition); err != nil {
		return err
	}

	if r.active[identity] {
		return fmt.Errorf("%w: cyclic policy-set import at %s", ErrInvalidCompiledTarget, identity)
	}

	if r.visited[identity] {
		return nil
	}

	r.active[identity] = true
	r.visited[identity] = true
	r.result = append(r.result, imported.Set())

	for _, nested := range set.definition.Imports() {
		if nested.Target().String() != r.target.String() || nested.Checkpoint() != r.checkpoint {
			continue
		}

		if err := r.resolve(set.ID().Namespace(), nested); err != nil {
			return err
		}
	}

	delete(r.active, identity)

	return nil
}

// validateImport enforces builtin isolation and exact cross-namespace capabilities.
func (r *runtimeCheckpointResolver) validateImport(
	ownerNamespace string,
	imported registry.PolicySetImport,
	definition registry.PolicySetDefinition,
) error {
	identity := definition.ID().String()
	if identity == registry.BuiltinStandardAuthPolicySet {
		if r.target.Namespace() != authnNamespace || ownerNamespace != authnNamespace || !definition.IsBuiltinStandardAuth() {
			return fmt.Errorf("%w: standard_auth cannot bind target %s from namespace %s", ErrInvalidCompiledTarget, r.target.String(), ownerNamespace)
		}
	}

	if ownerNamespace == definition.ID().Namespace() {
		return nil
	}

	contract, exported := definition.ExportContract()
	if definition.Visibility() != registry.PolicySetVisibilityExported || !exported {
		return fmt.Errorf("%w: private set %s cannot cross namespace %s", ErrInvalidCompiledTarget, identity, ownerNamespace)
	}

	requested := imported.Contract()
	if !requested.Complete() || !requested.Equal(contract) || !contract.SupportsCheckpoint(r.checkpoint) {
		return fmt.Errorf("%w: set %s has an incomplete or incompatible import contract", ErrInvalidCompiledTarget, identity)
	}

	if err := validateRuntimeImportCapability(requested, r.target, r.schema, r.effects); err != nil {
		return fmt.Errorf("%w: set %s: %v", ErrInvalidCompiledTarget, identity, err)
	}

	return nil
}

// validateRuntimeImportCapability resolves exact typed facts and effect allowlists.
func validateRuntimeImportCapability(
	contract registry.ExportContract,
	target decision.Target,
	schema registry.SchemaDefinition,
	effects map[string]registry.EffectDefinition,
) error {
	facts := make(map[string]registry.FactSchema, len(schema.Facts()))
	for _, fact := range schema.Facts() {
		facts[fact.ID()] = fact
	}

	for _, required := range contract.Facts() {
		fact, exists := facts[required.ID()]
		if !exists || !decision.ValueKindsCompatible(fact.Kind(), required.Kind()) {
			return fmt.Errorf("fact %s is absent or has an incompatible kind", required.ID())
		}
	}

	for _, effectID := range contract.Effects() {
		effect, exists := effects[effectID]
		if !exists || !effect.AllowsTarget(target) {
			return fmt.Errorf("effect %s is absent or disallows target %s", effectID, target.String())
		}
	}

	return nil
}

// equalPolicySetIDs compares exact ordered resolved set identities.
func equalPolicySetIDs(left []registry.PolicySetID, right []registry.PolicySetID) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if left[index].String() != right[index].String() {
			return false
		}
	}

	return true
}

// compileRuleRecords validates exact target, set, checkpoint, schema, and source bindings.
func compileRuleRecords(
	target decision.Target,
	schema registry.SchemaDefinition,
	checkpoint CheckpointRecord,
	policySets map[string]CompiledPolicySet,
) ([]CompiledRule, error) {
	instances, err := checkpointProviderInstances(checkpoint)
	if err != nil {
		return nil, err
	}

	expected := expectedRuntimeRuleRecords(target, checkpoint, policySets)
	if len(expected) != len(checkpoint.Rules) {
		return nil, fmt.Errorf(
			"%w: checkpoint %s has %d rule records, want exact source projection %d",
			ErrInvalidCompiledTarget,
			checkpoint.Name,
			len(checkpoint.Rules),
			len(expected),
		)
	}

	result := make([]CompiledRule, 0, len(expected))
	for index, record := range checkpoint.Rules {
		if err := validateCompiledRuleRecord(target, schema, checkpoint, record, expected[index], policySets, index); err != nil {
			return nil, err
		}

		requiredProviders, err := resolveRequiredProviderReferences(record.RequiredProviders, instances)
		if err != nil {
			return nil, fmt.Errorf("%w: rule %s: %v", ErrInvalidCompiledTarget, record.Name, err)
		}

		result = append(result, newCompiledRule(record, requiredProviders))
	}

	return result, nil
}

// validateCompiledRuleRecord revalidates source authenticity and target-local dependencies.
func validateCompiledRuleRecord(
	target decision.Target,
	schema registry.SchemaDefinition,
	checkpoint CheckpointRecord,
	record CompiledRuleRecord,
	expected CompiledRuleRecord,
	policySets map[string]CompiledPolicySet,
	index int,
) error {
	if record.Target.String() != target.String() || record.Checkpoint != checkpoint.Name ||
		!identifier.Action(record.Name) || !record.Expression.Valid() {
		return fmt.Errorf("%w: malformed rule %s at checkpoint %s", ErrInvalidCompiledTarget, record.Name, checkpoint.Name)
	}

	if !slices.ContainsFunc(checkpoint.PolicySetIDs, func(id registry.PolicySetID) bool {
		return id.String() == record.PolicySetID.String()
	}) {
		return fmt.Errorf("%w: rule %s references unbound set %s", ErrInvalidCompiledTarget, record.Name, record.PolicySetID.String())
	}

	set := policySets[record.PolicySetID.String()]
	if !runtimeRuleDecisionAllowed(
		record.Decision,
		target.Namespace() == authnNamespace && set.ID().Namespace() == authnNamespace,
	) {
		return fmt.Errorf("%w: rule %s has reserved result %s", ErrInvalidCompiledTarget, record.Name, record.Decision)
	}

	if err := validateRuntimeRuleFacts(schema, record); err != nil {
		return fmt.Errorf("%w: rule %s: %v", ErrInvalidCompiledTarget, record.Name, err)
	}

	instances, err := checkpointProviderInstances(checkpoint)
	if err != nil {
		return err
	}

	if _, err := resolveRequiredProviderReferences(record.RequiredProviders, instances); err != nil {
		return fmt.Errorf("%w: rule %s: %v", ErrInvalidCompiledTarget, record.Name, err)
	}

	if !equalCompiledRuleRecords(record, expected) {
		return fmt.Errorf("%w: rule %s does not match exact source projection index %d", ErrInvalidCompiledTarget, record.Name, index)
	}

	return nil
}

// validateRuntimeRuleFacts resolves expression and response-metadata facts through one exact schema.
func validateRuntimeRuleFacts(schema registry.SchemaDefinition, record CompiledRuleRecord) error {
	if err := validateRuntimeRuleExpression(schema, record.Expression); err != nil {
		return err
	}

	for _, factID := range []string{record.ResponseMessage.FactID(), record.ResponseLanguage.FactID()} {
		if factID != "" && !runtimeSchemaContainsFact(schema, factID, decision.ValueKindString) {
			return fmt.Errorf("response fact %s is absent or incompatible", factID)
		}
	}

	return nil
}

// newCompiledRule deeply owns one authenticated exact runtime record.
func newCompiledRule(record CompiledRuleRecord, requiredProviders []string) CompiledRule {
	record.RequiredProviders = append([]string(nil), requiredProviders...)
	record.Effects = append([]registry.EffectUse(nil), record.Effects...)
	record.Advice = append([]registry.EffectUse(nil), record.Advice...)

	return CompiledRule{record: record}
}

// runtimeRuleDecisionAllowed retains authn outcomes only within the authn target and policy-set boundary.
func runtimeRuleDecisionAllowed(effect decision.Effect, authn bool) bool {
	if effect == decision.EffectPermit || effect == decision.EffectDeny {
		return true
	}

	return authn && (effect == decision.EffectIndeterminate || effect == decision.EffectNotApplicable)
}

// runtimeSchemaContainsFact resolves one exact response metadata fact contract.
func runtimeSchemaContainsFact(schema registry.SchemaDefinition, factID string, kind decision.ValueKind) bool {
	for _, fact := range schema.Facts() {
		if fact.ID() == factID && fact.Kind() == kind {
			return true
		}
	}

	return false
}

// expectedRuntimeRuleRecords derives the sole ordered executable source projection.
func expectedRuntimeRuleRecords(
	target decision.Target,
	checkpoint CheckpointRecord,
	policySets map[string]CompiledPolicySet,
) []CompiledRuleRecord {
	result := make([]CompiledRuleRecord, 0)

	for _, setID := range checkpoint.PolicySetIDs {
		set := policySets[setID.String()]
		for _, rule := range set.definition.Rules() {
			if rule.Checkpoint() != checkpoint.Name || !rule.AllowsAction(target.Action()) {
				continue
			}

			result = append(result, ProjectPolicyRule(target, setID, checkpoint.Name, rule))
		}
	}

	return result
}

// equalCompiledRuleRecords compares every executable source-owned field.
func equalCompiledRuleRecords(left CompiledRuleRecord, right CompiledRuleRecord) bool {
	if left.Target.String() != right.Target.String() ||
		left.PolicySetID.String() != right.PolicySetID.String() ||
		left.Name != right.Name || left.Checkpoint != right.Checkpoint ||
		left.PresentationStage != right.PresentationStage || left.Decision != right.Decision {
		return false
	}

	return equalCompiledRuleInputs(left, right) && equalCompiledRuleOutputs(left, right)
}

// equalCompiledRuleInputs compares exact condition, provider, and effect selections.
func equalCompiledRuleInputs(left CompiledRuleRecord, right CompiledRuleRecord) bool {
	return slices.Equal(left.RequiredProviders, right.RequiredProviders) &&
		left.Expression.Equal(right.Expression) &&
		equalEffectUses(left.Effects, right.Effects) &&
		equalEffectUses(left.Advice, right.Advice)
}

// equalCompiledRuleOutputs compares retained decision metadata and control markers.
func equalCompiledRuleOutputs(left CompiledRuleRecord, right CompiledRuleRecord) bool {
	return left.Reason == right.Reason && left.OutcomeMarker == right.OutcomeMarker &&
		left.FSMEventMarker == right.FSMEventMarker && left.ResponseMarker == right.ResponseMarker &&
		left.ResponseMessage.Equal(right.ResponseMessage) && left.ResponseLanguage.Equal(right.ResponseLanguage) &&
		left.SkipRemainingCheckpointProviders == right.SkipRemainingCheckpointProviders
}

// equalEffectUses compares exact ordered selections and typed parameters.
func equalEffectUses(left []registry.EffectUse, right []registry.EffectUse) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if !left[index].Equal(right[index]) {
			return false
		}
	}

	return true
}

// validateRuntimeRuleExpression resolves one predicate through the selected exact schema.
func validateRuntimeRuleExpression(schema registry.SchemaDefinition, expression registry.PolicyExpression) error {
	facts := make(map[string]registry.FactSchema, len(schema.Facts()))
	for _, fact := range schema.Facts() {
		facts[fact.ID()] = fact
	}

	for _, required := range expression.FactContracts() {
		fact, exists := facts[required.ID()]
		if !exists || !decision.ValueKindsCompatible(fact.Kind(), required.Kind()) {
			return fmt.Errorf("fact %s is absent or has an incompatible kind", required.ID())
		}
	}

	return nil
}

// validateCompiledRules resolves every selected effect through the target registry.
func validateCompiledRules(rules []CompiledRule, effects map[string]registry.EffectDefinition) error {
	for _, rule := range rules {
		if err := validateCompiledRuleEffectUses(rule, rule.Effects(), registry.EffectKindObligation, effects); err != nil {
			return err
		}

		if err := validateCompiledRuleEffectUses(rule, rule.Advice(), registry.EffectKindAdvice, effects); err != nil {
			return err
		}
	}

	return nil
}

// validateCompiledRuleEffectUses resolves one exact obligation or advice class.
func validateCompiledRuleEffectUses(
	rule CompiledRule,
	uses []registry.EffectUse,
	wantKind registry.EffectKind,
	effects map[string]registry.EffectDefinition,
) error {
	for _, use := range uses {
		effect, exists := effects[use.ID()]
		if !exists {
			return fmt.Errorf("%w: rule %s references unknown effect %s", ErrInvalidCompiledTarget, rule.Name(), use.ID())
		}

		if effect.Kind() != wantKind {
			return fmt.Errorf("%w: rule %s effect %s has incompatible class", ErrInvalidCompiledTarget, rule.Name(), use.ID())
		}

		if err := effect.ValidateUse(use); err != nil {
			return fmt.Errorf("%w: rule %s effect %s: %v", ErrInvalidCompiledTarget, rule.Name(), use.ID(), err)
		}
	}

	return nil
}

// validateCompiledDefaults enforces target-specific fallback and no-match invariants.
func validateCompiledDefaults(
	target decision.Target,
	record TargetCatalogRecord,
	plan CompiledDomainPlan,
	policySets map[string]CompiledPolicySet,
) error {
	if !record.AuthorityMode.Valid() || (target.Namespace() != authnNamespace && record.AuthorityMode != registry.AuthorityModeEnforce) {
		return fmt.Errorf("%w: target %s has invalid authority mode %s", ErrInvalidCompiledTarget, target.String(), record.AuthorityMode)
	}

	if err := validateCompiledFallback(target, record, plan); err != nil {
		return err
	}

	if record.DefaultPolicySet.IsZero() {
		return nil
	}

	if _, exists := policySets[record.DefaultPolicySet.String()]; !exists {
		return fmt.Errorf("%w: target %s default set %s is unknown", ErrInvalidCompiledTarget, target.String(), record.DefaultPolicySet.String())
	}

	if record.DefaultPolicySet.Namespace() != target.Namespace() {
		return fmt.Errorf("%w: target %s default set %s has a foreign namespace", ErrInvalidCompiledTarget, target.String(), record.DefaultPolicySet.String())
	}

	for _, checkpoint := range plan.Checkpoints() {
		if checkpoint.ContainsPolicySet(record.DefaultPolicySet.String()) {
			return nil
		}
	}

	return fmt.Errorf("%w: target %s default set %s is unbound", ErrInvalidCompiledTarget, target.String(), record.DefaultPolicySet.String())
}

// validateCompiledFallback separates authn standard authority from generic no-match validation.
func validateCompiledFallback(
	target decision.Target,
	record TargetCatalogRecord,
	plan CompiledDomainPlan,
) error {
	if target.Namespace() == authnNamespace {
		if record.NoMatch != registry.NoMatchUnset || record.DefaultPolicySet.String() != registry.BuiltinStandardAuthPolicySet {
			return fmt.Errorf("%w: authn target %s has invalid fallback", ErrInvalidCompiledTarget, target.String())
		}

		return nil
	}

	if !record.NoMatch.ValidGeneric() {
		return fmt.Errorf("%w: generic target %s has invalid no-match", ErrInvalidCompiledTarget, target.String())
	}

	if _, exists := plan.Checkpoint("final_decision"); !exists {
		return fmt.Errorf("%w: generic target %s has no final_decision checkpoint", ErrInvalidCompiledTarget, target.String())
	}

	return nil
}

// compileTargetPolicySets groups exact instantiated rules under catalog-owned definitions.
func compileTargetPolicySets(
	definitions map[string]CompiledPolicySet,
	checkpoints []CheckpointRecord,
	rules []CompiledRule,
) map[string]CompiledPolicySet {
	result := make(map[string]CompiledPolicySet)

	for _, checkpoint := range checkpoints {
		for _, identity := range checkpoint.PolicySetIDs {
			result[identity.String()] = definitions[identity.String()]
		}
	}

	for _, rule := range rules {
		identity := rule.PolicySetID().String()
		set := result[identity]
		set.rules = append(set.rules, rule)
		result[identity] = set
	}

	return result
}

// cloneCompiledCheckpoint returns one detached checkpoint.
func cloneCompiledCheckpoint(checkpoint CompiledCheckpoint) CompiledCheckpoint {
	checkpoint.policySetIDs = checkpoint.PolicySetIDs()
	checkpoint.providerIDs = checkpoint.ProviderIDs()
	checkpoint.providerInstances = checkpoint.ProviderInstances()

	checkpoint.providerInstancesByName = make(map[string]CompiledProviderInstance, len(checkpoint.providerInstances))
	for _, instance := range checkpoint.providerInstances {
		checkpoint.providerInstancesByName[instance.Name()] = instance.clone()
	}

	checkpoint.providerLevels = checkpoint.ProviderLevels()
	checkpoint.productionPolicySetIDs = checkpoint.ProductionPolicySetIDs()
	checkpoint.comparisonPolicySetIDs = checkpoint.ComparisonPolicySetIDs()

	return checkpoint
}

// providerIndex owns target-local provider descriptors.
func providerIndex(values []registry.ProviderDefinition, target decision.Target) (map[string]registry.ProviderDefinition, error) {
	result := make(map[string]registry.ProviderDefinition, len(values))
	for _, value := range values {
		if _, exists := result[value.ID()]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateCompiledProvider, value.ID())
		}

		if !value.AllowsTarget(target) {
			return nil, fmt.Errorf("%w: provider %s does not allow target %s", ErrInvalidCompiledTarget, value.ID(), target.String())
		}

		result[value.ID()] = value
	}

	return result, nil
}

// effectIndex owns collision-free target-local canonical effect descriptors.
func effectIndex(
	values []registry.EffectDefinition,
	target decision.Target,
	providers map[string]registry.ProviderDefinition,
) (map[string]registry.EffectDefinition, error) {
	result := make(map[string]registry.EffectDefinition, len(values))

	for _, value := range values {
		if _, exists := result[value.ID()]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateCompiledEffect, value.ID())
		}

		if err := validateEffectBinding(value, target, providers); err != nil {
			return nil, err
		}

		result[value.ID()] = value
	}

	return result, nil
}

// validateEffectBinding resolves one exact target and internal host owner.
func validateEffectBinding(
	effect registry.EffectDefinition,
	target decision.Target,
	providers map[string]registry.ProviderDefinition,
) error {
	if !effect.AllowsTarget(target) {
		return fmt.Errorf("%w: effect %s does not allow target %s", ErrInvalidCompiledTarget, effect.ID(), target.String())
	}

	if effect.Execution() == registry.ExecutionReturnOnly {
		return nil
	}

	provider, exists := providers[effect.Provider()]
	if !exists || !provider.Supports(target, effect.Execution()) {
		return fmt.Errorf("%w: effect %s has unresolved provider %s", ErrInvalidCompiledTarget, effect.ID(), effect.Provider())
	}

	if effect.Execution() == registry.ExecutionHostPostAction && !provider.HasPostActionAcceptance() {
		return fmt.Errorf("%w: effect %s has no post-action acceptance", ErrInvalidCompiledTarget, effect.ID())
	}

	return nil
}

// newCompiledSchema constructs a private exact-schema index from validated definitions.
func newCompiledSchema(identity registry.SchemaIdentity, facts []registry.FactSchema) CompiledSchema {
	index := make(map[string]registry.FactSchema, len(facts))
	ordered := make([]string, 0, len(facts))

	for _, fact := range facts {
		index[fact.ID()] = fact
		ordered = append(ordered, fact.ID())
	}

	return CompiledSchema{identity: identity, facts: index, ordered: ordered}
}

// validateCompiledFact enforces type, category, source, and declared bounds.
func validateCompiledFact(definition registry.FactSchema, fact decision.Fact) error {
	if fact.Category() != definition.Category() {
		return fmt.Errorf("category %q does not match %q", fact.Category(), definition.Category())
	}

	if fact.Value().Kind() != definition.Kind() {
		return fmt.Errorf("value kind %q does not match %q", fact.Value().Kind(), definition.Kind())
	}

	if !slices.Contains(definition.AllowedSources(), fact.Provenance().Source()) {
		return fmt.Errorf("source %q is not allowed", fact.Provenance().Source())
	}

	return validateCompiledFactBounds(definition, fact.Value())
}

// validateCompiledFactBounds enforces the selected definition's exact size limits.
func validateCompiledFactBounds(definition registry.FactSchema, value decision.Value) error {
	switch definition.Kind() {
	case decision.ValueKindString:
		stringValue, _ := value.StringValue()
		if len(stringValue) > definition.MaxLength() {
			return fmt.Errorf("string exceeds maximum length %d", definition.MaxLength())
		}
	case decision.ValueKindStrings:
		stringsValue, _ := value.Strings()
		if len(stringsValue) > definition.MaxItems() {
			return fmt.Errorf("string list exceeds maximum items %d", definition.MaxItems())
		}

		for _, item := range stringsValue {
			if len(item) > definition.MaxLength() {
				return fmt.Errorf("string list member exceeds maximum length %d", definition.MaxLength())
			}
		}
	case decision.ValueKindBytes:
		bytesValue, _ := value.Bytes()
		if len(bytesValue) > definition.MaxBytes() {
			return fmt.Errorf("bytes exceed maximum size %d", definition.MaxBytes())
		}
	case decision.ValueKindRecords:
		recordSchema, exists := definition.RecordSchema()
		if !exists {
			return fmt.Errorf("records fact has no closed record schema")
		}

		if _, err := normalizeRecordValue(recordSchema, value); err != nil {
			return err
		}
	}

	return nil
}

// schemaFactError binds validation failure to the selected exact schema identity.
func schemaFactError(identity registry.SchemaIdentity, factID string, reason string) error {
	return fmt.Errorf("%w: schema %s fact %s: %s", registry.ErrFactSchemaMismatch, identity.String(), factID, reason)
}
