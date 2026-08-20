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
	"errors"
	"fmt"
	"slices"

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/internal/identifier"
)

const (
	authnDomainNamespace       = "authn"
	schedulerGuardOnMissingRun = "run"
)

var (
	// ErrInvalidDomainPlan identifies an incomplete target orchestration topology.
	ErrInvalidDomainPlan = errors.New("invalid policy domain plan")

	// ErrInvalidNoMatchBehavior identifies a value outside the closed generic fallback set.
	ErrInvalidNoMatchBehavior = errors.New("invalid generic no-match behavior")

	// ErrInvalidAuthorityMode identifies a target authority outside enforce or observe.
	ErrInvalidAuthorityMode = errors.New("invalid policy authority mode")

	// ErrInvalidProviderInstance identifies incomplete checkpoint-local provider metadata.
	ErrInvalidProviderInstance = errors.New("invalid policy provider instance")

	// ErrInvalidSchedulerGuard identifies incomplete plan-local scheduler metadata.
	ErrInvalidSchedulerGuard = errors.New("invalid policy scheduler guard")
)

// AuthorityMode controls configured versus builtin checkpoint authority.
type AuthorityMode string

const (
	// AuthorityModeEnforce permits configured checkpoint rules to own production decisions.
	AuthorityModeEnforce AuthorityMode = "enforce"

	// AuthorityModeObserve keeps builtin authn authority and evaluates configured rules for comparison only.
	AuthorityModeObserve AuthorityMode = "observe"
)

// Valid reports whether the mode belongs to the closed authority contract.
func (m AuthorityMode) Valid() bool {
	return m == AuthorityModeEnforce || m == AuthorityModeObserve
}

// NoMatchBehavior is the closed generic final-checkpoint fallback set.
type NoMatchBehavior string

const (
	// NoMatchUnset marks authn plans and incomplete generic activations.
	NoMatchUnset NoMatchBehavior = ""

	// NoMatchNotApplicable returns a completed non-decision.
	NoMatchNotApplicable NoMatchBehavior = "not_applicable"

	// NoMatchDeny applies a fail-closed generic fallback.
	NoMatchDeny NoMatchBehavior = "deny"
)

// ValidGeneric reports whether the value is one allowed generic fallback.
func (b NoMatchBehavior) ValidGeneric() bool {
	return b == NoMatchNotApplicable || b == NoMatchDeny
}

// ProviderInstanceDefinitionInput carries one source-owned provider binding into its constructor.
type ProviderInstanceDefinitionInput struct {
	Actions             []string
	After               []string
	SkipIf              []string
	Path                string
	Name                string
	Use                 string
	RunIfAuthState      string
	Output              string
	ObserveSafe         bool
	ObserveSafeAuthored bool
}

// ProviderInstanceDefinition is one immutable checkpoint-local provider binding.
type ProviderInstanceDefinition struct {
	actions             []string
	after               []string
	skipIf              []string
	path                string
	name                string
	use                 string
	runIfAuthState      string
	output              string
	observeSafe         bool
	observeSafeAuthored bool
}

// NewProviderInstanceDefinition validates and owns one configured provider instance.
func NewProviderInstanceDefinition(input ProviderInstanceDefinitionInput) (ProviderInstanceDefinition, error) {
	return newProviderInstanceDefinition(input)
}

// newProviderInstanceDefinition validates configured and provider-identity-named instances.
func newProviderInstanceDefinition(input ProviderInstanceDefinitionInput) (ProviderInstanceDefinition, error) {
	if !validProviderInstanceInput(input) {
		return ProviderInstanceDefinition{}, newValidationError(
			ErrInvalidProviderInstance,
			input.Path,
			input.Name,
			"must declare an exact source path, instance name, provider use, and scheduling metadata",
		)
	}

	actions, err := cloneProviderInstanceNames(input.Actions, input.Path+".actions", "action")
	if err != nil {
		return ProviderInstanceDefinition{}, err
	}

	after, err := cloneProviderInstanceNames(input.After, input.Path+".after", "dependency")
	if err != nil {
		return ProviderInstanceDefinition{}, err
	}

	if slices.Contains(after, input.Name) {
		return ProviderInstanceDefinition{}, newValidationError(
			ErrInvalidProviderInstance,
			input.Path+".after",
			input.Name,
			"provider instance cannot depend on itself",
		)
	}

	skipIf, err := cloneProviderInstanceNames(input.SkipIf, input.Path+".skip_if", "scheduler guard")
	if err != nil {
		return ProviderInstanceDefinition{}, err
	}

	return ProviderInstanceDefinition{
		path: input.Path, name: input.Name, use: input.Use,
		actions: actions, after: after, runIfAuthState: input.RunIfAuthState,
		skipIf: skipIf, output: input.Output,
		observeSafe: input.ObserveSafe, observeSafeAuthored: input.ObserveSafeAuthored,
	}, nil
}

// validProviderInstanceInput validates the scalar provider-instance contract.
func validProviderInstanceInput(input ProviderInstanceDefinitionInput) bool {
	validName := identifier.Action(input.Name) || input.Name == input.Use && validProviderID(input.Name)
	validOutput := input.Output == "" || identifier.Fact(input.Output)

	return input.Path != "" && validName && validProviderID(input.Use) &&
		validOutput && validRunIfAuthState(input.RunIfAuthState)
}

// Path returns the configuration-owned provider source path.
func (d ProviderInstanceDefinition) Path() string {
	return d.path
}

// Name returns the exact checkpoint-local instance identity.
func (d ProviderInstanceDefinition) Name() string {
	return d.name
}

// Use returns the qualified provider definition identity.
func (d ProviderInstanceDefinition) Use() string {
	return d.use
}

// Actions returns detached target-action restrictions.
func (d ProviderInstanceDefinition) Actions() []string {
	return append([]string(nil), d.actions...)
}

// After returns detached authored instance dependencies.
func (d ProviderInstanceDefinition) After() []string {
	return append([]string(nil), d.after...)
}

// RunIfAuthState returns the optional authn structural scheduling state.
func (d ProviderInstanceDefinition) RunIfAuthState() string {
	return d.runIfAuthState
}

// SkipIf returns detached plan-local scheduler guard references.
func (d ProviderInstanceDefinition) SkipIf() []string {
	return append([]string(nil), d.skipIf...)
}

// ObserveSafe returns the effective provider observation safety value.
func (d ProviderInstanceDefinition) ObserveSafe() bool {
	return d.observeSafe
}

// ObserveSafeAuthored reports whether observation safety was explicitly configured.
func (d ProviderInstanceDefinition) ObserveSafeAuthored() bool {
	return d.observeSafeAuthored
}

// Output returns the optional canonical fact output identity.
func (d ProviderInstanceDefinition) Output() string {
	return d.output
}

// Equal reports exact immutable provider-instance equality.
func (d ProviderInstanceDefinition) Equal(other ProviderInstanceDefinition) bool {
	return d.path == other.path && d.name == other.name && d.use == other.use &&
		d.runIfAuthState == other.runIfAuthState && d.output == other.output &&
		d.observeSafe == other.observeSafe && d.observeSafeAuthored == other.observeSafeAuthored &&
		slices.Equal(d.actions, other.actions) &&
		slices.Equal(d.after, other.after) && slices.Equal(d.skipIf, other.skipIf)
}

// clone returns one deeply detached provider-instance descriptor.
func (d ProviderInstanceDefinition) clone() ProviderInstanceDefinition {
	d.actions = d.Actions()
	d.after = d.After()
	d.skipIf = d.SkipIf()

	return d
}

// valid reports whether a provider instance still satisfies its constructor invariant.
func (d ProviderInstanceDefinition) valid() bool {
	input := ProviderInstanceDefinitionInput{
		Path: d.path, Name: d.name, Use: d.use, Actions: d.actions, After: d.after,
		RunIfAuthState: d.runIfAuthState, SkipIf: d.skipIf, Output: d.output,
		ObserveSafe: d.observeSafe, ObserveSafeAuthored: d.observeSafeAuthored,
	}

	_, err := newProviderInstanceDefinition(input)

	return err == nil
}

// SchedulerGuardDefinitionInput carries one plan-local scheduling predicate into its constructor.
type SchedulerGuardDefinitionInput struct {
	Expression         PolicyExpression
	Path               string
	Name               string
	OnMissingAttribute string
}

// SchedulerGuardDefinition is one immutable plan-local scheduling predicate.
type SchedulerGuardDefinition struct {
	expression         PolicyExpression
	path               string
	name               string
	onMissingAttribute string
}

// NewSchedulerGuardDefinition validates and owns one scheduler guard.
func NewSchedulerGuardDefinition(input SchedulerGuardDefinitionInput) (SchedulerGuardDefinition, error) {
	onMissingAttribute := input.OnMissingAttribute
	if onMissingAttribute == "" {
		onMissingAttribute = schedulerGuardOnMissingRun
	}

	if input.Path == "" || !identifier.Action(input.Name) || !input.Expression.Valid() ||
		onMissingAttribute != schedulerGuardOnMissingRun {
		return SchedulerGuardDefinition{}, newValidationError(
			ErrInvalidSchedulerGuard,
			input.Path,
			input.Name,
			"must declare an exact source path, local name, condition, and optional run-on-missing behavior",
		)
	}

	return SchedulerGuardDefinition{
		expression: input.Expression.clone(), path: input.Path,
		name: input.Name, onMissingAttribute: onMissingAttribute,
	}, nil
}

// Path returns the configuration-owned guard source path.
func (d SchedulerGuardDefinition) Path() string {
	return d.path
}

// Name returns the exact plan-local guard identity.
func (d SchedulerGuardDefinition) Name() string {
	return d.name
}

// Expression returns the detached immutable scheduling predicate.
func (d SchedulerGuardDefinition) Expression() PolicyExpression {
	return d.expression.clone()
}

// OnMissingAttribute returns the exact optional missing-fact behavior.
func (d SchedulerGuardDefinition) OnMissingAttribute() string {
	return d.onMissingAttribute
}

// Equal reports exact immutable scheduler-guard equality.
func (d SchedulerGuardDefinition) Equal(other SchedulerGuardDefinition) bool {
	return d.path == other.path && d.name == other.name &&
		d.onMissingAttribute == other.onMissingAttribute && d.expression.Equal(other.expression)
}

// clone returns one deeply detached scheduler-guard descriptor.
func (d SchedulerGuardDefinition) clone() SchedulerGuardDefinition {
	d.expression = d.Expression()

	return d
}

// valid reports whether a scheduler guard still satisfies its constructor invariant.
func (d SchedulerGuardDefinition) valid() bool {
	_, err := NewSchedulerGuardDefinition(SchedulerGuardDefinitionInput{
		Expression: d.expression, Path: d.path, Name: d.name, OnMissingAttribute: d.onMissingAttribute,
	})

	return err == nil
}

// CheckpointDefinition is one immutable target-local execution checkpoint.
type CheckpointDefinition struct {
	policySets        []PolicySetImport
	providerInstances []ProviderInstanceDefinition
	name              string
}

// NewCheckpointDefinition constructs one exact checkpoint binding.
func NewCheckpointDefinition(
	name string,
	policySets []PolicySetImport,
	providers []string,
) (CheckpointDefinition, error) {
	clonedProviders, err := cloneUniqueProviderIDs(providers, "domain_plan.checkpoints."+name+".providers")
	if err != nil {
		return CheckpointDefinition{}, err
	}

	instances := make([]ProviderInstanceDefinition, 0, len(clonedProviders))
	for index, providerID := range clonedProviders {
		path := fmt.Sprintf("domain_plan.checkpoints.%s.providers[%d]", name, index)

		instance, instanceErr := newProviderInstanceDefinition(ProviderInstanceDefinitionInput{
			Path: path, Name: providerID, Use: providerID,
		})
		if instanceErr != nil {
			return CheckpointDefinition{}, instanceErr
		}

		instances = append(instances, instance)
	}

	return NewCheckpointDefinitionWithProviderInstances(name, policySets, instances)
}

// NewCheckpointDefinitionWithProviderInstances constructs one exact instance-aware checkpoint binding.
func NewCheckpointDefinitionWithProviderInstances(
	name string,
	policySets []PolicySetImport,
	instances []ProviderInstanceDefinition,
) (CheckpointDefinition, error) {
	if !validCheckpoint(name) || len(policySets)+len(instances) > maximumPolicySetEntries {
		return CheckpointDefinition{}, newValidationError(
			ErrInvalidCheckpoint,
			"domain_plan.checkpoints",
			name,
			"must be exact, bounded, and contain bounded references",
		)
	}

	clonedInstances, err := cloneProviderInstances(name, instances)
	if err != nil {
		return CheckpointDefinition{}, err
	}

	sets := clonePolicySetImports(policySets)
	seen := make(map[string]struct{}, len(sets))

	for _, set := range sets {
		if set.Checkpoint() != name {
			return CheckpointDefinition{}, newValidationError(
				ErrInvalidCheckpoint,
				set.Path(),
				set.Set().String(),
				"set binding checkpoint does not match its containing checkpoint",
			)
		}

		if _, exists := seen[set.Set().String()]; exists {
			return CheckpointDefinition{}, newValidationError(
				ErrDuplicateDefinition,
				"domain_plan.checkpoints."+name+".policy_sets",
				set.Set().String(),
				"set binding occurs more than once",
			)
		}

		seen[set.Set().String()] = struct{}{}
	}

	return CheckpointDefinition{name: name, policySets: sets, providerInstances: clonedInstances}, nil
}

// Name returns the exact target-local checkpoint identity.
func (d CheckpointDefinition) Name() string {
	return d.name
}

// PolicySets returns detached exact set bindings.
func (d CheckpointDefinition) PolicySets() []PolicySetImport {
	return clonePolicySetImports(d.policySets)
}

// Providers returns detached exact provider bindings.
func (d CheckpointDefinition) Providers() []string {
	result := make([]string, 0, len(d.providerInstances))
	for _, instance := range d.providerInstances {
		result = append(result, instance.Use())
	}

	return result
}

// ProviderInstances returns detached exact checkpoint-local bindings.
func (d CheckpointDefinition) ProviderInstances() []ProviderInstanceDefinition {
	result := make([]ProviderInstanceDefinition, 0, len(d.providerInstances))
	for _, instance := range d.providerInstances {
		result = append(result, instance.clone())
	}

	return result
}

// clone returns one deeply detached checkpoint descriptor.
func (d CheckpointDefinition) clone() CheckpointDefinition {
	d.policySets = d.PolicySets()
	d.providerInstances = d.ProviderInstances()

	return d
}

// DomainPlanDefinition is one exact target orchestration topology.
type DomainPlanDefinition struct {
	checkpoints     []CheckpointDefinition
	schedulerGuards []SchedulerGuardDefinition
	target          decision.Target
	builtinAuth     bool
}

// NewDomainPlanDefinition constructs one target-owned checkpoint plan.
func NewDomainPlanDefinition(
	target decision.Target,
	checkpoints []CheckpointDefinition,
) (DomainPlanDefinition, error) {
	return NewDomainPlanDefinitionWithSchedulerGuards(target, checkpoints, nil)
}

// NewDomainPlanDefinitionWithSchedulerGuards constructs one target-owned checkpoint plan and its guards.
func NewDomainPlanDefinitionWithSchedulerGuards(
	target decision.Target,
	checkpoints []CheckpointDefinition,
	guards []SchedulerGuardDefinition,
) (DomainPlanDefinition, error) {
	validatedTarget, err := decision.NewTarget(target.Namespace(), target.Action())
	if err != nil || len(checkpoints) == 0 || len(checkpoints) > maximumPolicySetEntries {
		return DomainPlanDefinition{}, newValidationError(
			ErrInvalidDomainPlan,
			"domain_plan",
			target.String(),
			"must declare an exact target and bounded non-empty checkpoints",
		)
	}

	cloned := make([]CheckpointDefinition, 0, len(checkpoints))
	seen := make(map[string]struct{}, len(checkpoints))

	for _, checkpoint := range checkpoints {
		if err := validateDomainPlanCheckpoint(validatedTarget, checkpoint, seen); err != nil {
			return DomainPlanDefinition{}, err
		}

		seen[checkpoint.Name()] = struct{}{}
		cloned = append(cloned, checkpoint.clone())
	}

	clonedGuards, err := cloneSchedulerGuards(validatedTarget, guards)
	if err != nil {
		return DomainPlanDefinition{}, err
	}

	if err := validateCheckpointSchedulerGuards(validatedTarget, cloned, clonedGuards); err != nil {
		return DomainPlanDefinition{}, err
	}

	return DomainPlanDefinition{target: validatedTarget, checkpoints: cloned, schedulerGuards: clonedGuards}, nil
}

// validateDomainPlanCheckpoint validates one checkpoint against its containing target and siblings.
func validateDomainPlanCheckpoint(
	target decision.Target,
	checkpoint CheckpointDefinition,
	seen map[string]struct{},
) error {
	if !validCheckpoint(checkpoint.Name()) {
		return newValidationError(ErrInvalidCheckpoint, target.String()+".checkpoints", checkpoint.Name(), "must be constructor validated")
	}

	if target.Namespace() != authnDomainNamespace && authnCheckpoint(checkpoint.Name()) {
		return newValidationError(
			ErrInvalidCheckpoint,
			target.String()+".checkpoints",
			checkpoint.Name(),
			"authn checkpoints are restricted to authn targets",
		)
	}

	if _, exists := seen[checkpoint.Name()]; exists {
		return newValidationError(ErrDuplicateDefinition, target.String()+".checkpoints", checkpoint.Name(), "checkpoint occurs more than once")
	}

	for _, binding := range checkpoint.PolicySets() {
		if binding.Target().String() != target.String() {
			return newValidationError(
				ErrInvalidDomainPlan,
				binding.Path(),
				binding.Set().String(),
				"set binding target does not match its containing domain plan",
			)
		}
	}

	return validateCheckpointProviderInstances(target, checkpoint)
}

// NewAuthnDomainPlanDefinition constructs a trusted exact authn plan that retains builtin fallback provenance.
func NewAuthnDomainPlanDefinition(
	target decision.Target,
	checkpoints []CheckpointDefinition,
) (DomainPlanDefinition, error) {
	return NewAuthnDomainPlanDefinitionWithSchedulerGuards(target, checkpoints, nil)
}

// NewAuthnDomainPlanDefinitionWithSchedulerGuards constructs a trusted authn plan and its guards.
func NewAuthnDomainPlanDefinitionWithSchedulerGuards(
	target decision.Target,
	checkpoints []CheckpointDefinition,
	guards []SchedulerGuardDefinition,
) (DomainPlanDefinition, error) {
	if !validAuthnDomainTarget(target) {
		return DomainPlanDefinition{}, newValidationError(
			ErrInvalidDomainPlan,
			"domain_plan",
			target.String(),
			"must select one exact builtin authn target",
		)
	}

	for _, checkpoint := range checkpoints {
		if !authnCheckpoint(checkpoint.Name()) {
			return DomainPlanDefinition{}, newValidationError(
				ErrInvalidCheckpoint,
				target.String()+".checkpoints",
				checkpoint.Name(),
				"trusted authn plans contain only exact authn checkpoints",
			)
		}
	}

	plan, err := NewDomainPlanDefinitionWithSchedulerGuards(target, checkpoints, guards)
	if err != nil {
		return DomainPlanDefinition{}, err
	}

	plan.builtinAuth = true

	return plan, nil
}

// validAuthnDomainTarget restricts trusted plan provenance to the immutable authentication action vocabulary.
func validAuthnDomainTarget(target decision.Target) bool {
	if target.Namespace() != authnDomainNamespace {
		return false
	}

	switch policy.Operation(target.Action()) {
	case policy.OperationAuthenticate, policy.OperationLookupIdentity, policy.OperationListAccounts:
		return true
	default:
		return false
	}
}

// authnCheckpoint reports whether a checkpoint belongs to immutable authentication orchestration.
func authnCheckpoint(name string) bool {
	switch policy.Stage(name) {
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

// Target returns the exact planned target.
func (d DomainPlanDefinition) Target() decision.Target {
	return d.target
}

// Checkpoints returns detached ordered checkpoint descriptors.
func (d DomainPlanDefinition) Checkpoints() []CheckpointDefinition {
	result := make([]CheckpointDefinition, 0, len(d.checkpoints))
	for _, checkpoint := range d.checkpoints {
		result = append(result, checkpoint.clone())
	}

	return result
}

// SchedulerGuards returns detached ordered plan-local scheduling predicates.
func (d DomainPlanDefinition) SchedulerGuards() []SchedulerGuardDefinition {
	result := make([]SchedulerGuardDefinition, 0, len(d.schedulerGuards))
	for _, guard := range d.schedulerGuards {
		result = append(result, guard.clone())
	}

	return result
}

// IsBuiltinAuth reports immutable builtin provenance for authn orchestration topology.
func (d DomainPlanDefinition) IsBuiltinAuth() bool {
	return d.builtinAuth
}

// clone returns one deeply detached domain plan.
func (d DomainPlanDefinition) clone() DomainPlanDefinition {
	d.checkpoints = d.Checkpoints()
	d.schedulerGuards = d.SchedulerGuards()

	return d
}

// valid reports whether a plan satisfies its constructor invariant.
func (d DomainPlanDefinition) valid() bool {
	_, err := decision.NewTarget(d.target.Namespace(), d.target.Action())

	if err != nil || len(d.checkpoints) == 0 {
		return false
	}

	for _, checkpoint := range d.checkpoints {
		if !validCheckpoint(checkpoint.Name()) {
			return false
		}
	}

	for _, guard := range d.schedulerGuards {
		if !guard.valid() {
			return false
		}
	}

	return true
}

// parseNoMatch preserves invalid configured text for compiler path-specific rejection.
func parseNoMatch(value string) NoMatchBehavior {
	return NoMatchBehavior(value)
}

// validProviderID reports whether one exact provider reference is canonical.
func validProviderID(value string) bool {
	return identifier.ProviderIdentity(value)
}

// validRunIfAuthState recognizes the closed optional authentication-state vocabulary.
func validRunIfAuthState(value string) bool {
	return value == "" || value == policy.RunIfAny ||
		value == policy.RunIfAuthenticated || value == policy.RunIfUnauthenticated
}

// cloneProviderInstanceNames validates bounded canonical local-name lists.
func cloneProviderInstanceNames(values []string, path string, noun string) ([]string, error) {
	return cloneValidatedUniqueStrings(
		values,
		path,
		identifier.Action,
		ErrInvalidProviderInstance,
		"must contain exact local "+noun+" names",
		noun+" occurs more than once",
	)
}

// cloneProviderInstances owns provider metadata and validates checkpoint-local names and edges.
func cloneProviderInstances(name string, values []ProviderInstanceDefinition) ([]ProviderInstanceDefinition, error) {
	result := make([]ProviderInstanceDefinition, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		if !value.valid() {
			return nil, newValidationError(
				ErrInvalidProviderInstance,
				"domain_plan.checkpoints."+name+".providers",
				value.Name(),
				"must be constructor validated",
			)
		}

		if _, exists := seen[value.Name()]; exists {
			return nil, newValidationError(
				ErrDuplicateDefinition,
				"domain_plan.checkpoints."+name+".providers",
				value.Name(),
				"provider instance name occurs more than once",
			)
		}

		seen[value.Name()] = struct{}{}
		result = append(result, value.clone())
	}

	for _, value := range result {
		for _, dependency := range value.After() {
			if _, exists := seen[dependency]; !exists {
				return nil, newValidationError(
					ErrInvalidProviderInstance,
					value.Path()+".after",
					dependency,
					"references an unknown checkpoint-local provider instance",
				)
			}
		}
	}

	return result, nil
}

// validateCheckpointProviderInstances enforces target-aware scheduling metadata.
func validateCheckpointProviderInstances(target decision.Target, checkpoint CheckpointDefinition) error {
	for _, instance := range checkpoint.ProviderInstances() {
		if len(instance.Actions()) > 0 && !slices.Contains(instance.Actions(), target.Action()) {
			return newValidationError(
				ErrInvalidProviderInstance,
				instance.Path()+".actions",
				target.Action(),
				"must include the containing target action",
			)
		}

		if target.Namespace() != authnDomainNamespace && instance.RunIfAuthState() != "" {
			return newValidationError(
				ErrInvalidProviderInstance,
				instance.Path()+".run_if.auth_state",
				instance.RunIfAuthState(),
				"is restricted to authn domain plans",
			)
		}
	}

	return nil
}

// cloneSchedulerGuards owns exact plan-local guard names.
func cloneSchedulerGuards(target decision.Target, values []SchedulerGuardDefinition) ([]SchedulerGuardDefinition, error) {
	if len(values) > maximumPolicySetEntries {
		return nil, newValidationError(
			ErrInvalidSchedulerGuard,
			target.String()+".scheduler_guards",
			target.String(),
			"contains too many scheduler guards",
		)
	}

	result := make([]SchedulerGuardDefinition, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		if !value.valid() {
			return nil, newValidationError(ErrInvalidSchedulerGuard, target.String()+".scheduler_guards", value.Name(), "must be constructor validated")
		}

		if _, exists := seen[value.Name()]; exists {
			return nil, newValidationError(ErrDuplicateDefinition, target.String()+".scheduler_guards", value.Name(), "scheduler guard occurs more than once")
		}

		seen[value.Name()] = struct{}{}
		result = append(result, value.clone())
	}

	return result, nil
}

// validateCheckpointSchedulerGuards resolves every provider skip guard inside one plan.
func validateCheckpointSchedulerGuards(
	target decision.Target,
	checkpoints []CheckpointDefinition,
	guards []SchedulerGuardDefinition,
) error {
	known := make(map[string]struct{}, len(guards))
	for _, guard := range guards {
		known[guard.Name()] = struct{}{}
	}

	for _, checkpoint := range checkpoints {
		for _, instance := range checkpoint.ProviderInstances() {
			for _, guard := range instance.SkipIf() {
				if _, exists := known[guard]; !exists {
					return newValidationError(
						ErrInvalidSchedulerGuard,
						instance.Path()+".skip_if",
						guard,
						"references an unknown scheduler guard in "+target.String(),
					)
				}
			}
		}
	}

	return nil
}
