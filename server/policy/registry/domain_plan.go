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

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/internal/identifier"
)

const authnDomainNamespace = "authn"

var (
	// ErrInvalidDomainPlan identifies an incomplete target orchestration topology.
	ErrInvalidDomainPlan = errors.New("invalid policy domain plan")

	// ErrInvalidNoMatchBehavior identifies a value outside the closed generic fallback set.
	ErrInvalidNoMatchBehavior = errors.New("invalid generic no-match behavior")

	// ErrInvalidAuthorityMode identifies a target authority outside enforce or observe.
	ErrInvalidAuthorityMode = errors.New("invalid policy authority mode")
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

// CheckpointDefinition is one immutable target-local execution checkpoint.
type CheckpointDefinition struct {
	name       string
	policySets []PolicySetImport
	providers  []string
}

// NewCheckpointDefinition constructs one exact checkpoint binding.
func NewCheckpointDefinition(
	name string,
	policySets []PolicySetImport,
	providers []string,
) (CheckpointDefinition, error) {
	if !validCheckpoint(name) || len(policySets)+len(providers) > maximumPolicySetEntries {
		return CheckpointDefinition{}, newValidationError(
			ErrInvalidCheckpoint,
			"domain_plan.checkpoints",
			name,
			"must be exact, bounded, and contain bounded references",
		)
	}

	clonedProviders, err := cloneUniqueQualifiedIDs(providers, "domain_plan.checkpoints."+name+".providers")
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

	return CheckpointDefinition{name: name, policySets: sets, providers: clonedProviders}, nil
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
	return append([]string(nil), d.providers...)
}

// clone returns one deeply detached checkpoint descriptor.
func (d CheckpointDefinition) clone() CheckpointDefinition {
	d.policySets = d.PolicySets()
	d.providers = d.Providers()

	return d
}

// DomainPlanDefinition is one exact target orchestration topology.
type DomainPlanDefinition struct {
	target      decision.Target
	checkpoints []CheckpointDefinition
	builtinAuth bool
}

// NewDomainPlanDefinition constructs one target-owned checkpoint plan.
func NewDomainPlanDefinition(
	target decision.Target,
	checkpoints []CheckpointDefinition,
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
		if !validCheckpoint(checkpoint.Name()) {
			return DomainPlanDefinition{}, newValidationError(ErrInvalidCheckpoint, target.String()+".checkpoints", checkpoint.Name(), "must be constructor validated")
		}

		if validatedTarget.Namespace() != authnDomainNamespace && authnCheckpoint(checkpoint.Name()) {
			return DomainPlanDefinition{}, newValidationError(
				ErrInvalidCheckpoint,
				validatedTarget.String()+".checkpoints",
				checkpoint.Name(),
				"authn checkpoints are restricted to authn targets",
			)
		}

		if _, exists := seen[checkpoint.Name()]; exists {
			return DomainPlanDefinition{}, newValidationError(ErrDuplicateDefinition, target.String()+".checkpoints", checkpoint.Name(), "checkpoint occurs more than once")
		}

		for _, binding := range checkpoint.PolicySets() {
			if binding.Target().String() != validatedTarget.String() {
				return DomainPlanDefinition{}, newValidationError(
					ErrInvalidDomainPlan,
					binding.Path(),
					binding.Set().String(),
					"set binding target does not match its containing domain plan",
				)
			}
		}

		seen[checkpoint.Name()] = struct{}{}
		cloned = append(cloned, checkpoint.clone())
	}

	return DomainPlanDefinition{target: validatedTarget, checkpoints: cloned}, nil
}

// authnCheckpoint reports whether a checkpoint belongs to immutable authentication orchestration.
func authnCheckpoint(name string) bool {
	return name == string(policy.StagePreAuth) || name == string(policy.StageAuthDecision)
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

// IsBuiltinAuth reports immutable builtin provenance for authn orchestration topology.
func (d DomainPlanDefinition) IsBuiltinAuth() bool {
	return d.builtinAuth
}

// clone returns one deeply detached domain plan.
func (d DomainPlanDefinition) clone() DomainPlanDefinition {
	d.checkpoints = d.Checkpoints()

	return d
}

// valid reports whether a plan satisfies its constructor invariant.
func (d DomainPlanDefinition) valid() bool {
	_, err := decision.NewTarget(d.target.Namespace(), d.target.Action())

	return err == nil && len(d.checkpoints) > 0
}

// parseNoMatch preserves invalid configured text for compiler path-specific rejection.
func parseNoMatch(value string) NoMatchBehavior {
	return NoMatchBehavior(value)
}

// validProviderID reports whether one exact provider reference is qualified.
func validProviderID(value string) bool {
	return identifier.Qualified(value)
}
