// Copyright (C) 2026 Christian Roessner
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

package pluginapi

import (
	"context"
	"errors"
	"time"
)

const (
	maximumDecisionDefinitions      = 256
	maximumDecisionEffectParameters = 64

	// MaximumDecisionFactProviderTimeout bounds one host-supervised fact collection call.
	MaximumDecisionFactProviderTimeout = 10 * time.Minute
)

var (
	// ErrInvalidDecisionContract identifies a malformed generic decision extension value.
	ErrInvalidDecisionContract = errors.New("invalid generic decision extension contract")
)

// DecisionFactCategory identifies the policy category of a contributed fact.
type DecisionFactCategory string

const (
	// DecisionFactCategorySubject identifies evaluated-subject facts.
	DecisionFactCategorySubject DecisionFactCategory = "subject"

	// DecisionFactCategoryResource identifies evaluated-resource facts.
	DecisionFactCategoryResource DecisionFactCategory = "resource"

	// DecisionFactCategoryEnvironment identifies environment and additional input facts.
	DecisionFactCategoryEnvironment DecisionFactCategory = "environment"
)

// IsValid reports whether the category belongs to the closed fact vocabulary.
func (c DecisionFactCategory) IsValid() bool {
	return c == DecisionFactCategorySubject ||
		c == DecisionFactCategoryResource ||
		c == DecisionFactCategoryEnvironment
}

// DecisionTargetSelector identifies one exact target namespace and action.
type DecisionTargetSelector struct {
	Namespace string
	Action    string
}

// DecisionFactOutputDescriptor declares one host-qualifiable local fact output.
type DecisionFactOutputDescriptor struct {
	Name      string
	Category  DecisionFactCategory
	Kind      DecisionValueKind
	MaxLength int
	MaxItems  int
	MaxBytes  int
}

// DecisionFactProviderDescriptor declares one target-aware fact provider capability.
type DecisionFactProviderDescriptor struct {
	Targets   []DecisionTargetSelector
	Outputs   []DecisionFactOutputDescriptor
	Namespace string
	Name      string
	Timeout   time.Duration
}

// DecisionEffectExecution identifies one host-owned effect execution boundary.
type DecisionEffectExecution string

const (
	// DecisionEffectExecutionHostSync executes before the decision response is finalized.
	DecisionEffectExecutionHostSync DecisionEffectExecution = "host_sync"

	// DecisionEffectExecutionHostPostAction executes through the host post-action supervisor.
	DecisionEffectExecutionHostPostAction DecisionEffectExecution = "host_post_action"
)

// IsValid reports whether the execution class belongs to the public extension contract.
func (e DecisionEffectExecution) IsValid() bool {
	return e == DecisionEffectExecutionHostSync || e == DecisionEffectExecutionHostPostAction
}

// DecisionEffectParameterDescriptor declares one bounded typed policy-selected parameter.
type DecisionEffectParameterDescriptor struct {
	AllowedStrings []string
	Name           string
	Kind           DecisionValueKind
	MaxLength      int
	MaxItems       int
	MaxBytes       int
	NonEmpty       bool
	Required       bool
}

// DecisionEffectDescriptor declares one policy-selectable host effect.
type DecisionEffectDescriptor struct {
	Targets    []DecisionTargetSelector
	Parameters []DecisionEffectParameterDescriptor
	Name       string
	Execution  DecisionEffectExecution
}

// DecisionEffectProviderDescriptor declares one target-aware effect provider capability.
type DecisionEffectProviderDescriptor struct {
	Effects   []DecisionEffectDescriptor
	Namespace string
	Name      string
}

// DecisionErrorClass identifies one safe result failure category without control semantics.
type DecisionErrorClass string

const (
	// DecisionErrorClassInvalidInput reports rejected provider input or effect parameters.
	DecisionErrorClassInvalidInput DecisionErrorClass = "invalid_input"

	// DecisionErrorClassUnavailable reports an unavailable provider dependency.
	DecisionErrorClassUnavailable DecisionErrorClass = "unavailable"

	// DecisionErrorClassTimeout reports that provider work did not complete in its host budget.
	DecisionErrorClassTimeout DecisionErrorClass = "timeout"

	// DecisionErrorClassInternal reports a provider-local failure safe for host classification.
	DecisionErrorClassInternal DecisionErrorClass = "internal"
)

// IsValid reports whether the class belongs to the closed safe failure vocabulary.
func (c DecisionErrorClass) IsValid() bool {
	return c == DecisionErrorClassInvalidInput ||
		c == DecisionErrorClassUnavailable ||
		c == DecisionErrorClassTimeout ||
		c == DecisionErrorClassInternal
}

// DecisionFactOutput carries one host-qualifiable local fact value.
type DecisionFactOutput struct {
	Name  string
	Value DecisionValue
}

// DecisionFactResult carries emitted facts or one safe failure class.
type DecisionFactResult struct {
	Facts      []DecisionFactOutput
	ErrorClass DecisionErrorClass
}

// DecisionEffectOutcome identifies the observed outcome of one host-invoked effect.
type DecisionEffectOutcome string

const (
	// DecisionEffectOutcomeSucceeded reports a completed effect.
	DecisionEffectOutcomeSucceeded DecisionEffectOutcome = "succeeded"

	// DecisionEffectOutcomeFailed reports a definitely failed effect.
	DecisionEffectOutcomeFailed DecisionEffectOutcome = "failed"

	// DecisionEffectOutcomeUnknown reports that completion could not be established.
	DecisionEffectOutcomeUnknown DecisionEffectOutcome = "outcome_unknown"
)

// IsValid reports whether the outcome belongs to the closed effect result vocabulary.
func (o DecisionEffectOutcome) IsValid() bool {
	return o == DecisionEffectOutcomeSucceeded ||
		o == DecisionEffectOutcomeFailed ||
		o == DecisionEffectOutcomeUnknown
}

// DecisionEffectResult reports only the observed outcome and a safe failure class.
type DecisionEffectResult struct {
	Outcome    DecisionEffectOutcome
	ErrorClass DecisionErrorClass
}

// DecisionRegistrar is an optional additive registrar for generic decision extensions.
type DecisionRegistrar interface {
	RegisterDecisionFactProvider(DecisionFactProvider) error
	RegisterDecisionEffectProvider(DecisionEffectProvider) error
}

// DecisionFactProvider contributes facts without owning decisions or host scheduling.
type DecisionFactProvider interface {
	Descriptor() DecisionFactProviderDescriptor
	Collect(context.Context, DecisionFactRequest) (DecisionFactResult, error)
}

// DecisionEffectProvider executes only effects selected and invoked by the host.
type DecisionEffectProvider interface {
	Descriptor() DecisionEffectProviderDescriptor
	Execute(context.Context, DecisionEffectRequest) (DecisionEffectResult, error)
}
