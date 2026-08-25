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

// Package policyprovider defines the value-only generic Lua policy-provider
// boundary. Callback execution and generation activation remain host-owned.
// Execution adapters must validate and deeply copy exported request values
// before translating them into deterministic Lua tables.
package policyprovider

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

const (
	maximumDescriptorDefinitions = 256
	maximumEffectParameters      = 64
	maximumProviderTimeout       = 10 * time.Minute

	// PolicyFactsCollectCallback is the stable generic Lua fact callback name.
	PolicyFactsCollectCallback = "policy.facts.collect"
)

var (
	// ErrInvalidDescriptor identifies malformed generic Lua capability metadata.
	ErrInvalidDescriptor = errors.New("invalid Lua policy provider descriptor")

	// ErrInvalidResult identifies malformed generic Lua callback output.
	ErrInvalidResult = errors.New("invalid Lua policy provider result")
)

// TargetSelector identifies one exact catalog capability without activating it.
type TargetSelector struct {
	Namespace string
	Action    string
}

// CallerView contains detached, redacted caller identity evidence.
type CallerView struct {
	Scopes             []string
	Principal          string
	ClientID           string
	AuthenticationKind string
}

// FactView exposes one detached trusted fact without writable provenance.
type FactView struct {
	ID       string
	Value    decision.Value
	Category decision.FactCategory
}

// FactRequest is the generic input for one bounded fact collection callback.
type FactRequest struct {
	Facts  []FactView
	Target TargetSelector
	Caller CallerView
}

// FactOutputDescriptor declares one local fact name and its strict value shape.
type FactOutputDescriptor struct {
	Name      string
	Category  decision.FactCategory
	Kind      decision.ValueKind
	MaxLength int
	MaxItems  int
	MaxBytes  int
}

// FactProviderDescriptor declares one target-aware Lua fact capability.
type FactProviderDescriptor struct {
	Targets   []TargetSelector
	Outputs   []FactOutputDescriptor
	Namespace string
	Name      string
	Timeout   time.Duration
}

// FactValue returns one declared local fact value; the host assigns authority.
type FactValue struct {
	Name  string
	Value decision.Value
}

// ErrorClass identifies one secret-safe provider failure category.
type ErrorClass string

const (
	// ErrorClassInvalidInput reports rejected provider input or selected parameters.
	ErrorClassInvalidInput ErrorClass = "invalid_input"

	// ErrorClassUnavailable reports an unavailable provider dependency.
	ErrorClassUnavailable ErrorClass = "unavailable"

	// ErrorClassTimeout reports work that exceeded the host-provided deadline.
	ErrorClassTimeout ErrorClass = "timeout"

	// ErrorClassInternal reports one provider-local failure.
	ErrorClassInternal ErrorClass = "internal"
)

// IsValid reports whether the class belongs to the closed failure vocabulary.
func (c ErrorClass) IsValid() bool {
	return c == ErrorClassInvalidInput || c == ErrorClassUnavailable ||
		c == ErrorClassTimeout || c == ErrorClassInternal
}

// FactResult contains either detached declared facts or one secret-safe error class.
type FactResult struct {
	Facts      []FactValue
	ErrorClass ErrorClass
}

// FactCollector supplies generic Lua facts within the caller's context deadline.
type FactCollector interface {
	Descriptor() FactProviderDescriptor
	Collect(context.Context, FactRequest) (FactResult, error)
}

// EffectExecution identifies the only extension-executable effect ownership classes.
type EffectExecution string

const (
	// EffectExecutionHostSync executes a policy-selected effect before response finalization.
	EffectExecutionHostSync EffectExecution = "host_sync"

	// EffectExecutionHostPostAction prepares policy-selected work for the host supervisor.
	EffectExecutionHostPostAction EffectExecution = "host_post_action"
)

// ParameterDescriptor declares one bounded typed effect parameter.
type ParameterDescriptor struct {
	AllowedStrings []string
	Name           string
	Kind           decision.ValueKind
	MaxLength      int
	MaxItems       int
	MaxBytes       int
	NonEmpty       bool
	Required       bool
}

// EffectDescriptor declares one policy-selectable effect capability.
type EffectDescriptor struct {
	Targets    []TargetSelector
	Parameters []ParameterDescriptor
	Name       string
	Execution  EffectExecution
}

// EffectProviderDescriptor groups selected effects under one contributed provider.
type EffectProviderDescriptor struct {
	Effects   []EffectDescriptor
	Namespace string
	Name      string
}

// EffectParameter carries one selected strict parameter value.
type EffectParameter struct {
	Name  string
	Value decision.Value
}

// EffectRequest contains one policy-selected effect and detached evaluation views.
type EffectRequest struct {
	Facts      []FactView
	Parameters []EffectParameter
	Target     TargetSelector
	Caller     CallerView
	Effect     string
}

// EffectState is the closed callback outcome vocabulary.
type EffectState string

const (
	// EffectStateSucceeded reports that the selected effect completed.
	EffectStateSucceeded EffectState = "succeeded"

	// EffectStateFailed reports a known failed effect outcome.
	EffectStateFailed EffectState = "failed"

	// EffectStateOutcomeUnknown reports that completion could not be established.
	EffectStateOutcomeUnknown EffectState = "outcome_unknown"
)

// EffectResult returns a bounded outcome without response or scheduling controls.
type EffectResult struct {
	State      EffectState
	ErrorClass ErrorClass
}

// EffectExecutor handles only effects already selected by policy.
type EffectExecutor interface {
	Descriptor() EffectProviderDescriptor
	Execute(context.Context, EffectRequest) (EffectResult, error)
}

// Validate enforces exact identity, target, output, and timeout bounds.
func (d FactProviderDescriptor) Validate() error {
	if err := validateProviderIdentity(d.Namespace, d.Name, "fact provider"); err != nil {
		return err
	}

	if d.Timeout <= 0 || d.Timeout > maximumProviderTimeout {
		return invalidDescriptor("fact provider timeout must be positive and at most ten minutes")
	}

	if err := validateTargets(d.Targets, "fact provider"); err != nil {
		return err
	}

	if len(d.Outputs) == 0 || len(d.Outputs) > maximumDescriptorDefinitions {
		return invalidDescriptor("fact provider must declare a bounded non-empty output set")
	}

	seen := make(map[string]struct{}, len(d.Outputs))
	for _, output := range d.Outputs {
		if err := validateFactOutput(output); err != nil {
			return err
		}

		if _, exists := seen[output.Name]; exists {
			return invalidDescriptor("fact output %q occurs more than once", output.Name)
		}

		seen[output.Name] = struct{}{}
	}

	return nil
}

// ValidateResult rejects undeclared, duplicate, wrongly typed, or mixed fact results.
func (d FactProviderDescriptor) ValidateResult(result FactResult) error {
	if err := d.Validate(); err != nil {
		return err
	}

	if result.ErrorClass != "" {
		if len(result.Facts) != 0 {
			return invalidResult("fact result cannot contain facts and an error class")
		}

		if !result.ErrorClass.IsValid() {
			return invalidResult("fact result error class %q is not registered", result.ErrorClass)
		}

		return nil
	}

	if len(result.Facts) > len(d.Outputs) {
		return invalidResult("fact result contains more values than declared outputs")
	}

	declared := make(map[string]FactOutputDescriptor, len(d.Outputs))
	for _, output := range d.Outputs {
		declared[output.Name] = output
	}

	seen := make(map[string]struct{}, len(result.Facts))
	for _, fact := range result.Facts {
		output, exists := declared[fact.Name]
		if !exists {
			return invalidResult("fact %q is not a declared local output", fact.Name)
		}

		if _, duplicate := seen[fact.Name]; duplicate {
			return invalidResult("fact %q occurs more than once", fact.Name)
		}

		if err := validateFactValue(output, fact.Value); err != nil {
			return err
		}

		seen[fact.Name] = struct{}{}
	}

	return nil
}

// Validate enforces exact provider, selected-effect, target, and parameter metadata.
func (d EffectProviderDescriptor) Validate() error {
	if err := validateProviderIdentity(d.Namespace, d.Name, "effect provider"); err != nil {
		return err
	}

	if len(d.Effects) == 0 || len(d.Effects) > maximumDescriptorDefinitions {
		return invalidDescriptor("effect provider must declare a bounded non-empty effect set")
	}

	seen := make(map[string]struct{}, len(d.Effects))
	for _, effect := range d.Effects {
		if err := validateEffect(effect); err != nil {
			return err
		}

		if _, exists := seen[effect.Name]; exists {
			return invalidDescriptor("effect %q occurs more than once", effect.Name)
		}

		seen[effect.Name] = struct{}{}
	}

	return nil
}

// Validate enforces the closed outcome/error-class pairing.
func (r EffectResult) Validate() error {
	switch r.State {
	case EffectStateSucceeded:
		if r.ErrorClass != "" {
			return invalidResult("successful effect result cannot contain an error class")
		}
	case EffectStateFailed, EffectStateOutcomeUnknown:
		if !r.ErrorClass.IsValid() {
			return invalidResult("failed or unknown effect result requires a registered error class")
		}
	default:
		return invalidResult("effect state %q is not registered", r.State)
	}

	return nil
}

// validateProviderIdentity enforces exact contributed namespace and local-name grammar.
func validateProviderIdentity(namespace string, name string, kind string) error {
	if _, err := decision.NewTarget(namespace, name); err != nil {
		return invalidDescriptor("%s identity %q/%q is not canonical", kind, namespace, name)
	}

	return nil
}

// validateTargets enforces a bounded non-empty exact selector set.
func validateTargets(targets []TargetSelector, kind string) error {
	if len(targets) == 0 || len(targets) > maximumDescriptorDefinitions {
		return invalidDescriptor("%s must declare a bounded non-empty target set", kind)
	}

	seen := make(map[string]struct{}, len(targets))
	for _, selector := range targets {
		target, err := decision.NewTarget(selector.Namespace, selector.Action)
		if err != nil {
			return invalidDescriptor("%s target %q/%q is not canonical", kind, selector.Namespace, selector.Action)
		}

		if _, exists := seen[target.String()]; exists {
			return invalidDescriptor("%s target %q occurs more than once", kind, target.String())
		}

		seen[target.String()] = struct{}{}
	}

	return nil
}

// validateFactOutput reuses the internal schema constructor for strict kind bounds.
func validateFactOutput(output FactOutputDescriptor) error {
	if strings.HasPrefix(output.Name, "lua.") || strings.HasPrefix(output.Name, "plugin.") {
		return invalidDescriptor("fact output %q must be a local name without an authority prefix", output.Name)
	}

	_, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID:             "lua.provider." + output.Name,
		AllowedSources: []decision.FactSource{decision.FactSourceLua},
		Category:       output.Category,
		Kind:           output.Kind,
		MaxLength:      output.MaxLength,
		MaxItems:       output.MaxItems,
		MaxBytes:       output.MaxBytes,
	})
	if err != nil {
		return invalidDescriptor("fact output %q has an invalid category, kind, or bounds: %v", output.Name, err)
	}

	return nil
}

// validateFactValue checks one constructed strict value against its declaration.
func validateFactValue(output FactOutputDescriptor, value decision.Value) error {
	if value.Kind() != output.Kind {
		return invalidResult("fact %q has kind %q, want %q", output.Name, value.Kind(), output.Kind)
	}

	if _, ok := value.Any(); !ok {
		return invalidResult("fact %q is not a constructed strict value", output.Name)
	}

	switch output.Kind {
	case decision.ValueKindString:
		text, _ := value.StringValue()
		if len(text) > output.MaxLength {
			return invalidResult("fact %q exceeds maximum string length", output.Name)
		}
	case decision.ValueKindStrings:
		values, _ := value.Strings()
		if len(values) > output.MaxItems || slices.ContainsFunc(values, func(text string) bool { return len(text) > output.MaxLength }) {
			return invalidResult("fact %q exceeds string-list bounds", output.Name)
		}
	case decision.ValueKindBytes:
		valueBytes, _ := value.Bytes()
		if len(valueBytes) > output.MaxBytes {
			return invalidResult("fact %q exceeds maximum byte length", output.Name)
		}
	}

	return nil
}

// validateEffect enforces one exact selected-effect capability.
func validateEffect(effect EffectDescriptor) error {
	if err := validateAction(effect.Name, "effect name"); err != nil {
		return invalidDescriptor("%v", err)
	}

	if effect.Execution != EffectExecutionHostSync && effect.Execution != EffectExecutionHostPostAction {
		return invalidDescriptor("effect %q has unsupported execution %q", effect.Name, effect.Execution)
	}

	if err := validateTargets(effect.Targets, "effect "+effect.Name); err != nil {
		return err
	}

	if len(effect.Parameters) > maximumEffectParameters {
		return invalidDescriptor("effect %q contains too many parameters", effect.Name)
	}

	seen := make(map[string]struct{}, len(effect.Parameters))
	for _, parameter := range effect.Parameters {
		if _, err := registry.NewParameterSchema(registry.ParameterSchemaInput{
			Name:           parameter.Name,
			Kind:           parameter.Kind,
			MaxLength:      parameter.MaxLength,
			MaxItems:       parameter.MaxItems,
			MaxBytes:       parameter.MaxBytes,
			AllowedStrings: parameter.AllowedStrings,
			NonEmpty:       parameter.NonEmpty,
			Required:       parameter.Required,
		}); err != nil {
			return invalidDescriptor("effect %q parameter %q is invalid: %v", effect.Name, parameter.Name, err)
		}

		if _, exists := seen[parameter.Name]; exists {
			return invalidDescriptor("effect %q parameter %q occurs more than once", effect.Name, parameter.Name)
		}

		seen[parameter.Name] = struct{}{}
	}

	return nil
}

// validateAction reuses exact target-action validation without normalization.
func validateAction(value string, kind string) error {
	if _, err := decision.NewTarget("contract", value); err != nil {
		return fmt.Errorf("%s %q is not canonical", kind, value)
	}

	return nil
}

// invalidDescriptor constructs one stable descriptor validation error.
func invalidDescriptor(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidDescriptor, fmt.Sprintf(format, arguments...))
}

// invalidResult constructs one stable callback-result validation error.
func invalidResult(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidResult, fmt.Sprintf(format, arguments...))
}
