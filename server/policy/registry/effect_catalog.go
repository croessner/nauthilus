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
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/internal/identifier"
)

var (
	// ErrInvalidEffectDefinition identifies an incomplete typed effect descriptor.
	ErrInvalidEffectDefinition = errors.New("invalid policy effect definition")

	// ErrInvalidProviderDefinition identifies an incomplete provider binding.
	ErrInvalidProviderDefinition = errors.New("invalid policy provider definition")

	// ErrInvalidDiagnosticPublicID identifies an unsafe component alias.
	ErrInvalidDiagnosticPublicID = errors.New("invalid diagnostic public id")
)

// ExecutionClass assigns exactly one host/caller effect owner.
type ExecutionClass string

const (
	maximumEffectParameters           = 64
	maximumEffectParameterEnumMembers = 64
	maximumEffectParameterEnumBytes   = 64 * 1024
	maximumEffectArgumentBytes        = 64 * 1024

	// ExecutionReturnOnly returns the obligation to an external policy caller.
	ExecutionReturnOnly ExecutionClass = "return_only"

	// ExecutionHostSync executes through one host-owned synchronous provider.
	ExecutionHostSync ExecutionClass = "host_sync"

	// ExecutionHostPostAction requires supervisor acceptance before finalization.
	ExecutionHostPostAction ExecutionClass = "host_post_action"
)

// valid reports whether the class belongs to the closed contract.
func (c ExecutionClass) valid() bool {
	return c == ExecutionReturnOnly || c == ExecutionHostSync || c == ExecutionHostPostAction
}

// ProviderFailureBehavior controls one generic fact provider failure boundary.
type ProviderFailureBehavior string

const (
	maximumProviderTimeout = 10 * time.Minute

	// ProviderFailureIndeterminate fails the admitted evaluation closed.
	ProviderFailureIndeterminate ProviderFailureBehavior = "indeterminate"

	// ProviderFailureContinue omits failed output after compiler safety proof.
	ProviderFailureContinue ProviderFailureBehavior = "continue"
)

// Valid reports whether the behavior belongs to the closed generic provider contract.
func (b ProviderFailureBehavior) Valid() bool {
	return b == ProviderFailureIndeterminate || b == ProviderFailureContinue
}

// EffectKind separates authoritative obligations from non-authoritative advice.
type EffectKind string

const (
	// EffectKindObligation identifies a selected policy obligation.
	EffectKindObligation EffectKind = "obligation"

	// EffectKindAdvice identifies caller-returned non-authoritative advice.
	EffectKindAdvice EffectKind = "advice"
)

// valid reports whether the kind belongs to the closed contract.
func (k EffectKind) valid() bool {
	return k == EffectKindObligation || k == EffectKindAdvice
}

// ParameterSchemaInput carries one typed effect parameter into its constructor.
type ParameterSchemaInput struct {
	Name           string
	Kind           decision.ValueKind
	MaxLength      int
	MaxItems       int
	MaxBytes       int
	AllowedStrings []string
	NonEmpty       bool
	Required       bool
}

// ParameterSchema is one immutable typed effect parameter declaration.
type ParameterSchema struct {
	name           string
	kind           decision.ValueKind
	maxLength      int
	maxItems       int
	maxBytes       int
	allowedStrings []string
	nonEmpty       bool
	required       bool
}

// NewParameterSchema validates one exact bounded effect parameter.
func NewParameterSchema(input ParameterSchemaInput) (ParameterSchema, error) {
	if !identifier.Action(input.Name) || !input.Kind.IsValid() ||
		input.MaxLength < 0 || input.MaxItems < 0 || input.MaxBytes < 0 {
		return ParameterSchema{}, newValidationError(
			ErrInvalidEffectDefinition,
			"effect.parameters",
			input.Name,
			"must declare an exact name, value kind, and non-negative bounds",
		)
	}

	factBounds := FactSchemaInput{
		ID:        "input." + input.Name,
		Kind:      input.Kind,
		MaxLength: input.MaxLength,
		MaxItems:  input.MaxItems,
		MaxBytes:  input.MaxBytes,
	}
	if err := validateFactBounds(factBounds); err != nil {
		return ParameterSchema{}, newValidationError(
			ErrInvalidEffectDefinition,
			"effect.parameters."+input.Name,
			input.Name,
			"bounds must match the exact value kind",
		)
	}

	allowedStrings, err := cloneParameterAllowedStrings(input)
	if err != nil {
		return ParameterSchema{}, err
	}

	return ParameterSchema{
		name:           input.Name,
		kind:           input.Kind,
		maxLength:      input.MaxLength,
		maxItems:       input.MaxItems,
		maxBytes:       input.MaxBytes,
		allowedStrings: allowedStrings,
		nonEmpty:       input.NonEmpty,
		required:       input.Required,
	}, nil
}

// cloneParameterAllowedStrings validates one optional exact non-empty string enum.
func cloneParameterAllowedStrings(input ParameterSchemaInput) ([]string, error) {
	if (input.NonEmpty || len(input.AllowedStrings) > 0) && input.Kind != decision.ValueKindString {
		return nil, newValidationError(
			ErrInvalidEffectDefinition,
			"effect.parameters."+input.Name,
			input.Name,
			"non-empty and allowed-string constraints require a string kind",
		)
	}

	if len(input.AllowedStrings) > maximumEffectParameterEnumMembers {
		return nil, newValidationError(
			ErrInvalidEffectDefinition,
			"effect.parameters."+input.Name,
			input.Name,
			"allowed string enum contains too many members",
		)
	}

	result := append([]string(nil), input.AllowedStrings...)
	seen := make(map[string]struct{}, len(result))
	totalBytes := 0

	for _, value := range result {
		if value == "" || !utf8.ValidString(value) || len(value) > input.MaxLength {
			return nil, newValidationError(ErrInvalidEffectDefinition, "effect.parameters."+input.Name, value, "allowed string is invalid or out of bounds")
		}

		if _, exists := seen[value]; exists {
			return nil, newValidationError(ErrDuplicateDefinition, "effect.parameters."+input.Name, value, "allowed string occurs more than once")
		}

		if len(value) > maximumEffectParameterEnumBytes-totalBytes {
			return nil, newValidationError(
				ErrInvalidEffectDefinition,
				"effect.parameters."+input.Name,
				input.Name,
				"allowed string enum exceeds the aggregate byte bound",
			)
		}

		seen[value] = struct{}{}
		totalBytes += len(value)
	}

	return result, nil
}

// Name returns the exact parameter name.
func (s ParameterSchema) Name() string {
	return s.name
}

// Kind returns the required strict value kind.
func (s ParameterSchema) Kind() decision.ValueKind {
	return s.kind
}

// Required reports whether every selection must provide the parameter.
func (s ParameterSchema) Required() bool {
	return s.required
}

// AllowedStrings returns one detached exact string enum.
func (s ParameterSchema) AllowedStrings() []string {
	return append([]string(nil), s.allowedStrings...)
}

// NonEmpty reports whether a present string must contain non-whitespace text.
func (s ParameterSchema) NonEmpty() bool {
	return s.nonEmpty
}

// ProviderDefinitionInput carries one resolved host provider into its constructor.
type ProviderDefinitionInput struct {
	PostActionAcceptance effectsupervisor.Acceptor
	ID                   string
	Targets              []decision.Target
	Executions           []ExecutionClass
	Requires             []string
	ProducedFacts        []string
	Failure              ProviderFailureBehavior
	Timeout              time.Duration
	DiagnosticID         string
}

// ProviderDefinition is one immutable target-aware host provider binding.
type ProviderDefinition struct {
	postActionAcceptance effectsupervisor.Acceptor
	id                   string
	targets              []decision.Target
	executions           []ExecutionClass
	requires             []string
	producedFacts        []string
	diagnosticID         string
	failure              ProviderFailureBehavior
	timeout              time.Duration
	builtin              bool
}

// NewProviderDefinition validates one configured provider binding.
func NewProviderDefinition(input ProviderDefinitionInput) (ProviderDefinition, error) {
	return newProviderDefinition(input, false)
}

// newProviderDefinition validates configured and builtin provider bindings.
func newProviderDefinition(input ProviderDefinitionInput, builtin bool) (ProviderDefinition, error) {
	if !validProviderID(input.ID) || len(input.Targets) == 0 || len(input.Executions) == 0 {
		return ProviderDefinition{}, newValidationError(
			ErrInvalidProviderDefinition,
			"provider",
			input.ID,
			"must declare an exact identity, target allowlist, and execution allowlist",
		)
	}

	if err := validateDiagnosticPublicID(input.DiagnosticID, input.ID+".diagnostics.public_id"); err != nil {
		return ProviderDefinition{}, err
	}

	targets, err := cloneUniqueTargets(input.Targets, input.ID+".targets")
	if err != nil {
		return ProviderDefinition{}, err
	}

	executions := append([]ExecutionClass(nil), input.Executions...)
	seen := make(map[ExecutionClass]struct{}, len(executions))

	for _, execution := range executions {
		if !execution.valid() || execution == ExecutionReturnOnly {
			return ProviderDefinition{}, newValidationError(
				ErrInvalidProviderDefinition,
				input.ID+".executions",
				string(execution),
				"host providers support only exact host execution classes",
			)
		}

		if _, exists := seen[execution]; exists {
			return ProviderDefinition{}, newValidationError(ErrDuplicateDefinition, input.ID+".executions", string(execution), "execution occurs more than once")
		}

		seen[execution] = struct{}{}
	}

	requires, producedFacts, err := cloneProviderSchedule(input)
	if err != nil {
		return ProviderDefinition{}, err
	}

	return ProviderDefinition{
		postActionAcceptance: input.PostActionAcceptance,
		id:                   input.ID,
		targets:              targets,
		executions:           executions,
		requires:             requires,
		producedFacts:        producedFacts,
		diagnosticID:         input.DiagnosticID,
		failure:              input.Failure,
		timeout:              input.Timeout,
		builtin:              builtin,
	}, nil
}

// cloneProviderSchedule validates and owns one optional generic fact-provider schedule contract.
func cloneProviderSchedule(input ProviderDefinitionInput) ([]string, []string, error) {
	scheduled := len(input.Requires) > 0 || len(input.ProducedFacts) > 0 || input.Failure != "" || input.Timeout != 0
	if !scheduled {
		return nil, nil, nil
	}

	if !input.Failure.Valid() || input.Timeout <= 0 || input.Timeout > maximumProviderTimeout {
		return nil, nil, newValidationError(
			ErrInvalidProviderDefinition,
			input.ID+".schedule",
			input.ID,
			"generic providers require explicit failure behavior and a positive bounded timeout",
		)
	}

	requires, err := cloneUniqueProviderIDs(input.Requires, input.ID+".requires")
	if err != nil {
		return nil, nil, err
	}

	producedFacts := append([]string(nil), input.ProducedFacts...)
	seen := make(map[string]struct{}, len(producedFacts))

	for _, factID := range producedFacts {
		if !identifier.Fact(factID) {
			return nil, nil, newValidationError(ErrInvalidProviderDefinition, input.ID+".facts", factID, "must be a canonical fact identity")
		}

		if _, exists := seen[factID]; exists {
			return nil, nil, newValidationError(ErrDuplicateDefinition, input.ID+".facts", factID, "fact occurs more than once")
		}

		seen[factID] = struct{}{}
	}

	return requires, producedFacts, nil
}

// ID returns the exact provider identity.
func (d ProviderDefinition) ID() string {
	return d.id
}

// Targets returns the detached exact target allowlist.
func (d ProviderDefinition) Targets() []decision.Target {
	return append([]decision.Target(nil), d.targets...)
}

// Executions returns the detached supported host execution classes.
func (d ProviderDefinition) Executions() []ExecutionClass {
	return append([]ExecutionClass(nil), d.executions...)
}

// Requires returns detached exact same-checkpoint provider dependencies.
func (d ProviderDefinition) Requires() []string {
	return append([]string(nil), d.requires...)
}

// ProducedFacts returns detached canonical fact output declarations.
func (d ProviderDefinition) ProducedFacts() []string {
	return append([]string(nil), d.producedFacts...)
}

// Failure returns the explicit generic provider failure behavior.
func (d ProviderDefinition) Failure() ProviderFailureBehavior {
	return d.failure
}

// Timeout returns the provider-local budget compiled into this descriptor.
func (d ProviderDefinition) Timeout() time.Duration {
	return d.timeout
}

// Scheduled reports whether this descriptor participates in generic fact collection.
func (d ProviderDefinition) Scheduled() bool {
	return d.failure.Valid() && d.timeout > 0
}

// Supports reports whether the provider is compatible with an exact target and class.
func (d ProviderDefinition) Supports(target decision.Target, execution ExecutionClass) bool {
	return d.AllowsTarget(target) && slices.Contains(d.executions, execution)
}

// AllowsTarget reports whether this provider may serve one exact target.
func (d ProviderDefinition) AllowsTarget(target decision.Target) bool {
	return slices.ContainsFunc(d.targets, func(candidate decision.Target) bool {
		return candidate.String() == target.String()
	})
}

// PostActionAcceptance returns the resolved internal capability when present.
func (d ProviderDefinition) PostActionAcceptance() effectsupervisor.Acceptor {
	return d.postActionAcceptance
}

// HasPostActionAcceptance reports whether an internal acceptance capability is non-nil, including typed nils.
func (d ProviderDefinition) HasPostActionAcceptance() bool {
	if d.postActionAcceptance == nil {
		return false
	}

	value := reflect.ValueOf(d.postActionAcceptance)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

// DiagnosticID returns the optional target-local public alias.
func (d ProviderDefinition) DiagnosticID() string {
	return d.diagnosticID
}

// IsBuiltin reports whether the provider class is an immutable host contribution.
func (d ProviderDefinition) IsBuiltin() bool {
	return d.builtin
}

// EffectDefinitionInput carries one typed target-aware effect into its constructor.
type EffectDefinitionInput struct {
	ID           string
	Provider     string
	DiagnosticID string
	Targets      []decision.Target
	Parameters   []ParameterSchema
	Kind         EffectKind
	Execution    ExecutionClass
}

// EffectDefinition is one immutable target-aware effect descriptor.
type EffectDefinition struct {
	id           string
	provider     string
	selectionID  string
	diagnosticID string
	targets      []decision.Target
	parameters   []ParameterSchema
	kind         EffectKind
	execution    ExecutionClass
	builtin      bool
}

// NewEffectDefinition validates one configured effect descriptor.
func NewEffectDefinition(input EffectDefinitionInput) (EffectDefinition, error) {
	return newEffectDefinition(input, false)
}

// newEffectDefinition validates configured and immutable builtin descriptors.
func newEffectDefinition(input EffectDefinitionInput, builtin bool) (EffectDefinition, error) {
	return newEffectDefinitionWithSelection(input, builtin, "")
}

// newEffectDefinitionWithSelection validates one descriptor and optional immutable builtin selection binding.
func newEffectDefinitionWithSelection(
	input EffectDefinitionInput,
	builtin bool,
	selectionID string,
) (EffectDefinition, error) {
	if err := validateEffectDefinitionInput(input); err != nil {
		return EffectDefinition{}, err
	}

	targets, err := cloneUniqueTargets(input.Targets, input.ID+".targets")
	if err != nil {
		return EffectDefinition{}, err
	}

	parameters, err := cloneEffectParameters(input.ID, input.Parameters)
	if err != nil {
		return EffectDefinition{}, err
	}

	return EffectDefinition{
		id:           input.ID,
		provider:     input.Provider,
		selectionID:  selectionID,
		diagnosticID: input.DiagnosticID,
		targets:      targets,
		parameters:   parameters,
		kind:         input.Kind,
		execution:    input.Execution,
		builtin:      builtin,
	}, nil
}

// validateEffectDefinitionInput enforces class, ownership, and alias invariants.
func validateEffectDefinitionInput(input EffectDefinitionInput) error {
	if !identifier.Qualified(input.ID) || !input.Kind.valid() || !input.Execution.valid() || len(input.Targets) == 0 {
		return newValidationError(
			ErrInvalidEffectDefinition,
			"effect",
			input.ID,
			"must declare one exact identity, kind, execution class, and target allowlist",
		)
	}

	if input.Kind == EffectKindAdvice && input.Execution != ExecutionReturnOnly {
		return invalidEffectCombination(input.ID, "advice is always return_only")
	}

	if input.Execution == ExecutionReturnOnly && input.Provider != "" {
		return invalidEffectCombination(input.ID, "return_only cannot bind a host provider")
	}

	if input.Execution != ExecutionReturnOnly && !validProviderID(input.Provider) {
		return invalidEffectCombination(input.ID, "host execution requires one exact provider binding")
	}

	return validateDiagnosticPublicID(input.DiagnosticID, input.ID+".diagnostics.public_id")
}

// cloneEffectParameters owns and deduplicates typed parameter schemas.
func cloneEffectParameters(id string, input []ParameterSchema) ([]ParameterSchema, error) {
	if len(input) > maximumEffectParameters {
		return nil, newValidationError(ErrInvalidEffectDefinition, id+".parameters", id, "contains too many parameter definitions")
	}

	parameters := append([]ParameterSchema(nil), input...)
	seen := make(map[string]struct{}, len(parameters))

	for _, parameter := range parameters {
		if !identifier.Action(parameter.Name()) || !parameter.Kind().IsValid() {
			return nil, newValidationError(ErrInvalidEffectDefinition, id+".parameters", parameter.Name(), "must be constructor validated")
		}

		if _, exists := seen[parameter.Name()]; exists {
			return nil, newValidationError(ErrDuplicateDefinition, id+".parameters", parameter.Name(), "parameter occurs more than once")
		}

		seen[parameter.Name()] = struct{}{}
	}

	return parameters, nil
}

// ID returns the exact effect identity.
func (d EffectDefinition) ID() string {
	return d.id
}

// Provider returns the exact bound provider identity when host-owned.
func (d EffectDefinition) Provider() string {
	return d.provider
}

// SelectionID returns the immutable established builtin effect identity when present.
func (d EffectDefinition) SelectionID() string {
	return d.selectionID
}

// DiagnosticID returns the optional target-local public alias.
func (d EffectDefinition) DiagnosticID() string {
	return d.diagnosticID
}

// Targets returns the detached exact target allowlist.
func (d EffectDefinition) Targets() []decision.Target {
	return append([]decision.Target(nil), d.targets...)
}

// Parameters returns detached typed parameter schemas.
func (d EffectDefinition) Parameters() []ParameterSchema {
	return append([]ParameterSchema(nil), d.parameters...)
}

// Kind returns the obligation/advice class.
func (d EffectDefinition) Kind() EffectKind {
	return d.kind
}

// Execution returns the immutable exact execution class.
func (d EffectDefinition) Execution() ExecutionClass {
	return d.execution
}

// IsBuiltin reports whether the execution class is an immutable host contribution.
func (d EffectDefinition) IsBuiltin() bool {
	return d.builtin
}

// AllowsTarget reports whether the exact target may select this effect.
func (d EffectDefinition) AllowsTarget(target decision.Target) bool {
	return slices.ContainsFunc(d.targets, func(candidate decision.Target) bool {
		return candidate.String() == target.String()
	})
}

// ValidateUse validates one typed rule selection against the parameter schema.
func (d EffectDefinition) ValidateUse(use EffectUse) error {
	if use.parameters.Len() > maximumEffectParameters {
		return fmt.Errorf("effect %s contains too many parameter values", d.id)
	}

	values := use.Parameters().Values()

	definitions, err := d.validateDeclaredParameterValues(values)
	if err != nil {
		return err
	}

	return d.validateUnknownParameterValues(values, definitions)
}

// validateDeclaredParameterValues enforces required, kind, value, and aggregate-size constraints.
func (d EffectDefinition) validateDeclaredParameterValues(
	values map[string]decision.Value,
) (map[string]ParameterSchema, error) {
	definitions := make(map[string]ParameterSchema, len(d.parameters))
	totalBytes := 0

	for _, parameter := range d.parameters {
		definitions[parameter.Name()] = parameter

		value, exists := values[parameter.Name()]
		if parameter.Required() && !exists {
			return nil, fmt.Errorf("effect %s parameter %s is required", d.id, parameter.Name())
		}

		if exists && value.Kind() != parameter.Kind() {
			return nil, fmt.Errorf("effect %s parameter %s has kind %s, want %s", d.id, parameter.Name(), value.Kind(), parameter.Kind())
		}

		if exists {
			if err := validateParameterValue(parameter, value); err != nil {
				return nil, fmt.Errorf("effect %s parameter %s: %w", d.id, parameter.Name(), err)
			}

			totalBytes += parameterValueBytes(value)
			if totalBytes > maximumEffectArgumentBytes {
				return nil, fmt.Errorf("effect %s parameters exceed maximum total size %d", d.id, maximumEffectArgumentBytes)
			}
		}
	}

	return definitions, nil
}

// validateUnknownParameterValues deterministically rejects undeclared arguments.
func (d EffectDefinition) validateUnknownParameterValues(
	values map[string]decision.Value,
	definitions map[string]ParameterSchema,
) error {
	unknownNames := make([]string, 0, len(values))
	for name := range values {
		unknownNames = append(unknownNames, name)
	}

	sort.Strings(unknownNames)

	for _, name := range unknownNames {
		if _, exists := definitions[name]; !exists {
			return fmt.Errorf("effect %s parameter %s is not declared", d.id, name)
		}
	}

	return nil
}

// parameterValueBytes returns one deterministic bounded-size accounting value.
func parameterValueBytes(value decision.Value) int {
	switch value.Kind() {
	case decision.ValueKindString:
		text, _ := value.StringValue()

		return len(text)
	case decision.ValueKindStrings:
		values, _ := value.Strings()

		total := 0
		for _, text := range values {
			total += len(text)
		}

		return total
	case decision.ValueKindBytes:
		bytes, _ := value.Bytes()

		return len(bytes)
	default:
		return 16
	}
}

// validateParameterValue enforces the declared exact size bounds.
func validateParameterValue(parameter ParameterSchema, value decision.Value) error {
	switch parameter.kind {
	case decision.ValueKindString:
		return validateStringParameterValue(parameter, value)
	case decision.ValueKindStrings:
		return validateStringsParameterValue(parameter, value)
	case decision.ValueKindBytes:
		bytes, _ := value.Bytes()
		if len(bytes) > parameter.maxBytes {
			return fmt.Errorf("bytes exceed maximum size %d", parameter.maxBytes)
		}
	}

	return nil
}

// validateStringParameterValue enforces bounds, non-empty text, and exact enum membership.
func validateStringParameterValue(parameter ParameterSchema, value decision.Value) error {
	text, _ := value.StringValue()
	if len(text) > parameter.maxLength {
		return fmt.Errorf("string exceeds maximum length %d", parameter.maxLength)
	}

	if parameter.nonEmpty && strings.TrimSpace(text) == "" {
		return errors.New("string must not be empty")
	}

	if len(parameter.allowedStrings) > 0 && !slices.Contains(parameter.allowedStrings, text) {
		return errors.New("string is outside the allowed values")
	}

	return nil
}

// validateStringsParameterValue enforces exact list and member bounds.
func validateStringsParameterValue(parameter ParameterSchema, value decision.Value) error {
	values, _ := value.Strings()
	if len(values) > parameter.maxItems {
		return fmt.Errorf("string list exceeds maximum items %d", parameter.maxItems)
	}

	for _, text := range values {
		if len(text) > parameter.maxLength {
			return fmt.Errorf("string list member exceeds maximum length %d", parameter.maxLength)
		}
	}

	return nil
}

// invalidEffectCombination constructs one stable class/provider validation error.
func invalidEffectCombination(id string, reason string) error {
	return newValidationError(ErrInvalidEffectDefinition, id, id, reason)
}

// cloneUniqueTargets owns and deduplicates exact target allowlists.
func cloneUniqueTargets(values []decision.Target, path string) ([]decision.Target, error) {
	result := make([]decision.Target, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		target, err := decision.NewTarget(value.Namespace(), value.Action())
		if err != nil {
			return nil, newValidationError(ErrInvalidEffectDefinition, path, value.String(), "must contain exact constructed targets")
		}

		if _, exists := seen[target.String()]; exists {
			return nil, newValidationError(ErrDuplicateDefinition, path, target.String(), "target occurs more than once")
		}

		seen[target.String()] = struct{}{}
		result = append(result, target)
	}

	return result, nil
}
