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

package policyprovider

import (
	"context"
	"errors"
	"slices"
	"sort"
	"unicode/utf8"

	lua "github.com/yuin/gopher-lua"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

const (
	maximumCallbackFacts      = 4096
	maximumCallbackScopes     = 256
	maximumCallbackInputBytes = 1024 * 1024
	maximumCallbackTextBytes  = 512
	effectValidationNamespace = "contract"
	effectValidationProvider  = "contract/lua.executor"
)

var (
	_ FactCollector  = (*LuaFactCollector)(nil)
	_ EffectExecutor = (*LuaEffectExecutor)(nil)
)

// LuaFactCollector executes one immutable descriptor through a restricted script.
type LuaFactCollector struct {
	script     *Script
	descriptor FactProviderDescriptor
}

// LuaEffectExecutor executes only descriptor-declared, policy-selected effects.
type LuaEffectExecutor struct {
	script      *Script
	definitions map[string]registry.EffectDefinition
	descriptor  EffectProviderDescriptor
}

// NewLuaFactCollector validates one callback registration and owns its descriptor.
func NewLuaFactCollector(
	ctx context.Context,
	script *Script,
	descriptor FactProviderDescriptor,
) (*LuaFactCollector, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}

	if script == nil {
		return nil, ErrCallbackRegistration
	}

	if err := script.validateCallback(ctx, PolicyFactsCollectCallback); err != nil {
		return nil, err
	}

	return &LuaFactCollector{script: script, descriptor: cloneExecutorFactDescriptor(descriptor)}, nil
}

// Descriptor returns one detached copy of the generation-owned fact capability.
func (c *LuaFactCollector) Descriptor() FactProviderDescriptor {
	if c == nil {
		return FactProviderDescriptor{}
	}

	return cloneExecutorFactDescriptor(c.descriptor)
}

// Collect invokes the exact fact callback with a target-aware bounded request.
func (c *LuaFactCollector) Collect(ctx context.Context, request FactRequest) (FactResult, error) {
	if c == nil || c.script == nil || ctx == nil {
		return FactResult{ErrorClass: ErrorClassInvalidInput}, ErrCallbackInput
	}

	prepared, err := prepareFactRequest(c.descriptor, request)
	if err != nil {
		return FactResult{ErrorClass: ErrorClassInvalidInput}, ErrCallbackInput
	}

	callbackCtx, cancel := context.WithTimeout(ctx, c.descriptor.Timeout)
	defer cancel()

	result := FactResult{}

	err = c.script.invoke(
		callbackCtx,
		PolicyFactsCollectCallback,
		func(state *lua.LState) lua.LValue { return buildFactRequestTable(state, prepared) },
		func(value lua.LValue) error {
			parsed, parseErr := parseFactResult(value, c.descriptor)
			if parseErr == nil {
				result = parsed
			}

			return parseErr
		},
	)
	if err != nil {
		return FactResult{ErrorClass: callbackErrorClass(err)}, err
	}

	return result, nil
}

// NewLuaEffectExecutor validates one callback registration and owns selected-effect definitions.
func NewLuaEffectExecutor(
	ctx context.Context,
	script *Script,
	descriptor EffectProviderDescriptor,
) (*LuaEffectExecutor, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}

	if script == nil {
		return nil, ErrCallbackRegistration
	}

	definitions, err := buildEffectValidationDefinitions(descriptor)
	if err != nil {
		return nil, err
	}

	if err = script.validateCallback(ctx, PolicyEffectsExecuteCallback); err != nil {
		return nil, err
	}

	return &LuaEffectExecutor{
		script:      script,
		definitions: definitions,
		descriptor:  cloneExecutorEffectDescriptor(descriptor),
	}, nil
}

// Descriptor returns one detached copy of the generation-owned effect capability.
func (e *LuaEffectExecutor) Descriptor() EffectProviderDescriptor {
	if e == nil {
		return EffectProviderDescriptor{}
	}

	return cloneExecutorEffectDescriptor(e.descriptor)
}

// Execute invokes the exact callback only after validating the selected effect request.
func (e *LuaEffectExecutor) Execute(ctx context.Context, request EffectRequest) (EffectResult, error) {
	if e == nil || e.script == nil || ctx == nil {
		return failedEffectInput(), ErrCallbackInput
	}

	prepared, err := prepareEffectRequest(e.definitions, request)
	if err != nil {
		return failedEffectInput(), ErrCallbackInput
	}

	result := EffectResult{}

	err = e.script.invoke(
		ctx,
		PolicyEffectsExecuteCallback,
		func(state *lua.LState) lua.LValue { return buildEffectRequestTable(state, prepared) },
		func(value lua.LValue) error {
			parsed, parseErr := parseEffectResult(value)
			if parseErr == nil {
				result = parsed
			}

			return parseErr
		},
	)
	if err != nil {
		return EffectResult{State: EffectStateOutcomeUnknown, ErrorClass: callbackErrorClass(err)}, err
	}

	return result, nil
}

// prepareFactRequest validates and detaches one exact fact callback input.
func prepareFactRequest(descriptor FactProviderDescriptor, request FactRequest) (FactRequest, error) {
	if !targetAllowed(descriptor.Targets, request.Target) {
		return FactRequest{}, ErrCallbackInput
	}

	caller, callerBytes, err := prepareCallerView(request.Caller)
	if err != nil {
		return FactRequest{}, err
	}

	facts, factBytes, err := prepareFactViews(request.Facts)
	if err != nil || callerBytes+factBytes > maximumCallbackInputBytes {
		return FactRequest{}, ErrCallbackInput
	}

	return FactRequest{Facts: facts, Target: request.Target, Caller: caller}, nil
}

// prepareEffectRequest validates selection, target, parameters, and detached common views.
func prepareEffectRequest(
	definitions map[string]registry.EffectDefinition,
	request EffectRequest,
) (EffectRequest, error) {
	definition, exists := definitions[request.Effect]
	if !exists {
		return EffectRequest{}, ErrCallbackInput
	}

	target, err := decision.NewTarget(request.Target.Namespace, request.Target.Action)
	if err != nil || !definition.AllowsTarget(target) {
		return EffectRequest{}, ErrCallbackInput
	}

	parameters, parameterValues, err := prepareEffectParameters(request.Parameters)
	if err != nil {
		return EffectRequest{}, err
	}

	selection, err := registry.NewEffectUse(definition.ID(), parameterValues)
	if err != nil || definition.ValidateUse(selection) != nil {
		return EffectRequest{}, ErrCallbackInput
	}

	caller, callerBytes, err := prepareCallerView(request.Caller)
	if err != nil {
		return EffectRequest{}, err
	}

	facts, factBytes, err := prepareFactViews(request.Facts)
	if err != nil || callerBytes+factBytes > maximumCallbackInputBytes {
		return EffectRequest{}, ErrCallbackInput
	}

	return EffectRequest{
		Facts:      facts,
		Parameters: parameters,
		Target:     request.Target,
		Caller:     caller,
		Effect:     request.Effect,
	}, nil
}

// prepareCallerView validates bounded redacted identity fields and sorts detached scopes.
func prepareCallerView(input CallerView) (CallerView, int, error) {
	if !validRequiredCallbackText(input.Principal) ||
		!validRequiredCallbackText(input.AuthenticationKind) ||
		!validOptionalCallbackText(input.ClientID) ||
		len(input.Scopes) > maximumCallbackScopes {
		return CallerView{}, 0, ErrCallbackInput
	}

	result := CallerView{
		Scopes:             append([]string(nil), input.Scopes...),
		Principal:          input.Principal,
		ClientID:           input.ClientID,
		AuthenticationKind: input.AuthenticationKind,
	}
	sort.Strings(result.Scopes)

	seen := make(map[string]struct{}, len(result.Scopes))
	totalBytes := len(result.Principal) + len(result.ClientID) + len(result.AuthenticationKind)

	for _, scope := range result.Scopes {
		if !validRequiredCallbackText(scope) {
			return CallerView{}, 0, ErrCallbackInput
		}

		if _, exists := seen[scope]; exists {
			return CallerView{}, 0, ErrCallbackInput
		}

		seen[scope] = struct{}{}
		totalBytes += len(scope)
	}

	return result, totalBytes, nil
}

// prepareFactViews validates, bounds, sorts, and detaches trusted fact views.
func prepareFactViews(input []FactView) ([]FactView, int, error) {
	if len(input) > maximumCallbackFacts {
		return nil, 0, ErrCallbackInput
	}

	result := append([]FactView(nil), input...)
	sort.Slice(result, func(left int, right int) bool { return result[left].ID < result[right].ID })

	totalBytes := 0

	for index, fact := range result {
		if index > 0 && result[index-1].ID == fact.ID {
			return nil, 0, ErrCallbackInput
		}

		valueBytes, err := validateFactView(fact)
		if err != nil || valueBytes > maximumCallbackInputBytes-totalBytes {
			return nil, 0, ErrCallbackInput
		}

		totalBytes += len(fact.ID) + valueBytes
	}

	return result, totalBytes, nil
}

// validateFactView reconstructs a temporary schema to check canonical typed input.
func validateFactView(fact FactView) (int, error) {
	maximumLength, maximumItems, maximumBytes, valueBytes, ok := strictValueBounds(fact.Value)
	if !ok {
		return 0, ErrCallbackInput
	}

	_, err := registry.NewProviderFactOutput(registry.ProviderFactOutputInput{
		ID: fact.ID, Category: fact.Category, Kind: fact.Value.Kind(),
		MaxLength: maximumLength, MaxItems: maximumItems, MaxBytes: maximumBytes,
	})
	if err != nil {
		return 0, ErrCallbackInput
	}

	return valueBytes, nil
}

// prepareEffectParameters rejects duplicates and detaches values in deterministic name order.
func prepareEffectParameters(input []EffectParameter) ([]EffectParameter, map[string]decision.Value, error) {
	if len(input) > maximumEffectParameters {
		return nil, nil, ErrCallbackInput
	}

	result := append([]EffectParameter(nil), input...)
	sort.Slice(result, func(left int, right int) bool { return result[left].Name < result[right].Name })
	values := make(map[string]decision.Value, len(result))

	for index, parameter := range result {
		if index > 0 && result[index-1].Name == parameter.Name {
			return nil, nil, ErrCallbackInput
		}

		if _, ok := parameter.Value.Any(); !ok {
			return nil, nil, ErrCallbackInput
		}

		values[parameter.Name] = parameter.Value
	}

	return result, values, nil
}

// buildEffectValidationDefinitions reuses registry validation for strict selected parameters.
func buildEffectValidationDefinitions(
	descriptor EffectProviderDescriptor,
) (map[string]registry.EffectDefinition, error) {
	definitions := make(map[string]registry.EffectDefinition, len(descriptor.Effects))

	for _, effect := range descriptor.Effects {
		targets := make([]decision.Target, 0, len(effect.Targets))
		for _, selector := range effect.Targets {
			target, err := decision.NewTarget(selector.Namespace, selector.Action)
			if err != nil {
				return nil, err
			}

			targets = append(targets, target)
		}

		parameters, err := buildParameterSchemas(effect.Parameters)
		if err != nil {
			return nil, err
		}

		definition, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
			ID:         effectValidationNamespace + "/" + effect.Name,
			Provider:   effectValidationProvider,
			Targets:    targets,
			Parameters: parameters,
			Kind:       registry.EffectKindObligation,
			Execution:  validationExecution(effect.Execution),
		})
		if err != nil {
			return nil, err
		}

		definitions[descriptor.Namespace+"/"+effect.Name] = definition
	}

	return definitions, nil
}

// buildParameterSchemas converts detached callback descriptors through the shared constructor.
func buildParameterSchemas(descriptors []ParameterDescriptor) ([]registry.ParameterSchema, error) {
	parameters := make([]registry.ParameterSchema, 0, len(descriptors))

	for _, descriptor := range descriptors {
		parameter, err := registry.NewParameterSchema(registry.ParameterSchemaInput{
			Name:           descriptor.Name,
			Kind:           descriptor.Kind,
			MaxLength:      descriptor.MaxLength,
			MaxItems:       descriptor.MaxItems,
			MaxBytes:       descriptor.MaxBytes,
			AllowedStrings: descriptor.AllowedStrings,
			NonEmpty:       descriptor.NonEmpty,
			Required:       descriptor.Required,
		})
		if err != nil {
			return nil, err
		}

		parameters = append(parameters, parameter)
	}

	return parameters, nil
}

// validationExecution maps the closed callback class to the shared registry class.
func validationExecution(execution EffectExecution) registry.ExecutionClass {
	if execution == EffectExecutionHostPostAction {
		return registry.ExecutionHostPostAction
	}

	return registry.ExecutionHostSync
}

// targetAllowed reports whether a constructed exact target belongs to a descriptor allowlist.
func targetAllowed(targets []TargetSelector, requested TargetSelector) bool {
	target, err := decision.NewTarget(requested.Namespace, requested.Action)
	if err != nil {
		return false
	}

	return slices.ContainsFunc(targets, func(candidate TargetSelector) bool {
		return candidate.Namespace == target.Namespace() && candidate.Action == target.Action()
	})
}

// validRequiredCallbackText enforces the redacted caller text boundary.
func validRequiredCallbackText(value string) bool {
	return value != "" && len(value) <= maximumCallbackTextBytes && utf8.ValidString(value)
}

// validOptionalCallbackText enforces the optional redacted caller text boundary.
func validOptionalCallbackText(value string) bool {
	return value == "" || validRequiredCallbackText(value)
}

// callbackErrorClass maps contained execution failures to the closed public class vocabulary.
func callbackErrorClass(err error) ErrorClass {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrorClassTimeout
	}

	return ErrorClassInternal
}

// failedEffectInput returns the deterministic pre-invocation rejection state.
func failedEffectInput() EffectResult {
	return EffectResult{State: EffectStateFailed, ErrorClass: ErrorClassInvalidInput}
}

// cloneExecutorFactDescriptor deeply owns all slice-bearing fact descriptor fields.
func cloneExecutorFactDescriptor(input FactProviderDescriptor) FactProviderDescriptor {
	input.Targets = append([]TargetSelector(nil), input.Targets...)
	input.Outputs = append([]FactOutputDescriptor(nil), input.Outputs...)

	return input
}

// cloneExecutorEffectDescriptor deeply owns nested effect and parameter descriptor fields.
func cloneExecutorEffectDescriptor(input EffectProviderDescriptor) EffectProviderDescriptor {
	input.Effects = append([]EffectDescriptor(nil), input.Effects...)

	for effectIndex := range input.Effects {
		input.Effects[effectIndex].Targets = append([]TargetSelector(nil), input.Effects[effectIndex].Targets...)
		input.Effects[effectIndex].Parameters = append([]ParameterDescriptor(nil), input.Effects[effectIndex].Parameters...)

		for parameterIndex := range input.Effects[effectIndex].Parameters {
			parameter := &input.Effects[effectIndex].Parameters[parameterIndex]
			parameter.AllowedStrings = append([]string(nil), parameter.AllowedStrings...)
		}
	}

	return input
}

// strictValueBounds derives exact temporary schema bounds and aggregate accounting.
func strictValueBounds(value decision.Value) (int, int, int, int, bool) {
	switch value.Kind() {
	case decision.ValueKindString:
		text, ok := value.StringValue()

		return max(1, len(text)), 0, 0, len(text), ok
	case decision.ValueKindBoolean:
		_, ok := value.Boolean()

		return 0, 0, 0, 1, ok
	case decision.ValueKindInteger:
		_, ok := value.Integer()

		return 0, 0, 0, 8, ok
	case decision.ValueKindDouble:
		_, ok := value.Double()

		return 0, 0, 0, 8, ok
	case decision.ValueKindStrings:
		values, ok := value.Strings()
		maximumLength := 1
		totalBytes := 0

		for _, text := range values {
			maximumLength = max(maximumLength, len(text))
			totalBytes += len(text)
		}

		return maximumLength, max(1, len(values)), 0, totalBytes, ok
	case decision.ValueKindBytes:
		valueBytes, ok := value.Bytes()

		return 0, 0, max(1, len(valueBytes)), len(valueBytes), ok
	case decision.ValueKindTimestamp:
		_, ok := value.Timestamp()

		return 0, 0, 0, 16, ok
	case decision.ValueKindRecords:
		records, ok := value.Records()
		if !ok || len(records.Records()) > maximumCallbackListItems {
			return 0, 0, 0, 0, false
		}

		totalBytes := 0

		for _, record := range records.Records() {
			if len(record.Fields()) > maximumCallbackListItems {
				return 0, 0, 0, 0, false
			}

			for _, field := range record.Fields() {
				_, _, _, memberBytes, memberOK := strictValueBounds(field.Value().Value())
				if !memberOK || len(field.Name())+memberBytes > maximumCallbackInputBytes-totalBytes {
					return 0, 0, 0, 0, false
				}

				totalBytes += len(field.Name()) + memberBytes
			}
		}

		return 0, 0, 0, totalBytes, true
	default:
		return 0, 0, 0, 0, false
	}
}
