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

package pluginruntime

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/nativebinding"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const nativeDecisionProviderPrefix = "plugin."

var (
	errDecisionProviderContract = errors.New("native decision provider contract rejected")
	errDecisionProviderFailure  = errors.New("native decision provider reported failure")
	errDecisionProviderInternal = errors.New("native decision provider failed")
)

type nativeDecisionBindingBuilder struct {
	generation    *GenerationBindings
	observer      Observer
	factProviders map[string]policyruntime.FactProviderBinding
	syncEffects   map[string]policyruntime.SyncEffectProvider
	postActions   map[string]policyruntime.PostActionProvider
	providerIDs   map[string]struct{}
}

type nativeDecisionFactProvider struct {
	provider   pluginapi.DecisionFactProvider
	observer   Observer
	outputs    map[string]policyregistry.ProviderFactOutput
	descriptor pluginapi.DecisionFactProviderDescriptor
	definition policyregistry.ProviderDefinition
	moduleName string
	component  string
}

type nativeDecisionEffectProvider struct {
	provider   pluginapi.DecisionEffectProvider
	observer   Observer
	effects    map[string]nativeDecisionEffectBinding
	definition policyregistry.ProviderDefinition
	moduleName string
	component  string
}

type nativeDecisionEffectBinding struct {
	descriptor pluginapi.DecisionEffectDescriptor
	definition policyregistry.EffectDefinition
}

type nativeDecisionValueProjection struct {
	stringValue    *string
	booleanValue   *bool
	integerValue   *int64
	doubleValue    *float64
	timestampValue *time.Time
	stringsValue   []string
	bytesValue     []byte
}

type nativeDecisionPostActionWork struct {
	provider    *nativeDecisionEffectProvider
	request     pluginapi.DecisionEffectRequest
	cleanupOnce sync.Once
	mu          sync.Mutex
	valid       bool
}

// PrepareDecisionBindings resolves configured native providers only from immutable generation captures.
func (b *GenerationBindings) PrepareDecisionBindings(
	ctx context.Context,
	input DecisionBindingInput,
) (DecisionBindings, error) {
	ctx = normalizeDecisionContext(ctx)
	if err := ctx.Err(); err != nil {
		return DecisionBindings{}, err
	}

	if b == nil && (len(input.FactProviders) > 0 || len(input.EffectProviders) > 0) {
		return DecisionBindings{}, invalidDecisionBinding("native generation is unavailable")
	}

	builder := newNativeDecisionBindingBuilder(b, input.Observer)
	for _, registration := range input.FactProviders {
		if err := ctx.Err(); err != nil {
			return DecisionBindings{}, err
		}

		if err := builder.addFactProvider(registration); err != nil {
			return DecisionBindings{}, err
		}
	}

	for _, registration := range input.EffectProviders {
		if err := ctx.Err(); err != nil {
			return DecisionBindings{}, err
		}

		if err := builder.addEffectProvider(registration); err != nil {
			return DecisionBindings{}, err
		}
	}

	return builder.bindings(), nil
}

// newNativeDecisionBindingBuilder initializes collision-checked candidate maps.
func newNativeDecisionBindingBuilder(
	generation *GenerationBindings,
	observer Observer,
) *nativeDecisionBindingBuilder {
	if nilDecisionDependency(observer) {
		observer = nil
	}

	return &nativeDecisionBindingBuilder{
		generation:    generation,
		observer:      observer,
		factProviders: make(map[string]policyruntime.FactProviderBinding),
		syncEffects:   make(map[string]policyruntime.SyncEffectProvider),
		postActions:   make(map[string]policyruntime.PostActionProvider),
		providerIDs:   make(map[string]struct{}),
	}
}

// addFactProvider resolves and freezes one exact configured fact-provider binding.
func (b *nativeDecisionBindingBuilder) addFactProvider(input DecisionFactBindingInput) error {
	component, err := b.generation.resolveDecisionComponent(
		input.ModuleName,
		input.ComponentName,
		pluginregistry.ComponentKindDecisionFactProvider,
	)
	if err != nil {
		return err
	}

	provider, ok := component.Value.(pluginapi.DecisionFactProvider)
	if !ok || nilDecisionDependency(provider) {
		return invalidDecisionBinding("captured fact component has an invalid provider owner")
	}

	descriptor := component.DecisionFactProviderDescriptor

	outputs, err := validateNativeFactSelection(input, component, descriptor)
	if err != nil {
		return err
	}

	if err = b.reserveProviderID(input.Definition.ID()); err != nil {
		return err
	}

	adapter := &nativeDecisionFactProvider{
		provider: provider, observer: b.observer, outputs: outputs,
		descriptor: descriptor, definition: input.Definition,
		moduleName: input.ModuleName, component: input.ComponentName,
	}
	b.factProviders[input.Definition.ID()] = policyruntime.FactProviderBinding{
		Provider: adapter, Source: decision.FactSourcePlugin,
		Authority: input.ModuleName, Component: input.Definition.ID(),
	}

	return nil
}

// addEffectProvider resolves and freezes one exact configured selected-effect binding.
func (b *nativeDecisionBindingBuilder) addEffectProvider(input DecisionEffectBindingInput) error {
	component, err := b.generation.resolveDecisionComponent(
		input.ModuleName,
		input.ComponentName,
		pluginregistry.ComponentKindDecisionEffectProvider,
	)
	if err != nil {
		return err
	}

	provider, ok := component.Value.(pluginapi.DecisionEffectProvider)
	if !ok || nilDecisionDependency(provider) {
		return invalidDecisionBinding("captured effect component has an invalid provider owner")
	}

	effects, executions, err := validateNativeEffectSelection(input, component)
	if err != nil {
		return err
	}

	if err = b.reserveProviderID(input.Definition.ID()); err != nil {
		return err
	}

	adapter := &nativeDecisionEffectProvider{
		provider: provider, observer: b.observer, effects: effects,
		definition: input.Definition, moduleName: input.ModuleName, component: input.ComponentName,
	}
	if slices.Contains(executions, policyregistry.ExecutionHostSync) {
		b.syncEffects[input.Definition.ID()] = adapter
	}

	if slices.Contains(executions, policyregistry.ExecutionHostPostAction) {
		b.postActions[input.Definition.ID()] = adapter
	}

	return nil
}

// reserveProviderID rejects duplicate or cross-kind configured provider identities.
func (b *nativeDecisionBindingBuilder) reserveProviderID(providerID string) error {
	if _, exists := b.providerIDs[providerID]; exists {
		return invalidDecisionBinding("configured provider identity occurs more than once")
	}

	b.providerIDs[providerID] = struct{}{}

	return nil
}

// bindings detaches the prepared candidate maps from builder-owned storage.
func (b *nativeDecisionBindingBuilder) bindings() DecisionBindings {
	return nativebinding.NewDecisionBindings(b.factProviders, b.syncEffects, b.postActions)
}

// resolveDecisionComponent selects one exact generic component without ambient registry lookup.
func (b *GenerationBindings) resolveDecisionComponent(
	moduleName string,
	componentName string,
	kind pluginregistry.ComponentKind,
) (pluginregistry.Component, error) {
	if b == nil || pluginapi.ValidateModuleName(moduleName) != nil || pluginapi.ValidateComponentName(componentName) != nil {
		return pluginregistry.Component{}, invalidDecisionBinding("configured native component identity is invalid")
	}

	for _, module := range b.modules {
		if module.moduleName != moduleName {
			continue
		}

		for _, component := range module.components {
			if component.LocalName == componentName && component.Kind == kind &&
				component.ModuleName == moduleName && component.Origin == pluginregistry.ComponentOriginNative {
				return component.Clone(), nil
			}
		}
	}

	return pluginregistry.Component{}, invalidDecisionBinding("configured native component is not registered in the generation")
}

// validateNativeFactSelection cross-checks operator scheduling against a frozen public capability.
func validateNativeFactSelection(
	input DecisionFactBindingInput,
	component pluginregistry.Component,
	descriptor pluginapi.DecisionFactProviderDescriptor,
) (map[string]policyregistry.ProviderFactOutput, error) {
	if err := validateNativeFactCapability(input, component, descriptor); err != nil {
		return nil, err
	}

	definition := input.Definition
	declared := make(map[string]pluginapi.DecisionFactOutputDescriptor, len(descriptor.Outputs))

	for _, output := range descriptor.Outputs {
		declared[nativeDecisionFactID(input.ModuleName, output.Name)] = output
	}

	configured := make(map[string]policyregistry.ProviderFactOutput, len(definition.Outputs()))

	for _, output := range definition.Outputs() {
		publicOutput, exists := declared[output.ID()]
		if !exists || !nativeFactOutputMatches(output, publicOutput) {
			return nil, invalidDecisionBinding("configured fact output exceeds the registered capability")
		}

		configured[publicOutput.Name] = output
	}

	if len(configured) == 0 {
		return nil, invalidDecisionBinding("configured fact provider has no selected output")
	}

	return configured, nil
}

// validateNativeFactCapability checks one configured fact provider against its frozen registration.
func validateNativeFactCapability(
	input DecisionFactBindingInput,
	component pluginregistry.Component,
	descriptor pluginapi.DecisionFactProviderDescriptor,
) error {
	if err := pluginapi.ValidateDecisionFactProviderDescriptor(descriptor); err != nil ||
		descriptor.Name != component.LocalName {
		return invalidDecisionBinding("captured fact descriptor is invalid")
	}

	expectedID := nativeDecisionProviderID(descriptor.Namespace, input.ModuleName, input.ComponentName)
	definition := input.Definition

	if definition.ID() != expectedID || !definition.Scheduled() || len(definition.Executions()) != 0 ||
		definition.Timeout() > descriptor.Timeout || !decisionTargetsCovered(definition.Targets(), descriptor.Targets) {
		return invalidDecisionBinding("configured fact definition exceeds the registered capability")
	}

	return nil
}

// validateNativeEffectSelection cross-checks selected typed effects against one frozen capability.
func validateNativeEffectSelection(
	input DecisionEffectBindingInput,
	component pluginregistry.Component,
) (map[string]nativeDecisionEffectBinding, []policyregistry.ExecutionClass, error) {
	descriptor := component.DecisionEffectProviderDescriptor
	if err := pluginapi.ValidateDecisionEffectProviderDescriptor(descriptor); err != nil ||
		descriptor.Name != component.LocalName {
		return nil, nil, invalidDecisionBinding("captured effect descriptor is invalid")
	}

	definition := input.Definition

	expectedID := nativeDecisionProviderID(descriptor.Namespace, input.ModuleName, input.ComponentName)
	if definition.ID() != expectedID || definition.Scheduled() || len(definition.Outputs()) > 0 ||
		len(definition.Requires()) > 0 || len(definition.ProducedFacts()) > 0 ||
		!decisionTargetsCovered(definition.Targets(), nativeDecisionEffectTargets(descriptor.Effects)) {
		return nil, nil, invalidDecisionBinding("configured effect definition exceeds the registered capability")
	}

	declared := nativeDecisionEffectDescriptorIndex(descriptor)

	selected, executions, err := validateSelectedNativeEffects(input, definition, declared)
	if err != nil {
		return nil, nil, err
	}

	if !sameDecisionExecutions(definition.Executions(), executions) {
		return nil, nil, invalidDecisionBinding("configured effect execution classes do not match selected effects")
	}

	if !nativeDecisionProviderTargetsMatchEffects(definition, selected) {
		return nil, nil, invalidDecisionBinding("configured effect targets do not match selected effects")
	}

	return selected, executions, nil
}

// validateSelectedNativeEffects owns selected definitions after exact capability checks.
func validateSelectedNativeEffects(
	input DecisionEffectBindingInput,
	provider policyregistry.ProviderDefinition,
	declared map[string]pluginapi.DecisionEffectDescriptor,
) (map[string]nativeDecisionEffectBinding, []policyregistry.ExecutionClass, error) {
	selected := make(map[string]nativeDecisionEffectBinding, len(input.Effects))

	var executions []policyregistry.ExecutionClass

	for _, definition := range input.Effects {
		publicEffect, exists := declared[definition.ID()]
		if !exists || definition.Provider() != provider.ID() || definition.Kind() != policyregistry.EffectKindObligation ||
			!nativeDecisionProviderSupports(provider, definition.Targets(), definition.Execution()) ||
			!nativeDecisionEffectMatches(definition, publicEffect) {
			return nil, nil, invalidDecisionBinding("configured selected effect exceeds the registered capability")
		}

		if _, duplicate := selected[definition.ID()]; duplicate {
			return nil, nil, invalidDecisionBinding("configured selected effect occurs more than once")
		}

		selected[definition.ID()] = nativeDecisionEffectBinding{descriptor: publicEffect, definition: definition}
		if !slices.Contains(executions, definition.Execution()) {
			executions = append(executions, definition.Execution())
		}
	}

	if len(selected) == 0 {
		return nil, nil, invalidDecisionBinding("configured effect provider has no selected effect")
	}

	return selected, executions, nil
}

// nativeDecisionProviderSupports checks every selected effect target against its provider class.
func nativeDecisionProviderSupports(
	provider policyregistry.ProviderDefinition,
	targets []decision.Target,
	execution policyregistry.ExecutionClass,
) bool {
	if len(targets) == 0 {
		return false
	}

	for _, target := range targets {
		if !provider.Supports(target, execution) {
			return false
		}
	}

	return true
}

// nativeDecisionProviderTargetsMatchEffects rejects provider target authority unused by selected effects.
func nativeDecisionProviderTargetsMatchEffects(
	provider policyregistry.ProviderDefinition,
	effects map[string]nativeDecisionEffectBinding,
) bool {
	selected := make(map[string]struct{})

	for _, effect := range effects {
		for _, target := range effect.definition.Targets() {
			selected[target.String()] = struct{}{}
		}
	}

	providerTargets := provider.Targets()
	if len(providerTargets) != len(selected) {
		return false
	}

	for _, target := range providerTargets {
		if _, exists := selected[target.String()]; !exists {
			return false
		}
	}

	return true
}

// Collect invokes one frozen target-aware native fact provider under the configured deadline.
func (p *nativeDecisionFactProvider) Collect(
	ctx context.Context,
	input policyruntime.FactProviderInput,
) ([]policyruntime.ProvidedFact, error) {
	ctx = normalizeDecisionContext(ctx)

	callCtx, cancel := context.WithTimeout(ctx, p.definition.Timeout())
	defer cancel()

	request, err := newNativeDecisionFactRequest(input)
	if err != nil || !p.definition.AllowsTarget(input.Target()) ||
		!nativeDecisionTargetAllowed(p.descriptor.Targets, request.Target()) {
		return nil, decisionProviderContractError("native fact request was rejected")
	}

	var (
		provided     []policyruntime.ProvidedFact
		failureClass pluginapi.DecisionErrorClass
	)

	invokeErr := invokePluginCall(callCtx, p.observer, p.invokeSpec("Collect"), func(callbackCtx context.Context) error {
		result, callbackErr := p.provider.Collect(callbackCtx, request)
		if contextErr := callbackCtx.Err(); contextErr != nil {
			return contextErr
		}

		if callbackErr != nil {
			return boundedDecisionCallbackError(callbackErr)
		}

		if validateErr := pluginapi.ValidateDecisionFactResult(p.descriptor, result); validateErr != nil {
			return errDecisionProviderContract
		}

		if result.ErrorClass != "" {
			failureClass = result.ErrorClass

			return errDecisionProviderFailure
		}

		provided, callbackErr = p.convertFacts(input, result.Facts)
		if callbackErr != nil {
			return errDecisionProviderContract
		}

		if contextErr := callbackCtx.Err(); contextErr != nil {
			provided = nil

			return contextErr
		}

		return nil
	})

	return p.factCallResult(callCtx, invokeErr, provided, failureClass)
}

// convertFacts qualifies configured local outputs and rejects collisions before host admission.
func (p *nativeDecisionFactProvider) convertFacts(
	input policyruntime.FactProviderInput,
	outputs []pluginapi.DecisionFactOutput,
) ([]policyruntime.ProvidedFact, error) {
	provided := make([]policyruntime.ProvidedFact, 0, len(outputs))
	for _, output := range outputs {
		configured, exists := p.outputs[output.Name]
		if !exists {
			return nil, errDecisionProviderContract
		}

		if _, collision := input.Facts().Get(configured.ID()); collision {
			return nil, errDecisionProviderContract
		}

		value, err := nativeDecisionValue(output.Value)
		if err != nil {
			return nil, errDecisionProviderContract
		}

		fact, err := policyruntime.NewProvidedFact(policyruntime.ProvidedFactInput{
			ID: configured.ID(), Category: configured.Category(), Value: value,
		})
		if err != nil {
			return nil, errDecisionProviderContract
		}

		provided = append(provided, fact)
	}

	return provided, nil
}

// factCallResult maps only bounded native outcomes into shared scheduler errors.
func (p *nativeDecisionFactProvider) factCallResult(
	ctx context.Context,
	err error,
	provided []policyruntime.ProvidedFact,
	failureClass pluginapi.DecisionErrorClass,
) ([]policyruntime.ProvidedFact, error) {
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}

	if err == nil {
		return provided, nil
	}

	if contextErr := decisionContextError(err); contextErr != nil {
		return nil, contextErr
	}

	if errors.Is(err, ErrPluginPanic) || errors.Is(err, errDecisionProviderContract) {
		return nil, decisionProviderContractError("native fact callback was rejected")
	}

	if errors.Is(err, errDecisionProviderFailure) {
		if failureClass == pluginapi.DecisionErrorClassTimeout {
			return nil, errors.Join(errDecisionProviderFailure, context.DeadlineExceeded)
		}

		return nil, fmt.Errorf("%w: %s", errDecisionProviderFailure, failureClass)
	}

	return nil, errDecisionProviderInternal
}

// Execute invokes one exact selected synchronous native effect.
func (p *nativeDecisionEffectProvider) Execute(
	ctx context.Context,
	execution policyruntime.EffectExecution,
) effectsupervisor.Result {
	request, err := p.effectRequest(execution, policyregistry.ExecutionHostSync)
	if err != nil {
		return effectsupervisor.Failed("invalid_input")
	}

	return p.execute(normalizeDecisionContext(ctx), request)
}

// Prepare captures selected post-action input without invoking plugin code.
func (p *nativeDecisionEffectProvider) Prepare(
	ctx context.Context,
	execution policyruntime.EffectExecution,
) (effectsupervisor.Work, error) {
	ctx = normalizeDecisionContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	request, err := p.effectRequest(execution, policyregistry.ExecutionHostPostAction)
	if err != nil {
		return nil, decisionProviderContractError("native post-action request was rejected")
	}

	if err = effectsupervisor.ValidateBoundedValue(request, effectsupervisor.DefaultWorkBounds()); err != nil {
		return nil, decisionProviderContractError("native post-action request exceeded host bounds")
	}

	return &nativeDecisionPostActionWork{provider: p, request: request, valid: true}, nil
}

// effectRequest validates the selected provider, target, class, and typed parameters.
func (p *nativeDecisionEffectProvider) effectRequest(
	execution policyruntime.EffectExecution,
	expectedClass policyregistry.ExecutionClass,
) (pluginapi.DecisionEffectRequest, error) {
	binding, exists := p.effects[execution.EffectID()]
	if !exists || binding.definition.Execution() != expectedClass ||
		binding.definition.Provider() != execution.Provider() || execution.Provider() != p.definition.ID() ||
		!binding.definition.AllowsTarget(execution.Target()) || !p.definition.Supports(execution.Target(), expectedClass) {
		return pluginapi.DecisionEffectRequest{}, errDecisionProviderContract
	}

	use, err := policyregistry.NewEffectUse(execution.EffectID(), execution.Parameters().Values())
	if err != nil {
		return pluginapi.DecisionEffectRequest{}, err
	}

	if err = binding.definition.ValidateUse(use); err != nil {
		return pluginapi.DecisionEffectRequest{}, err
	}

	return newNativeDecisionEffectRequest(execution, binding.descriptor.Name)
}

// execute maps one closed native result into the shared effect supervisor vocabulary.
func (p *nativeDecisionEffectProvider) execute(
	ctx context.Context,
	request pluginapi.DecisionEffectRequest,
) effectsupervisor.Result {
	var (
		callbackResult pluginapi.DecisionEffectResult
		attempted      bool
		validResult    bool
	)

	invokeErr := invokePluginCall(ctx, p.observer, p.invokeSpec("Execute"), func(callbackCtx context.Context) error {
		attempted = true

		result, callbackErr := p.provider.Execute(callbackCtx, request)
		callbackResult = result

		if contextErr := callbackCtx.Err(); contextErr != nil {
			return contextErr
		}

		if callbackErr != nil {
			return boundedDecisionCallbackError(callbackErr)
		}

		if validateErr := pluginapi.ValidateDecisionEffectResult(result); validateErr != nil {
			return errDecisionProviderContract
		}

		if contextErr := callbackCtx.Err(); contextErr != nil {
			return contextErr
		}

		validResult = true

		if result.Outcome != pluginapi.DecisionEffectOutcomeSucceeded {
			return errDecisionProviderFailure
		}

		return nil
	})

	return nativeDecisionEffectResult(ctx, invokeErr, callbackResult, attempted, validResult)
}

// invokeSpec returns bounded observation metadata for this captured component.
func (p *nativeDecisionFactProvider) invokeSpec(method string) invokeSpec {
	return invokeSpec{
		moduleName: p.moduleName, componentName: p.component,
		extensionPoint: string(pluginregistry.ComponentKindDecisionFactProvider), method: method,
	}
}

// invokeSpec returns bounded observation metadata for this captured component.
func (p *nativeDecisionEffectProvider) invokeSpec(method string) invokeSpec {
	return invokeSpec{
		moduleName: p.moduleName, componentName: p.component,
		extensionPoint: string(pluginregistry.ComponentKindDecisionEffectProvider), method: method,
	}
}

// Validate proves the supervisor received one immutable prepared native callback request.
func (w *nativeDecisionPostActionWork) Validate() error {
	if w == nil {
		return effectsupervisor.ErrInvalidWork
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.valid || w.provider == nil {
		return effectsupervisor.ErrInvalidWork
	}

	return nil
}

// Execute delegates the supervisor-owned native post-action attempt to its captured provider.
func (w *nativeDecisionPostActionWork) Execute(ctx context.Context) effectsupervisor.Result {
	if w == nil {
		return effectsupervisor.Failed("invalid_work")
	}

	w.mu.Lock()
	if !w.valid || w.provider == nil {
		w.mu.Unlock()

		return effectsupervisor.Failed("invalid_work")
	}

	provider := w.provider
	request := w.request
	w.mu.Unlock()

	return provider.execute(normalizeDecisionContext(ctx), request)
}

// Cleanup releases captured request values once after execution completion or rejection.
func (w *nativeDecisionPostActionWork) Cleanup() {
	if w == nil {
		return
	}

	w.cleanupOnce.Do(func() {
		w.mu.Lock()
		w.valid = false
		w.provider = nil
		w.request = pluginapi.DecisionEffectRequest{}
		w.mu.Unlock()
	})
}

// newNativeDecisionFactRequest constructs immutable redacted public fact input.
func newNativeDecisionFactRequest(input policyruntime.FactProviderInput) (pluginapi.DecisionFactRequest, error) {
	caller, err := nativeDecisionCallerView(input.Caller())
	if err != nil {
		return pluginapi.DecisionFactRequest{}, err
	}

	facts, err := nativeDecisionFactViews(input.Facts())
	if err != nil {
		return pluginapi.DecisionFactRequest{}, err
	}

	return pluginapi.NewDecisionFactRequest(nativeDecisionTargetSelector(input.Target()), caller, facts)
}

// newNativeDecisionEffectRequest constructs immutable redacted selected-effect input.
func newNativeDecisionEffectRequest(
	input policyruntime.EffectExecution,
	localEffect string,
) (pluginapi.DecisionEffectRequest, error) {
	caller, err := nativeDecisionCallerView(input.Caller())
	if err != nil {
		return pluginapi.DecisionEffectRequest{}, err
	}

	facts, err := nativeDecisionFactViews(input.Facts())
	if err != nil {
		return pluginapi.DecisionEffectRequest{}, err
	}

	parameters, err := nativeDecisionParameters(input.Parameters())
	if err != nil {
		return pluginapi.DecisionEffectRequest{}, err
	}

	return pluginapi.NewDecisionEffectRequest(pluginapi.DecisionEffectRequestInput{
		Parameters: parameters, Facts: facts, Target: nativeDecisionTargetSelector(input.Target()),
		Caller: caller, Effect: localEffect,
	})
}

// nativeDecisionFactViews returns deterministic immutable public fact views.
func nativeDecisionFactViews(input decision.FactSet) ([]pluginapi.DecisionFactView, error) {
	facts := input.Facts()
	sort.Slice(facts, func(left int, right int) bool { return facts[left].ID() < facts[right].ID() })

	result := make([]pluginapi.DecisionFactView, 0, len(facts))
	for _, fact := range facts {
		value, err := pluginDecisionValue(fact.Value())
		if err != nil {
			return nil, err
		}

		view, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{
			ID: fact.ID(), Category: pluginapi.DecisionFactCategory(fact.Category()), Value: value,
		})
		if err != nil {
			return nil, err
		}

		result = append(result, view)
	}

	return result, nil
}

// nativeDecisionCallerView projects only the stable redacted caller subset.
func nativeDecisionCallerView(input decision.CallerContext) (pluginapi.DecisionCallerView, error) {
	return pluginapi.NewDecisionCallerView(pluginapi.DecisionCallerViewInput{
		Scopes: input.Scopes(), Principal: input.Principal(), ClientID: input.ClientID(),
		AuthenticationKind: input.AuthenticationKind(),
	})
}

// nativeDecisionParameters converts selected strict parameters without sharing mutable values.
func nativeDecisionParameters(input decision.ValueMap) (map[string]pluginapi.DecisionValue, error) {
	values := input.Values()
	result := make(map[string]pluginapi.DecisionValue, len(values))

	for name, value := range values {
		converted, err := pluginDecisionValue(value)
		if err != nil {
			return nil, err
		}

		result[name] = converted
	}

	return result, nil
}

// pluginDecisionValue translates one internal strict value through the public constructor.
func pluginDecisionValue(input decision.Value) (pluginapi.DecisionValue, error) {
	if records, ok := input.Records(); ok {
		converted, err := pluginDecisionRecordList(records)
		if err != nil {
			return pluginapi.DecisionValue{}, errDecisionProviderContract
		}

		return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{Records: &converted})
	}

	member, present := input.Any()

	projection, err := newNativeDecisionValueProjection(member, present)
	if err != nil {
		return pluginapi.DecisionValue{}, errDecisionProviderContract
	}

	return projection.pluginValue()
}

// nativeDecisionValue translates one public strict value through the internal constructor.
func nativeDecisionValue(input pluginapi.DecisionValue) (decision.Value, error) {
	if records, ok := input.Records(); ok {
		converted, err := nativeDecisionRecordList(records)
		if err != nil {
			return decision.Value{}, errDecisionProviderContract
		}

		return decision.NewValue(decision.ValueInput{Records: &converted})
	}

	member, present := input.Any()

	projection, err := newNativeDecisionValueProjection(member, present)
	if err != nil {
		return decision.Value{}, errDecisionProviderContract
	}

	return projection.nativeValue()
}

// pluginDecisionRecordList converts one internal record collection through public constructors.
func pluginDecisionRecordList(input decision.RecordList) (pluginapi.DecisionRecordList, error) {
	return convertDecisionRecordList(
		input.Records(),
		func(record decision.Record) []decision.RecordField { return record.Fields() },
		pluginDecisionRecordField,
		pluginapi.NewDecisionRecord,
		pluginapi.NewDecisionRecordList,
	)
}

// nativeDecisionRecordList converts one public record collection through internal constructors.
func nativeDecisionRecordList(input pluginapi.DecisionRecordList) (decision.RecordList, error) {
	return convertDecisionRecordList(
		input.Records(),
		func(record pluginapi.DecisionRecord) []pluginapi.DecisionRecordField { return record.Fields() },
		nativeDecisionRecordField,
		decision.NewRecord,
		decision.NewRecordList,
	)
}

// pluginDecisionRecordField converts one internal field through the public leaf constructors.
func pluginDecisionRecordField(input decision.RecordField) (pluginapi.DecisionRecordField, error) {
	leaf, err := pluginDecisionValue(input.Value().Value())
	if err != nil {
		return pluginapi.DecisionRecordField{}, err
	}

	value, err := pluginapi.NewDecisionRecordFieldValue(leaf)
	if err != nil {
		return pluginapi.DecisionRecordField{}, err
	}

	return pluginapi.NewDecisionRecordField(input.Name(), value)
}

// nativeDecisionRecordField converts one public field through the internal leaf constructors.
func nativeDecisionRecordField(input pluginapi.DecisionRecordField) (decision.RecordField, error) {
	leaf, err := nativeDecisionValue(input.Value().Value())
	if err != nil {
		return decision.RecordField{}, err
	}

	value, err := decision.NewRecordFieldValueFromValue(leaf)
	if err != nil {
		return decision.RecordField{}, err
	}

	return decision.NewRecordField(input.Name(), value)
}

// convertDecisionRecordList shares ordered record traversal across both native boundary directions.
func convertDecisionRecordList[
	SourceRecord any,
	SourceField any,
	TargetField any,
	TargetRecord any,
	TargetList any,
](
	sourceRecords []SourceRecord,
	fieldsFor func(SourceRecord) []SourceField,
	convertField func(SourceField) (TargetField, error),
	newRecord func([]TargetField) (TargetRecord, error),
	newList func([]TargetRecord) (TargetList, error),
) (TargetList, error) {
	records := make([]TargetRecord, 0, len(sourceRecords))

	for _, sourceRecord := range sourceRecords {
		sourceFields := fieldsFor(sourceRecord)
		fields := make([]TargetField, 0, len(sourceFields))

		for _, sourceField := range sourceFields {
			field, err := convertField(sourceField)
			if err != nil {
				var zero TargetList

				return zero, err
			}

			fields = append(fields, field)
		}

		record, err := newRecord(fields)
		if err != nil {
			var zero TargetList

			return zero, err
		}

		records = append(records, record)
	}

	return newList(records)
}

// newNativeDecisionValueProjection normalizes one closed strict-value member for either boundary constructor.
func newNativeDecisionValueProjection(member any, present bool) (nativeDecisionValueProjection, error) {
	if !present {
		return nativeDecisionValueProjection{}, errDecisionProviderContract
	}

	projection := nativeDecisionValueProjection{}

	switch value := member.(type) {
	case string:
		projection.stringValue = &value
	case bool:
		projection.booleanValue = &value
	case int64:
		projection.integerValue = &value
	case float64:
		projection.doubleValue = &value
	case []string:
		projection.stringsValue = value
	case []byte:
		projection.bytesValue = value
	case time.Time:
		projection.timestampValue = &value
	default:
		return nativeDecisionValueProjection{}, errDecisionProviderContract
	}

	return projection, nil
}

// pluginValue constructs one detached public strict value from the shared projection.
func (p nativeDecisionValueProjection) pluginValue() (pluginapi.DecisionValue, error) {
	return pluginapi.NewDecisionValue(pluginapi.DecisionValueInput{
		String: p.stringValue, Boolean: p.booleanValue, Integer: p.integerValue,
		Double: p.doubleValue, Timestamp: p.timestampValue,
		Strings: p.stringsValue, Bytes: p.bytesValue,
	})
}

// nativeValue constructs one detached internal strict value from the shared projection.
func (p nativeDecisionValueProjection) nativeValue() (decision.Value, error) {
	return decision.NewValue(decision.ValueInput{
		String: p.stringValue, Boolean: p.booleanValue, Integer: p.integerValue,
		Double: p.doubleValue, Timestamp: p.timestampValue,
		Strings: p.stringsValue, Bytes: p.bytesValue,
	})
}

// nativeDecisionEffectResult maps callback failure and closed outcome vocabularies safely.
func nativeDecisionEffectResult(
	ctx context.Context,
	err error,
	result pluginapi.DecisionEffectResult,
	attempted bool,
	validResult bool,
) effectsupervisor.Result {
	if !attempted {
		if contextErr := firstDecisionContextError(ctx.Err(), err); contextErr != nil {
			return effectsupervisor.Failed(decisionContextErrorClass(contextErr))
		}

		return effectsupervisor.Failed("internal")
	}

	if contextErr := decisionContextError(ctx.Err()); contextErr != nil {
		return effectsupervisor.OutcomeUnknown(decisionContextErrorClass(contextErr))
	}

	if validResult {
		return mappedNativeDecisionEffectResult(result)
	}

	if errors.Is(err, ErrPluginPanic) {
		return effectsupervisor.Failed("panic")
	}

	if errors.Is(err, errDecisionProviderContract) {
		return effectsupervisor.Failed("invalid_result")
	}

	return effectsupervisor.Failed("internal")
}

// mappedNativeDecisionEffectResult translates a valid closed provider outcome exactly once.
func mappedNativeDecisionEffectResult(result pluginapi.DecisionEffectResult) effectsupervisor.Result {
	switch result.Outcome {
	case pluginapi.DecisionEffectOutcomeSucceeded:
		return effectsupervisor.Succeeded()
	case pluginapi.DecisionEffectOutcomeUnknown:
		return effectsupervisor.OutcomeUnknown(string(result.ErrorClass))
	default:
		return effectsupervisor.Failed(string(result.ErrorClass))
	}
}

// nativeDecisionProviderID derives one configured provider identity from frozen capability metadata.
func nativeDecisionProviderID(namespace string, moduleName string, componentName string) string {
	return namespace + "/" + nativeDecisionProviderPrefix + moduleName + "." + componentName
}

// nativeDecisionFactID qualifies one plugin-local output under the host-assigned module authority.
func nativeDecisionFactID(moduleName string, localName string) string {
	return nativeDecisionProviderPrefix + moduleName + "." + localName
}

// nativeFactOutputMatches checks exact type, category, and memory bounds.
func nativeFactOutputMatches(
	configured policyregistry.ProviderFactOutput,
	declared pluginapi.DecisionFactOutputDescriptor,
) bool {
	return configured.Category() == decision.FactCategory(declared.Category) &&
		configured.Kind() == decision.ValueKind(declared.Kind) &&
		configured.MaxLength() == declared.MaxLength &&
		configured.MaxItems() == declared.MaxItems &&
		configured.MaxBytes() == declared.MaxBytes
}

// nativeDecisionEffectMatches checks target, class, and parameter capability coverage.
func nativeDecisionEffectMatches(
	configured policyregistry.EffectDefinition,
	declared pluginapi.DecisionEffectDescriptor,
) bool {
	execution, ok := nativeDecisionExecutionClass(declared.Execution)
	if !ok || configured.Execution() != execution || !decisionTargetsCovered(configured.Targets(), declared.Targets) {
		return false
	}

	return nativeDecisionParametersMatch(configured.Parameters(), declared.Parameters)
}

// nativeDecisionParametersMatch compares selected parameter schemas by exact name and bounds.
func nativeDecisionParametersMatch(
	configured []policyregistry.ParameterSchema,
	declared []pluginapi.DecisionEffectParameterDescriptor,
) bool {
	if len(configured) != len(declared) {
		return false
	}

	configuredIndex := make(map[string]policyregistry.ParameterSchema, len(configured))
	for _, parameter := range configured {
		configuredIndex[parameter.Name()] = parameter
	}

	for _, parameter := range declared {
		expected, err := policyregistry.NewParameterSchema(policyregistry.ParameterSchemaInput{
			Name: parameter.Name, Kind: decision.ValueKind(parameter.Kind), MaxLength: parameter.MaxLength,
			MaxItems: parameter.MaxItems, MaxBytes: parameter.MaxBytes,
			AllowedStrings: append([]string(nil), parameter.AllowedStrings...),
			NonEmpty:       parameter.NonEmpty, Required: parameter.Required,
		})
		if err != nil || !reflect.DeepEqual(configuredIndex[parameter.Name], expected) {
			return false
		}
	}

	return true
}

// nativeDecisionEffectDescriptorIndex resolves exact qualified effect identities.
func nativeDecisionEffectDescriptorIndex(
	descriptor pluginapi.DecisionEffectProviderDescriptor,
) map[string]pluginapi.DecisionEffectDescriptor {
	result := make(map[string]pluginapi.DecisionEffectDescriptor, len(descriptor.Effects))
	for _, effect := range descriptor.Effects {
		result[descriptor.Namespace+"/"+effect.Name] = effect
	}

	return result
}

// nativeDecisionEffectTargets returns the de-duplicated target capability union.
func nativeDecisionEffectTargets(
	effects []pluginapi.DecisionEffectDescriptor,
) []pluginapi.DecisionTargetSelector {
	var result []pluginapi.DecisionTargetSelector

	for _, effect := range effects {
		for _, target := range effect.Targets {
			if !slices.Contains(result, target) {
				result = append(result, target)
			}
		}
	}

	return result
}

// nativeDecisionExecutionClass maps the closed public execution vocabulary inward.
func nativeDecisionExecutionClass(
	input pluginapi.DecisionEffectExecution,
) (policyregistry.ExecutionClass, bool) {
	switch input {
	case pluginapi.DecisionEffectExecutionHostSync:
		return policyregistry.ExecutionHostSync, true
	case pluginapi.DecisionEffectExecutionHostPostAction:
		return policyregistry.ExecutionHostPostAction, true
	default:
		return "", false
	}
}

// decisionTargetsCovered reports whether every configured target is explicitly registered.
func decisionTargetsCovered(
	configured []decision.Target,
	declared []pluginapi.DecisionTargetSelector,
) bool {
	if len(configured) == 0 {
		return false
	}

	for _, target := range configured {
		if !nativeDecisionTargetAllowed(declared, nativeDecisionTargetSelector(target)) {
			return false
		}
	}

	return true
}

// nativeDecisionTargetAllowed reports exact namespace/action capability membership.
func nativeDecisionTargetAllowed(
	declared []pluginapi.DecisionTargetSelector,
	target pluginapi.DecisionTargetSelector,
) bool {
	return slices.Contains(declared, target)
}

// nativeDecisionTargetSelector projects one internal exact target without normalization.
func nativeDecisionTargetSelector(target decision.Target) pluginapi.DecisionTargetSelector {
	return pluginapi.DecisionTargetSelector{Namespace: target.Namespace(), Action: target.Action()}
}

// sameDecisionExecutions compares closed execution sets without depending on declaration order.
func sameDecisionExecutions(
	left []policyregistry.ExecutionClass,
	right []policyregistry.ExecutionClass,
) bool {
	if len(left) != len(right) {
		return false
	}

	for _, execution := range left {
		if !slices.Contains(right, execution) {
			return false
		}
	}

	return true
}

// boundedDecisionCallbackError removes provider-controlled error values before observation or return.
func boundedDecisionCallbackError(_ error) error {
	return errDecisionProviderInternal
}

// decisionContextError returns one canonical cancellation member when present.
func decisionContextError(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, context.Canceled):
		return context.Canceled
	default:
		return nil
	}
}

// firstDecisionContextError returns the first canonical cancellation across ordered candidates.
func firstDecisionContextError(candidates ...error) error {
	for _, candidate := range candidates {
		if contextErr := decisionContextError(candidate); contextErr != nil {
			return contextErr
		}
	}

	return nil
}

// decisionContextErrorClass maps cancellation into the bounded effect failure vocabulary.
func decisionContextErrorClass(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return pluginCallResultTimeout
	}

	return pluginCallResultCanceled
}

// decisionProviderContractError wraps one static safe contract classification.
func decisionProviderContractError(reason string) error {
	return errors.Join(policyruntime.ErrProviderContractViolation, errors.New(reason))
}

// normalizeDecisionContext supplies a usable cancellation root for direct adapter callers.
func normalizeDecisionContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}

	return ctx
}

// nilDecisionDependency rejects both nil and typed-nil provider owners.
func nilDecisionDependency(input any) bool {
	if input == nil {
		return true
	}

	value := reflect.ValueOf(input)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// invalidDecisionBinding returns one bounded preparation failure without provider-controlled values.
func invalidDecisionBinding(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidDecisionBinding, strings.TrimSpace(reason))
}
