// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyprovider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"sync"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

var (
	// ErrInvalidGenerationRegistration identifies incomplete generic Lua generation input.
	ErrInvalidGenerationRegistration = errors.New("invalid Lua policy generation registration")
)

// FactProviderRegistration binds one configured schedule to an immutable Lua collector.
type FactProviderRegistration struct {
	Collector    FactCollector
	Requires     []string
	DiagnosticID string
	Failure      registry.ProviderFailureBehavior
}

// EffectProviderRegistration binds selected typed effects to an immutable Lua executor.
type EffectProviderRegistration struct {
	Executor     EffectExecutor
	DiagnosticID string
}

// GenerationInput contains one host-assigned Lua authority and its configured callbacks.
type GenerationInput struct {
	PostActionAcceptance effectsupervisor.Acceptor
	Ownership            registry.NamespaceOwnership
	FactProviders        []FactProviderRegistration
	EffectProviders      []EffectProviderRegistration
	Authority            string
}

// PreparedGeneration owns immutable definitions and callback bindings for one candidate.
type PreparedGeneration struct {
	acceptance    effectsupervisor.Acceptor
	contribution  registry.DefinitionContribution
	factProviders map[string]policyruntime.FactProviderBinding
	syncEffects   map[string]policyruntime.SyncEffectProvider
	postActions   map[string]policyruntime.PostActionProvider
}

type configuredFactSchedule struct {
	requires     []string
	diagnosticID string
	failure      registry.ProviderFailureBehavior
}

type generationFactProvider struct {
	collector  FactCollector
	descriptor FactProviderDescriptor
	authority  string
}

type generationEffectProvider struct {
	executor    EffectExecutor
	descriptor  EffectProviderDescriptor
	definitions map[string]registry.EffectDefinition
}

type generationPostActionWork struct {
	provider *generationEffectProvider
	request  EffectRequest
	once     sync.Once
	valid    bool
}

// PrepareGeneration validates and freezes Lua contributions before catalog compilation.
func PrepareGeneration(ctx context.Context, input GenerationInput) (PreparedGeneration, error) {
	if err := normalizeContext(ctx).Err(); err != nil {
		return PreparedGeneration{}, err
	}

	if nilPreparedDependency(input.PostActionAcceptance) {
		return PreparedGeneration{}, invalidGenerationRegistration("post-action acceptance is required")
	}

	adapter, err := NewDefinitionAdapter(input.Ownership, input.Authority)
	if err != nil {
		return PreparedGeneration{}, invalidGenerationRegistration("definition adapter rejected authority")
	}

	factDescriptors, factSchedules, factBindings, err := prepareFactRegistrations(input.Authority, input.FactProviders)
	if err != nil {
		return PreparedGeneration{}, err
	}

	effectDescriptors, effectBindings, effectDiagnostics, err := prepareEffectRegistrations(
		input.Authority,
		input.EffectProviders,
	)
	if err != nil {
		return PreparedGeneration{}, err
	}

	base, err := adapter.Adapt(factDescriptors, effectDescriptors)
	if err != nil {
		return PreparedGeneration{}, invalidGenerationRegistration("definition contribution was rejected")
	}

	contribution, providers, err := configureContribution(
		base,
		input.Authority,
		input.PostActionAcceptance,
		factSchedules,
		effectDiagnostics,
	)
	if err != nil {
		return PreparedGeneration{}, err
	}

	return buildPreparedGeneration(
		input.PostActionAcceptance,
		contribution,
		providers,
		factBindings,
		effectBindings,
		input.Authority,
	), nil
}

// ExtensionPreparation returns detached bindings ready for one off-side runtime candidate.
func (p PreparedGeneration) ExtensionPreparation(
	nativeModules []policyruntime.NativeModuleBindingInput,
) (policyruntime.ExtensionPreparation, error) {
	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		FactProviders:        clonePreparedMap(p.factProviders),
		SyncEffects:          clonePreparedMap(p.syncEffects),
		PostActions:          clonePreparedMap(p.postActions),
		NativeModules:        append([]policyruntime.NativeModuleBindingInput(nil), nativeModules...),
		PostActionAcceptance: p.acceptance,
	})
	if err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	return policyruntime.ExtensionPreparation{
		Definitions: []registry.DefinitionContribution{p.contribution},
		Bindings:    bindings,
	}, nil
}

// prepareFactRegistrations validates descriptors once and owns their configured schedules.
func prepareFactRegistrations(
	authority string,
	registrations []FactProviderRegistration,
) ([]FactProviderDescriptor, map[string]configuredFactSchedule, map[string]*generationFactProvider, error) {
	descriptors := make([]FactProviderDescriptor, 0, len(registrations))
	schedules := make(map[string]configuredFactSchedule, len(registrations))
	bindings := make(map[string]*generationFactProvider, len(registrations))

	for _, registration := range registrations {
		if nilPreparedDependency(registration.Collector) || !registration.Failure.Valid() {
			return nil, nil, nil, invalidGenerationRegistration("fact provider registration is incomplete")
		}

		descriptor := cloneGenerationFactDescriptor(registration.Collector.Descriptor())
		if err := descriptor.Validate(); err != nil {
			return nil, nil, nil, invalidGenerationRegistration("fact provider descriptor was rejected")
		}

		providerID := luaProviderID(descriptor.Namespace, authority, descriptor.Name)
		if _, exists := schedules[providerID]; exists {
			return nil, nil, nil, invalidGenerationRegistration("fact provider identity occurs more than once")
		}

		descriptors = append(descriptors, descriptor)
		schedules[providerID] = configuredFactSchedule{
			requires:     append([]string(nil), registration.Requires...),
			diagnosticID: registration.DiagnosticID,
			failure:      registration.Failure,
		}
		bindings[providerID] = &generationFactProvider{
			collector: registration.Collector, descriptor: descriptor, authority: authority,
		}
	}

	return descriptors, schedules, bindings, nil
}

// prepareEffectRegistrations validates and owns every selected-effect descriptor once.
func prepareEffectRegistrations(
	authority string,
	registrations []EffectProviderRegistration,
) (
	[]EffectProviderDescriptor,
	map[string]*generationEffectProvider,
	map[string]string,
	error,
) {
	descriptors := make([]EffectProviderDescriptor, 0, len(registrations))
	bindings := make(map[string]*generationEffectProvider, len(registrations))
	diagnostics := make(map[string]string, len(registrations))

	for _, registration := range registrations {
		if nilPreparedDependency(registration.Executor) {
			return nil, nil, nil, invalidGenerationRegistration("effect provider registration is incomplete")
		}

		descriptor := cloneGenerationEffectDescriptor(registration.Executor.Descriptor())
		if err := descriptor.Validate(); err != nil {
			return nil, nil, nil, invalidGenerationRegistration("effect provider descriptor was rejected")
		}

		key := descriptor.Namespace + "/" + descriptor.Name
		if _, exists := bindings[key]; exists {
			return nil, nil, nil, invalidGenerationRegistration("effect provider identity occurs more than once")
		}

		descriptors = append(descriptors, descriptor)
		bindings[key] = &generationEffectProvider{executor: registration.Executor, descriptor: descriptor}
		diagnostics[luaProviderID(descriptor.Namespace, authority, descriptor.Name)] = registration.DiagnosticID
	}

	return descriptors, bindings, diagnostics, nil
}

// configureContribution overlays operator-owned scheduling and host acceptance on adapted definitions.
func configureContribution(
	base registry.DefinitionContribution,
	authority string,
	acceptance effectsupervisor.Acceptor,
	factSchedules map[string]configuredFactSchedule,
	effectDiagnostics map[string]string,
) (registry.DefinitionContribution, map[string]registry.ProviderDefinition, error) {
	providers := make([]registry.ExtensionProviderDefinition, 0, len(base.Providers()))
	providerIndex := make(map[string]registry.ProviderDefinition, len(base.Providers()))

	for _, definition := range base.Providers() {
		input := registry.ProviderDefinitionInput{
			ID: definition.ID(), Targets: definition.Targets(), Executions: definition.Executions(),
			ProducedFacts: definition.ProducedFacts(), Outputs: definition.Outputs(),
			Failure: definition.Failure(), Timeout: definition.Timeout(),
		}
		prefix := ""

		if schedule, exists := factSchedules[definition.ID()]; exists {
			input.Requires = append([]string(nil), schedule.requires...)
			input.DiagnosticID = schedule.diagnosticID
			input.Failure = schedule.failure
			prefix = "lua." + authority + "."
		} else {
			input.DiagnosticID = effectDiagnostics[definition.ID()]
		}

		if slices.Contains(input.Executions, registry.ExecutionHostPostAction) {
			input.PostActionAcceptance = acceptance
		}

		configured, err := registry.NewProviderDefinition(input)
		if err != nil {
			return registry.DefinitionContribution{}, nil, invalidGenerationRegistration(
				"configured provider definition was rejected",
			)
		}

		providers = append(providers, registry.ExtensionProviderDefinition{
			Definition: configured, ProducedFactPrefix: prefix,
		})
		providerIndex[configured.ID()] = configured
	}

	contribution, err := registry.NewExtensionDefinitionContribution(registry.ExtensionDefinitionContributionInput{
		Ownership: base.Ownership(), Providers: providers, Effects: base.Effects(),
	})
	if err != nil {
		return registry.DefinitionContribution{}, nil, invalidGenerationRegistration(
			"configured contribution was rejected",
		)
	}

	return contribution, providerIndex, nil
}

// buildPreparedGeneration joins adapted definitions with exact runtime binding classes.
func buildPreparedGeneration(
	acceptance effectsupervisor.Acceptor,
	contribution registry.DefinitionContribution,
	providers map[string]registry.ProviderDefinition,
	factAdapters map[string]*generationFactProvider,
	effectAdapters map[string]*generationEffectProvider,
	authority string,
) PreparedGeneration {
	prepared := PreparedGeneration{
		acceptance: acceptance, contribution: contribution,
		factProviders: make(map[string]policyruntime.FactProviderBinding, len(factAdapters)),
		syncEffects:   make(map[string]policyruntime.SyncEffectProvider),
		postActions:   make(map[string]policyruntime.PostActionProvider),
	}

	for providerID, adapter := range factAdapters {
		prepared.factProviders[providerID] = policyruntime.FactProviderBinding{
			Provider: adapter, Source: decision.FactSourceLua,
			Authority: adapter.authority, Component: providerID,
		}
	}

	for _, adapter := range effectAdapters {
		providerID := luaProviderID(adapter.descriptor.Namespace, authority, adapter.descriptor.Name)

		definition, exists := providers[providerID]
		if !exists {
			continue
		}

		adapter.definitions = effectDefinitionIndex(contribution.Effects(), providerID)
		if slices.Contains(definition.Executions(), registry.ExecutionHostSync) {
			prepared.syncEffects[providerID] = adapter
		}

		if slices.Contains(definition.Executions(), registry.ExecutionHostPostAction) {
			prepared.postActions[providerID] = adapter
		}
	}

	return prepared
}

// effectDefinitionIndex selects exact effects owned by one provider.
func effectDefinitionIndex(
	effects []registry.EffectDefinition,
	providerID string,
) map[string]registry.EffectDefinition {
	result := make(map[string]registry.EffectDefinition)

	for _, definition := range effects {
		if definition.Provider() == providerID {
			result[definition.ID()] = definition
		}
	}

	return result
}

// Collect invokes one target-aware callback and returns only host-qualified facts.
func (p *generationFactProvider) Collect(
	ctx context.Context,
	input policyruntime.FactProviderInput,
) (facts []policyruntime.ProvidedFact, err error) {
	defer func() {
		if recover() != nil {
			facts = nil
			err = errors.Join(policyruntime.ErrProviderContractViolation, errors.New("lua fact callback panicked"))
		}
	}()

	request := newFactRequest(input)
	if !descriptorAllowsTarget(p.descriptor.Targets, request.Target) {
		return nil, errors.Join(policyruntime.ErrProviderContractViolation, errors.New("lua fact target rejected"))
	}

	result, collectErr := p.collector.Collect(normalizeContext(ctx), request)
	if collectErr != nil {
		return nil, factCollectionError(ctx, collectErr)
	}

	if validateErr := p.descriptor.ValidateResult(result); validateErr != nil {
		return nil, errors.Join(policyruntime.ErrProviderContractViolation, errors.New("lua fact result rejected"))
	}

	if result.ErrorClass != "" {
		return nil, safeCallbackError(ctx, result.ErrorClass)
	}

	outputs := factOutputIndex(p.descriptor.Outputs)
	provided := make([]policyruntime.ProvidedFact, 0, len(result.Facts))

	for _, resultFact := range result.Facts {
		output := outputs[resultFact.Name]

		fact, factErr := policyruntime.NewProvidedFact(policyruntime.ProvidedFactInput{
			ID:       "lua." + p.authority + "." + resultFact.Name,
			Value:    resultFact.Value,
			Category: output.Category,
		})
		if factErr != nil {
			return nil, errors.Join(policyruntime.ErrProviderContractViolation, errors.New("lua fact conversion rejected"))
		}

		provided = append(provided, fact)
	}

	return provided, nil
}

// factCollectionError preserves cancellation and classifies all other callback failures safely.
func factCollectionError(ctx context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}

	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}

	if luaProviderContractError(err) {
		return errors.Join(
			policyruntime.ErrProviderContractViolation,
			errors.New("lua fact callback contract rejected"),
		)
	}

	return safeCallbackError(ctx, ErrorClassInternal)
}

// luaProviderContractError identifies fail-closed callback and typed-boundary violations.
func luaProviderContractError(err error) bool {
	return errors.Is(err, ErrInvalidDescriptor) ||
		errors.Is(err, ErrInvalidResult) ||
		errors.Is(err, ErrScriptPreparation) ||
		errors.Is(err, ErrCallbackRegistration) ||
		errors.Is(err, ErrCallbackInput)
}

// Execute invokes one selected synchronous effect exactly once.
func (p *generationEffectProvider) Execute(
	ctx context.Context,
	execution policyruntime.EffectExecution,
) effectsupervisor.Result {
	request, err := p.effectRequest(execution)
	if err != nil {
		return effectsupervisor.Failed("invalid_input")
	}

	return p.execute(normalizeContext(ctx), request)
}

// Prepare captures immutable selected-effect input without launching host work.
func (p *generationEffectProvider) Prepare(
	ctx context.Context,
	execution policyruntime.EffectExecution,
) (effectsupervisor.Work, error) {
	if err := normalizeContext(ctx).Err(); err != nil {
		return nil, err
	}

	request, err := p.effectRequest(execution)
	if err != nil {
		return nil, errors.Join(policyruntime.ErrProviderContractViolation, errors.New("lua effect input rejected"))
	}

	return &generationPostActionWork{provider: p, request: request, valid: true}, nil
}

// effectRequest validates the selected target, execution class, and typed parameters.
func (p *generationEffectProvider) effectRequest(
	execution policyruntime.EffectExecution,
) (EffectRequest, error) {
	definition, exists := p.definitions[execution.EffectID()]
	if !exists || !definition.AllowsTarget(execution.Target()) || definition.Provider() != execution.Provider() {
		return EffectRequest{}, errors.New("selected effect is outside the registered capability")
	}

	use, err := registry.NewEffectUse(execution.EffectID(), execution.Parameters().Values())
	if err != nil {
		return EffectRequest{}, err
	}

	if err = definition.ValidateUse(use); err != nil {
		return EffectRequest{}, err
	}

	return newEffectRequest(execution), nil
}

// execute maps one closed Lua effect result into the host supervisor vocabulary.
func (p *generationEffectProvider) execute(ctx context.Context, request EffectRequest) (result effectsupervisor.Result) {
	defer func() {
		if recover() != nil {
			result = effectsupervisor.Failed("panic")
		}
	}()

	callbackResult, err := p.executor.Execute(ctx, request)
	if err != nil {
		if ctx.Err() != nil {
			return effectsupervisor.OutcomeUnknown(contextErrorClass(ctx.Err()))
		}

		return effectsupervisor.Failed("internal")
	}

	if err = callbackResult.Validate(); err != nil {
		return effectsupervisor.Failed("invalid_result")
	}

	switch callbackResult.State {
	case EffectStateSucceeded:
		return effectsupervisor.Succeeded()
	case EffectStateOutcomeUnknown:
		return effectsupervisor.OutcomeUnknown(string(callbackResult.ErrorClass))
	default:
		return effectsupervisor.Failed(string(callbackResult.ErrorClass))
	}
}

// Validate proves the supervisor received one immutable prepared callback request.
func (w *generationPostActionWork) Validate() error {
	if w == nil || !w.valid || w.provider == nil {
		return effectsupervisor.ErrInvalidWork
	}

	return nil
}

// Execute delegates the one accepted post-action attempt to its captured provider.
func (w *generationPostActionWork) Execute(ctx context.Context) effectsupervisor.Result {
	if err := w.Validate(); err != nil {
		return effectsupervisor.Failed("invalid_work")
	}

	return w.provider.execute(normalizeContext(ctx), w.request)
}

// Cleanup releases captured request slices exactly once after supervisor completion.
func (w *generationPostActionWork) Cleanup() {
	if w == nil {
		return
	}

	w.once.Do(func() {
		w.valid = false
		w.request = EffectRequest{}
		w.provider = nil
	})
}

// newFactRequest constructs the detached redacted generic callback input.
func newFactRequest(input policyruntime.FactProviderInput) FactRequest {
	return FactRequest{
		Facts: factViews(input.Facts()),
		Target: TargetSelector{
			Namespace: input.Target().Namespace(),
			Action:    input.Target().Action(),
		},
		Caller: callerView(input.Caller()),
	}
}

// newEffectRequest constructs one detached selected-effect callback input.
func newEffectRequest(input policyruntime.EffectExecution) EffectRequest {
	values := input.Parameters().Values()
	names := make([]string, 0, len(values))

	for name := range values {
		names = append(names, name)
	}

	sort.Strings(names)
	parameters := make([]EffectParameter, 0, len(names))

	for _, name := range names {
		parameters = append(parameters, EffectParameter{Name: name, Value: values[name]})
	}

	return EffectRequest{
		Facts:      factViews(input.Facts()),
		Parameters: parameters,
		Target: TargetSelector{
			Namespace: input.Target().Namespace(),
			Action:    input.Target().Action(),
		},
		Caller: callerView(input.Caller()),
		Effect: input.EffectID(),
	}
}

// factViews returns deterministic detached fact values without writable provenance.
func factViews(facts decision.FactSet) []FactView {
	values := facts.Facts()
	sort.Slice(values, func(left int, right int) bool { return values[left].ID() < values[right].ID() })

	result := make([]FactView, 0, len(values))
	for _, fact := range values {
		result = append(result, FactView{ID: fact.ID(), Value: fact.Value(), Category: fact.Category()})
	}

	return result
}

// callerView projects only the frozen redacted caller subset.
func callerView(caller decision.CallerContext) CallerView {
	return CallerView{
		Scopes: caller.Scopes(), Principal: caller.Principal(), ClientID: caller.ClientID(),
		AuthenticationKind: caller.AuthenticationKind(),
	}
}

// descriptorAllowsTarget enforces exact target registration at the callback boundary.
func descriptorAllowsTarget(targets []TargetSelector, target TargetSelector) bool {
	return slices.ContainsFunc(targets, func(candidate TargetSelector) bool {
		return candidate == target
	})
}

// factOutputIndex resolves already validated local output metadata.
func factOutputIndex(outputs []FactOutputDescriptor) map[string]FactOutputDescriptor {
	result := make(map[string]FactOutputDescriptor, len(outputs))

	for _, output := range outputs {
		result[output.Name] = output
	}

	return result
}

// safeCallbackError preserves cancellation and otherwise emits only a closed error class.
func safeCallbackError(ctx context.Context, class ErrorClass) error {
	if err := normalizeContext(ctx).Err(); err != nil {
		return err
	}

	if !class.IsValid() {
		class = ErrorClassInternal
	}

	return fmt.Errorf("lua policy callback failed: %s", class)
}

// contextErrorClass maps cancellation without including context or callback values.
func contextErrorClass(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}

	return "canceled"
}

// cloneGenerationFactDescriptor deeply owns mutable capability slices.
func cloneGenerationFactDescriptor(input FactProviderDescriptor) FactProviderDescriptor {
	input.Targets = append([]TargetSelector(nil), input.Targets...)
	input.Outputs = append([]FactOutputDescriptor(nil), input.Outputs...)

	return input
}

// cloneGenerationEffectDescriptor deeply owns nested effect capability slices.
func cloneGenerationEffectDescriptor(input EffectProviderDescriptor) EffectProviderDescriptor {
	input.Effects = append([]EffectDescriptor(nil), input.Effects...)

	for index := range input.Effects {
		input.Effects[index].Targets = append([]TargetSelector(nil), input.Effects[index].Targets...)
		input.Effects[index].Parameters = append([]ParameterDescriptor(nil), input.Effects[index].Parameters...)

		for parameter := range input.Effects[index].Parameters {
			input.Effects[index].Parameters[parameter].AllowedStrings = append(
				[]string(nil),
				input.Effects[index].Parameters[parameter].AllowedStrings...,
			)
		}
	}

	return input
}

// luaProviderID derives the one canonical configured and adapted provider identity.
func luaProviderID(namespace string, authority string, name string) string {
	return namespace + "/lua." + authority + "." + name
}

// clonePreparedMap returns a detached map over immutable prepared provider owners.
func clonePreparedMap[T any](input map[string]T) map[string]T {
	result := make(map[string]T, len(input))

	for key, value := range input {
		result[key] = value
	}

	return result
}

// nilPreparedDependency rejects both nil and typed-nil callback owners.
func nilPreparedDependency(input any) bool {
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

// normalizeContext supplies a usable cancellation root for direct adapter callers.
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}

	return ctx
}

// invalidGenerationRegistration returns one bounded registration failure without callback values.
func invalidGenerationRegistration(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidGenerationRegistration, reason)
}
