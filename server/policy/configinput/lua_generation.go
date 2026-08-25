// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	luaprovider "github.com/croessner/nauthilus/v3/server/lualib/policyprovider"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

// ConfiguredLuaGenerationInput carries standalone Lua configuration into one off-side candidate.
type ConfiguredLuaGenerationInput struct {
	PostActionAcceptance effectsupervisor.Acceptor
	Policy               policyconfig.PolicyConfig
	NativeModules        []policyruntime.NativeModuleBindingInput
}

type configuredGenerationBuilder struct {
	ctx                 context.Context
	acceptance          effectsupervisor.Acceptor
	policy              policyconfig.PolicyConfig
	providers           map[string]registry.ProviderDefinition
	effectsByProvider   map[string][]registry.EffectDefinition
	effectIDs           map[string]struct{}
	configuredEffects   map[string]policyconfig.EffectConfig
	authorities         map[string]*configuredLuaAuthority
	scripts             map[string]*luaprovider.Script
	preparedDefinitions []registry.DefinitionContribution
	factBindings        map[string]policyruntime.FactProviderBinding
	syncBindings        map[string]policyruntime.SyncEffectProvider
	postBindings        map[string]policyruntime.PostActionProvider
}

type configuredLuaAuthority struct {
	namespaces      map[string]struct{}
	factProviders   []luaprovider.FactProviderRegistration
	effectProviders []luaprovider.EffectProviderRegistration
	providers       []registry.ProviderDefinition
	effects         []registry.EffectDefinition
	authority       string
}

// PrepareConfiguredLuaGeneration validates configured Lua owners and returns only their candidate material.
func PrepareConfiguredLuaGeneration(
	ctx context.Context,
	input ConfiguredLuaGenerationInput,
) (policyruntime.ExtensionPreparation, error) {
	ctx = normalizeLuaPreparationContext(ctx)
	if err := ctx.Err(); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	if nilLuaPreparationDependency(input.PostActionAcceptance) {
		return policyruntime.ExtensionPreparation{}, invalidGenerationRegistration(
			"post-action acceptance is required",
		)
	}

	normalized, err := Normalize(ctx, policyconfig.Document{Policy: input.Policy})
	if err != nil {
		return policyruntime.ExtensionPreparation{}, configuredPreparationError(ctx, "policy configuration was rejected")
	}

	builder := newConfiguredGenerationBuilder(ctx, normalized.Policy, input.PostActionAcceptance)
	if err = builder.indexDefinitions(normalized.Definitions); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	if err = builder.prepareAuthorities(); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	return builder.extensionPreparation(input.NativeModules)
}

// newConfiguredGenerationBuilder initializes isolated indexes for one normalized policy snapshot.
func newConfiguredGenerationBuilder(
	ctx context.Context,
	policy policyconfig.PolicyConfig,
	acceptance effectsupervisor.Acceptor,
) *configuredGenerationBuilder {
	return &configuredGenerationBuilder{
		ctx: ctx, acceptance: acceptance, policy: policy,
		providers:         make(map[string]registry.ProviderDefinition),
		effectsByProvider: make(map[string][]registry.EffectDefinition),
		effectIDs:         make(map[string]struct{}),
		configuredEffects: make(map[string]policyconfig.EffectConfig),
		authorities:       make(map[string]*configuredLuaAuthority),
		scripts:           make(map[string]*luaprovider.Script),
		factBindings:      make(map[string]policyruntime.FactProviderBinding),
		syncBindings:      make(map[string]policyruntime.SyncEffectProvider),
		postBindings:      make(map[string]policyruntime.PostActionProvider),
	}
}

// indexDefinitions retains exact normalized provider and effect contracts by identity.
func (b *configuredGenerationBuilder) indexDefinitions(
	contributions []registry.DefinitionContribution,
) error {
	for _, contribution := range contributions {
		for _, provider := range contribution.Providers() {
			if _, exists := b.providers[provider.ID()]; exists {
				return invalidGenerationRegistration("normalized provider identity is ambiguous")
			}

			b.providers[provider.ID()] = provider
		}

		for _, effect := range contribution.Effects() {
			if _, exists := b.effectIDs[effect.ID()]; exists {
				return invalidGenerationRegistration("normalized effect identity is ambiguous")
			}

			b.effectIDs[effect.ID()] = struct{}{}

			configured, exists := configuredEffect(b.policy, effect.ID())
			if exists {
				b.configuredEffects[effect.ID()] = configured
			}

			if effect.Provider() != "" {
				b.effectsByProvider[effect.Provider()] = append(b.effectsByProvider[effect.Provider()], effect)
			}
		}
	}

	return nil
}

// prepareAuthorities compiles configured scripts and freezes each module authority independently.
func (b *configuredGenerationBuilder) prepareAuthorities() error {
	for _, namespace := range sortedConfiguredKeys(b.policy.Namespaces) {
		if err := b.ctx.Err(); err != nil {
			return err
		}

		configuredNamespace := b.policy.Namespaces[namespace]

		for _, name := range sortedConfiguredKeys(configuredNamespace.Providers) {
			if err := b.ctx.Err(); err != nil {
				return err
			}

			provider := configuredNamespace.Providers[name]
			if provider.Kind != policyconfig.ProviderKindLua {
				continue
			}

			if err := b.prepareProvider(namespace, name, provider); err != nil {
				return err
			}
		}
	}

	for _, authority := range sortedConfiguredKeys(b.authorities) {
		if err := b.ctx.Err(); err != nil {
			return err
		}

		if err := b.freezeAuthority(b.authorities[authority]); err != nil {
			return err
		}
	}

	return nil
}

// prepareProvider reconstructs exact Lua descriptors from one normalized provider definition.
func (b *configuredGenerationBuilder) prepareProvider(
	namespace string,
	name string,
	configured policyconfig.ProviderConfig,
) error {
	if err := b.ctx.Err(); err != nil {
		return err
	}

	providerID := CanonicalProviderID(namespace, name, configured)

	definition, exists := b.providers[providerID]
	if !exists || definition.ID() != providerID {
		return invalidGenerationRegistration("configured Lua provider definition is missing")
	}

	if definition.Timeout() <= 0 {
		return invalidGenerationRegistration("configured Lua provider deadline is missing")
	}

	script, err := b.compiledScript(configured.ScriptPath)
	if err != nil {
		return configuredPreparationError(b.ctx, "configured Lua script was rejected")
	}

	group := b.authority(configured.Module)
	group.namespaces[namespace] = struct{}{}
	group.providers = append(group.providers, definition)

	registered := false

	if len(definition.Outputs()) > 0 {
		if err = b.registerFacts(group, namespace, name, configured.Module, definition, script); err != nil {
			return err
		}

		registered = true
	}

	effects := b.effectsByProvider[providerID]
	if len(effects) > 0 {
		if err = b.registerEffects(group, namespace, name, definition, effects, script); err != nil {
			return err
		}

		registered = true
	}

	if !registered || !providerExecutionsMatchEffects(definition.Executions(), effects) {
		return invalidGenerationRegistration("configured Lua provider capability is incomplete")
	}

	return nil
}

// compiledScript compiles each exact configured path once for one candidate snapshot.
func (b *configuredGenerationBuilder) compiledScript(path string) (*luaprovider.Script, error) {
	if err := b.ctx.Err(); err != nil {
		return nil, err
	}

	if script, exists := b.scripts[path]; exists {
		return script, nil
	}

	script, err := luaprovider.CompileScriptFile(path)
	if err != nil {
		return nil, err
	}

	b.scripts[path] = script

	return script, nil
}

// authority returns one deterministic module-owned preparation group.
func (b *configuredGenerationBuilder) authority(name string) *configuredLuaAuthority {
	group, exists := b.authorities[name]
	if exists {
		return group
	}

	group = &configuredLuaAuthority{
		authority: name, namespaces: make(map[string]struct{}),
	}
	b.authorities[name] = group

	return group
}

// registerFacts binds schema-projected local outputs to one validated exact callback.
func (b *configuredGenerationBuilder) registerFacts(
	group *configuredLuaAuthority,
	namespace string,
	name string,
	authority string,
	definition registry.ProviderDefinition,
	script *luaprovider.Script,
) error {
	descriptor, err := configuredFactDescriptor(namespace, name, authority, definition)
	if err != nil {
		return err
	}

	validationCtx, cancel := context.WithTimeout(b.ctx, definition.Timeout())
	collector, err := luaprovider.NewLuaFactCollector(validationCtx, script, descriptor)

	cancel()

	if err != nil {
		return configuredPreparationError(b.ctx, "configured Lua fact callback was rejected")
	}

	group.factProviders = append(group.factProviders, luaprovider.FactProviderRegistration{
		Collector: collector, Requires: definition.Requires(), Failure: definition.Failure(),
		DiagnosticID: definition.DiagnosticID(),
	})

	return nil
}

// registerEffects binds only normalized host effects to one selected-effect callback.
func (b *configuredGenerationBuilder) registerEffects(
	group *configuredLuaAuthority,
	namespace string,
	name string,
	definition registry.ProviderDefinition,
	effects []registry.EffectDefinition,
	script *luaprovider.Script,
) error {
	descriptor, err := b.configuredEffectDescriptor(namespace, name, definition, effects)
	if err != nil {
		return err
	}

	validationCtx, cancel := context.WithTimeout(b.ctx, definition.Timeout())
	executor, err := luaprovider.NewLuaEffectExecutor(validationCtx, script, descriptor)

	cancel()

	if err != nil {
		return configuredPreparationError(b.ctx, "configured Lua effect callback was rejected")
	}

	group.effectProviders = append(group.effectProviders, luaprovider.EffectProviderRegistration{
		Executor: executor, DiagnosticID: definition.DiagnosticID(),
	})
	group.effects = append(group.effects, effects...)

	return nil
}

// freezeAuthority runs the internal contribution adapter and retains exact normalized metadata.
func (b *configuredGenerationBuilder) freezeAuthority(group *configuredLuaAuthority) error {
	if err := b.ctx.Err(); err != nil {
		return err
	}

	ownership, err := registry.NewNamespaceOwnership(
		"lua."+group.authority,
		sortedConfiguredKeys(group.namespaces),
	)
	if err != nil {
		return invalidGenerationRegistration("configured Lua namespace ownership was rejected")
	}

	prepared, err := luaprovider.PrepareGeneration(b.ctx, luaprovider.GenerationInput{
		PostActionAcceptance: b.acceptance,
		Ownership:            ownership,
		FactProviders:        group.factProviders,
		EffectProviders:      group.effectProviders,
		Authority:            group.authority,
	})
	if err != nil {
		return configuredPreparationError(b.ctx, "configured Lua generation was rejected")
	}

	contribution, err := b.exactContribution(ownership, group)
	if err != nil {
		return err
	}

	preparedExtension, err := prepared.ExtensionPreparation(nil)
	if err != nil {
		return configuredPreparationError(b.ctx, "configured Lua bindings were rejected")
	}

	if err = b.mergePreparedBindings(preparedExtension.Bindings); err != nil {
		return err
	}

	b.preparedDefinitions = append(b.preparedDefinitions, contribution)

	return nil
}

// exactContribution preserves normalized schedule, diagnostics, effects, and host acceptance.
func (b *configuredGenerationBuilder) exactContribution(
	ownership registry.NamespaceOwnership,
	group *configuredLuaAuthority,
) (registry.DefinitionContribution, error) {
	providers := make([]registry.ExtensionProviderDefinition, 0, len(group.providers))
	for _, definition := range group.providers {
		configured, err := configuredProviderDefinition(definition, b.acceptance)
		if err != nil {
			return registry.DefinitionContribution{}, invalidGenerationRegistration(
				"configured Lua provider metadata was rejected",
			)
		}

		prefix := ""
		if len(configured.Outputs()) > 0 {
			prefix = "lua." + group.authority + "."
		}

		providers = append(providers, registry.ExtensionProviderDefinition{
			Definition: configured, ProducedFactPrefix: prefix,
		})
	}

	contribution, err := registry.NewExtensionDefinitionContribution(registry.ExtensionDefinitionContributionInput{
		Ownership: ownership, Providers: providers, Effects: group.effects,
	})
	if err != nil {
		return registry.DefinitionContribution{}, invalidGenerationRegistration(
			"configured Lua contribution metadata was rejected",
		)
	}

	return contribution, nil
}

// mergePreparedBindings rejects collisions while aggregating authority-owned callback owners.
func (b *configuredGenerationBuilder) mergePreparedBindings(prepared *policyruntime.BindingSet) error {
	if err := mergeConfiguredBindings(b.factBindings, prepared.FactProviders()); err != nil {
		return err
	}

	if err := mergeConfiguredBindings(b.syncBindings, prepared.SyncEffects()); err != nil {
		return err
	}

	return mergeConfiguredBindings(b.postBindings, prepared.PostActions())
}

// extensionPreparation owns the aggregate maps and includes native module bindings exactly once.
func (b *configuredGenerationBuilder) extensionPreparation(
	nativeModules []policyruntime.NativeModuleBindingInput,
) (policyruntime.ExtensionPreparation, error) {
	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		FactProviders: b.factBindings, SyncEffects: b.syncBindings, PostActions: b.postBindings,
		NativeModules: nativeModules, PostActionAcceptance: b.acceptance,
	})
	if err != nil {
		return policyruntime.ExtensionPreparation{}, invalidGenerationRegistration(
			"configured Lua binding aggregate was rejected",
		)
	}

	return policyruntime.ExtensionPreparation{
		Definitions: append([]registry.DefinitionContribution(nil), b.preparedDefinitions...),
		Bindings:    bindings,
	}, nil
}

// configuredFactDescriptor projects exact normalized targets and local fact capabilities.
func configuredFactDescriptor(
	namespace string,
	name string,
	authority string,
	definition registry.ProviderDefinition,
) (luaprovider.FactProviderDescriptor, error) {
	prefix := "lua." + authority + "."
	outputs := make([]luaprovider.FactOutputDescriptor, 0, len(definition.Outputs()))

	for _, output := range definition.Outputs() {
		local, found := strings.CutPrefix(output.ID(), prefix)
		if !found || local == "" {
			return luaprovider.FactProviderDescriptor{}, invalidGenerationRegistration(
				"configured Lua fact authority does not match its schema output",
			)
		}

		outputs = append(outputs, luaprovider.FactOutputDescriptor{
			Name: local, Category: output.Category(), Kind: output.Kind(),
			MaxLength: output.MaxLength(), MaxItems: output.MaxItems(), MaxBytes: output.MaxBytes(),
		})
	}

	return luaprovider.FactProviderDescriptor{
		Targets: targetSelectors(definition.Targets()), Outputs: outputs,
		Namespace: namespace, Name: name, Timeout: definition.Timeout(),
	}, nil
}

// configuredEffectDescriptor converts normalized selected effects without widening ownership.
func (b *configuredGenerationBuilder) configuredEffectDescriptor(
	namespace string,
	name string,
	provider registry.ProviderDefinition,
	effects []registry.EffectDefinition,
) (luaprovider.EffectProviderDescriptor, error) {
	descriptors := make([]luaprovider.EffectDescriptor, 0, len(effects))

	for _, effect := range effects {
		descriptor, err := b.configuredEffect(namespace, provider, effect)
		if err != nil {
			return luaprovider.EffectProviderDescriptor{}, err
		}

		descriptors = append(descriptors, descriptor)
	}

	return luaprovider.EffectProviderDescriptor{Namespace: namespace, Name: name, Effects: descriptors}, nil
}

// configuredEffect validates provider ownership and reconstructs exact typed parameter bounds.
func (b *configuredGenerationBuilder) configuredEffect(
	namespace string,
	provider registry.ProviderDefinition,
	effect registry.EffectDefinition,
) (luaprovider.EffectDescriptor, error) {
	local, found := strings.CutPrefix(effect.ID(), namespace+"/")

	configured, configuredFound := b.configuredEffects[effect.ID()]
	if !found || local == "" || !configuredFound || effect.Provider() != provider.ID() ||
		effect.Kind() != registry.EffectKindObligation {
		return luaprovider.EffectDescriptor{}, invalidGenerationRegistration("configured Lua effect ownership does not match")
	}

	for _, target := range effect.Targets() {
		if !provider.Supports(target, effect.Execution()) {
			return luaprovider.EffectDescriptor{}, invalidGenerationRegistration("configured Lua effect exceeds provider capability")
		}
	}

	parameters, err := configuredParameters(configured.Parameters, effect.Parameters())
	if err != nil {
		return luaprovider.EffectDescriptor{}, err
	}

	execution, err := configuredExecution(effect.Execution())
	if err != nil {
		return luaprovider.EffectDescriptor{}, err
	}

	return luaprovider.EffectDescriptor{
		Targets: targetSelectors(effect.Targets()), Parameters: parameters,
		Name: local, Execution: execution,
	}, nil
}

// configuredParameters joins normalized types with authored bounds from the validated snapshot.
func configuredParameters(
	configured map[string]policyconfig.EffectParameterConfig,
	parameters []registry.ParameterSchema,
) ([]luaprovider.ParameterDescriptor, error) {
	if len(configured) != len(parameters) {
		return nil, invalidGenerationRegistration("configured Lua effect parameters are ambiguous")
	}

	result := make([]luaprovider.ParameterDescriptor, 0, len(parameters))
	for _, parameter := range parameters {
		bounds, exists := configured[parameter.Name()]
		if !exists || decision.ValueKind(bounds.Type) != parameter.Kind() {
			return nil, invalidGenerationRegistration("configured Lua effect parameter does not match")
		}

		result = append(result, luaprovider.ParameterDescriptor{
			AllowedStrings: parameter.AllowedStrings(), Name: parameter.Name(), Kind: parameter.Kind(),
			MaxLength: bounds.MaxLength, MaxItems: bounds.MaxItems, MaxBytes: bounds.MaxBytes,
			NonEmpty: parameter.NonEmpty(), Required: parameter.Required(),
		})
	}

	return result, nil
}

// configuredProviderDefinition attaches mandatory host acceptance without changing normalized metadata.
func configuredProviderDefinition(
	definition registry.ProviderDefinition,
	acceptance effectsupervisor.Acceptor,
) (registry.ProviderDefinition, error) {
	input := registry.ProviderDefinitionInput{
		ID: definition.ID(), Targets: definition.Targets(), Executions: definition.Executions(),
		Requires: definition.Requires(), ProducedFacts: definition.ProducedFacts(), Outputs: definition.Outputs(),
		Failure: definition.Failure(), Timeout: definition.Timeout(), DiagnosticID: definition.DiagnosticID(),
	}

	if slices.Contains(input.Executions, registry.ExecutionHostPostAction) {
		input.PostActionAcceptance = acceptance
	}

	return registry.NewProviderDefinition(input)
}

// providerExecutionsMatchEffects rejects dangling or undeclared effect execution capabilities.
func providerExecutionsMatchEffects(
	executions []registry.ExecutionClass,
	effects []registry.EffectDefinition,
) bool {
	actual := make(map[registry.ExecutionClass]struct{}, len(effects))
	for _, effect := range effects {
		actual[effect.Execution()] = struct{}{}
	}

	if len(actual) != len(executions) {
		return false
	}

	for _, execution := range executions {
		if _, exists := actual[execution]; !exists {
			return false
		}
	}

	return true
}

// configuredExecution maps the closed registry execution vocabulary inward.
func configuredExecution(execution registry.ExecutionClass) (luaprovider.EffectExecution, error) {
	switch execution {
	case registry.ExecutionHostSync:
		return luaprovider.EffectExecutionHostSync, nil
	case registry.ExecutionHostPostAction:
		return luaprovider.EffectExecutionHostPostAction, nil
	default:
		return "", invalidGenerationRegistration("configured Lua effect execution was rejected")
	}
}

// targetSelectors converts exact immutable targets into callback capability metadata.
func targetSelectors(targets []decision.Target) []luaprovider.TargetSelector {
	result := make([]luaprovider.TargetSelector, 0, len(targets))
	for _, target := range targets {
		result = append(result, luaprovider.TargetSelector{Namespace: target.Namespace(), Action: target.Action()})
	}

	return result
}

// configuredEffect resolves one authored effect by its canonical identity.
func configuredEffect(
	policy policyconfig.PolicyConfig,
	effectID string,
) (policyconfig.EffectConfig, bool) {
	namespace, name, found := strings.Cut(effectID, "/")
	if !found {
		return policyconfig.EffectConfig{}, false
	}

	configuredNamespace, exists := policy.Namespaces[namespace]
	if !exists {
		return policyconfig.EffectConfig{}, false
	}

	effect, exists := configuredNamespace.Effects[name]

	return effect, exists
}

// mergeConfiguredBindings inserts immutable owners once across all Lua authorities.
func mergeConfiguredBindings[T any](destination map[string]T, source map[string]T) error {
	for id, binding := range source {
		if _, exists := destination[id]; exists {
			return invalidGenerationRegistration("configured Lua binding identity occurs more than once")
		}

		destination[id] = binding
	}

	return nil
}

// sortedConfiguredKeys returns deterministic keys for maps used during preparation.
func sortedConfiguredKeys[V any](values map[string]V) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}

	sort.Strings(result)

	return result
}

// configuredPreparationError preserves cancellation and otherwise returns one bounded class.
func configuredPreparationError(ctx context.Context, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return invalidGenerationRegistration(reason)
}

// normalizeLuaPreparationContext supplies a usable cancellation root for direct callers.
func normalizeLuaPreparationContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}

	return ctx
}

// nilLuaPreparationDependency rejects nil and typed-nil host capabilities.
func nilLuaPreparationDependency(input any) bool {
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

// invalidGenerationRegistration returns the shared bounded Lua registration class.
func invalidGenerationRegistration(reason string) error {
	return fmt.Errorf("%w: %s", luaprovider.ErrInvalidGenerationRegistration, reason)
}
