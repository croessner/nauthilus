// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package policyfx wires the sole atomic policy runtime generation coordinator.
package policyfx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/app/reloadfx"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/core"
	corelanguage "github.com/croessner/nauthilus/v3/server/core/language"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v3/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/pluginregistry"
	"github.com/croessner/nauthilus/v3/server/pluginruntime"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/admission"
	"github.com/croessner/nauthilus/v3/server/policy/callerauth"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/observability"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/secret"

	"go.uber.org/fx"
)

const (
	defaultPostActionCapacity = 256
	defaultPostActionWorkers  = 8
	defaultEvaluationTimeout  = 5 * time.Second
	defaultPostActionBudget   = 30 * time.Second
	defaultDiagnosticsEntries = 128
	defaultReportEntries      = 256
	internalTransportKind     = "internal"
	internalListenerName      = "nauthilus-authn"
	authnSourceEnvironment    = "environment"
	authnSourceSubject        = "subject"
)

// AccessTokenValidatorFactory builds candidate-scoped token authority from the unpublished config.
type AccessTokenValidatorFactory func(context.Context, config.File) (callerauth.AccessTokenValidator, error)

// BasicThrottlerFactory builds candidate-scoped Policy-Basic attempt authority.
type BasicThrottlerFactory func(context.Context, config.File) (callerauth.BasicThrottler, error)

// TransportCapabilitiesFactory validates and projects protected Policy transport capabilities.
type TransportCapabilitiesFactory func(context.Context, config.File) (callerauth.TransportCapabilities, error)

type policyPreparationSlot struct{}

type artifactSnapshotResourceContextKey struct{}

type extensionPreparationSlot struct {
	native *pluginruntime.GenerationBindings
	pools  *vmpool.Manager
	logger *slog.Logger
}

type extensionCandidateBuilder struct {
	ctx                context.Context
	input              policyruntime.PreparationInput
	slot               extensionPreparationSlot
	prepared           *configinput.PreparedPolicy
	supervisor         *effectsupervisor.Supervisor
	resource           *supervisorResource
	artifacts          *config.ArtifactSnapshot
	modules            *luaseal.Modules
	observer           *pluginruntime.OperationalObserver
	nativeModules      []policyruntime.NativeModuleBindingInput
	nativeCapabilities []registry.NativeFactProviderCapability
}

type preparedAuthnExtensions struct {
	native        *pluginruntime.AuthenticationBindings
	hostProviders map[string]policyruntime.AuthnHostProvider
	luaProviders  map[string]policyruntime.AuthnHostProvider
	luaFacts      []registry.AuthnLuaFactDeclaration
	conditionSets map[string][]decision.Value
	timeWindows   map[string]policyruntime.CompiledTimeWindow
	actions       policyruntime.ExtensionPreparation
	nativeEffects *policyruntime.BindingSet
}

type preparedGenericExtensions struct {
	lua           policyruntime.ExtensionPreparation
	nativeFacts   policyruntime.ExtensionPreparation
	nativeEffects policyruntime.ExtensionPreparation
}

type catalogPreparationSlot struct{}

type callerAuthenticationPreparationSlot struct {
	tokens     AccessTokenValidatorFactory
	throttlers BasicThrottlerFactory
	transports TransportCapabilitiesFactory
}

type admissionPreparationSlot struct{}

type settingsPreparationSlot struct {
	system  localization.Catalog
	startup *StartupCatalog
}

type supervisorResource struct {
	supervisor *effectsupervisor.Supervisor
}

type artifactSnapshotResource struct {
	snapshot *config.ArtifactSnapshot
	once     sync.Once
}

// Coordinator adapts config snapshots to the sole runtime generation protocol.
type Coordinator struct {
	runtime *policyruntime.Coordinator
	restart RestartBaselineValidator
}

type coordinatorOutput struct {
	fx.Out

	Coordinator *Coordinator
	Reload      reloadfx.GenerationCoordinator
}

type decisionServiceOutput struct {
	fx.Out

	Concrete *decisionservice.DecisionService
	Prepared decisionservice.PreparedService
	Sessions decisionservice.DecisionSessionFactory
}

// Module registers the sole coordinator, Decision Service, and captured-session authority.
func Module() fx.Option {
	return fx.Options(
		fx.Provide(provideStartupCatalog),
		fx.Provide(provideRestartBaseline),
		fx.Provide(provideCoordinator),
		fx.Provide(provideDecisionService),
	)
}

// NewCoordinator constructs production preparation over the injected sole store and process plugin capture.
func NewCoordinator(
	store *policyruntime.GenerationStore,
	logger *slog.Logger,
	pluginState *pluginloader.State,
	tokens AccessTokenValidatorFactory,
	throttlers BasicThrottlerFactory,
	transports TransportCapabilitiesFactory,
	system localization.Catalog,
	startup *StartupCatalog,
	restart RestartBaselineValidator,
) (*Coordinator, error) {
	if store == nil || pluginState == nil || tokens == nil || throttlers == nil || transports == nil ||
		system == nil || startup == nil || restart == nil {
		return nil, fmt.Errorf("%w: production Policy dependencies are incomplete", policyruntime.ErrInvalidGeneration)
	}

	native, err := pluginruntime.CaptureGenerationBindings(pluginState.Instances())
	if err != nil {
		return nil, err
	}

	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{
		Store:  store,
		Logger: logger,
		Slots: policyruntime.PreparationSlots{
			Policy:               policyPreparationSlot{},
			Extensions:           extensionPreparationSlot{native: native, pools: vmpool.NewManager(), logger: logger},
			Catalog:              catalogPreparationSlot{},
			CallerAuthentication: callerAuthenticationPreparationSlot{tokens: tokens, throttlers: throttlers, transports: transports},
			Admission:            admissionPreparationSlot{},
			Settings:             settingsPreparationSlot{system: system, startup: startup},
			Application:          decisionservice.NewRuntimeApplicationPreparationSlot(),
			Validators:           []policyruntime.GenerationValidator{artifactSnapshotGenerationValidator{}},
		},
	})
	if err != nil {
		return nil, err
	}

	return &Coordinator{runtime: coordinator, restart: restart}, nil
}

// provideCoordinator publishes concrete and reload views of the same coordinator instance.
func provideCoordinator(
	store *policyruntime.GenerationStore,
	logger *slog.Logger,
	pluginState *pluginloader.State,
	tokens AccessTokenValidatorFactory,
	throttlers BasicThrottlerFactory,
	transports TransportCapabilitiesFactory,
	languageManager corelanguage.Manager,
	startup *StartupCatalog,
	restart RestartBaselineValidator,
) (coordinatorOutput, error) {
	if languageManager == nil {
		return coordinatorOutput{}, fmt.Errorf("%w: language manager is required", policyruntime.ErrInvalidGeneration)
	}

	coordinator, err := NewCoordinator(
		store,
		logger,
		pluginState,
		tokens,
		throttlers,
		transports,
		localization.NewManagerCatalog(languageManager),
		startup,
		restart,
	)
	if err != nil {
		return coordinatorOutput{}, err
	}

	return coordinatorOutput{Coordinator: coordinator, Reload: coordinator}, nil
}

// provideDecisionService exposes every transport and internal-session view over one captured store source.
func provideDecisionService(store *policyruntime.GenerationStore, logger *slog.Logger) (decisionServiceOutput, error) {
	source, err := decisionservice.NewStoreGenerationSource(store)
	if err != nil {
		return decisionServiceOutput{}, err
	}

	observer, err := observability.NewDecisionServiceObserver(logger, nil)
	if err != nil {
		return decisionServiceOutput{}, err
	}

	service, err := decisionservice.NewDecisionService(source, decisionservice.WithDecisionObserver(observer))
	if err != nil {
		return decisionServiceOutput{}, err
	}

	return decisionServiceOutput{Concrete: service, Prepared: service, Sessions: service}, nil
}

// Apply prepares, validates, and commits one complete config-derived generation.
func (c *Coordinator) Apply(ctx context.Context, snapshot configfx.Snapshot) error {
	if c == nil || c.runtime == nil || c.restart == nil || snapshot.File == nil || snapshot.Version == 0 {
		return policyruntime.ErrInvalidGeneration
	}

	ctx, resource, err := claimCandidateArtifactContext(ctx, snapshot.File)
	if err != nil {
		return err
	}

	if err = c.restart.Validate(snapshot.File); err != nil {
		_ = resource.Dispose(ctx)

		return err
	}

	generation, err := c.runtime.Apply(ctx, policyruntime.PrepareInput{Config: snapshot.File, ID: snapshot.Version})
	if err != nil && generation == nil {
		_ = resource.Dispose(ctx)
	}

	return err
}

// claimCandidateArtifactContext seals one config and binds its transferable lifecycle owner to preparation.
func claimCandidateArtifactContext(
	ctx context.Context,
	configured config.File,
) (context.Context, *artifactSnapshotResource, error) {
	artifacts, err := config.EnsureArtifactSnapshot(configured)
	if err != nil {
		return ctx, nil, err
	}

	resource, err := newArtifactSnapshotResource(artifacts)
	if err != nil {
		return ctx, nil, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	return context.WithValue(ctx, artifactSnapshotResourceContextKey{}, resource), resource, nil
}

// newArtifactSnapshotResource claims one candidate lease for transfer into a committed generation.
func newArtifactSnapshotResource(snapshot *config.ArtifactSnapshot) (*artifactSnapshotResource, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("%w: candidate artifact snapshot is nil", policyruntime.ErrInvalidGeneration)
	}

	if err := snapshot.ClaimCandidateOwner(); err != nil {
		return nil, fmt.Errorf("%w: %v", policyruntime.ErrInvalidGeneration, err)
	}

	return &artifactSnapshotResource{snapshot: snapshot}, nil
}

// Prepare freezes the normalized top-level Policy model without publishing it.
func (policyPreparationSlot) Prepare(
	ctx context.Context,
	input policyruntime.PreparationInput,
) (policyruntime.PolicyPreparation, error) {
	resource, ok := ctx.Value(artifactSnapshotResourceContextKey{}).(*artifactSnapshotResource)
	if !ok || resource == nil || resource.snapshot == nil {
		return policyruntime.PolicyPreparation{}, fmt.Errorf(
			"%w: candidate artifact ownership is missing",
			policyruntime.ErrInvalidGeneration,
		)
	}

	prepared, err := configinput.PreparePolicy(ctx, input.ID(), input.Config().GetPolicy())
	if err != nil {
		return policyruntime.PolicyPreparation{}, err
	}

	return policyruntime.PolicyPreparation{
		Policy:    prepared,
		Resources: []policyruntime.CandidateResource{resource},
	}, nil
}

// Dispose releases one candidate or retired generation's artifact ownership exactly once.
func (r *artifactSnapshotResource) Dispose(context.Context) error {
	if r == nil {
		return nil
	}

	r.once.Do(func() {
		r.snapshot.Release()
	})

	return nil
}

type artifactSnapshotGenerationValidator struct{}

// Validate rejects exact-byte or directory-membership drift after candidate preparation.
func (artifactSnapshotGenerationValidator) Validate(
	_ context.Context,
	generation *policyruntime.Generation,
) error {
	if generation == nil {
		return policyruntime.ErrInvalidGeneration
	}

	snapshot, err := config.ArtifactSnapshotFor(generation.Config())
	if err != nil {
		return fmt.Errorf("%w: candidate artifact snapshot is missing: %v", policyruntime.ErrInvalidGeneration, err)
	}

	if err = snapshot.ValidateLive(); err != nil {
		return fmt.Errorf("%w: %v", config.ErrArtifactSnapshotDrift, err)
	}

	return nil
}

// Prepare builds one candidate-owned supervisor and composes builtin, Lua, and native bindings.
func (s extensionPreparationSlot) Prepare(
	ctx context.Context,
	input policyruntime.PreparationInput,
) (policyruntime.ExtensionPreparation, error) {
	if err := validateExtensionPluginReload(input); err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	builder, err := newExtensionCandidateBuilder(ctx, input, s)
	if err != nil {
		if builder != nil {
			return builder.failure(err)
		}

		return policyruntime.ExtensionPreparation{}, err
	}

	return builder.prepare()
}

// validateExtensionPluginReload rejects process-owned native plugin drift before allocating candidate resources.
func validateExtensionPluginReload(input policyruntime.PreparationInput) error {
	previous := input.PreviousConfig()
	if previous == nil || reflect.DeepEqual(previous.GetPlugins(), input.Config().GetPlugins()) {
		return nil
	}

	return fmt.Errorf("%w: native plugin configuration changed", pluginruntime.ErrRestartRequired)
}

// newExtensionCandidateBuilder captures shared candidate dependencies and one owned post-action supervisor.
func newExtensionCandidateBuilder(
	ctx context.Context,
	input policyruntime.PreparationInput,
	slot extensionPreparationSlot,
) (*extensionCandidateBuilder, error) {
	prepared, err := preparedPolicy(input.Policy())
	if err != nil {
		return nil, err
	}

	providerIDs, err := slot.extensionPostActionProviderIDs(prepared)
	if err != nil {
		return nil, err
	}

	supervisor, err := newEffectSupervisor(providerIDs, slot.logger)
	if err != nil {
		return nil, err
	}

	builder := &extensionCandidateBuilder{
		ctx: ctx, input: input, slot: slot, prepared: prepared, supervisor: supervisor,
		resource: &supervisorResource{supervisor: supervisor},
		observer: pluginruntime.NewOperationalObserver(slot.logger),
	}
	if err = builder.captureInputs(); err != nil {
		return builder, err
	}

	return builder, nil
}

// extensionPostActionProviderIDs merges configured and captured native provider identities.
func (s extensionPreparationSlot) extensionPostActionProviderIDs(
	prepared *configinput.PreparedPolicy,
) ([]string, error) {
	nativeIDs, err := s.native.AuthenticationPostActionProviderIDs()
	if err != nil {
		return nil, err
	}

	return uniqueBindingIDs(prepared.PostActionProviderIDs(), nativeIDs, "post-action provider")
}

// captureInputs freezes artifacts, modules, native metadata, and native capabilities for the builder.
func (b *extensionCandidateBuilder) captureInputs() error {
	artifacts, err := config.ArtifactSnapshotFor(b.input.Config())
	if err != nil {
		return fmt.Errorf("open generation-owned Lua artifacts: %w", err)
	}

	modules, err := luaseal.CaptureSnapshot(config.EffectiveLuaPackagePatterns(b.input.Config()), artifacts)
	if err != nil {
		return fmt.Errorf("capture generation-owned Lua modules: %w", err)
	}

	capabilities, err := nativeFactCapabilities(b.slot.native)
	if err != nil {
		return err
	}

	b.artifacts = artifacts
	b.modules = modules
	b.nativeModules = nativeModuleBindingInputs(b.slot.native)
	b.nativeCapabilities = capabilities

	return nil
}

// failure returns the candidate resource so the coordinator disposes it after preparation failure.
func (b *extensionCandidateBuilder) failure(cause error) (policyruntime.ExtensionPreparation, error) {
	return policyruntime.ExtensionPreparation{
		Resources: []policyruntime.CandidateResource{b.resource},
	}, cause
}

// prepare composes all extension families into one complete candidate preparation.
func (b *extensionCandidateBuilder) prepare() (policyruntime.ExtensionPreparation, error) {
	authn, err := b.prepareAuthnExtensions()
	if err != nil {
		return b.failure(err)
	}

	generic, err := b.prepareGenericExtensions()
	if err != nil {
		return b.failure(err)
	}

	result, err := b.composeExtensions(authn, generic)
	if err != nil {
		return b.failure(err)
	}

	return result, nil
}

// prepareAuthnExtensions builds scheduled Lua and native authn sources, facts, conditions, and effects.
func (b *extensionCandidateBuilder) prepareAuthnExtensions() (preparedAuthnExtensions, error) {
	configured := b.prepared.Config()

	pluginSources, err := b.prepared.AuthnPluginSources()
	if err != nil {
		return preparedAuthnExtensions{}, err
	}

	nativeSources, err := authenticationSourceBindingInputs(pluginSources)
	if err != nil {
		return preparedAuthnExtensions{}, err
	}

	native, err := b.slot.native.PrepareAuthenticationBindings(b.ctx, pluginruntime.AuthenticationBindingInput{
		PostActionAcceptance: b.supervisor, Observer: b.observer, Sources: nativeSources,
	})
	if err != nil {
		return preparedAuthnExtensions{}, err
	}

	luaProviders, err := configinput.PrepareConfiguredAuthnLuaSources(
		b.ctx, b.input.ID(), configured, b.artifacts, b.modules, b.slot.pools,
	)
	if err != nil {
		return preparedAuthnExtensions{}, err
	}

	hostProviders := maps.Clone(luaProviders)
	if err = mergeBindingMap(hostProviders, native.AuthnHostProviders(), "authn host provider"); err != nil {
		return preparedAuthnExtensions{}, err
	}

	return b.prepareAuthnMaterial(configured, native, hostProviders, luaProviders)
}

// prepareAuthnMaterial completes authn registry, condition, and effect material after sources are bound.
func (b *extensionCandidateBuilder) prepareAuthnMaterial(
	configured policyconfig.PolicyConfig,
	native *pluginruntime.AuthenticationBindings,
	hostProviders map[string]policyruntime.AuthnHostProvider,
	luaProviders map[string]policyruntime.AuthnHostProvider,
) (preparedAuthnExtensions, error) {
	luaFacts, err := configinput.PrepareConfiguredAuthnLuaFacts(b.ctx, configured, b.artifacts)
	if err != nil {
		return preparedAuthnExtensions{}, err
	}

	conditionSets, timeWindows, err := configinput.PrepareConditionMaterial(configured)
	if err != nil {
		return preparedAuthnExtensions{}, err
	}

	actions, err := configinput.PrepareConfiguredAuthnLuaActions(b.ctx, configinput.ConfiguredAuthnLuaActionInput{
		PostActionAcceptance: b.supervisor, Artifacts: b.artifacts, Modules: b.modules,
		Pools: b.slot.pools, Policy: configured, Generation: b.input.ID(),
	})
	if err != nil {
		return preparedAuthnExtensions{}, err
	}

	nativeEffects, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		SyncEffects: native.SyncEffects(), PostActions: native.PostActions(), PostActionAcceptance: b.supervisor,
	})
	if err != nil {
		return preparedAuthnExtensions{}, err
	}

	return preparedAuthnExtensions{
		native: native, hostProviders: hostProviders, luaProviders: luaProviders, luaFacts: luaFacts,
		conditionSets: conditionSets, timeWindows: timeWindows, actions: actions, nativeEffects: nativeEffects,
	}, nil
}

// prepareGenericExtensions prepares configured Lua and native fact/effect owners.
func (b *extensionCandidateBuilder) prepareGenericExtensions() (preparedGenericExtensions, error) {
	configured := b.prepared.Config()

	lua, err := configinput.PrepareConfiguredLuaGeneration(b.ctx, configinput.ConfiguredLuaGenerationInput{
		PostActionAcceptance: b.supervisor, Artifacts: b.artifacts, Policy: configured,
	})
	if err != nil {
		return preparedGenericExtensions{}, err
	}

	nativeFacts, err := configinput.PrepareBoundNativeFactGeneration(b.ctx, configinput.BoundNativeFactGenerationInput{
		Bindings: b.slot.native, PostActionAcceptance: b.supervisor, Observer: b.observer,
		Policy: configured, Capabilities: b.nativeCapabilities, NativeModules: b.nativeModules,
	})
	if err != nil {
		return preparedGenericExtensions{}, err
	}

	nativeEffects, err := configinput.PrepareConfiguredNativeGeneration(b.ctx, configinput.ConfiguredNativeGenerationInput{
		Bindings: b.slot.native, PostActionAcceptance: b.supervisor, Observer: b.observer,
		Policy: configured, FactProvidersPrepared: true,
	})
	if err != nil {
		return preparedGenericExtensions{}, err
	}

	return preparedGenericExtensions{lua: lua, nativeFacts: nativeFacts, nativeEffects: nativeEffects}, nil
}

// composeExtensions merges prepared owners and projects their complete resources and definitions.
func (b *extensionCandidateBuilder) composeExtensions(
	authn preparedAuthnExtensions,
	generic preparedGenericExtensions,
) (policyruntime.ExtensionPreparation, error) {
	bindings, err := composeBindingSet(
		b.supervisor, b.nativeModules, authn.hostProviders, authn.luaFacts, authn.native.PolicyAttributes(),
		authn.conditionSets, authn.timeWindows, authn.actions.Bindings, generic.lua.Bindings,
		generic.nativeFacts.Bindings, generic.nativeEffects.Bindings, authn.nativeEffects,
	)
	if err != nil {
		return policyruntime.ExtensionPreparation{}, err
	}

	resources := b.extensionResources(authn, generic)
	definitions := append([]registry.DefinitionContribution(nil), generic.lua.Definitions...)
	definitions = append(definitions, generic.nativeFacts.Definitions...)
	definitions = append(definitions, generic.nativeEffects.Definitions...)

	return policyruntime.ExtensionPreparation{
		Bindings: bindings, Definitions: definitions,
		ImplicitDefinitions: authn.native.Definitions(), Resources: resources,
	}, nil
}

// extensionResources orders every candidate-owned resource behind the supervisor owner.
func (b *extensionCandidateBuilder) extensionResources(
	authn preparedAuthnExtensions,
	generic preparedGenericExtensions,
) []policyruntime.CandidateResource {
	resources := []policyruntime.CandidateResource{b.resource}
	resources = append(resources, configinput.AuthnLuaSourceResources(authn.luaProviders)...)
	resources = append(resources, authn.actions.Resources...)
	resources = append(resources, generic.lua.Resources...)
	resources = append(resources, generic.nativeFacts.Resources...)
	resources = append(resources, generic.nativeEffects.Resources...)

	return resources
}

// Dispose closes admission and drains every accepted generation-owned post action.
func (r *supervisorResource) Dispose(ctx context.Context) error {
	if r == nil || r.supervisor == nil {
		return nil
	}

	return r.supervisor.Shutdown(ctx)
}

// newEffectSupervisor allocates one executable-work acceptor for every configured post-action owner.
func newEffectSupervisor(providerIDs []string, logger *slog.Logger) (*effectsupervisor.Supervisor, error) {
	bindings := make([]effectsupervisor.ProviderBinding, 0, len(providerIDs))
	for _, providerID := range providerIDs {
		bindings = append(bindings, effectsupervisor.ProviderBinding{
			Name: providerID, Provider: effectsupervisor.NewExecutableProvider(),
		})
	}

	observer := effectsupervisor.NewOperationalObserver(
		logger,
		nil,
		effectsupervisor.NewLoggingAuditSink(logger),
	)

	return effectsupervisor.New(effectsupervisor.Config{
		Lifetime: context.Background(), Observer: observer,
		Capacity: defaultPostActionCapacity, Workers: defaultPostActionWorkers,
	}, bindings...)
}

// composeBindingSet merges standard and prepared extension owners with collision rejection.
func composeBindingSet(
	acceptance effectsupervisor.Acceptor,
	nativeModules []policyruntime.NativeModuleBindingInput,
	authnHostProviders map[string]policyruntime.AuthnHostProvider,
	authnLuaFacts []registry.AuthnLuaFactDeclaration,
	authnPolicyAttributes map[string]registry.AttributeDefinition,
	conditionSets map[string][]decision.Value,
	timeWindows map[string]policyruntime.CompiledTimeWindow,
	parts ...*policyruntime.BindingSet,
) (*policyruntime.BindingSet, error) {
	syncEffects, postActions := core.AuthnStandardEffectBindings()
	factProviders := make(map[string]policyruntime.FactProviderBinding)

	for _, part := range parts {
		if part == nil {
			return nil, fmt.Errorf("%w: extension preparation returned no bindings", policyruntime.ErrInvalidGenerationBinding)
		}

		if err := mergeBindingMap(factProviders, part.FactProviders(), "fact provider"); err != nil {
			return nil, err
		}

		if err := mergeBindingMap(syncEffects, part.SyncEffects(), "synchronous effect"); err != nil {
			return nil, err
		}

		if err := mergeBindingMap(postActions, part.PostActions(), "post action"); err != nil {
			return nil, err
		}
	}

	return policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		FactProviders: factProviders, SyncEffects: syncEffects, PostActions: postActions,
		AuthnHostProviders:    authnHostProviders,
		AuthnLuaFacts:         authnLuaFacts,
		AuthnPolicyAttributes: authnPolicyAttributes,
		ConditionSets:         conditionSets,
		TimeWindows:           timeWindows,
		NativeModules:         nativeModules, PostActionAcceptance: acceptance,
	})
}

// authenticationSourceBindingInputs maps normalized scheduled selections to the native preparation boundary.
func authenticationSourceBindingInputs(
	sources []configinput.AuthnPluginSourceDefinition,
) ([]pluginruntime.AuthenticationSourceBindingInput, error) {
	result := make([]pluginruntime.AuthenticationSourceBindingInput, 0, len(sources))
	for _, source := range sources {
		kind := pluginruntime.AuthenticationSourceEnvironment

		switch source.Family {
		case authnSourceEnvironment:
		case authnSourceSubject:
			kind = pluginruntime.AuthenticationSourceSubject
		default:
			return nil, fmt.Errorf("unsupported native authn source family %s", source.Family)
		}

		result = append(result, pluginruntime.AuthenticationSourceBindingInput{
			InstanceNames: source.InstanceNames, Operations: source.Operations, ProviderID: source.ProviderID,
			ModuleName: source.ModuleName, ComponentName: source.ComponentName,
			Kind: kind, Order: source.Order,
		})
	}

	return result, nil
}

// uniqueBindingIDs joins sorted provider identities without permitting duplicate owners.
func uniqueBindingIDs(parts []string, additions []string, kind string) ([]string, error) {
	seen := make(map[string]struct{}, len(parts)+len(additions))

	result := make([]string, 0, len(parts)+len(additions))
	for _, identity := range append(append([]string(nil), parts...), additions...) {
		if _, duplicate := seen[identity]; duplicate {
			return nil, fmt.Errorf("%w: duplicate %s %s", policyruntime.ErrInvalidGenerationBinding, kind, identity)
		}

		seen[identity] = struct{}{}
		result = append(result, identity)
	}

	sort.Strings(result)

	return result, nil
}

// mergeBindingMap adds one prepared owner map without permitting ambiguous identities.
func mergeBindingMap[T any](destination map[string]T, source map[string]T, kind string) error {
	for identity, owner := range source {
		if _, duplicate := destination[identity]; duplicate {
			return fmt.Errorf("%w: duplicate %s %s", policyruntime.ErrInvalidGenerationBinding, kind, identity)
		}

		destination[identity] = owner
	}

	return nil
}

// nativeModuleBindingInputs maps the frozen process capture into generation-owned metadata.
func nativeModuleBindingInputs(bindings *pluginruntime.GenerationBindings) []policyruntime.NativeModuleBindingInput {
	modules := bindings.Modules()
	result := make([]policyruntime.NativeModuleBindingInput, 0, len(modules))
	for _, module := range modules {
		components := module.Components()
		componentInputs := make([]policyruntime.NativeComponentBindingInput, 0, len(components))
		for _, component := range components {
			componentInputs = append(componentInputs, policyruntime.NativeComponentBindingInput{
				Value: component.Value, QualifiedName: component.QualifiedName, Kind: string(component.Kind),
			})
		}

		capabilities := module.Capabilities()
		capabilityNames := make([]string, 0, len(capabilities))
		for _, capability := range capabilities {
			capabilityNames = append(capabilityNames, string(capability))
		}

		digest := module.ArtifactDigest()
		result = append(result, policyruntime.NativeModuleBindingInput{
			Components: componentInputs, Capabilities: capabilityNames,
			ModuleName: module.ModuleName(), ArtifactPath: module.ArtifactPath(),
			ArtifactDigest: hex.EncodeToString(digest[:]),
		})
	}

	return result
}

// nativeFactCapabilities projects captured descriptors through the transport-neutral registry boundary.
func nativeFactCapabilities(
	bindings *pluginruntime.GenerationBindings,
) ([]registry.NativeFactProviderCapability, error) {
	capabilities := make([]registry.NativeFactProviderCapability, 0)

	for _, module := range bindings.Modules() {
		for _, component := range module.Components() {
			if component.Kind != pluginregistry.ComponentKindDecisionFactProvider {
				continue
			}

			descriptor := component.DecisionFactProviderDescriptor
			if err := pluginapi.ValidateDecisionFactProviderDescriptor(descriptor); err != nil {
				return nil, fmt.Errorf("native fact provider %s descriptor: %w", component.QualifiedName, err)
			}

			targets := make([]decision.Target, 0, len(descriptor.Targets))
			for _, target := range descriptor.Targets {
				projected, err := decision.NewTarget(target.Namespace, target.Action)
				if err != nil {
					return nil, err
				}

				targets = append(targets, projected)
			}

			outputs := make([]registry.NativeFactOutputCapabilityInput, 0, len(descriptor.Outputs))
			for _, output := range descriptor.Outputs {
				outputs = append(outputs, registry.NativeFactOutputCapabilityInput{
					Name: output.Name, Category: decision.FactCategory(output.Category),
					Kind: decision.ValueKind(output.Kind), MaxLength: output.MaxLength,
					MaxItems: output.MaxItems, MaxBytes: output.MaxBytes,
				})
			}

			capability, err := registry.NewNativeFactProviderCapability(
				registry.NativeFactProviderCapabilityInput{
					Targets: targets, Outputs: outputs, ModuleName: module.ModuleName(),
					Namespace: descriptor.Namespace, ComponentName: descriptor.Name,
					MaximumTimeout: descriptor.Timeout,
				},
			)
			if err != nil {
				return nil, err
			}

			capabilities = append(capabilities, capability)
		}
	}

	return capabilities, nil
}

// Prepare compiles configured activations only after real extension definitions are available.
func (catalogPreparationSlot) Prepare(
	ctx context.Context,
	input policyruntime.CatalogPreparationInput,
) (policyruntime.CatalogPreparation, error) {
	prepared, err := preparedPolicy(input.Policy())
	if err != nil {
		return policyruntime.CatalogPreparation{}, err
	}

	catalog, definitions, err := prepared.CompileCandidateWithAuthnExtensions(
		ctx,
		input.Bindings().PostActionAcceptance(),
		input.Definitions(),
		input.Bindings().AuthnLuaFacts(),
		input.Bindings().AuthnPolicyAttributes(),
		input.ImplicitDefinitions(),
	)
	if err != nil {
		return policyruntime.CatalogPreparation{}, err
	}

	return policyruntime.CatalogPreparation{Catalog: catalog, Definitions: definitions}, nil
}

// Prepare builds external and exact code-owned internal credential presentations together.
func (s callerAuthenticationPreparationSlot) Prepare(
	ctx context.Context,
	input policyruntime.AuthorityPreparationInput,
) (policyruntime.CallerAuthenticationPreparation, error) {
	prepared, err := preparedPolicy(input.Policy())
	if err != nil {
		return policyruntime.CallerAuthenticationPreparation{}, err
	}

	configuration := prepared.CallerAuthentication()
	if requiresBearer(configuration) {
		configuration.TokenValidator, err = s.tokens(ctx, input.Config())
		if err != nil {
			return policyruntime.CallerAuthenticationPreparation{}, err
		}
	}

	if configuration.RequiresBasicThrottler() {
		configuration.Throttler, err = s.throttlers(ctx, input.Config())
		if err != nil {
			return policyruntime.CallerAuthenticationPreparation{}, err
		}
	}

	configuration.TransportCapabilities, err = s.transports(ctx, input.Config())
	if err != nil {
		return policyruntime.CallerAuthenticationPreparation{}, err
	}

	profiles, presentations, err := internalCallerMaterial()
	if err != nil {
		return policyruntime.CallerAuthenticationPreparation{}, err
	}

	configuration.InternalCallers = profiles

	result, err := callerauth.Prepare(configuration)
	if err != nil {
		return policyruntime.CallerAuthenticationPreparation{}, err
	}

	result.InternalPresentations = presentations

	return result, nil
}

// requiresBearer reports whether any external profile activates access-token authentication.
func requiresBearer(configuration callerauth.Configuration) bool {
	for _, profile := range configuration.ExternalProfiles {
		if slices.Contains(profile.AuthenticationKinds, policy.CallerAuthenticationKindBearer) {
			return true
		}
	}

	return false
}

// internalCallerMaterial creates paired verifier and presentation material for every code-owned profile.
func internalCallerMaterial() ([]callerauth.InternalCaller, map[string]decision.AuthenticationInput, error) {
	profileIDs, err := core.AuthnInternalProfileIDs()
	if err != nil {
		return nil, nil, err
	}

	callers := make([]callerauth.InternalCaller, 0, len(profileIDs))

	presentations := make(map[string]decision.AuthenticationInput, len(profileIDs))
	for _, profileID := range profileIDs {
		capability := make([]byte, 32)
		if _, err = rand.Read(capability); err != nil {
			return nil, nil, fmt.Errorf("prepare internal Policy caller capability: %w", err)
		}

		evidenceKind := "nauthilus.authn." + strings.ReplaceAll(profileID.String(), ":", ".")

		presentation, presentationErr := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
			Kind: evidenceKind, Credential: capability, TransportKind: internalTransportKind,
			Listener: internalListenerName, Protected: true,
		})
		if presentationErr != nil {
			return nil, nil, presentationErr
		}

		callers = append(callers, callerauth.InternalCaller{
			Capability: secret.FromBytes(capability), EvidenceKind: evidenceKind,
			Principal: profileID.String(), TransportKinds: []string{internalTransportKind},
			RequireProtected: true,
		})
		presentations[profileID.String()] = presentation
	}

	return callers, presentations, nil
}

// Prepare adds exact code-owned internal grants to operator-owned external admission profiles.
func (admissionPreparationSlot) Prepare(
	_ context.Context,
	input policyruntime.AdmissionPreparationInput,
) (policyruntime.AdmissionPreparation, error) {
	prepared, err := preparedPolicy(input.Policy())
	if err != nil {
		return policyruntime.AdmissionPreparation{}, err
	}

	configuration := prepared.CallerAdmission()

	profiles, err := internalAdmissionProfiles(input.TargetCatalog())
	if err != nil {
		return policyruntime.AdmissionPreparation{}, err
	}

	configuration.Profiles = append(configuration.Profiles, profiles...)

	return admission.Prepare(configuration, input.TargetCatalog(), input.CredentialProfiles())
}

// internalAdmissionProfiles maps each code-owned operation to its activated exact authn target/schema.
func internalAdmissionProfiles(catalog *policyruntime.TargetCatalog) ([]admission.Profile, error) {
	profileIDs, err := core.AuthnInternalProfileIDs()
	if err != nil {
		return nil, err
	}

	profiles := make([]admission.Profile, 0, len(profileIDs))
	for _, profileID := range profileIDs {
		target, targetErr := decision.NewTarget(policy.AuthnNamespace, profileID.Operation())
		if targetErr != nil {
			return nil, targetErr
		}

		compiled, found := catalog.Lookup(target)
		if !found {
			return nil, fmt.Errorf("internal Policy profile %s target is unavailable", profileID.String())
		}

		reference, referenceErr := registry.NewClientAdmissionReference(
			"internal."+profileID.String(),
			target.Namespace(),
			target.Action(),
			compiled.Schema().Identity().String(),
		)
		if referenceErr != nil {
			return nil, referenceErr
		}

		fields := callerSchemaFields(compiled.Schema())
		profiles = append(profiles, admission.Profile{
			Principal: profileID.String(), AuthenticationKinds: []string{policy.CallerAuthenticationKindInternal},
			References:               []registry.ClientAdmissionReference{reference},
			AllowedSubjectAttributes: fields.subject, AllowedResourceAttributes: fields.resource,
			AllowedEnvironmentAttributes: fields.environment, AllowedInputAttributes: fields.input,
			Diagnostics: true, Internal: true,
		})
	}

	return profiles, nil
}

type internalSchemaFields struct {
	subject     []string
	resource    []string
	environment []string
	input       []string
}

// callerSchemaFields derives only caller-source relative fields from one exact schema.
func callerSchemaFields(schema policyruntime.CompiledSchema) internalSchemaFields {
	result := internalSchemaFields{}

	for _, fact := range schema.Facts() {
		if !slices.Contains(fact.AllowedSources(), decision.FactSourceCaller) {
			continue
		}

		prefix, relative, found := strings.Cut(fact.ID(), ".")
		if !found || relative == "" {
			continue
		}

		switch {
		case prefix == authnSourceSubject && fact.Category() == decision.FactCategorySubject:
			result.subject = append(result.subject, relative)
		case prefix == "resource" && fact.Category() == decision.FactCategoryResource:
			result.resource = append(result.resource, relative)
		case prefix == authnSourceEnvironment && fact.Category() == decision.FactCategoryEnvironment:
			result.environment = append(result.environment, relative)
		case prefix == "input":
			result.input = append(result.input, relative)
		}
	}

	sort.Strings(result.subject)
	sort.Strings(result.resource)
	sort.Strings(result.environment)
	sort.Strings(result.input)

	return result
}

// Prepare derives bounded generation settings from the same normalized Policy candidate.
func (s settingsPreparationSlot) Prepare(
	_ context.Context,
	input policyruntime.SettingsPreparationInput,
) (policyruntime.SettingsPreparation, error) {
	prepared, err := preparedPolicy(input.Policy())
	if err != nil {
		return policyruntime.SettingsPreparation{}, err
	}

	limits := prepared.Config().API.Limits
	evaluationTimeout := positiveDuration(limits.EvaluationTimeout, defaultEvaluationTimeout)
	postActionBudget := positiveDuration(max(limits.ProviderTimeout, limits.EvaluationTimeout), defaultPostActionBudget)
	diagnosticEntries := positiveInt(limits.MaxObligations+limits.MaxAdvice, defaultDiagnosticsEntries)
	reportEntries := positiveInt(limits.MaxFacts+diagnosticEntries, defaultReportEntries)

	startupOverlays, err := s.startup.overlaysForCandidate(input.Config())
	if err != nil {
		return policyruntime.SettingsPreparation{}, err
	}

	overlays := append(
		localization.CloneCatalogOverlays(startupOverlays),
		policyCatalogOverlays(prepared.Config())...,
	)

	effectiveCatalog, _, err := localization.NewEffectiveCatalog(
		s.system,
		overlays...,
	)
	if err != nil {
		return policyruntime.SettingsPreparation{}, fmt.Errorf("prepare Policy localization catalog: %w", err)
	}

	if err = validatePolicyLocalizationKeys(input.TargetCatalog(), effectiveCatalog); err != nil {
		return policyruntime.SettingsPreparation{}, err
	}

	resolver := localization.NewResolver(
		effectiveCatalog,
		input.Config().GetServer().Frontend.GetDefaultLanguage(),
	)

	return policyruntime.SettingsPreparation{
		MessageResolver: resolver,
		Settings: policyruntime.GenerationSettings{
			Limits: policyruntime.DecisionLimits{
				EvaluationTimeout: evaluationTimeout, PostActionBudget: postActionBudget,
				MaxDiagnosticsEntries: diagnosticEntries,
			},
			Reports: policyruntime.DecisionReportSettings{Enabled: true, MaxEntries: reportEntries},
		},
	}, nil
}

// policyCatalogOverlays projects namespace-owned configuration into detached immutable layers.
func policyCatalogOverlays(configured policyconfig.PolicyConfig) []localization.CatalogOverlay {
	namespaces := make([]string, 0, len(configured.Namespaces))
	for namespace := range configured.Namespaces {
		namespaces = append(namespaces, namespace)
	}

	sort.Strings(namespaces)

	overlays := make([]localization.CatalogOverlay, 0)

	for _, namespace := range namespaces {
		for _, catalog := range configured.Namespaces[namespace].Localization.Catalogs {
			entries := make(map[string]string, len(catalog.Entries))
			for key, value := range catalog.Entries {
				entries[key] = value
			}

			overlays = append(overlays, localization.CatalogOverlay{
				Namespace: catalog.Namespace,
				Entries: map[string]map[string]string{
					catalog.Language: entries,
				},
			})
		}
	}

	return overlays
}

// validatePolicyLocalizationKeys rejects i18n selections absent from every effective language.
func validatePolicyLocalizationKeys(
	catalog *policyruntime.TargetCatalog,
	translations localization.Catalog,
) error {
	for _, target := range catalog.Targets() {
		for _, checkpoint := range target.DomainPlan().Checkpoints() {
			for _, setID := range checkpoint.PolicySetIDs() {
				identity, err := registry.ParsePolicySetID("policy.localization", setID)
				if err != nil {
					return err
				}

				set, found := target.LookupPolicySet(identity)
				if !found {
					return fmt.Errorf("policy localization references unavailable set %s", setID)
				}

				for _, rule := range set.Rules() {
					key := rule.ResponseMessage().I18NKey()
					if key != "" && !catalogContainsLocalizationKey(translations, key) {
						return fmt.Errorf("policy localization key %s is unavailable", key)
					}
				}
			}
		}
	}

	return nil
}

// catalogContainsLocalizationKey checks an exact key without introducing fallback selection.
func catalogContainsLocalizationKey(catalog localization.Catalog, key string) bool {
	for _, tag := range catalog.Tags() {
		if _, found := catalog.Lookup(tag, key); found {
			return true
		}
	}

	return false
}

// positiveDuration applies one finite code-owned bound when the optional operator value is absent.
func positiveDuration(value time.Duration, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}

	return fallback
}

// positiveInt applies one finite code-owned bound when derived optional limits are absent.
func positiveInt(value int, fallback int) int {
	if value > 0 {
		return value
	}

	return fallback
}

// preparedPolicy proves that every production slot consumes the same frozen model type.
func preparedPolicy(model policyruntime.PolicyModel) (*configinput.PreparedPolicy, error) {
	prepared, ok := model.(*configinput.PreparedPolicy)
	if !ok || prepared == nil {
		return nil, fmt.Errorf("%w: prepared Policy model is unavailable", policyruntime.ErrInvalidGeneration)
	}

	return prepared, nil
}

var _ reloadfx.GenerationCoordinator = (*Coordinator)(nil)
var _ policyruntime.CandidateResource = (*supervisorResource)(nil)
