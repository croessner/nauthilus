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
	"sync"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/nativebinding"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	nativeRuntimeTargetID         = "mail/filter"
	nativeRuntimeProviderID       = "mail/plugin.reputation.notifier"
	nativeRuntimePrincipal        = "native-runtime"
	nativeRuntimeGenerationID     = uint64(1)
	nativeRuntimeCompletionBudget = 2 * time.Second
)

func TestConfiguredNativeProviderGenerationRunsThroughSharedDecisionRuntimeAndSupervisor(t *testing.T) {
	fixture := newConfiguredNativeRuntimeFixture(t)
	response, finalization := fixture.evaluate(t)

	assertConfiguredNativeRuntimeBeforeFinalization(t, fixture, response)
	finalization.Complete()
	fixture.waitForPostAction(t)
	assertConfiguredNativeRuntimeAfterFinalization(t, fixture, response)
}

type configuredNativeRuntimeFixture struct {
	service    *decisionservice.DecisionService
	supervisor *effectsupervisor.Supervisor
	observer   *nativeRuntimeObserver
}

// newConfiguredNativeRuntimeFixture assembles one real catalog, native binding generation, and Decision Service.
func newConfiguredNativeRuntimeFixture(t *testing.T) *configuredNativeRuntimeFixture {
	t.Helper()

	observer := &nativeRuntimeObserver{}
	supervisor := newConfiguredNativeRuntimeSupervisor(t, observer)
	configured := configuredNativeRuntimePolicy(t)
	catalog, preparation := prepareConfiguredNativeRuntime(t, configured, supervisor, observer)
	store := policyruntime.NewGenerationStore()
	service := commitConfiguredNativeRuntime(t, store, catalog, preparation)

	registerConfiguredNativeRuntimeCleanup(t, store, supervisor)

	return &configuredNativeRuntimeFixture{service: service, supervisor: supervisor, observer: observer}
}

// evaluate invokes the configured mail/filter target with one real response finalization gate.
func (f *configuredNativeRuntimeFixture) evaluate(
	t *testing.T,
) (decision.DecisionResponse, decision.EvaluationFinalization) {
	t.Helper()

	target, err := decision.NewTarget("mail", "filter")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	authentication, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind: "test", Credential: []byte("opaque-native-runtime"), TransportKind: "internal", Protected: true,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	finalization := decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit)

	response, err := f.service.Evaluate(t.Context(), decision.Invocation{
		Request: decision.DecisionRequestInput{
			Version: decision.ContractVersion, RequestID: "native-runtime-request", Target: target,
		},
		Authentication: authentication,
		Finalization:   finalization,
	})
	if err != nil {
		t.Fatalf("DecisionService.Evaluate() error = %v", err)
	}

	return response, finalization
}

// waitForPostAction opens only after finalization and bounds supervisor-owned completion.
func (f *configuredNativeRuntimeFixture) waitForPostAction(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), nativeRuntimeCompletionBudget)
	defer cancel()

	if err := f.supervisor.WaitIdle(ctx); err != nil {
		t.Fatalf("Supervisor.WaitIdle() error = %v", err)
	}
}

// compileConfiguredNativeTargetCatalog compiles exactly the configured target without builtin authn activations.
func compileConfiguredNativeTargetCatalog(
	t *testing.T,
	normalized UnifiedPolicyInput,
	acceptance effectsupervisor.Acceptor,
) *policyruntime.TargetCatalog {
	t.Helper()

	contributors, err := normalized.Contributors(t.Context(), acceptance)
	if err != nil {
		t.Fatalf("Contributors() error = %v", err)
	}

	activations := make([]registry.TargetActivation, 0, 1)

	for _, activation := range normalized.Activations {
		if activation.Target().String() == nativeRuntimeTargetID {
			activations = append(activations, activation)
		}
	}

	if len(activations) != 1 {
		t.Fatalf("configured target activations = %v, want %s only", activations, nativeRuntimeTargetID)
	}

	catalog, err := compiler.NewTargetCatalogCompiler(contributors...).Compile(t.Context(), activations)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	return catalog
}

// configuredNativeRuntimePolicy selects sync, post-action, return-only, and advice effects in one rule.
func configuredNativeRuntimePolicy(t *testing.T) policyconfig.PolicyConfig {
	t.Helper()

	configured := decodePolicy(t, configuredNativePolicyFixture).Policy
	namespace := configured.Namespaces["mail"]

	unusedProvider := namespace.Providers["notifier"]
	unusedProvider.Executions = []string{string(registry.ExecutionHostSync)}
	unusedProvider.Diagnostics.PublicID = "native-unused-notifier"
	namespace.Providers["unused_notifier"] = unusedProvider

	unselected := namespace.Effects["notify"]
	unselected.Provider = "mail/plugin.reputation.unused_notifier"
	unselected.Diagnostics.PublicID = "native-unselected"
	namespace.Effects["unselected"] = unselected
	namespace.Effects["client_note"] = policyconfig.EffectConfig{
		Kind: string(registry.EffectKindObligation), Targets: []policyconfig.TargetReferenceConfig{{Action: "filter"}},
		Execution: string(registry.ExecutionReturnOnly), Diagnostics: policyconfig.DiagnosticsConfig{PublicID: "client-note"},
	}
	namespace.Effects["hint"] = policyconfig.EffectConfig{
		Kind: string(registry.EffectKindAdvice), Targets: []policyconfig.TargetReferenceConfig{{Action: "filter"}},
		Execution: string(registry.ExecutionReturnOnly), Diagnostics: policyconfig.DiagnosticsConfig{PublicID: "hint"},
	}

	always := true
	policySet := namespace.PolicySets["default"]
	policySet.Rules = []policyconfig.PolicyRuleConfig{{
		Name: "native-runtime", Checkpoint: decision.CheckpointFinalDecision, Actions: []string{"filter"},
		RequireProviders: []string{"risk"}, If: policyconfig.ConditionConfig{Always: &always},
		Then: policyconfig.ThenConfig{
			Decision: string(decision.EffectPermit),
			Obligations: []policyconfig.EffectSelectionConfig{
				{ID: "mail/notify", Parameters: map[string]any{"level": "sync"}},
				{ID: "mail/archive", Parameters: map[string]any{"level": "post"}},
				{ID: "mail/client_note"},
			},
			Advice: []policyconfig.EffectSelectionConfig{{ID: "mail/hint"}},
		},
	}}
	namespace.PolicySets["default"] = policySet
	configured.Namespaces["mail"] = namespace

	return configured
}

// prepareConfiguredNativeRuntime freezes configured adapters and validates them against the compiled catalog.
func prepareConfiguredNativeRuntime(
	t *testing.T,
	configured policyconfig.PolicyConfig,
	supervisor *effectsupervisor.Supervisor,
	observer *nativeRuntimeObserver,
) (*policyruntime.TargetCatalog, policyruntime.ExtensionPreparation) {
	t.Helper()

	normalized, err := Normalize(t.Context(), policyconfig.Document{Policy: configured})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	catalog := compileConfiguredNativeTargetCatalog(t, normalized, supervisor)
	factProvider := &nativeFactProvider{descriptor: nativeFactDescriptor(), collect: observer.recordFactTarget}
	effectProvider := &nativeEffectProvider{
		descriptor: nativeEffectDescriptor(),
		results: map[string]pluginapi.DecisionEffectResult{
			"archive": {Outcome: pluginapi.DecisionEffectOutcomeFailed, ErrorClass: pluginapi.DecisionErrorClassInternal},
		},
	}
	bindings := configuredNativeBindingsWithProviders(t, factProvider, effectProvider, true)

	preparation, err := PrepareConfiguredNativeGeneration(t.Context(), ConfiguredNativeGenerationInput{
		Policy: configured, Bindings: bindings, PostActionAcceptance: supervisor, Observer: observer,
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredNativeGeneration() error = %v", err)
	}

	if err = preparation.Bindings.ValidateCatalog(catalog); err != nil {
		t.Fatalf("ValidateCatalog() error = %v", err)
	}

	return catalog, preparation
}

// newConfiguredNativeRuntimeSupervisor creates the real executable-work supervisor for the native provider ID.
func newConfiguredNativeRuntimeSupervisor(
	t *testing.T,
	observer *nativeRuntimeObserver,
) *effectsupervisor.Supervisor {
	t.Helper()

	supervisor, err := effectsupervisor.New(effectsupervisor.Config{
		Lifetime: context.Background(), Observer: observer, Capacity: 4, Workers: 1,
	}, effectsupervisor.ProviderBinding{
		Name: nativeRuntimeProviderID, Provider: effectsupervisor.NewExecutableProvider(),
	})
	if err != nil {
		t.Fatalf("effectsupervisor.New() error = %v", err)
	}

	return supervisor
}

// commitConfiguredNativeRuntime publishes one complete generation through the coordinator and returns its service.
func commitConfiguredNativeRuntime(
	t *testing.T,
	store *policyruntime.GenerationStore,
	catalog *policyruntime.TargetCatalog,
	preparation policyruntime.ExtensionPreparation,
) *decisionservice.DecisionService {
	t.Helper()

	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{
		Store: store, Slots: configuredNativeRuntimeSlots(t, catalog, preparation),
	})
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	if _, err = coordinator.Apply(t.Context(), policyruntime.PrepareInput{
		Config: &config.FileSettings{}, ID: nativeRuntimeGenerationID,
	}); err != nil {
		t.Fatalf("Coordinator.Apply() error = %v", err)
	}

	source, err := decisionservice.NewStoreGenerationSource(store)
	if err != nil {
		t.Fatalf("NewStoreGenerationSource() error = %v", err)
	}

	service, err := decisionservice.NewDecisionService(source)
	if err != nil {
		t.Fatalf("NewDecisionService() error = %v", err)
	}

	return service
}

// configuredNativeRuntimeSlots builds the complete coordinator graph around prepared native bindings.
func configuredNativeRuntimeSlots(
	t *testing.T,
	catalog *policyruntime.TargetCatalog,
	preparation policyruntime.ExtensionPreparation,
) policyruntime.PreparationSlots {
	t.Helper()

	authorities := mustConfiguredNativeRuntimeAuthorities(t)

	return policyruntime.PreparationSlots{
		Policy: policyruntime.PolicyPreparationFunc(func(
			_ context.Context,
			input policyruntime.PreparationInput,
		) (policyruntime.PolicyPreparation, error) {
			return policyruntime.PolicyPreparation{
				Snapshot: &policyruntime.Snapshot{Generation: input.ID(), Mode: nativeRuntimePrincipal},
			}, nil
		}),
		Extensions: policyruntime.ExtensionPreparationFunc(func(
			context.Context,
			policyruntime.PreparationInput,
		) (policyruntime.ExtensionPreparation, error) {
			return preparation, nil
		}),
		Catalog: configuredNativeRuntimeCatalogSlot(catalog),
		CallerAuthentication: policyruntime.CallerAuthenticationPreparationFunc(func(
			context.Context,
			policyruntime.AuthorityPreparationInput,
		) (policyruntime.CallerAuthenticationPreparation, error) {
			return policyruntime.CallerAuthenticationPreparation{
				Authenticator: &nativeRuntimeAuthenticator{caller: authorities.caller},
				Credentials:   authorities.credentials,
			}, nil
		}),
		Admission: policyruntime.AdmissionPreparationFunc(func(
			context.Context,
			policyruntime.AdmissionPreparationInput,
		) (policyruntime.AdmissionPreparation, error) {
			return policyruntime.AdmissionPreparation{
				Authority: &nativeRuntimeAdmissionAuthority{facts: authorities.facts},
				Profiles:  authorities.admissionProfiles,
			}, nil
		}),
		Settings: policyruntime.SettingsPreparationFunc(func(
			context.Context,
			policyruntime.SettingsPreparationInput,
		) (policyruntime.SettingsPreparation, error) {
			return configuredNativeRuntimeSettings(), nil
		}),
		Application: decisionservice.NewRuntimeApplicationPreparationSlot(),
	}
}

type configuredNativeRuntimeAuthorities struct {
	caller            decision.CallerContext
	facts             decision.FactSet
	credentials       policyruntime.CredentialProfiles
	admissionProfiles policyruntime.AdmissionProfiles
}

// mustConfiguredNativeRuntimeAuthorities constructs matching caller and admission generation metadata.
func mustConfiguredNativeRuntimeAuthorities(t *testing.T) configuredNativeRuntimeAuthorities {
	t.Helper()

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	credentials, err := policyruntime.NewCredentialProfiles([]string{nativeRuntimePrincipal})
	if err != nil {
		t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	admissionProfiles, err := policyruntime.NewAdmissionProfiles([]string{nativeRuntimePrincipal})
	if err != nil {
		t.Fatalf("NewAdmissionProfiles() error = %v", err)
	}

	return configuredNativeRuntimeAuthorities{
		caller: mustConfiguredNativeRuntimeCaller(t), facts: facts,
		credentials: credentials, admissionProfiles: admissionProfiles,
	}
}

// configuredNativeRuntimeCatalogSlot preserves the compiled catalog while proving native definitions reach the slot.
func configuredNativeRuntimeCatalogSlot(
	catalog *policyruntime.TargetCatalog,
) policyruntime.CatalogPreparationSlot {
	return policyruntime.CatalogPreparationFunc(func(
		_ context.Context,
		input policyruntime.CatalogPreparationInput,
	) (policyruntime.CatalogPreparation, error) {
		definitions := input.Definitions()
		if len(definitions) != 1 {
			return policyruntime.CatalogPreparation{}, fmt.Errorf(
				"native runtime definitions = %d, want one module contribution",
				len(definitions),
			)
		}

		for _, definition := range definitions {
			if definition.Ownership().Owner() != "plugin.reputation" {
				return policyruntime.CatalogPreparation{}, fmt.Errorf(
					"native runtime definition owner = %q, want plugin.reputation",
					definition.Ownership().Owner(),
				)
			}
		}

		return policyruntime.CatalogPreparation{Catalog: catalog}, nil
	})
}

// configuredNativeRuntimeSettings returns bounded settings for one candidate generation.
func configuredNativeRuntimeSettings() policyruntime.SettingsPreparation {
	return policyruntime.SettingsPreparation{Settings: policyruntime.GenerationSettings{
		Limits: policyruntime.DecisionLimits{
			EvaluationTimeout: time.Second, PostActionBudget: time.Second, MaxDiagnosticsEntries: 64,
		},
		Reports: policyruntime.DecisionReportSettings{MaxEntries: 64},
	}}
}

// mustConfiguredNativeRuntimeCaller constructs trusted authenticator output for the integration generation.
func mustConfiguredNativeRuntimeCaller(t *testing.T) decision.CallerContext {
	t.Helper()

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: nativeRuntimePrincipal, AuthenticationKind: "test", TransportKind: "internal",
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	return caller
}

type nativeRuntimeAuthenticator struct {
	caller decision.CallerContext
}

// Authenticate returns the generation-bound trusted caller after honoring cancellation.
func (a *nativeRuntimeAuthenticator) Authenticate(
	ctx context.Context,
	_ decision.AuthenticationInput,
) (decision.CallerContext, error) {
	if err := ctx.Err(); err != nil {
		return decision.CallerContext{}, err
	}

	return a.caller, nil
}

type nativeRuntimeAdmissionAuthority struct {
	facts decision.FactSet
}

// Admit grants the exact request an immutable empty starting fact set.
func (a *nativeRuntimeAdmissionAuthority) Admit(
	ctx context.Context,
	_ decision.CallerContext,
	_ decision.DecisionRequest,
) (policyruntime.AdmissionPermit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return &nativeRuntimeAdmissionPermit{facts: a.facts}, nil
}

type nativeRuntimeAdmissionPermit struct {
	facts decision.FactSet
}

// Facts returns the immutable admitted fact set.
func (p *nativeRuntimeAdmissionPermit) Facts() decision.FactSet {
	return p.facts
}

// Release completes request-scoped admission ownership.
func (*nativeRuntimeAdmissionPermit) Release() {}

type nativeRuntimeObserver struct {
	pluginCalls      []nativebinding.CallRecord
	supervisorEvents []effectsupervisor.Event
	factTargets      []string
	mu               sync.Mutex
}

// ObservePluginCall records bounded native callback metadata.
func (o *nativeRuntimeObserver) ObservePluginCall(record nativebinding.CallRecord) {
	o.mu.Lock()
	o.pluginCalls = append(o.pluginCalls, record)
	o.mu.Unlock()
}

// Observe records bounded supervisor lifecycle metadata.
func (o *nativeRuntimeObserver) Observe(_ context.Context, event effectsupervisor.Event) {
	o.mu.Lock()
	o.supervisorEvents = append(o.supervisorEvents, event)
	o.mu.Unlock()
}

// recordFactTarget captures the immutable target visible to the native fact provider.
func (o *nativeRuntimeObserver) recordFactTarget(request pluginapi.DecisionFactRequest) {
	target := request.Target()

	o.mu.Lock()
	o.factTargets = append(o.factTargets, target.Namespace+"/"+target.Action)
	o.mu.Unlock()
}

// pluginCallCount returns matching synchronized callback attempts.
func (o *nativeRuntimeObserver) pluginCallCount(component string, method string) int {
	o.mu.Lock()
	defer o.mu.Unlock()

	count := 0

	for _, record := range o.pluginCalls {
		if record.ModuleName == "reputation" && record.ComponentName == component && record.Method == method {
			count++
		}
	}

	return count
}

// failedPluginCallCount returns matching callback attempts with one contained error.
func (o *nativeRuntimeObserver) failedPluginCallCount(component string, method string) int {
	o.mu.Lock()
	defer o.mu.Unlock()

	count := 0

	for _, record := range o.pluginCalls {
		if record.ComponentName == component && record.Method == method && record.Err != nil {
			count++
		}
	}

	return count
}

// supervisorEventCount returns matching synchronized lifecycle transitions.
func (o *nativeRuntimeObserver) supervisorEventCount(state effectsupervisor.State, phase effectsupervisor.Phase) int {
	o.mu.Lock()
	defer o.mu.Unlock()

	count := 0

	for _, event := range o.supervisorEvents {
		if event.Provider == nativeRuntimeProviderID && event.State == state && event.Phase == phase {
			count++
		}
	}

	return count
}

// recordedFactTargets returns detached target identities observed by native fact callbacks.
func (o *nativeRuntimeObserver) recordedFactTargets() []string {
	o.mu.Lock()
	defer o.mu.Unlock()

	return append([]string(nil), o.factTargets...)
}

// assertConfiguredNativeRuntimeBeforeFinalization proves synchronous selection and a closed post-action gate.
func assertConfiguredNativeRuntimeBeforeFinalization(
	t *testing.T,
	fixture *configuredNativeRuntimeFixture,
	response decision.DecisionResponse,
) {
	t.Helper()

	assertConfiguredNativeRuntimeResponse(t, response)

	if got := fixture.observer.recordedFactTargets(); len(got) != 1 || got[0] != nativeRuntimeTargetID {
		t.Fatalf("native fact targets = %v, want [%s]", got, nativeRuntimeTargetID)
	}

	if got := fixture.observer.pluginCallCount("risk", "Collect"); got != 1 {
		t.Fatalf("native fact calls = %d, want 1", got)
	}

	if got := fixture.observer.pluginCallCount("notifier", "Execute"); got != 1 {
		t.Fatalf("native selected sync calls = %d, want 1", got)
	}

	assertConfiguredNativeUnselectedCalls(t, fixture.observer)

	if fixture.supervisor.InFlight() != 1 ||
		fixture.observer.supervisorEventCount(effectsupervisor.StateAccepted, effectsupervisor.PhaseAcceptance) != 1 ||
		fixture.observer.supervisorEventCount(effectsupervisor.StateAttempted, effectsupervisor.PhaseExecution) != 0 {
		t.Fatalf("post-action was not accepted behind the finalization gate")
	}

	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()

	<-timer.C

	if fixture.observer.pluginCallCount("notifier", "Execute") != 1 ||
		fixture.observer.supervisorEventCount(effectsupervisor.StateAttempted, effectsupervisor.PhaseExecution) != 0 {
		t.Fatal("native post-action executed before response finalization")
	}
}

// assertConfiguredNativeRuntimeAfterFinalization proves one late failed attempt cannot alter the response.
func assertConfiguredNativeRuntimeAfterFinalization(
	t *testing.T,
	fixture *configuredNativeRuntimeFixture,
	response decision.DecisionResponse,
) {
	t.Helper()

	assertConfiguredNativeRuntimeResponse(t, response)

	if got := fixture.observer.pluginCallCount("risk", "Collect"); got != 1 {
		t.Fatalf("native fact calls after finalization = %d, want 1", got)
	}

	if got := fixture.observer.pluginCallCount("notifier", "Execute"); got != 2 {
		t.Fatalf("native selected sync/post calls = %d, want 2", got)
	}

	if got := fixture.observer.failedPluginCallCount("notifier", "Execute"); got != 1 {
		t.Fatalf("native late failed calls = %d, want 1", got)
	}

	assertConfiguredNativeUnselectedCalls(t, fixture.observer)

	if fixture.observer.supervisorEventCount(effectsupervisor.StateAttempted, effectsupervisor.PhaseExecution) != 1 ||
		fixture.observer.supervisorEventCount(effectsupervisor.StateFailed, effectsupervisor.PhaseExecution) != 1 {
		t.Fatal("native post-action did not produce exactly one supervisor-owned failed attempt")
	}
}

// assertConfiguredNativeRuntimeResponse verifies only return-only selections reach the immutable response.
func assertConfiguredNativeRuntimeResponse(t *testing.T, response decision.DecisionResponse) {
	t.Helper()

	var (
		obligations = response.Obligations()
		advice      = response.Advice()
	)

	if response.Effect() != decision.EffectPermit || len(obligations) != 1 || obligations[0].ID() != "mail/client_note" {
		t.Fatalf("native runtime response effect/obligations = %q/%v", response.Effect(), obligations)
	}

	if len(advice) != 1 || advice[0].ID() != "mail/hint" {
		t.Fatalf("native runtime response advice = %v, want mail/hint", advice)
	}
}

// assertConfiguredNativeUnselectedCalls proves a configured but unselected effect provider remains untouched.
func assertConfiguredNativeUnselectedCalls(t *testing.T, observer *nativeRuntimeObserver) {
	t.Helper()

	if got := observer.pluginCallCount("unused_notifier", "Execute"); got != 0 {
		t.Fatalf("unselected native effect calls = %d, want 0", got)
	}
}

// registerConfiguredNativeRuntimeCleanup shuts down committed generations before their shared supervisor.
func registerConfiguredNativeRuntimeCleanup(
	t *testing.T,
	store *policyruntime.GenerationStore,
	supervisor *effectsupervisor.Supervisor,
) {
	t.Helper()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), nativeRuntimeCompletionBudget)
		defer cancel()

		if err := store.Shutdown(ctx); err != nil {
			t.Errorf("GenerationStore.Shutdown() error = %v", err)
		}

		if err := supervisor.Shutdown(ctx); err != nil {
			t.Errorf("Supervisor.Shutdown() error = %v", err)
		}
	})
}
