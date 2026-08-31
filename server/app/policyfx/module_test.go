// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/app/bootfx"
	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/callerauth"
	"github.com/croessner/nauthilus/v4/server/policy/configinput"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

var (
	errCandidateToken     = errors.New("candidate token validation failed")
	errCandidateThrottler = errors.New("candidate Basic throttler preparation failed")
	errCandidateTransport = errors.New("candidate transport validation failed")
)

type candidateFactoryGate struct {
	rejected string
}

// tokenValidator rejects only the selected candidate preparation phase.
func (g *candidateFactoryGate) tokenValidator(context.Context, config.File) (callerauth.AccessTokenValidator, error) {
	if g.rejected == "token" {
		return nil, errCandidateToken
	}

	return nil, nil
}

// basicThrottler rejects only the selected candidate preparation phase.
func (g *candidateFactoryGate) basicThrottler(context.Context, config.File) (callerauth.BasicThrottler, error) {
	if g.rejected == "throttler" {
		return nil, errCandidateThrottler
	}

	return &productionBasicThrottler{}, nil
}

// transportCapabilities rejects only the selected candidate preparation phase.
func (g *candidateFactoryGate) transportCapabilities(
	context.Context,
	config.File,
) (callerauth.TransportCapabilities, error) {
	if g.rejected == "transport" {
		return callerauth.TransportCapabilities{}, errCandidateTransport
	}

	return callerauth.TransportCapabilities{HTTPProtected: true, GRPCProtected: true}, nil
}

// TestProductionCoordinatorRetainsCompleteGenerationOnCandidateFactoryFailure proves atomic publication.
func TestProductionCoordinatorRetainsCompleteGenerationOnCandidateFactoryFailure(t *testing.T) {
	store := policyruntime.NewGenerationStore()
	gate := &candidateFactoryGate{}
	configured := productionNonAuthDecisionCandidate(t)
	coordinator := newCandidateFactoryCoordinator(t, store, configured, gate)

	if err := coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 1}); err != nil {
		t.Fatalf("Apply(initial) error = %v", err)
	}

	active := activePreparedGeneration(t, store)
	assertCandidateFactoryRejections(t, coordinator, store, active, gate)
	assertPluginMutationRejected(t, coordinator, store, active, gate)
}

// newCandidateFactoryCoordinator constructs the candidate-phase failure harness.
func newCandidateFactoryCoordinator(
	t *testing.T,
	store *policyruntime.GenerationStore,
	configured config.File,
	gate *candidateFactoryGate,
) *Coordinator {
	t.Helper()

	coordinator, err := NewCoordinator(
		store,
		nil,
		&pluginloader.State{},
		gate.tokenValidator,
		gate.basicThrottler,
		gate.transportCapabilities,
		localization.NewMapCatalog(nil),
		mustStartupCatalog(t, configured, nil),
		mustRestartBaseline(t, configured),
	)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	return coordinator
}

// activePreparedGeneration returns and verifies the complete initial generation.
func activePreparedGeneration(t *testing.T, store *policyruntime.GenerationStore) *policyruntime.Generation {
	t.Helper()

	active := store.Active()
	if active == nil || active.ID() != 1 {
		t.Fatalf("active generation = %#v, want generation 1", active)
	}

	prepared, ok := active.Policy().(*configinput.PreparedPolicy)
	if !ok || prepared.GenerationID() != 1 {
		t.Fatalf("active Policy model = %#v, want PreparedPolicy generation 1", active.Policy())
	}

	return active
}

// assertCandidateFactoryRejections verifies every dependency failure retains the complete generation.
func assertCandidateFactoryRejections(
	t *testing.T,
	coordinator *Coordinator,
	store *policyruntime.GenerationStore,
	active *policyruntime.Generation,
	gate *candidateFactoryGate,
) {
	t.Helper()

	tests := []struct {
		candidate *config.FileSettings
		want      error
		factory   string
	}{
		{candidate: productionBearerNonAuthDecisionCandidate(t), want: errCandidateToken, factory: "token"},
		{candidate: productionNonAuthDecisionCandidate(t), want: errCandidateThrottler, factory: "throttler"},
		{candidate: productionNonAuthDecisionCandidate(t), want: errCandidateTransport, factory: "transport"},
	}
	for _, test := range tests {
		t.Run(test.factory, func(t *testing.T) {
			gate.rejected = test.factory

			err := coordinator.Apply(t.Context(), configfx.Snapshot{File: test.candidate, Version: 2})
			if !errors.Is(err, test.want) {
				t.Fatalf("Apply(rejected) error = %v, want %v", err, test.want)
			}

			if store.Active() != active {
				t.Fatal("failed candidate replaced the complete active generation")
			}

			if snapshot := test.candidate.ArtifactSnapshot(); snapshot == nil || !snapshot.IsReleased() {
				t.Fatal("failed candidate retained its sealed artifact snapshot")
			}
		})
	}
}

// assertPluginMutationRejected verifies restart-bound plugin drift retains the complete generation.
func assertPluginMutationRejected(
	t *testing.T,
	coordinator *Coordinator,
	store *policyruntime.GenerationStore,
	active *policyruntime.Generation,
	gate *candidateFactoryGate,
) {
	t.Helper()

	gate.rejected = ""
	pluginMutation := productionNonAuthDecisionCandidate(t)
	pluginMutation.Plugins = &config.PluginsSection{VerificationPolicy: "strict"}

	err := coordinator.Apply(t.Context(), configfx.Snapshot{
		File:    pluginMutation,
		Version: 2,
	})
	if !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("Apply(plugin mutation) error = %v, want restart-required rejection", err)
	}

	if store.Active() != active {
		t.Fatal("restart-bound plugin mutation replaced the complete active generation")
	}

	if snapshot := pluginMutation.ArtifactSnapshot(); snapshot == nil || !snapshot.IsReleased() {
		t.Fatal("restart-bound rejection retained its sealed artifact snapshot")
	}
}

func TestProductionCoordinatorLayersStartupCatalogBetweenSystemAndPolicy(t *testing.T) {
	const (
		key           = "auth.policy.company.account_blocked"
		systemOnlyKey = "auth.policy.company.system_only"
	)

	configured := policyLocalizationCandidate(key, "Policy message.")
	startupOverlays := []localization.CatalogOverlay{{
		Namespace: "startup",
		Entries: map[string]map[string]string{
			"en": {key: "Startup message."},
		},
	}}
	startup := mustStartupCatalog(t, configured, startupOverlays)
	startupOverlays[0].Entries["en"][key] = "Mutated input."
	store := policyruntime.NewGenerationStore()

	coordinator, err := NewCoordinator(
		store,
		nil,
		&pluginloader.State{},
		unusedTokenFactory,
		unusedThrottlerFactory,
		func(context.Context, config.File) (callerauth.TransportCapabilities, error) {
			return callerauth.TransportCapabilities{}, nil
		},
		localization.NewMapCatalog(map[string]map[string]string{
			"en": {key: "System message.", systemOnlyKey: "System-only message."},
		}),
		startup,
		mustRestartBaseline(t, configured),
	)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 1}); err != nil {
		t.Fatalf("Apply(G1) error = %v", err)
	}

	service := productionDecisionService(t, store)
	withoutPolicyOverlay := &config.FileSettings{}

	var generationTwoResolver localization.MessageResolver

	withCapturedProductionResolver(t, service, func(generationOneResolver localization.MessageResolver) {
		assertResolvedMessage(t, generationOneResolver, key, "Policy message.")

		if applyErr := coordinator.Apply(t.Context(), configfx.Snapshot{File: withoutPolicyOverlay, Version: 2}); applyErr != nil {
			t.Fatalf("Apply(G2) error = %v", applyErr)
		}

		generationTwoResolver = capturedProductionResolverFromService(t, service)
		assertResolvedMessage(t, generationOneResolver, key, "Policy message.")
	})
	assertResolvedMessage(t, generationTwoResolver, key, "Startup message.")
	assertResolvedMessage(t, generationTwoResolver, systemOnlyKey, "System-only message.")
}

func TestProductionCoordinatorRejectsStartupScriptDriftWithoutReplacingGeneration(t *testing.T) {
	initialScript := filepath.Join(t.TempDir(), "init.lua")
	if err := os.WriteFile(initialScript, []byte("return 'initial'\n"), 0o600); err != nil {
		t.Fatalf("write initial startup script: %v", err)
	}

	configured := startupScriptCandidate(initialScript)
	startup := mustStartupCatalog(t, configured, nil)
	store := policyruntime.NewGenerationStore()

	coordinator, err := NewCoordinator(
		store,
		nil,
		&pluginloader.State{},
		unusedTokenFactory,
		unusedThrottlerFactory,
		func(context.Context, config.File) (callerauth.TransportCapabilities, error) {
			return callerauth.TransportCapabilities{}, nil
		},
		localization.NewMapCatalog(nil),
		startup,
		mustRestartBaseline(t, configured),
	)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 1}); err != nil {
		t.Fatalf("Apply(G1) error = %v", err)
	}

	active := store.Active()

	if err = os.WriteFile(initialScript, []byte("return 'changed'\n"), 0o600); err != nil {
		t.Fatalf("change startup script: %v", err)
	}

	err = coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 2})
	if !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("Apply(content drift) error = %v, want restart required", err)
	}

	if store.Active() != active {
		t.Fatal("startup content drift replaced the active generation")
	}

	replacementScript := filepath.Join(t.TempDir(), "replacement.lua")
	if err = os.WriteFile(replacementScript, []byte("return 'initial'\n"), 0o600); err != nil {
		t.Fatalf("write replacement startup script: %v", err)
	}

	err = coordinator.Apply(t.Context(), configfx.Snapshot{File: startupScriptCandidate(replacementScript), Version: 2})
	if !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("Apply(path drift) error = %v, want restart required", err)
	}

	if store.Active() != active {
		t.Fatal("startup path drift replaced the active generation")
	}
}

func TestProductionCoordinatorRejectsSystemLocalizationDriftWithoutReplacingGeneration(t *testing.T) {
	resourcePath := writeSystemLocalizationResources(t, map[string]string{
		"en": `{"baseline":"english"}`,
	})
	configured := systemLocalizationCandidate(resourcePath, []string{"en"}, "en")
	startup := mustStartupCatalog(t, configured, nil)
	store := policyruntime.NewGenerationStore()

	coordinator, err := NewCoordinator(
		store,
		nil,
		&pluginloader.State{},
		unusedTokenFactory,
		unusedThrottlerFactory,
		func(context.Context, config.File) (callerauth.TransportCapabilities, error) {
			return callerauth.TransportCapabilities{}, nil
		},
		localization.NewMapCatalog(nil),
		startup,
		mustRestartBaseline(t, configured),
	)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 1}); err != nil {
		t.Fatalf("Apply(G1) error = %v", err)
	}

	active := store.Active()

	writeSystemLocalizationResource(t, resourcePath, "en", `{"candidate":"changed"}`)

	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 2}); !errors.Is(err, pluginruntime.ErrRestartRequired) {
		t.Fatalf("Apply(system resource drift) error = %v, want restart required", err)
	}

	if store.Active() != active {
		t.Fatal("system localization drift replaced the active generation")
	}
}

// TestInternalCallerMaterialIsPairedAndDetached proves code-owned verifier/presentation completeness.
func TestInternalCallerMaterialIsPairedAndDetached(t *testing.T) {
	callers, presentations, err := internalCallerMaterial()
	if err != nil {
		t.Fatalf("internalCallerMaterial() error = %v", err)
	}

	if len(callers) != 14 || len(presentations) != len(callers) {
		t.Fatalf("internal caller material = %d/%d, want 14 paired profiles", len(callers), len(presentations))
	}

	for _, caller := range callers {
		if _, found := presentations[caller.Principal]; !found {
			t.Fatalf("presentation for %q is missing", caller.Principal)
		}
	}
}

// unusedTokenFactory fails if a test unexpectedly activates bearer authority.
func unusedTokenFactory(context.Context, config.File) (callerauth.AccessTokenValidator, error) {
	return nil, errors.New("unexpected bearer factory call")
}

// unusedThrottlerFactory fails if a test unexpectedly activates Basic authority.
func unusedThrottlerFactory(context.Context, config.File) (callerauth.BasicThrottler, error) {
	return nil, errors.New("unexpected Basic factory call")
}

// mustStartupCatalog freezes one test-owned startup layer and script baseline.
func mustStartupCatalog(
	t *testing.T,
	configured config.File,
	overlays []localization.CatalogOverlay,
) *StartupCatalog {
	t.Helper()

	artifacts, err := config.EnsureArtifactSnapshot(configured)
	if err != nil {
		t.Fatalf("seal startup scripts: %v", err)
	}

	scripts, err := bootfx.FingerprintPreparedLuaInitScripts(
		artifacts,
		configured.GetLuaInitScriptPaths(),
	)
	if err != nil {
		t.Fatalf("fingerprint startup scripts: %v", err)
	}

	startup := NewStartupCatalog()
	if err = startup.capture(configured, overlays, scripts); err != nil {
		t.Fatalf("capture startup catalog: %v", err)
	}

	return startup
}

// mustRestartBaseline freezes one test-owned process configuration baseline.
func mustRestartBaseline(t *testing.T, configured config.File) RestartBaselineValidator {
	t.Helper()

	baseline, err := NewRestartBaseline(configured)
	if err != nil {
		t.Fatalf("capture restart baseline: %v", err)
	}

	return baseline
}

// policyLocalizationCandidate constructs one top-level Policy localization overlay.
func policyLocalizationCandidate(key string, message string) *config.FileSettings {
	return &config.FileSettings{Policy: policyconfig.PolicyConfig{Namespaces: map[string]policyconfig.NamespaceConfig{
		"company": {
			Localization: policyconfig.LocalizationConfig{Catalogs: []policyconfig.TranslationCatalogConfig{{
				Namespace: "policy", Language: "en", Entries: map[string]string{key: message},
			}}},
		},
	}}}
}

// startupScriptCandidate constructs one restart-bound init-script carrier.
func startupScriptCandidate(scriptPath string) *config.FileSettings {
	return &config.FileSettings{Lua: &config.LuaSection{Config: &config.LuaConf{
		InitScriptPaths: []string{scriptPath},
	}}}
}

// productionDecisionService constructs the production capture boundary over one exact store.
func productionDecisionService(
	t *testing.T,
	store *policyruntime.GenerationStore,
) *decisionservice.DecisionService {
	t.Helper()

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

// capturedProductionResolverFromService captures one resolver through a real internal session.
func capturedProductionResolverFromService(
	t *testing.T,
	service *decisionservice.DecisionService,
) localization.MessageResolver {
	t.Helper()

	var resolver localization.MessageResolver

	withCapturedProductionResolver(t, service, func(captured localization.MessageResolver) {
		resolver = captured
	})

	return resolver
}

// withCapturedProductionResolver keeps the owning generation leased for the callback scope.
func withCapturedProductionResolver(
	t *testing.T,
	service *decisionservice.DecisionService,
	use func(localization.MessageResolver),
) {
	t.Helper()

	profileID, err := decisionservice.NewInternalProfileID(
		core.AuthnEntryBackchannel.String(),
		string(policy.OperationAuthenticate),
	)
	if err != nil {
		t.Fatalf("NewInternalProfileID() error = %v", err)
	}

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	err = service.WithInternalSession(t.Context(), decisionservice.InternalSessionInput{
		ProfileID: profileID,
		Request: decision.DecisionRequestInput{
			Version: decision.ContractVersion, RequestID: "localization-generation", Target: target,
		},
		Finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryGRPCUnaryReturn),
	}, func(session decisionservice.DecisionSession) error {
		resolver, found := decisionservice.CapturedMessageResolverFromContext(session.RequestContext(t.Context()))
		if !found {
			return errors.New("captured generation resolver is unavailable")
		}

		if use != nil {
			use(resolver)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("WithInternalSession() error = %v", err)
	}
}

// assertResolvedMessage checks one exact English generation-owned translation.
func assertResolvedMessage(
	t *testing.T,
	resolver localization.MessageResolver,
	key string,
	want string,
) {
	t.Helper()

	resolved := resolver.ResolveStatusMessage(
		t.Context(),
		localization.StatusMessage{Text: "fallback", I18NKey: key},
		localization.LanguagePreference{Default: "en"},
	)
	if resolved.Text != want {
		t.Fatalf("resolved message = %q, want %q", resolved.Text, want)
	}
}
