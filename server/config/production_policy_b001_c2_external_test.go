// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/app/bootfx"
	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/app/policyfx"
	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/core"
	coreauth "github.com/croessner/nauthilus/v3/server/core/auth"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/callerauth"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

const (
	productionMigrationGenerationOne = uint64(1)
	productionMigrationGenerationTwo = uint64(2)
	productionMigrationRegistryFact  = "lua.contract.registry_flag"
	productionMigrationActionID      = "authn/lua_action_notify"
	productionMigrationActionHeader  = "X-Nauthilus-Policy-Action"
)

// TestProductionB001C2RestartBaselineAcceptsProductionLoadedSparseCandidate guards optional-section nil safety.
func TestProductionB001C2RestartBaselineAcceptsProductionLoadedSparseCandidate(t *testing.T) {
	baseline, err := policyfx.NewRestartBaseline(prepareResolvedProductionMigrationFixture(t))
	if err != nil {
		t.Fatalf("NewRestartBaseline(B001-C2) error = %v", err)
	}

	if err = baseline.Validate(prepareResolvedProductionMigrationFixture(t)); err != nil {
		t.Fatalf("Validate(B001-C2) error = %v", err)
	}
}

// TestProductionB001C2GenerationPublishesRegistryAndExactAuthnPlan proves the frozen fixture reaches the sole store.
func TestProductionB001C2GenerationPublishesRegistryAndExactAuthnPlan(t *testing.T) {
	candidate := prepareResolvedProductionMigrationFixture(t)
	runtime := newProductionMigrationRuntime(t, candidate)
	active := runtime.store.Active()

	if active == nil || active.ID() != productionMigrationGenerationOne {
		t.Fatalf("active production generation = %#v, want generation 1", active)
	}

	assertProductionMigrationRegistryFact(t, active)

	input := newProductionMigrationInternalSessionInput(t)
	defer input.Finalization.Complete()

	err := runtime.service.WithInternalSession(t.Context(), input, func(session decisionservice.DecisionSession) error {
		assertProductionMigrationCheckpointPlan(t, session.Checkpoints())

		captured, ok := decisionservice.CapturedGenerationIDFromContext(session.RequestContext(t.Context()))
		if !ok || captured != productionMigrationGenerationOne {
			t.Fatalf("captured generation = (%d, %v), want (1, true)", captured, ok)
		}

		hostSession, ok := session.(decisionservice.AuthnHostProviderSession)
		if !ok {
			t.Fatal("production session does not expose generation-owned authn host providers")
		}

		assertProductionMigrationHostProvider(t, hostSession, "authn/lua_environment_shared", decisionservice.AuthnHostProviderKindLuaEnvironment)
		assertProductionMigrationHostProvider(t, hostSession, "authn/lua_subject_shared", decisionservice.AuthnHostProviderKindLuaSubject)

		return nil
	})
	if err != nil {
		t.Fatalf("WithInternalSession() error = %v", err)
	}
}

// TestProductionB001C2SessionRetainsG1AcrossG2Publication proves a held request never switches generation.
func TestProductionB001C2SessionRetainsG1AcrossG2Publication(t *testing.T) {
	runtime := newProductionMigrationRuntime(t, prepareResolvedProductionMigrationFixture(t))

	input := newProductionMigrationInternalSessionInput(t)
	defer input.Finalization.Complete()

	err := runtime.service.WithInternalSession(t.Context(), input, func(session decisionservice.DecisionSession) error {
		g1Context := session.RequestContext(t.Context())
		if generation, ok := decisionservice.CapturedGenerationIDFromContext(g1Context); !ok || generation != productionMigrationGenerationOne {
			t.Fatalf("initial session generation = (%d, %v), want (1, true)", generation, ok)
		}

		g2 := prepareResolvedProductionMigrationFixture(t)
		if applyErr := runtime.coordinator.Apply(t.Context(), configfx.Snapshot{
			File: g2, Version: productionMigrationGenerationTwo,
		}); applyErr != nil {
			t.Fatalf("Apply(G2) error = %v", applyErr)
		}

		if active := runtime.store.Active(); active == nil || active.ID() != productionMigrationGenerationTwo {
			t.Fatalf("active generation after G2 = %#v, want generation 2", active)
		}

		if generation, ok := decisionservice.CapturedGenerationIDFromContext(session.RequestContext(t.Context())); !ok || generation != productionMigrationGenerationOne {
			t.Fatalf("held session generation after G2 = (%d, %v), want (1, true)", generation, ok)
		}

		assertProductionMigrationCheckpointPlan(t, session.Checkpoints())

		return nil
	})
	if err != nil {
		t.Fatalf("WithInternalSession() error = %v", err)
	}
}

// TestProductionB001C2RejectsInvalidExtensionCandidatesAndRetainsG1 proves all extension inputs are candidate-owned.
func TestProductionB001C2RejectsInvalidExtensionCandidatesAndRetainsG1(t *testing.T) {
	tests := []struct {
		mutate func(*config.FileSettings)
		name   string
	}{
		{name: "environment", mutate: func(settings *config.FileSettings) {
			updateProductionMigrationProviderPath(settings, "lua_environment_shared", filepath.Join(t.TempDir(), "missing-environment.lua"))
		}},
		{name: "subject", mutate: func(settings *config.FileSettings) {
			updateProductionMigrationProviderPath(settings, "lua_subject_shared", filepath.Join(t.TempDir(), "missing-subject.lua"))
		}},
		{name: "action", mutate: func(settings *config.FileSettings) {
			updateProductionMigrationActionPath(settings, filepath.Join(t.TempDir(), "missing-action.lua"))
		}},
		{name: "registry", mutate: func(settings *config.FileSettings) {
			authn := settings.Policy.Namespaces[policy.AuthnNamespace]
			authn.SchemaContributions.Lua.RegistryScripts = []string{filepath.Join(t.TempDir(), "missing-registry.lua")}
			settings.Policy.Namespaces[policy.AuthnNamespace] = authn
		}},
		{name: "registry collision", mutate: func(settings *config.FileSettings) {
			authn := settings.Policy.Namespaces[policy.AuthnNamespace]
			scripts := authn.SchemaContributions.Lua.RegistryScripts
			authn.SchemaContributions.Lua.RegistryScripts = append(append([]string(nil), scripts...), scripts[0])
			settings.Policy.Namespaces[policy.AuthnNamespace] = authn
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := newProductionMigrationRuntime(t, prepareResolvedProductionMigrationFixture(t))
			g1 := runtime.store.Active()
			candidate := productionMigrationSettings(t, prepareResolvedProductionMigrationFixture(t))
			test.mutate(candidate)

			err := runtime.coordinator.Apply(t.Context(), configfx.Snapshot{
				File: candidate, Version: productionMigrationGenerationTwo,
			})
			if err == nil {
				t.Fatalf("Apply(invalid %s) error = nil; invalid candidate was published", test.name)
			}

			if runtime.store.Active() != g1 {
				t.Fatalf("invalid %s candidate replaced G1", test.name)
			}
		})
	}
}

// TestProductionB001C2AuthApplicationRunsConfiguredChainAndSelectedActionOnce is the end-to-end authn cutover gate.
func TestProductionB001C2AuthApplicationRunsConfiguredChainAndSelectedActionOnce(t *testing.T) {
	core.InitPassDBResultPool()

	candidate := productionMigrationSettings(t, prepareResolvedProductionMigrationFixture(t))
	selectProductionMigrationAction(candidate)
	configureProductionMigrationTestBackend(t, candidate)

	runtime := newProductionMigrationRuntime(t, candidate)
	assertProductionMigrationActionSelectedOnce(t, runtime.store.Active())
	application := newProductionMigrationApplication(t, candidate, runtime)

	requestContext, finalization := core.ContextWithPostActionExecutionGate(t.Context())
	defer finalization.Complete()

	outcome, err := application.Authenticate(requestContext, core.AuthInput{
		Credentials: core.NewCredentials(
			core.WithUsername("b001-c2@example.test"),
			core.WithPassword(secret.FromBytes([]byte("opaque-b001-c2-password"))),
		),
		Context: core.NewAuthContext(
			core.WithProtocol(definitions.ProtoPOP3),
			core.WithClientIP("192.0.2.24"),
		),
		CorrelationID: "b001-c2-production-authn",
		EntryPoint:    core.AuthnEntryBackchannel,
		Service:       definitions.ServGRPC,
	})
	if err != nil {
		var admissionCauses interface{ Unwrap() []error }
		if errors.As(err, &admissionCauses) {
			causes := admissionCauses.Unwrap()
			if len(causes) == 1 && errors.As(causes[0], &admissionCauses) {
				causes = admissionCauses.Unwrap()
			}

			t.Fatalf("Authenticate() error = %v; admission causes = %v", err, causes)
		}

		t.Fatalf("Authenticate() error = %v", err)
	}

	if outcome == nil || outcome.Decision != core.AuthDecisionFail || !outcome.PolicyTerminal {
		t.Fatalf("production authn outcome = %#v, want configured terminal denial", outcome)
	}

	values := outcome.ResponseHeaders.Values(productionMigrationActionHeader)
	if len(values) != 1 || values[0] != "b001-c2" {
		t.Fatalf("production configured action values = %#v, want one exact execution", values)
	}
}

// TestProductionB001C2SchedulerUsesAdmittedProtocol proves plan guards see caller protocol from admission.
func TestProductionB001C2SchedulerUsesAdmittedProtocol(t *testing.T) {
	core.InitPassDBResultPool()

	candidate := productionMigrationSettings(t, prepareResolvedProductionMigrationFixture(t))
	configureProductionMigrationTestBackend(t, candidate)

	runtime := newProductionMigrationRuntime(t, candidate)
	application := newProductionMigrationApplication(t, candidate, runtime)

	requestContext, finalization := core.ContextWithPostActionExecutionGate(t.Context())
	defer finalization.Complete()

	outcome, err := application.Authenticate(requestContext, core.AuthInput{
		Credentials: core.NewCredentials(
			core.WithUsername("protocol-guard@example.test"),
			core.WithPassword(secret.FromBytes([]byte("opaque-protocol-guard-password"))),
		),
		Context: core.NewAuthContext(
			core.WithProtocol(definitions.ProtoIMAP),
			core.WithClientIP("192.0.2.25"),
		),
		CorrelationID: "b001-c2-protocol-guard",
		EntryPoint:    core.AuthnEntryBackchannel,
		Service:       definitions.ServGRPC,
	})
	if err != nil {
		t.Fatalf("Authenticate(IMAP) error = %v", err)
	}

	if outcome == nil || outcome.Decision != core.AuthDecisionFail || !outcome.PolicyTerminal {
		t.Fatalf("protocol-guard outcome = %#v, want final configured denial after skipped environment provider", outcome)
	}
}

// newProductionMigrationApplication binds the real production authn application to one captured runtime.
func newProductionMigrationApplication(
	t *testing.T,
	candidate *config.FileSettings,
	runtime *productionMigrationRuntime,
) core.AuthApplicationService {
	t.Helper()

	database, _ := redismock.NewClientMock()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	application, err := core.NewProductionAuthApplicationService(core.AuthDeps{
		Cfg:           candidate,
		Env:           config.NewTestEnvironmentConfig(),
		Logger:        logger,
		Redis:         rediscli.NewTestClient(database),
		AccountCache:  accountcache.NewManager(candidate),
		HostServices:  productionMigrationHostServices(t),
		LDAPQueue:     priorityqueue.NewLDAPRequestQueue(logger),
		LDAPAuthQueue: priorityqueue.NewLDAPAuthRequestQueue(logger),
	}, runtime.service)
	if err != nil {
		t.Fatalf("NewProductionAuthApplicationService() error = %v", err)
	}

	return application
}

type productionMigrationRuntime struct {
	coordinator *policyfx.Coordinator
	store       *policyruntime.GenerationStore
	service     *decisionservice.DecisionService
}

// newProductionMigrationRuntime commits one real config-loaded candidate through every production preparation slot.
func newProductionMigrationRuntime(t *testing.T, candidate config.File) *productionMigrationRuntime {
	t.Helper()

	store := policyruntime.NewGenerationStore()

	startup := policyfx.NewStartupCatalog()
	if err := startup.Capture(candidate, bootfx.LuaInitCatalogPreparation{}); err != nil {
		t.Fatalf("capture startup catalog: %v", err)
	}

	restart, err := policyfx.NewRestartBaseline(candidate)
	if err != nil {
		t.Fatalf("capture restart baseline: %v", err)
	}

	coordinator, err := policyfx.NewCoordinator(
		store,
		nil,
		&pluginloader.State{},
		unexpectedProductionMigrationTokenFactory,
		unexpectedProductionMigrationThrottlerFactory,
		productionMigrationTransportFactory,
		localization.NewMapCatalog(nil),
		startup,
		restart,
	)
	if err != nil {
		t.Fatalf("policyfx.NewCoordinator() error = %v", err)
	}

	if err = coordinator.Apply(t.Context(), configfx.Snapshot{
		File: candidate, Version: productionMigrationGenerationOne,
	}); err != nil {
		t.Fatalf("Apply(G1) error = %v", err)
	}

	source, err := decisionservice.NewStoreGenerationSource(store)
	if err != nil {
		t.Fatalf("NewStoreGenerationSource() error = %v", err)
	}

	service, err := decisionservice.NewDecisionService(source)
	if err != nil {
		t.Fatalf("NewDecisionService() error = %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if shutdownErr := store.Shutdown(ctx); shutdownErr != nil {
			t.Errorf("GenerationStore.Shutdown() error = %v", shutdownErr)
		}
	})

	return &productionMigrationRuntime{coordinator: coordinator, store: store, service: service}
}

// unexpectedProductionMigrationTokenFactory rejects accidental bearer activation in this internal-only fixture.
func unexpectedProductionMigrationTokenFactory(context.Context, config.File) (callerauth.AccessTokenValidator, error) {
	return nil, errors.New("unexpected B001-C2 access-token factory call")
}

// unexpectedProductionMigrationThrottlerFactory rejects accidental Policy-Basic activation in this fixture.
func unexpectedProductionMigrationThrottlerFactory(context.Context, config.File) (callerauth.BasicThrottler, error) {
	return nil, errors.New("unexpected B001-C2 Basic throttler factory call")
}

// productionMigrationTransportFactory returns the disabled external transport projection authored by the fixture.
func productionMigrationTransportFactory(context.Context, config.File) (callerauth.TransportCapabilities, error) {
	return callerauth.TransportCapabilities{}, nil
}

// newProductionMigrationInternalSessionInput creates the real internal caller request for authn/authenticate.
func newProductionMigrationInternalSessionInput(t *testing.T) decisionservice.InternalSessionInput {
	t.Helper()

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	profileID, err := decisionservice.NewInternalProfileID(
		core.AuthnEntryBackchannel.String(),
		string(policy.OperationAuthenticate),
	)
	if err != nil {
		t.Fatalf("NewInternalProfileID() error = %v", err)
	}

	return decisionservice.InternalSessionInput{
		ProfileID: profileID,
		Request: decision.DecisionRequestInput{
			Version:   decision.ContractVersion,
			RequestID: "b001-c2-production-session",
			Target:    target,
		},
		Finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryGRPCUnaryReturn),
	}
}

// assertProductionMigrationRegistryFact verifies the registry declaration and target schema are the same authority.
func assertProductionMigrationRegistryFact(t *testing.T, generation *policyruntime.Generation) {
	t.Helper()

	declarations := generation.Bindings().AuthnLuaFacts()
	if len(declarations) != 1 {
		t.Fatalf("authn Lua registry declarations = %d, want 1", len(declarations))
	}

	assertProductionMigrationRegistryDeclaration(t, declarations[0])

	targetID, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	target, found := generation.TargetCatalog().Lookup(targetID)
	if !found {
		t.Fatal("production generation has no authn/authenticate target")
	}

	if !productionTargetHasRegistryFact(target) {
		t.Fatalf("production target schema has no exact registry fact %q", productionMigrationRegistryFact)
	}
}

// assertProductionMigrationRegistryDeclaration verifies the exact generation-owned Lua declaration.
func assertProductionMigrationRegistryDeclaration(t *testing.T, declaration registry.AuthnLuaFactDeclaration) {
	t.Helper()

	if declaration.ID() != productionMigrationRegistryFact ||
		declaration.Stage() != policy.StagePreAuth ||
		declaration.Category() != decision.FactCategoryEnvironment ||
		declaration.Kind() != decision.ValueKindBoolean ||
		!reflect.DeepEqual(declaration.Actions(), []policy.Operation{policy.OperationAuthenticate}) {
		t.Fatalf("authn Lua registry declaration = %#v, want exact B001-C2 fact", declaration)
	}
}

// productionTargetHasRegistryFact reports whether the target schema owns the exact Lua fact declaration.
func productionTargetHasRegistryFact(target policyruntime.CompiledTarget) bool {
	for _, fact := range target.Schema().Facts() {
		if fact.ID() == productionMigrationRegistryFact &&
			fact.Category() == decision.FactCategoryEnvironment &&
			fact.Kind() == decision.ValueKindBoolean &&
			slices.Contains(fact.AllowedSources(), decision.FactSourceLua) {
			return true
		}
	}

	return false
}

// assertProductionMigrationCheckpointPlan verifies the frozen host execution order without legacy translation.
func assertProductionMigrationCheckpointPlan(t *testing.T, plans []decisionservice.CheckpointPlan) {
	t.Helper()

	type checkpoint struct {
		name      string
		providers []string
	}

	want := []checkpoint{
		{name: string(policy.StagePreAuth), providers: []string{policy.AuthnProviderBruteForce, "authn/lua_environment_shared"}},
		{name: "auth_backend", providers: []string{policy.AuthnProviderLDAPBackend}},
		{name: "subject_analysis", providers: []string{"authn/lua_subject_shared"}},
		{name: string(policy.StageAuthDecision), providers: []string{}},
	}

	got := make([]checkpoint, 0, len(plans))
	for _, plan := range plans {
		got = append(got, checkpoint{name: plan.Name(), providers: plan.ProviderIDs()})
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("production checkpoint plan = %#v, want %#v", got, want)
	}
}

// assertProductionMigrationActionSelectedOnce verifies the executable rule owns one exact configured action use.
func assertProductionMigrationActionSelectedOnce(t *testing.T, generation *policyruntime.Generation) {
	t.Helper()

	targetID, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("decision.NewTarget() error = %v", err)
	}

	target, found := generation.TargetCatalog().Lookup(targetID)
	if !found {
		t.Fatal("production generation has no authn/authenticate target")
	}

	setID, err := registry.ParsePolicySetID("b001_c2.policy_set", "authn/configured")
	if err != nil {
		t.Fatalf("ParsePolicySetID() error = %v", err)
	}

	configured, found := target.LookupPolicySet(setID)
	if !found {
		t.Fatal("production target has no authn/configured policy set")
	}

	for _, rule := range configured.Rules() {
		if rule.Name() != "final_contract_deny" {
			continue
		}

		effects := rule.Effects()
		if len(effects) != 1 || effects[0].ID() != productionMigrationActionID {
			t.Fatalf("configured final action uses = %#v, want one %s", effects, productionMigrationActionID)
		}

		return
	}

	t.Fatal("production target has no final_contract_deny rule")
}

// assertProductionMigrationHostProvider verifies one exact compiled Lua source remains session-bound.
func assertProductionMigrationHostProvider(
	t *testing.T,
	session decisionservice.AuthnHostProviderSession,
	id string,
	kind string,
) {
	t.Helper()

	provider, found := session.AuthnHostProvider(id)
	if !found || provider == nil || provider.ID() != id || provider.Kind() != kind {
		t.Fatalf("production authn host provider %q = %#v/%v, want kind %q", id, provider, found, kind)
	}
}

// productionMigrationSettings resolves the mutable test candidate behind the config.File boundary.
func productionMigrationSettings(t *testing.T, candidate config.File) *config.FileSettings {
	t.Helper()

	settings, ok := candidate.(*config.FileSettings)
	if !ok || settings == nil {
		t.Fatalf("production migration candidate = %T, want *config.FileSettings", candidate)
	}

	return settings
}

// updateProductionMigrationProviderPath changes one in-memory candidate without touching the frozen fixture.
func updateProductionMigrationProviderPath(settings *config.FileSettings, name string, path string) {
	authn := settings.Policy.Namespaces[policy.AuthnNamespace]
	provider := authn.Providers[name]
	provider.ScriptPath = path
	authn.Providers[name] = provider
	settings.Policy.Namespaces[policy.AuthnNamespace] = authn
}

// updateProductionMigrationActionPath changes only the candidate-owned configured action path.
func updateProductionMigrationActionPath(settings *config.FileSettings, path string) {
	authn := settings.Policy.Namespaces[policy.AuthnNamespace]
	effect := authn.Effects["lua_action_notify"]
	effect.ScriptPath = path
	authn.Effects["lua_action_notify"] = effect
	settings.Policy.Namespaces[policy.AuthnNamespace] = authn
}

// selectProductionMigrationAction promotes the fixture rule to enforce and selects its configured action once.
func selectProductionMigrationAction(settings *config.FileSettings) {
	target := settings.Policy.Targets[0]
	target.Mode = string(registry.AuthorityModeEnforce)
	settings.Policy.Targets[0] = target

	authn := settings.Policy.Namespaces[policy.AuthnNamespace]
	effect := authn.Effects["lua_action_notify"]
	effect.Parameters = map[string]policyconfig.EffectParameterConfig{
		policy.ObligationArgAction: {
			Type: string(decision.ValueKindString), MaxLength: 128,
			AllowedStrings: []string{policy.LuaActionDispatchLua}, Required: true,
		},
	}
	authn.Effects["lua_action_notify"] = effect

	configured := authn.PolicySets["configured"]
	for index := range configured.Rules {
		if configured.Rules[index].Name != "final_contract_deny" {
			continue
		}

		configured.Rules[index].Then.Obligations = []policyconfig.EffectSelectionConfig{{
			ID: productionMigrationActionID,
			Parameters: map[string]any{
				policy.ObligationArgAction: policy.LuaActionDispatchLua,
			},
		}}
	}

	authn.PolicySets["configured"] = configured
	settings.Policy.Namespaces[policy.AuthnNamespace] = authn
}

// configureProductionMigrationTestBackend keeps the production host traversal hermetic after exact plan dispatch.
func configureProductionMigrationTestBackend(t *testing.T, settings *config.FileSettings) {
	t.Helper()

	if settings.Server == nil {
		settings.Server = &config.ServerSection{}
	}

	var backend config.Backend
	if err := backend.Set(definitions.BackendLDAPName); err != nil {
		t.Fatalf("configure B001-C2 test backend: %v", err)
	}

	settings.Server.Backends = []*config.Backend{&backend}
}

// productionMigrationPasswordVerifier returns one deterministic backend denial without external I/O.
type productionMigrationPasswordVerifier struct{}

// Verify preserves typed LDAP traversal while keeping the production migration fixture hermetic.
func (productionMigrationPasswordVerifier) Verify(
	_ *gin.Context,
	auth *core.AuthState,
	_ []*core.PassDBMap,
) (*core.PassDBResult, error) {
	result := core.GetPassDBResultFromPool()
	result.UserFound = true
	result.Authenticated = false
	result.AccountField = "uid"
	result.Account = auth.Request.Username
	result.Backend = definitions.BackendLDAP
	result.Attributes = map[string][]any{
		"uid": {auth.Request.Username},
	}

	return result, nil
}

// productionMigrationHostServices replaces only backend I/O in the real production host bundle.
func productionMigrationHostServices(t *testing.T) core.AuthnHostServices {
	t.Helper()

	services, err := core.NewAuthnHostServices(core.AuthnHostServicesInput{
		PasswordVerifier: productionMigrationPasswordVerifier{},
		Cache:            coreauth.DefaultCacheService{},
		BruteForce:       coreauth.DefaultBruteForceService{},
		Subject:          coreauth.DefaultLuaSubject{},
		RBL:              coreauth.DefaultRBLService{},
	})
	if err != nil {
		t.Fatalf("construct B001-C2 production host services: %v", err)
	}

	return services
}
