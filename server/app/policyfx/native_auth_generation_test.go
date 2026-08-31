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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/core"
	coreauth "github.com/croessner/nauthilus/v4/server/core/auth"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/callerauth"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

const nativeAuthGenerationFixture = `policy:
  namespaces:
    authn:
      providers:
        plugin.example.environment:
          kind: plugin
          module: example
          targets: [{action: authenticate}]
          executions: [host_sync]
        plugin.example.subject.risk:
          kind: plugin
          module: example
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          checkpoints:
            pre_auth:
              providers:
                - {name: native_environment, use: authn/plugin.example.environment}
            auth_backend:
              providers:
                - {name: ldap_backend, use: authn/builtin/ldap_backend}
            subject_analysis:
              providers:
                - {name: native_subject, use: authn/plugin.example.subject.risk}
            auth_decision: {providers: []}
      policy_sets:
        configured:
          rules:
            - name: selected_native_obligation
              checkpoint: pre_auth
              require_providers: [native_environment]
              if:
                attribute: plugin.environment.example.score
                gte: 0.5
              then:
                decision: deny
                reason: native_environment_score
                outcome_marker: auth.outcome.auth_failure
                fsm_event_marker: auth.fsm.event.pre_auth_deny
                response_marker: auth.response.fail
                obligations: [{id: authn/plugin.example.enforce}]
            - name: selected_native_post_action
              checkpoint: auth_decision
              if: {always: true}
              then:
                decision: deny
                obligations: [{id: authn/plugin.example.post_action}]
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
      default_policy: authn/standard_auth
      plans:
        pre_auth: {policy_sets: [authn/configured]}
        auth_decision: {policy_sets: [authn/configured]}
`

// TestProductionCoordinatorPublishesNativeAuthSourcesAttributesAndSelectedEffectsTogether proves the sole graph.
func TestProductionCoordinatorPublishesNativeAuthSourcesAttributesAndSelectedEffectsTogether(t *testing.T) {
	configured, state := nativeAuthGenerationCandidate(t)
	runtime := newNativeAuthGenerationRuntime(t, configured, state)

	active := runtime.store.Active()
	if active == nil || active.ID() != 1 {
		t.Fatalf("active generation = %#v, want G1", active)
	}

	assertNativeGenerationBindings(t, active)
	assertNativeGenerationCatalog(t, active)
	assertInvalidNativeCandidatesRetainGeneration(t, runtime, configured, active)
}

// assertNativeGenerationBindings verifies selected sources, effects, and policy attributes share one owner.
func assertNativeGenerationBindings(t *testing.T, active *policyruntime.Generation) {
	t.Helper()

	bindings := active.Bindings()
	for _, providerID := range []string{
		"authn/plugin.example.environment",
		"authn/plugin.example.subject.risk",
	} {
		if _, found := bindings.AuthnHostProvider(providerID); !found {
			t.Fatalf("generation bindings lost native auth source %s", providerID)
		}
	}

	if _, found := bindings.PostActions()["authn/plugin.example.post_action"]; !found {
		t.Fatal("generation bindings lost selected native post-action owner")
	}

	attributes := bindings.AuthnPolicyAttributes()

	generated := attributes[policy.PluginEnvironmentAttributeID("example", "environment", "triggered")]
	if generated.ProducerCheck != "native_environment" {
		t.Fatalf("generated native attribute producer = %q, want exact plan instance", generated.ProducerCheck)
	}

	if registered := attributes["plugin.environment.example.score"]; registered.ProducerCheck != "" {
		t.Fatalf("public ProducerTypes attribute gained synthetic producer check %q", registered.ProducerCheck)
	}
}

// assertNativeGenerationCatalog verifies canonical effects and every contributed fact are compiled together.
func assertNativeGenerationCatalog(t *testing.T, active *policyruntime.Generation) {
	t.Helper()

	target, err := decision.NewTarget("authn", "authenticate")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	compiled, found := active.TargetCatalog().Lookup(target)
	if !found {
		t.Fatal("active catalog lost authn/authenticate")
	}

	if _, found = compiled.LookupEffect("authn/plugin.example.post_action"); !found {
		t.Fatal("active catalog lost canonical native post-action effect")
	}

	if _, found = compiled.LookupEffect("authn/example.post_action"); found {
		t.Fatal("active catalog retained a bare native effect alias")
	}

	facts := make(map[string]struct{})
	for _, fact := range compiled.Schema().Facts() {
		facts[fact.ID()] = struct{}{}
	}

	for _, factID := range []string{
		"plugin.environment.example.score",
		"plugin.resource.example.enforced",
		"nauthilus.auth.plugin.environment.example.environment.triggered",
		"nauthilus.auth.plugin.subject.example.risk.rejected",
	} {
		if _, exists := facts[factID]; !exists {
			t.Fatalf("active authn schema lost native fact %s", factID)
		}
	}
}

// assertInvalidNativeCandidatesRetainGeneration proves validation failures cannot replace the active graph.
func assertInvalidNativeCandidatesRetainGeneration(
	t *testing.T,
	runtime *nativeAuthGenerationRuntime,
	configured *config.FileSettings,
	active *policyruntime.Generation,
) {
	t.Helper()

	invalid := nativeAuthCandidateWithMissingSubject(t, configured)

	err := runtime.coordinator.Apply(t.Context(), configfx.Snapshot{File: invalid, Version: 2})
	if err == nil {
		t.Fatal("Apply(missing native source) error = nil")
	}

	if runtime.store.Active() != active {
		t.Fatal("failed native source candidate replaced the complete G1 generation")
	}

	invalid = nativeAuthCandidateWithUnboundSecret(configured)

	err = runtime.coordinator.Apply(t.Context(), configfx.Snapshot{File: invalid, Version: 3})
	if err == nil || !strings.Contains(err.Error(), "policy.namespaces.authn.providers.plugin.example.environment.secrets") {
		t.Fatalf("Apply(unbound native secret) error = %v, want exact credential-owner path", err)
	}

	if runtime.store.Active() != active {
		t.Fatal("failed native credential candidate replaced the complete G1 generation")
	}
}

// TestProductionNativeAuthFactSelectsExactEffectAndFailedReloadRetainsG1 exercises the real application boundary.
func TestProductionNativeAuthFactSelectsExactEffectAndFailedReloadRetainsG1(t *testing.T) {
	core.InitPassDBResultPool()

	probe := &nativeAuthExecutionProbe{}
	configured, state := nativeAuthGenerationCandidateWithProbe(t, probe)
	runtime := newNativeAuthGenerationRuntime(t, configured, state)
	application := newNativeAuthApplication(t, configured, runtime.service)

	assertNativeAuthRequest(t, application, "native-auth-g1-first")
	assertNativeAuthProbe(t, probe, 1)

	generationOne := runtime.store.Active()
	invalid := nativeAuthCandidateWithMissingSubject(t, configured)

	err := runtime.coordinator.Apply(t.Context(), configfx.Snapshot{File: invalid, Version: 2})
	if err == nil {
		t.Fatal("Apply(invalid G2) error = nil")
	}

	if runtime.store.Active() != generationOne {
		t.Fatal("failed G2 replaced the executable G1 native auth generation")
	}

	assertNativeAuthRequest(t, application, "native-auth-g1-after-failed-g2")
	assertNativeAuthProbe(t, probe, 2)
}

type nativeAuthGenerationRuntime struct {
	coordinator *Coordinator
	store       *policyruntime.GenerationStore
	service     *decisionservice.DecisionService
}

// newNativeAuthGenerationRuntime commits one production candidate and exposes its sole Decision Service.
func newNativeAuthGenerationRuntime(
	t *testing.T,
	configured config.File,
	state *pluginloader.State,
) *nativeAuthGenerationRuntime {
	t.Helper()

	store := policyruntime.NewGenerationStore()

	coordinator, err := NewCoordinator(
		store,
		nil,
		state,
		unusedTokenFactory,
		unusedThrottlerFactory,
		func(context.Context, config.File) (callerauth.TransportCapabilities, error) {
			return callerauth.TransportCapabilities{}, nil
		},
		localization.NewMapCatalog(nil),
		mustStartupCatalog(t, configured, nil),
		mustRestartBaseline(t, configured),
	)
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	if err = coordinator.Apply(t.Context(), configfx.Snapshot{File: configured, Version: 1}); err != nil {
		t.Fatalf("Apply(initial) error = %v", err)
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

	return &nativeAuthGenerationRuntime{coordinator: coordinator, store: store, service: service}
}

// newNativeAuthApplication binds real production request projection to the sole committed generation store.
func newNativeAuthApplication(
	t *testing.T,
	configured config.File,
	service *decisionservice.DecisionService,
) core.AuthApplicationService {
	t.Helper()

	database, _ := redismock.NewClientMock()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	hostServices, err := core.NewAuthnHostServices(core.AuthnHostServicesInput{
		PasswordVerifier: nativeAuthTestPasswordVerifier{},
		Cache:            coreauth.DefaultCacheService{},
		BruteForce:       coreauth.DefaultBruteForceService{},
		Subject:          coreauth.DefaultLuaSubject{},
		RBL:              coreauth.DefaultRBLService{},
	})
	if err != nil {
		t.Fatalf("NewAuthnHostServices() error = %v", err)
	}

	application, err := core.NewProductionAuthApplicationService(core.AuthDeps{
		Cfg: configured, Env: config.NewTestEnvironmentConfig(), Logger: logger,
		Redis: rediscli.NewTestClient(database), AccountCache: accountcache.NewManager(configured),
		HostServices: hostServices, NativeRuntime: pluginruntime.NewAuthnRequestRuntime(),
		LDAPQueue:     priorityqueue.NewLDAPRequestQueue(logger),
		LDAPAuthQueue: priorityqueue.NewLDAPAuthRequestQueue(logger),
	}, service)
	if err != nil {
		t.Fatalf("NewProductionAuthApplicationService() error = %v", err)
	}

	return application
}

// assertNativeAuthRequest runs one admitted production authentication request.
func assertNativeAuthRequest(t *testing.T, application core.AuthApplicationService, correlationID string) {
	t.Helper()

	requestContext, finalization := core.ContextWithPostActionExecutionGate(t.Context())
	defer finalization.Complete()

	outcome, err := application.Authenticate(requestContext, core.AuthInput{
		Credentials: core.NewCredentials(
			core.WithUsername("native@example.test"),
			core.WithPassword(secret.FromBytes([]byte("native-auth-test-password"))),
		),
		Context: core.NewAuthContext(
			core.WithProtocol(definitions.ProtoPOP3),
			core.WithClientIP("192.0.2.34"),
		),
		CorrelationID: correlationID,
		EntryPoint:    core.AuthnEntryBackchannel,
		Service:       definitions.ServGRPC,
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	if outcome == nil || outcome.Decision != core.AuthDecisionFail || !outcome.PolicyTerminal {
		t.Fatalf("native auth outcome = %#v, want exact Policy-terminal deny", outcome)
	}
}

// assertNativeAuthProbe proves the selected environment fact/effect graph and later-provider non-execution.
func assertNativeAuthProbe(t *testing.T, probe *nativeAuthExecutionProbe, want int32) {
	t.Helper()

	if probe.environmentCalls.Load() != want || probe.subjectCalls.Load() != 0 ||
		probe.obligationCalls.Load() != want {
		t.Fatalf(
			"native source/subject/obligation calls = %d/%d/%d, want %d/0/%d",
			probe.environmentCalls.Load(), probe.subjectCalls.Load(), probe.obligationCalls.Load(),
			want, want,
		)
	}

	if probe.postActionCalls.Load() != 0 {
		t.Fatalf("unselected native post-action calls = %d, want 0", probe.postActionCalls.Load())
	}

	if !probe.sawScoreFact.Load() {
		t.Fatal("selected native obligation did not receive the exact native environment fact")
	}
}

type nativeAuthTestPasswordVerifier struct{}

// Verify returns one deterministic typed LDAP denial for the production host traversal.
func (nativeAuthTestPasswordVerifier) Verify(
	_ *gin.Context,
	auth *core.AuthState,
	_ []*core.PassDBMap,
) (*core.PassDBResult, error) {
	result := core.GetPassDBResultFromPool()
	result.UserFound = true
	result.Authenticated = true
	result.AccountField = "uid"
	result.Account = auth.Request.Username
	result.Backend = definitions.BackendLDAP
	result.Attributes = map[string][]any{"uid": {auth.Request.Username}}

	return result, nil
}

// nativeAuthGenerationCandidate loads one real registrar state and matching top-level Policy candidate.
func nativeAuthGenerationCandidate(t *testing.T) (*config.FileSettings, *pluginloader.State) {
	return nativeAuthGenerationCandidateWithProbe(t, nil)
}

// nativeAuthGenerationCandidateWithProbe loads one executable public plugin behind explicit test instrumentation.
func nativeAuthGenerationCandidateWithProbe(
	t *testing.T,
	probe *nativeAuthExecutionProbe,
) (*config.FileSettings, *pluginloader.State) {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(nativeAuthGenerationFixture))
	if err != nil {
		t.Fatalf("decode native auth policy: %v", err)
	}

	artifact := filepath.Join(t.TempDir(), "example.so")
	if err = os.WriteFile(artifact, []byte("native-auth-test-artifact"), 0o600); err != nil {
		t.Fatalf("write plugin artifact: %v", err)
	}

	digest, err := pluginloader.DigestArtifact(artifact)
	if err != nil {
		t.Fatalf("DigestArtifact() error = %v", err)
	}

	module := config.PluginModule{Name: "example", Path: artifact}
	loader := pluginloader.NewLoader(
		pluginloader.WithLoaderArtifactReader(os.ReadFile),
		pluginloader.WithOpener(nativeAuthTestOpener{probe: probe}),
	)

	state, err := loader.Load([]pluginloader.VerifiedModule{{
		Module: module, ArtifactPath: artifact, ArtifactDigest: digest,
	}})
	if err != nil {
		t.Fatalf("Load(native auth plugin) error = %v", err)
	}

	backend := &config.Backend{}
	if err = backend.Set(definitions.BackendLDAPName); err != nil {
		t.Fatalf("configure native auth test backend: %v", err)
	}

	configured := &config.FileSettings{
		Policy: document.Policy,
		Plugins: &config.PluginsSection{
			VerificationPolicy: config.PluginVerificationPolicyOff,
			Modules:            []config.PluginModule{module},
		},
		Server: &config.ServerSection{Backends: []*config.Backend{backend}},
	}

	return configured, state
}

// nativeAuthCandidateWithMissingSubject changes only Policy source selection to an uncaptured component.
func nativeAuthCandidateWithMissingSubject(
	t *testing.T,
	baseline *config.FileSettings,
) *config.FileSettings {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(strings.ReplaceAll(
		nativeAuthGenerationFixture,
		"subject.risk",
		"subject.missing",
	)))
	if err != nil {
		t.Fatalf("decode missing native source candidate: %v", err)
	}

	return &config.FileSettings{Policy: document.Policy, Plugins: baseline.Plugins, Server: baseline.Server}
}

// nativeAuthCandidateWithUnboundSecret adds credentials to a provider SPI that intentionally has no secret carrier.
func nativeAuthCandidateWithUnboundSecret(baseline *config.FileSettings) *config.FileSettings {
	configured := policyconfig.Normalize(policyconfig.Document{Policy: baseline.Policy}).Policy
	authn := configured.Namespaces["authn"]
	provider := authn.Providers["plugin.example.environment"]
	provider.Secrets = map[string]secret.Value{"token": secret.New("unbound-native-secret")}
	authn.Providers["plugin.example.environment"] = provider
	configured.Namespaces["authn"] = authn

	return &config.FileSettings{Policy: configured, Plugins: baseline.Plugins, Server: baseline.Server}
}

type nativeAuthTestHandle struct {
	probe *nativeAuthExecutionProbe
}

// Lookup returns the exact required public factory symbol.
func (h nativeAuthTestHandle) Lookup(symbol string) (any, error) {
	if symbol != "NauthilusPlugin" {
		return nil, errors.New("unexpected plugin symbol")
	}

	return func() (pluginapi.Plugin, error) { return &nativeAuthTestPlugin{probe: h.probe}, nil }, nil
}

type nativeAuthTestOpener struct {
	probe *nativeAuthExecutionProbe
}

// Open returns the hermetic public plugin handle for the staged artifact.
func (o nativeAuthTestOpener) Open(string) (pluginloader.PluginHandle, error) {
	return nativeAuthTestHandle(o), nil
}

type nativeAuthTestPlugin struct {
	probe *nativeAuthExecutionProbe
}

// Metadata returns one compatible test plugin contract.
func (*nativeAuthTestPlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{Name: "native-auth-test", Version: "1.0.0", APIVersion: pluginapi.APIVersion}
}

// Register publishes all four public auth-shaped component families and one Policy attribute.
func (p *nativeAuthTestPlugin) Register(registrar pluginapi.Registrar) error {
	registrations := []func() error{
		func() error { return registrar.RegisterEnvironmentSource(nativeAuthTestEnvironment{probe: p.probe}) },
		func() error { return registrar.RegisterSubjectSource(nativeAuthTestSubject{probe: p.probe}) },
		func() error { return registrar.RegisterObligationTarget(nativeAuthTestObligation{probe: p.probe}) },
		func() error { return registrar.RegisterPostActionTarget(nativeAuthTestPostAction{probe: p.probe}) },
		func() error {
			return registrar.RegisterPolicyAttribute(pluginapi.AttributeDefinition{
				ID: "plugin.environment.example.score", Stage: pluginapi.PolicyStagePreAuth,
				Operations:    []pluginapi.PolicyOperation{pluginapi.PolicyOperationAuthenticate},
				ProducerTypes: []string{"plugin.environment"},
				Category:      pluginapi.AttributeCategoryEnvironment, Type: pluginapi.AttributeTypeNumber,
			})
		},
		func() error {
			return registrar.RegisterPolicyAttribute(pluginapi.AttributeDefinition{
				ID: "plugin.resource.example.enforced", Stage: pluginapi.PolicyStageAuthDecision,
				Operations: []pluginapi.PolicyOperation{pluginapi.PolicyOperationAuthenticate},
				Category:   pluginapi.AttributeCategoryResource, Type: pluginapi.AttributeTypeBool,
			})
		},
	}
	for _, register := range registrations {
		if err := register(); err != nil {
			return err
		}
	}

	return nil
}

type nativeAuthExecutionProbe struct {
	environmentCalls atomic.Int32
	subjectCalls     atomic.Int32
	obligationCalls  atomic.Int32
	postActionCalls  atomic.Int32
	sawScoreFact     atomic.Bool
}

type nativeAuthTestEnvironment struct {
	probe *nativeAuthExecutionProbe
}

// Descriptor returns the exact configured environment component.
func (nativeAuthTestEnvironment) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{Name: "environment", Timeout: time.Second}
}

// Evaluate returns one typed registered fact without touching ambient state.
func (s nativeAuthTestEnvironment) Evaluate(
	context.Context,
	pluginapi.EnvironmentRequest,
) (pluginapi.EnvironmentResult, error) {
	if s.probe != nil {
		s.probe.environmentCalls.Add(1)
	}

	return pluginapi.EnvironmentResult{Facts: []pluginapi.PolicyFact{{
		Attribute: "plugin.environment.example.score", Value: float64(1),
	}}}, nil
}

type nativeAuthTestSubject struct {
	probe *nativeAuthExecutionProbe
}

// Descriptor returns the exact configured subject component.
func (nativeAuthTestSubject) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{Name: "risk", Timeout: time.Second}
}

// Evaluate returns one neutral subject result.
func (s nativeAuthTestSubject) Evaluate(
	context.Context,
	pluginapi.SubjectRequest,
) (pluginapi.SubjectResult, error) {
	if s.probe != nil {
		s.probe.subjectCalls.Add(1)
	}

	return pluginapi.SubjectResult{}, nil
}

type nativeAuthTestObligation struct {
	probe *nativeAuthExecutionProbe
}

// Name returns the unchanged public component identity.
func (nativeAuthTestObligation) Name() string { return "enforce" }

// Execute returns one successful public obligation outcome.
func (o nativeAuthTestObligation) Execute(
	_ context.Context,
	request pluginapi.ObligationRequest,
) (pluginapi.ObligationResult, error) {
	if o.probe != nil {
		o.probe.obligationCalls.Add(1)

		for _, fact := range request.Facts {
			if fact.Attribute == "plugin.environment.example.score" && fact.Value == float64(1) {
				o.probe.sawScoreFact.Store(true)
			}
		}
	}

	return pluginapi.ObligationResult{Applied: true}, nil
}

type nativeAuthTestPostAction struct {
	probe *nativeAuthExecutionProbe
}

// Name returns the unchanged public component identity.
func (nativeAuthTestPostAction) Name() string { return "post_action" }

// Enqueue returns one successful detached enqueue outcome.
func (a nativeAuthTestPostAction) Enqueue(
	context.Context,
	pluginapi.PostActionRequest,
) (pluginapi.PostActionEnqueueResult, error) {
	if a.probe != nil {
		a.probe.postActionCalls.Add(1)
	}

	return pluginapi.PostActionEnqueueResult{Enqueued: true}, nil
}
