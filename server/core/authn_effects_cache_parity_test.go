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

package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/luamod"
	"github.com/croessner/nauthilus/v3/server/lualib/luaseal"
	"github.com/croessner/nauthilus/v3/server/lualib/vmpool"
	"github.com/croessner/nauthilus/v3/server/model/authdto"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/catalogcompile"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/rediscli"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	lua "github.com/yuin/gopher-lua"
)

// authnCandidatePolicyModel is test-owned opaque policy material for one generation.
type authnCandidatePolicyModel struct {
	AttributeRegistry map[string]registry.AttributeDefinition
	Mode              string
	Generation        uint64
}

// ClonePolicyModel returns a detached copy for generation ownership.
func (m *authnCandidatePolicyModel) ClonePolicyModel() policyruntime.PolicyModel {
	return m.clone()
}

// ValidatePolicyModel validates the minimum opaque generation identity.
func (m *authnCandidatePolicyModel) ValidatePolicyModel() error {
	if m == nil || m.Generation == 0 {
		return fmt.Errorf("candidate policy model requires a positive generation")
	}

	return nil
}

// GenerationID returns the immutable candidate identity.
func (m *authnCandidatePolicyModel) GenerationID() uint64 {
	if m == nil {
		return 0
	}

	return m.Generation
}

// clone returns a detached concrete policy model for test assembly.
func (m *authnCandidatePolicyModel) clone() *authnCandidatePolicyModel {
	if m == nil {
		return nil
	}

	attributes := make(map[string]registry.AttributeDefinition, len(m.AttributeRegistry))
	for id, definition := range m.AttributeRegistry {
		attributes[id] = registry.CloneDefinition(definition)
	}

	return &authnCandidatePolicyModel{
		AttributeRegistry: attributes,
		Mode:              m.Mode,
		Generation:        m.Generation,
	}
}

// installAuthnCandidateServices installs one request-pipeline fixture and restores global seams.
func installAuthnCandidateServices(
	t *testing.T,
	verifier PasswordVerifier,
	subject CapturedLuaSubject,
) {
	t.Helper()

	previousVerifier := getPasswordVerifier()
	previousSubject := getLuaSubject()

	RegisterPasswordVerifier(verifier)
	RegisterLuaSubject(subject)
	t.Cleanup(func() {
		RegisterPasswordVerifier(previousVerifier)
		RegisterLuaSubject(previousSubject)
	})
}

func TestAuthnCandidateSynchronousFailureClearsStaleLocalization(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	db, _ := redismock.NewClientMock()
	base := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	})
	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(execution *authnCandidateExecution) {
			execution.preAuthReady = true
			execution.auth.Security.BruteForceName = "localized_sync_failure"
			execution.auth.Runtime.EnvironmentName = definitions.ControlBruteForce
			execution.auth.Runtime.StatusMessage = "localized success"
			execution.auth.Runtime.StatusMessageI18NKey = "auth.success"
			execution.auth.Runtime.ResponseLanguage = "de"
			execution.auth.recordPolicyBruteForce(execution.ginCtx, true)
			execution.executeEffect = func(report.EffectRequest) effectsupervisor.Result {
				return effectsupervisor.Failed("synchronous_failure")
			}
		},
	}
	acceptor := &authnCandidateAcceptAll{}
	runtime := newAuthnCandidateDecisionService(t, cfg, acceptor)

	adapter, err := NewAuthnCandidateApplicationService(host, runtime, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	outcome := authenticateAuthnCandidate(
		t,
		"synchronous localization failure",
		adapter,
		authnApplicationTestInput(AuthModeAuthenticate),
	)

	if outcome.Decision != AuthDecisionTempFail || outcome.StatusMessage != definitions.TempFailDefault {
		t.Fatalf("synchronous failure result = %q/%q, want tempfail/default", outcome.Decision, outcome.StatusMessage)
	}

	if outcome.StatusMessageI18NKey != "" || outcome.ResponseLanguage != "" {
		t.Fatalf(
			"synchronous failure localization = %q/%q, want empty",
			outcome.StatusMessageI18NKey,
			outcome.ResponseLanguage,
		)
	}
}

func TestAuthnCandidateAcceptanceTempFailReplacesSelectedLocalization(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	input := authnApplicationTestInput(AuthModeAuthenticate)

	execution, complete := prepareAuthnCandidateLocalizationExecution(t, cfg, input)
	defer complete()

	execution.auth.Runtime.StatusMessage = "subject accepted"
	execution.auth.Runtime.StatusMessageI18NKey = "auth.success"
	execution.auth.Runtime.ResponseLanguage = "de"

	execution.CaptureAuthnDecision(
		context.Background(),
		decision.Target{},
		string(policy.StageAuthDecision),
		authnCandidateLocalizedDenyDecision(),
	)

	result, err := execution.finalize(
		string(policy.StageAuthDecision),
		mustAuthnDecisionResponseWithCode(
			t,
			decision.EffectIndeterminate,
			decision.StatusCodeEffectAcceptanceRejected,
		),
		authnApplicationResult{auth: &AuthOutcome{Decision: AuthDecisionOK}},
	)
	if err != nil {
		t.Fatalf("finalize() error = %v", err)
	}

	if result.auth == nil || result.auth.Decision != AuthDecisionTempFail {
		t.Fatalf("acceptance result = %#v, want tempfail", result.auth)
	}

	if result.auth.StatusMessage != definitions.TempFailDefault ||
		result.auth.StatusMessageI18NKey != "" ||
		result.auth.ResponseLanguage != "" {
		t.Fatalf(
			"acceptance presentation = %q/%q/%q, want default tempfail without deny localization",
			result.auth.StatusMessage,
			result.auth.StatusMessageI18NKey,
			result.auth.ResponseLanguage,
		)
	}
}

// prepareAuthnCandidateLocalizationExecution creates one response-capturing candidate request.
func prepareAuthnCandidateLocalizationExecution(
	t *testing.T,
	cfg config.File,
	input AuthInput,
) (*authnCandidateExecution, func()) {
	t.Helper()

	db, _ := redismock.NewClientMock()
	base := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	})
	ctx, gate := authnCandidateTestContext(context.Background(), input)

	execution, _, err := base.prepareAuthnCandidateExecution(ctx, input, policy.OperationAuthenticate)
	if err != nil {
		t.Fatalf("prepareAuthnCandidateExecution() error = %v", err)
	}

	return execution, gate.Complete
}

// authnCandidateLocalizedDenyDecision returns one selected localized denial fixture.
func authnCandidateLocalizedDenyDecision() *report.FinalDecision {
	return &report.FinalDecision{
		Effect: policy.DecisionDeny, Stage: policy.StageAuthDecision,
		FSMEventMarker: policy.FSMEventMarkerAuthDeny, ResponseMarker: policy.ResponseMarkerFail,
		ResponseMessage: &report.ResponseMessageSelection{
			Source: policy.ResponseSourceI18N, Message: "localized denial",
			I18NKey: "auth.policy.denied",
		},
		ResponseLanguage: &report.ResponseLanguageSelection{
			Source: policy.ResponseSourceLiteral, Language: "de",
		},
	}
}

func TestAuthnCandidateAcceptanceRejectionReplacesSelectedTempFailCause(t *testing.T) {
	selected := &report.FinalDecision{
		Effect: policy.DecisionTempFail, Stage: policy.StagePreAuth,
		OutcomeMarker: "auth.outcome.tls_required", ResponseMarker: policy.ResponseMarkerTempFailNoTLS,
		FSMEventMarker: policy.FSMEventMarkerPreAuthTempFail,
	}
	response := mustAuthnDecisionResponseWithCode(
		t,
		decision.EffectIndeterminate,
		decision.StatusCodeEffectAcceptanceRejected,
	)

	presentation, acceptanceFailure := authnCandidateRuntimePresentation(response, selected)
	if !acceptanceFailure || presentation.OutcomeMarker != authnCandidateOutcomeEffectAcceptanceFailure {
		t.Fatalf("acceptance tempfail presentation = %#v/%t", presentation, acceptanceFailure)
	}
}

func TestAuthnPolicyEffectRequestPreservesCanonicalEffectAndParameters(t *testing.T) {
	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: "authn-parity", AuthenticationKind: "internal", TransportKind: "internal", Internal: true,
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	environment := "candidate_environment"
	environmentValue := mustAuthnStringValue(t, environment)

	bindings := registry.BuiltinAuthEffectBindings()
	if len(bindings) != 1 || bindings[0].EffectID != policy.EffectBruteForceUpdate {
		t.Fatalf("builtin auth effect bindings = %#v, want brute-force update only", bindings)
	}

	for ordinal, binding := range bindings {
		parameters := map[string]decision.Value{policy.ObligationArgEnvironment: environmentValue}
		wantArgs := map[string]any{policy.ObligationArgEnvironment: environment}

		valueMap, mapErr := decision.NewValueMap(parameters)
		if mapErr != nil {
			t.Fatalf("NewValueMap(%q) error = %v", binding.EffectID, mapErr)
		}

		execution, executionErr := policyruntime.NewEffectExecution(policyruntime.EffectExecutionInput{
			Facts: facts, Caller: caller,
			Parameters: valueMap, Target: target, EffectID: binding.EffectID,
			DecisionID: "decision-authn-effect", Provider: binding.Provider,
			Generation: 1, Ordinal: uint32(ordinal + 1),
		})
		if executionErr != nil {
			t.Fatalf("NewEffectExecution(%q) error = %v", binding.EffectID, executionErr)
		}

		request, requestErr := authnPolicyEffectRequest(execution)
		if requestErr != nil {
			t.Fatalf("authnPolicyEffectRequest(%q) error = %v", binding.EffectID, requestErr)
		}

		if request.ID != binding.EffectID || !reflect.DeepEqual(request.Args, wantArgs) {
			t.Fatalf("restored effect = %#v, want %q/%#v", request, binding.EffectID, wantArgs)
		}
	}
}

// newAuthnCandidateTestSupervisor owns deterministic cleanup for one post-action test runtime.
func newAuthnCandidateTestSupervisor(
	t *testing.T,
	observer effectsupervisor.Observer,
) *effectsupervisor.Supervisor {
	t.Helper()

	supervisor, err := effectsupervisor.New(
		effectsupervisor.Config{Capacity: 4, Workers: 1, Observer: observer},
		effectsupervisor.ProviderBinding{Name: "authn/post_action", Provider: effectsupervisor.NewExecutableProvider()},
	)
	if err != nil {
		t.Fatalf("effectsupervisor.New() error = %v", err)
	}

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		if shutdownErr := supervisor.Shutdown(shutdownCtx); shutdownErr != nil {
			t.Errorf("post-action supervisor shutdown: %v", shutdownErr)
		}
	})

	return supervisor
}

func TestAuthnCandidateObserveSuppressesStandardEffectsWithoutChangingDeny(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	db, _ := redismock.NewClientMock()
	base := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	})
	effectCalls := &atomic.Int32{}
	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(execution *authnCandidateExecution) {
			execution.preAuthReady = true
			execution.auth.Security.BruteForceName = "candidate_observe_block"
			execution.auth.Runtime.EnvironmentName = definitions.ControlBruteForce
			execution.auth.recordPolicyBruteForce(execution.ginCtx, true)
			execution.executeEffect = func(report.EffectRequest) effectsupervisor.Result {
				effectCalls.Add(1)

				return effectsupervisor.Succeeded()
			}
		},
	}
	runtime := newAuthnCandidateDecisionServiceWithModel(
		t,
		cfg,
		&authnCandidateAcceptAll{},
		&authnCandidatePolicyModel{Generation: 704, Mode: "observe"},
	)

	adapter, err := NewAuthnCandidateApplicationService(host, runtime, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	outcome := authenticateAuthnCandidate(
		t, "observe suppression", adapter, authnApplicationTestInput(AuthModeAuthenticate),
	)

	if effectCalls.Load() != 0 {
		t.Fatalf("observe-mode effect calls = %d, want 0", effectCalls.Load())
	}

	if outcome.Decision != AuthDecisionFail || outcome.TerminalState != string(authFSMStateAuthFail) {
		t.Fatalf("observe result = %q/%q, want unchanged fail/auth_fail", outcome.Decision, outcome.TerminalState)
	}

	wantFSM := []string{policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthDeny}
	if !reflect.DeepEqual(outcome.FSMEventPath, wantFSM) {
		t.Fatalf("observe FSM = %v, want %v", outcome.FSMEventPath, wantFSM)
	}
}

func TestAuthnCandidateUsesCapturedModeWithoutAmbientAuthority(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	db, _ := redismock.NewClientMock()
	base := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	})
	effectCalls := &atomic.Int32{}
	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(execution *authnCandidateExecution) {
			generation, ok := policyruntime.GenerationFromContext(execution.ginCtx.Request.Context())

			mode, modeOK := decisionservice.CapturedPolicyMode(execution.ginCtx.Request.Context())
			if !ok || generation != 701 || !modeOK || mode != "enforce" {
				t.Fatalf("captured generation = %#v mode=%q, want generation 701 enforce", generation, mode)
			}

			execution.preAuthReady = true
			execution.auth.Security.BruteForceName = "captured_generation_block"
			execution.auth.Runtime.EnvironmentName = definitions.ControlBruteForce
			execution.auth.recordPolicyBruteForce(execution.ginCtx, true)
			execution.executeEffect = func(report.EffectRequest) effectsupervisor.Result {
				effectCalls.Add(1)

				return effectsupervisor.Succeeded()
			}
		},
	}
	captured := &authnCandidatePolicyModel{
		Generation: 701, Mode: "enforce",
	}
	rejector := &authnCandidateRejectingAcceptor{log: &authnCandidateEffectLog{}}
	runtime := newAuthnCandidateDecisionServiceWithModel(t, cfg, rejector, captured)

	adapter, err := NewAuthnCandidateApplicationService(host, runtime, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	outcome := authenticateAuthnCandidate(
		t, "captured generation", adapter, authnApplicationTestInput(AuthModeAuthenticate),
	)

	if effectCalls.Load() != 1 {
		t.Fatalf("captured-generation effect calls = %d, want one enforce-mode owner", effectCalls.Load())
	}

	if outcome.Decision != AuthDecisionFail {
		t.Fatalf("captured-generation decision = %q, want captured enforce denial", outcome.Decision)
	}
}

func TestAuthnOutcomesKeepCapturedResolverAcrossGenerationReload(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	acceptor := &authnCandidateAcceptAll{}
	model := authnCandidateModelWithBuiltins(t, &authnCandidatePolicyModel{
		Generation: 701, Mode: "enforce",
	})
	catalog := compileAuthnCandidateCatalogWithModel(t, acceptor, model)
	runtime := newAuthnCandidateReloadableDecisionRuntime(t, cfg, acceptor, catalog, model, nil)
	current := newAuthnResolverLeaseApplication(cfg)

	installAuthnCandidateServices(t, failingPasswordVerifier{}, testLuaSubject{})

	adapter, err := NewAuthnCandidateApplicationService(current, runtime.service, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	firstResult := startAuthnResolverLease(t, adapter)
	waitForAuthnResolverLease(t, current, firstResult)

	if _, err = runtime.coordinator.Apply(context.Background(), policyruntime.PrepareInput{Config: cfg, ID: 702}); err != nil {
		t.Fatalf("second generation Apply() error = %v", err)
	}

	second := authenticateAuthnResolverGeneration(t, adapter)
	accounts := listAuthnResolverGenerationAccounts(t, adapter)

	close(current.release)

	first := <-firstResult
	if first.err != nil {
		t.Fatalf("first-generation Authenticate() error = %v", first.err)
	}

	assertAuthnCapturedResolverMessage(t, first.outcome.MessageResolver, "generation-701 configured denial")
	assertAuthnCapturedResolverMessage(t, second.MessageResolver, "generation-702 configured denial")
	assertAuthnCapturedResolverMessage(t, accounts.MessageResolver, "generation-702 configured denial")

	if got := current.localizedMessages(); !reflect.DeepEqual(got, []string{
		"generation-701 configured denial",
		"generation-702 configured denial",
		"generation-702 configured denial",
	}) {
		t.Fatalf("request Lua localized messages = %v, want generation-owned 701/702/702 values", got)
	}
}

// startAuthnResolverLease starts one authentication that remains bound to its admitted generation.
func startAuthnResolverLease(
	t *testing.T,
	adapter AuthApplicationService,
) <-chan authnResolverLeaseResult {
	t.Helper()

	input := authnApplicationTestInput(AuthModeAuthenticate)
	ctx, gate := authnCandidateTestContext(context.Background(), input)
	result := make(chan authnResolverLeaseResult, 1)

	go func() {
		outcome, err := adapter.Authenticate(ctx, input)

		gate.Complete()

		result <- authnResolverLeaseResult{outcome: outcome, err: err}
	}()

	return result
}

// waitForAuthnResolverLease verifies that the first admitted generation remains blocked in its host lease.
func waitForAuthnResolverLease(
	t *testing.T,
	current *authnResolverLeaseApplication,
	result <-chan authnResolverLeaseResult,
) {
	t.Helper()

	select {
	case <-current.started:
	case early := <-result:
		t.Fatalf("first-generation authentication completed before lease block: outcome=%#v error=%v", early.outcome, early.err)
	case <-time.After(time.Second):
		t.Fatal("first-generation authentication did not reach the lease block")
	}
}

// authenticateAuthnResolverGeneration runs and completes one authentication in the current generation.
func authenticateAuthnResolverGeneration(t *testing.T, adapter AuthApplicationService) *AuthOutcome {
	t.Helper()

	input := authnApplicationTestInput(AuthModeAuthenticate)
	ctx, gate := authnCandidateTestContext(context.Background(), input)
	outcome, err := adapter.Authenticate(ctx, input)

	gate.Complete()

	if err != nil {
		t.Fatalf("current-generation Authenticate() error = %v", err)
	}

	return outcome
}

// listAuthnResolverGenerationAccounts runs and completes one account listing in the current generation.
func listAuthnResolverGenerationAccounts(
	t *testing.T,
	adapter AuthApplicationService,
) *ListAccountsOutcome {
	t.Helper()

	input := authnApplicationTestInput(AuthModeListAccounts)
	ctx, gate := authnCandidateTestContext(context.Background(), input)
	outcome, err := adapter.ListAccounts(ctx, input)

	gate.Complete()

	if err != nil {
		t.Fatalf("current-generation ListAccounts() error = %v", err)
	}

	return outcome
}

func TestAuthnCandidateIndeterminateCausePreservesTruthfulTempFailMarker(t *testing.T) {
	final := &report.FinalDecision{
		Stage: policy.StageAuthDecision, Effect: policy.DecisionPermit,
		OutcomeMarker:  policy.OutcomeMarkerAuthSuccess,
		FSMEventMarker: policy.FSMEventMarkerAuthPermit,
		ResponseMarker: policy.ResponseMarkerOK,
	}

	tests := []struct {
		name           string
		code           decision.StatusCode
		wantAcceptance bool
	}{
		{name: "acceptance rejection", code: decision.StatusCodeEffectAcceptanceRejected, wantAcceptance: true},
		{name: "synchronous failure", code: decision.StatusCodeEvaluationFailed},
		{name: "outcome unknown", code: decision.StatusCodeEffectOutcomeUnknown},
		{name: "provider failure", code: decision.StatusCodeProviderUnavailable},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := mustAuthnDecisionResponseWithCode(t, decision.EffectIndeterminate, test.code)
			presentation, acceptance := authnCandidateRuntimePresentation(response, final)

			if acceptance != test.wantAcceptance {
				t.Fatalf("acceptance classification = %t, want %t", acceptance, test.wantAcceptance)
			}

			if presentation.Effect != policy.DecisionTempFail ||
				presentation.FSMEventMarker != policy.FSMEventMarkerAuthTempFail ||
				presentation.ResponseMarker != policy.ResponseMarkerTempFail {
				t.Fatalf("runtime tempfail presentation = %#v", presentation)
			}

			isAcceptanceMarker := presentation.OutcomeMarker == "auth.outcome.effect_acceptance_failure"
			if isAcceptanceMarker != test.wantAcceptance {
				t.Fatalf("acceptance marker = %q, want acceptance=%t", presentation.OutcomeMarker, test.wantAcceptance)
			}
		})
	}
}

func TestAuthnCandidateConfiguredFinalPreservesResponseFSMAndDefaultPreAuth(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	username := "candidate-configured@example.test"
	manager := accountcache.NewManager(cfg)
	manager.Set(cfg, username, definitions.ProtoIMAP, "", username)

	db, mock := redismock.NewClientMock()
	current := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: manager,
		BackendAuthenticationCache: NewPositiveBackendAuthenticationCache(time.Now),
	})
	acceptor := &authnCandidateAcceptAll{}
	catalog := compileAuthnCandidateConfiguredCatalog(t, acceptor)
	runtime := newAuthnCandidateDecisionServiceFromCatalog(t, cfg, acceptor, catalog)
	recorder := &authnCandidateCheckpointFactory{delegate: runtime, checkpoints: make(map[string][]string)}

	adapter, err := NewAuthnCandidateApplicationService(current, recorder, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}

	installAuthnCandidateServices(
		t,
		backendAuthenticationContractVerifier{calls: verifierCalls},
		backendAuthenticationContractSubject{calls: subjectCalls},
	)
	bindRegisteredAuthnApplicationHostServicesForTest(current)

	input := NewAuthInputFromStructuredRequest(
		definitions.ServGRPC,
		AuthModeAuthenticate,
		authdto.Request{
			Username: username, Password: "candidate-secret", Protocol: definitions.ProtoIMAP,
			ClientIP: "203.0.113.78", Method: "plain",
		},
	)
	outcome := authenticateAuthnCandidate(t, "configured final", adapter, input)

	assertAuthnCandidateConfiguredParity(t, outcome, recorder, verifierCalls, subjectCalls)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected Redis operation: %v", err)
	}
}

func TestAuthnCandidateConfiguredAndDefaultCheckpointParityUsesSharedRuntime(t *testing.T) {
	for _, operation := range authnApplicationOperationCases() {
		checkpoints := []policy.Stage{policy.StageAuthDecision}

		if operation.operation != policy.OperationListAccounts {
			checkpoints = append([]policy.Stage{policy.StagePreAuth}, checkpoints...)
		}

		for _, checkpoint := range checkpoints {
			t.Run(operation.name+"/"+string(checkpoint), func(t *testing.T) {
				runAuthnCandidateConfiguredCheckpointParity(t, operation, checkpoint)
			})
		}
	}
}

func TestAuthnCandidateConfiguredPreAuthNoMatchContinuesToDefaultFinalDecision(t *testing.T) {
	for _, operation := range authnApplicationOperationCases() {
		if operation.operation == policy.OperationListAccounts {
			continue
		}

		t.Run(operation.name, func(t *testing.T) {
			assertAuthnCandidateConfiguredPreAuthNoMatch(t, operation)
		})
	}
}

func TestAuthnCandidateDefaultBruteForceProtectionPrecedesConfiguredFinal(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	db, _ := redismock.NewClientMock()
	base := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	})

	var (
		execution *authnCandidateExecution
		syncCalls atomic.Int32
	)

	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(current *authnCandidateExecution) {
			execution = current
			current.preAuthReady = true
			current.auth.Security.BruteForceName = "configured_final_protection"
			current.auth.Runtime.EnvironmentName = definitions.ControlBruteForce
			current.auth.recordPolicyBruteForce(current.ginCtx, true)
			current.executeEffect = func(report.EffectRequest) effectsupervisor.Result {
				syncCalls.Add(1)

				return effectsupervisor.Succeeded()
			}
		},
	}
	acceptor := newAuthnCandidateTestSupervisor(t, nil)
	catalog := compileAuthnCandidateConfiguredCatalog(t, acceptor)
	runtime := newAuthnCandidateDecisionServiceFromCatalog(t, cfg, acceptor, catalog)
	recorder := &authnCandidateCheckpointFactory{delegate: runtime, checkpoints: make(map[string][]string)}

	adapter, err := NewAuthnCandidateApplicationService(host, recorder, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	installAuthnCandidateServices(t, failingPasswordVerifier{}, testLuaSubject{})
	bindRegisteredAuthnApplicationHostServicesForTest(base)

	assertAuthnCandidateDefaultBruteForceResult(
		t, adapter, acceptor, recorder, &execution, &syncCalls,
	)
}

// assertAuthnCandidateDefaultBruteForceResult verifies terminal protection before configured final work.
func assertAuthnCandidateDefaultBruteForceResult(
	t *testing.T,
	adapter AuthApplicationService,
	acceptor *effectsupervisor.Supervisor,
	recorder *authnCandidateCheckpointFactory,
	execution **authnCandidateExecution,
	syncCalls *atomic.Int32,
) {
	t.Helper()

	outcome := authenticateAuthnCandidate(
		t,
		"default brute-force before configured final",
		adapter,
		authnApplicationTestInput(AuthModeAuthenticate),
	)

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := acceptor.WaitIdle(waitCtx); err != nil {
		t.Fatalf("default brute-force post-action wait: %v", err)
	}

	if outcome.Decision != AuthDecisionFail {
		t.Fatalf("default brute-force decision = %q, want fail", outcome.Decision)
	}

	wantTraversal := map[string][]string{
		policy.AuthnNamespace + "/" + string(policy.OperationAuthenticate): {string(policy.StagePreAuth)},
	}
	if got := recorder.snapshot(); !reflect.DeepEqual(got, wantTraversal) {
		t.Fatalf("default brute-force traversal = %#v, want %#v", got, wantTraversal)
	}

	current := *execution
	if current == nil {
		t.Fatal("default brute-force execution was not captured")
	}

	if selected := current.selectedDecision(string(policy.StagePreAuth)); selected == nil || selected.PolicyName != "standard_brute_force_deny" {
		t.Fatalf("default brute-force selection = %#v", selected)
	}

	if selected := current.selectedDecision(string(policy.StageAuthDecision)); selected != nil {
		t.Fatalf("configured final unexpectedly selected = %#v", selected)
	}

	if current.finalReady || syncCalls.Load() != 1 {
		t.Fatalf(
			"backend/sync execution = %t/%d, want false/1",
			current.finalReady, syncCalls.Load(),
		)
	}
}

// assertAuthnCandidateConfiguredPreAuthNoMatch proves configured absence retains standard final authority.
func assertAuthnCandidateConfiguredPreAuthNoMatch(
	t *testing.T,
	operation authnApplicationOperationCase,
) {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	db, _ := redismock.NewClientMock()
	base := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	})

	var execution *authnCandidateExecution

	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(current *authnCandidateExecution) {
			execution = current
			current.preAuthReady = true
			current.finalReady = true
			current.authResult = definitions.AuthResultFail
		},
	}
	acceptor := &authnCandidateAcceptAll{}
	rule := newAuthnCandidateConfiguredNoMatchRule(t, operation.operation)
	catalog := compileAuthnCandidateConfiguredCatalogWithRule(
		t,
		acceptor,
		operation.operation,
		policy.StagePreAuth,
		rule,
	)
	runtime := newAuthnCandidateDecisionServiceFromCatalog(t, cfg, acceptor, catalog)
	recorder := &authnCandidateCheckpointFactory{delegate: runtime, checkpoints: make(map[string][]string)}

	adapter, err := NewAuthnCandidateApplicationService(host, recorder, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	installAuthnCandidateServices(t, failingPasswordVerifier{}, testLuaSubject{})
	bindRegisteredAuthnApplicationHostServicesForTest(base)

	result, err := operation.runForDecision(
		context.Background(),
		adapter,
		authnApplicationTestInput(operation.mode),
	)
	if err != nil {
		t.Fatalf("candidate operation error = %v", err)
	}

	assertAuthnCandidateConfiguredPreAuthNoMatchResult(t, operation, result, recorder, execution, host)
}

// assertAuthnCandidateConfiguredPreAuthNoMatchResult verifies both checkpoint selections and traversal.
func assertAuthnCandidateConfiguredPreAuthNoMatchResult(
	t *testing.T,
	operation authnApplicationOperationCase,
	result authnMappedTestResult,
	recorder *authnCandidateCheckpointFactory,
	execution *authnCandidateExecution,
	host *authnCandidateInjectedHost,
) {
	t.Helper()

	if result.decision != AuthDecisionFail {
		t.Fatalf("configured no-match decision = %q, want fail", result.decision)
	}

	wantTraversal := map[string][]string{
		policy.AuthnNamespace + "/" + string(operation.operation): operation.checkpointNames(),
	}
	if got := recorder.snapshot(); !reflect.DeepEqual(got, wantTraversal) {
		t.Fatalf("configured no-match traversal = %#v, want %#v", got, wantTraversal)
	}

	if execution == nil {
		t.Fatal("configured no-match execution was not captured")
	}

	preAuth := execution.selectedDecision(string(policy.StagePreAuth))
	if preAuth == nil || preAuth.PolicyName != "implicit_pre_auth_pass" {
		t.Fatalf("configured no-match pre-auth = %#v, want implicit standard pass", preAuth)
	}

	wantFinal := "standard_auth_failure"
	if operation.operation == policy.OperationLookupIdentity {
		wantFinal = "standard_lookup_identity_failure"
	}

	final := execution.selectedDecision(string(policy.StageAuthDecision))
	if final == nil || final.PolicyName != wantFinal {
		t.Fatalf("configured no-match final = %#v, want %s", final, wantFinal)
	}

	if host.calls.Load() != 0 {
		t.Fatalf("legacy aggregate calls = %d, want 0", host.calls.Load())
	}
}

func TestAuthnCandidateCompiledPreAuthPlanStopsEnvironmentBeforeConfiguredDeny(t *testing.T) {
	tests := []struct {
		name            string
		operation       authnApplicationOperationCase
		wantEnvironment int32
		wantBruteForce  bool
	}{
		{
			name:            "authenticate",
			operation:       authnApplicationOperationCases()[0],
			wantEnvironment: 0,
			wantBruteForce:  true,
		},
		{
			name:            "lookup identity",
			operation:       authnApplicationOperationCases()[1],
			wantEnvironment: 1,
			wantBruteForce:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertAuthnCandidateCompiledPreAuthProviders(t, test.operation, test.wantEnvironment, test.wantBruteForce)
		})
	}
}

func TestAuthnPolicyDispatcherExecutesCapturedLuaEnvironmentSource(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlLua)
	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)

	prototype := compileAuthnCandidateLuaSource(t, "captured.lua", `
function nauthilus_call_environment(_request)
    nauthilus_builtin.status_message_set("captured environment status")
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)

	const providerID = "authn/lua_environment_captured"

	session := &authnConfiguredHostSession{
		recordingAuthnDecisionSession: newRecordingAuthnDecisionSession([]string{"pre_auth"}),
		provider: authnConfiguredLuaSource{
			id: providerID, kind: decisionservice.AuthnHostProviderKindLuaEnvironment,
			name: "captured", prototype: prototype, pools: vmpool.NewManager(),
		},
	}
	execution := &authnCandidateExecution{
		auth: auth, ginCtx: ctx, selected: make(map[string]*report.FinalDecision),
		operation: policy.OperationAuthenticate,
	}

	terminal, err := execution.prepareConfiguredHostProvider(session, providerID)
	if err != nil {
		t.Fatalf("prepareConfiguredHostProvider() error = %v", err)
	}

	if !terminal || execution.preAuthResult != definitions.AuthResultLuaEnvironment {
		t.Fatalf("captured provider terminal=%t result=%q, want true/%q", terminal, execution.preAuthResult, definitions.AuthResultLuaEnvironment)
	}

	if !ctx.GetBool(definitions.CtxEnvironmentRejectedKey) {
		t.Fatal("captured Lua environment trigger did not mark the request rejected")
	}

	if auth.Runtime.StatusMessage != "captured environment status" {
		t.Fatalf("captured Lua environment status = %q, want exact script result", auth.Runtime.StatusMessage)
	}
}

func TestAuthnPolicyDispatcherExecutesCapturedNativeEnvironmentSource(t *testing.T) {
	auth, ctx, _ := newCurrentBehaviorAuthState(t, newCurrentBehaviorConfig(t))
	auth.deps.NativeRuntime = authnCapturedNativeRuntime{}
	provider := &authnCapturedNativeEnvironmentSource{id: "authn/plugin.example.environment"}
	session := &authnConfiguredHostSession{
		recordingAuthnDecisionSession: newRecordingAuthnDecisionSession([]string{"pre_auth"}),
		provider:                      provider,
	}
	execution := &authnCandidateExecution{
		auth: auth, ginCtx: ctx, selected: make(map[string]*report.FinalDecision),
		operation: policy.OperationAuthenticate,
	}

	terminal, err := execution.prepareConfiguredHostProvider(session, provider.id)
	if err != nil {
		t.Fatalf("prepareConfiguredHostProvider() error = %v", err)
	}

	if terminal {
		t.Fatal("neutral captured native environment provider became terminal")
	}

	if provider.calls.Load() != 1 {
		t.Fatalf("captured native environment provider calls = %d, want 1", provider.calls.Load())
	}
}

func TestAuthnPolicyDispatcherExecutesCapturedNativeSubjectSource(t *testing.T) {
	auth, ctx, _ := newCurrentBehaviorAuthState(t, newCurrentBehaviorConfig(t))
	auth.deps.NativeRuntime = authnCapturedNativeRuntime{}
	provider := &authnCapturedNativeSubjectSource{id: "authn/plugin.example.subject.risk", rejected: true}
	session := &authnConfiguredHostSession{
		recordingAuthnDecisionSession: newRecordingAuthnDecisionSession([]string{"subject_analysis"}),
		provider:                      provider,
	}
	backendResult := GetPassDBResultFromPool()
	backendResult.Authenticated = true
	backendResult.UserFound = true

	execution := &authnCandidateExecution{
		auth: auth, ginCtx: ctx, selected: make(map[string]*report.FinalDecision),
		operation: policy.OperationAuthenticate, backendResult: backendResult, backendReady: true,
	}
	defer execution.release()

	terminal, err := execution.prepareConfiguredHostProvider(session, provider.id)
	if err != nil {
		t.Fatalf("prepareConfiguredHostProvider() error = %v", err)
	}

	if !terminal || execution.authResult != definitions.AuthResultFail {
		t.Fatalf(
			"captured native subject terminal=%t result=%q, want true/%q",
			terminal,
			execution.authResult,
			definitions.AuthResultFail,
		)
	}

	if provider.calls.Load() != 1 {
		t.Fatalf("captured native subject provider calls = %d, want 1", provider.calls.Load())
	}
}

func TestAuthnPolicyDispatcherTreatsCapturedLuaEnvironmentAbortAsNonTerminal(t *testing.T) {
	auth, ctx, _ := newCurrentBehaviorAuthState(t, newCurrentBehaviorConfig(t, definitions.ControlLua))
	prototype := compileAuthnCandidateLuaSource(t, "abort.lua", `
function nauthilus_call_environment(_request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_YES, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)

	const providerID = "authn/lua_environment_abort"

	session := &authnConfiguredHostSession{
		recordingAuthnDecisionSession: newRecordingAuthnDecisionSession([]string{"pre_auth"}),
		provider: authnConfiguredLuaSource{
			id: providerID, kind: decisionservice.AuthnHostProviderKindLuaEnvironment,
			name: "abort", prototype: prototype, pools: vmpool.NewManager(),
		},
	}
	execution := &authnCandidateExecution{
		auth: auth, ginCtx: ctx, selected: make(map[string]*report.FinalDecision),
		operation: policy.OperationAuthenticate,
	}

	terminal, err := execution.prepareConfiguredHostProvider(session, providerID)
	if err != nil {
		t.Fatalf("prepareConfiguredHostProvider() error = %v", err)
	}

	if terminal || execution.preAuthResult != definitions.AuthResultOK {
		t.Fatalf("captured abort terminal=%t result=%q, want false/%q", terminal, execution.preAuthResult, definitions.AuthResultOK)
	}
}

func TestAuthnPolicyDispatcherExecutesCapturedLuaSubjectSource(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	prototype := compileAuthnCandidateLuaSource(t, "captured_subject.lua", `
function nauthilus_call_subject(_request)
    return nauthilus_builtin.SUBJECT_REJECT, nauthilus_builtin.SUBJECT_RESULT_OK
end
`)

	runner := &authnCapturedSubjectRunner{}
	previous := getLuaSubject()

	RegisterLuaSubject(runner)
	t.Cleanup(func() { RegisterLuaSubject(previous) })
	bindRegisteredAuthnHostServicesForTest(auth)

	backendResult := GetPassDBResultFromPool()
	backendResult.Authenticated = true
	backendResult.UserFound = true

	const providerID = "authn/lua_subject_captured"

	session := &authnConfiguredHostSession{
		recordingAuthnDecisionSession: newRecordingAuthnDecisionSession([]string{"subject_analysis"}),
		provider: authnConfiguredLuaSource{
			id: providerID, kind: decisionservice.AuthnHostProviderKindLuaSubject,
			name: "captured", prototype: prototype, pools: vmpool.NewManager(),
		},
	}

	execution := &authnCandidateExecution{
		auth: auth, ginCtx: ctx, selected: make(map[string]*report.FinalDecision),
		operation: policy.OperationAuthenticate, backendResult: backendResult, backendReady: true,
	}
	defer execution.release()

	terminal, err := execution.prepareConfiguredHostProvider(session, providerID)
	if err != nil {
		t.Fatalf("prepareConfiguredHostProvider() error = %v", err)
	}

	if !terminal || execution.authResult != definitions.AuthResultFail || runner.calls.Load() != 1 {
		t.Fatalf(
			"captured subject terminal=%t result=%q calls=%d, want true/%q/1",
			terminal,
			execution.authResult,
			runner.calls.Load(),
			definitions.AuthResultFail,
		)
	}
}

// compileAuthnCandidateLuaSource compiles one exact test-owned source.
func compileAuthnCandidateLuaSource(t *testing.T, name string, source string) *lua.FunctionProto {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatalf("write captured Lua source: %v", err)
	}

	prototype, err := compileLuaTestFile(path)
	if err != nil {
		t.Fatalf("compileLuaTestFile() error = %v", err)
	}

	return prototype
}

type authnConfiguredHostSession struct {
	*recordingAuthnDecisionSession
	provider decisionservice.AuthnHostProvider
}

// AuthnHostProvider resolves the test generation's exact configured source.
func (s *authnConfiguredHostSession) AuthnHostProvider(id string) (decisionservice.AuthnHostProvider, bool) {
	if s == nil || s.provider == nil || s.provider.ID() != id {
		return nil, false
	}

	return s.provider, true
}

type authnConfiguredLuaSource struct {
	prototype *lua.FunctionProto
	pools     *vmpool.Manager
	id        string
	kind      string
	name      string
}

type authnCapturedNativeEnvironmentSource struct {
	id    string
	calls atomic.Int32
}

type authnCapturedNativeSubjectSource struct {
	id       string
	calls    atomic.Int32
	rejected bool
}

type authnCapturedNativeRuntime struct{}

// Capture returns one request-owned empty projection for exact provider tests.
func (authnCapturedNativeRuntime) Capture(
	context.Context,
	AuthnNativeCaptureInput,
) (AuthnNativeCapture, error) {
	return AuthnNativeCapture{}, nil
}

// ApplyRuntimeDelta accepts only the empty result used by this provider fixture.
func (authnCapturedNativeRuntime) ApplyRuntimeDelta(*AuthState, pluginapi.RuntimeDelta) error {
	return nil
}

// ID returns the exact generation-owned native environment provider identity.
func (s *authnCapturedNativeEnvironmentSource) ID() string { return s.id }

// Kind identifies the captured public environment source family.
func (*authnCapturedNativeEnvironmentSource) Kind() string {
	return decisionservice.AuthnHostProviderKindNativeEnvironment
}

// Capabilities returns the detached grant captured with the provider.
func (*authnCapturedNativeEnvironmentSource) Capabilities() []pluginapi.Capability { return nil }

// EvaluateEnvironment records one exact session-yielded invocation.
func (s *authnCapturedNativeEnvironmentSource) EvaluateEnvironment(
	context.Context,
	pluginapi.EnvironmentRequest,
) (pluginapi.EnvironmentResult, error) {
	s.calls.Add(1)

	return pluginapi.EnvironmentResult{}, nil
}

// ID returns the exact generation-owned native subject provider identity.
func (s *authnCapturedNativeSubjectSource) ID() string { return s.id }

// Kind identifies the captured public subject source family.
func (*authnCapturedNativeSubjectSource) Kind() string {
	return decisionservice.AuthnHostProviderKindNativeSubject
}

// Capabilities returns the detached grant captured with the provider.
func (*authnCapturedNativeSubjectSource) Capabilities() []pluginapi.Capability { return nil }

// EvaluateSubject records one exact session-yielded invocation.
func (s *authnCapturedNativeSubjectSource) EvaluateSubject(
	context.Context,
	pluginapi.SubjectRequest,
) (pluginapi.SubjectResult, error) {
	s.calls.Add(1)

	return pluginapi.SubjectResult{Rejected: s.rejected}, nil
}

type authnCapturedSubjectRunner struct {
	calls atomic.Int32
}

// Analyze rejects ambient subject execution in this generation-owned fixture.
func (*authnCapturedSubjectRunner) Analyze(*gin.Context, *StateView, *PassDBResult) definitions.AuthResult {
	return definitions.AuthResultTempFail
}

// AnalyzeSource records exact captured-source selection.
func (r *authnCapturedSubjectRunner) AnalyzeSource(
	_ *gin.Context,
	_ *StateView,
	_ *PassDBResult,
	name string,
	prototype *lua.FunctionProto,
	_ *vmpool.Manager,
	_ vmpool.PoolKey,
	_ *luaseal.Modules,
) definitions.AuthResult {
	if name == "captured" && prototype != nil {
		r.calls.Add(1)
	}

	return definitions.AuthResultFail
}

// ID returns the exact test provider identity.
func (s authnConfiguredLuaSource) ID() string {
	return s.id
}

// Kind returns the exact test host-provider kind.
func (s authnConfiguredLuaSource) Kind() string {
	return s.kind
}

// OpenCompiledLuaSource returns the detached test source capability.
func (s authnConfiguredLuaSource) OpenCompiledLuaSource() (string, *lua.FunctionProto, error) {
	return s.name, s.prototype, nil
}

// LuaPoolKey returns the test generation/source pool identity.
func (s authnConfiguredLuaSource) LuaPoolKey() string {
	return "test:authn:" + s.id
}

// LuaPoolManager returns the test generation's isolated VM pool owner.
func (s authnConfiguredLuaSource) LuaPoolManager() *vmpool.Manager {
	return s.pools
}

// SealedLuaModules returns the empty immutable module set for this source-only fixture.
func (authnConfiguredLuaSource) SealedLuaModules() *luaseal.Modules {
	return nil
}

type authnCandidateCompiledProviderFixture struct {
	adapter   AuthApplicationService
	acceptor  *effectsupervisor.Supervisor
	execution *authnCandidateExecution
}

// newAuthnCandidateCompiledProviderFixture assembles one captured-plan provider fixture.
func newAuthnCandidateCompiledProviderFixture(
	t *testing.T,
	operation authnApplicationOperationCase,
) *authnCandidateCompiledProviderFixture {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	db, _ := redismock.NewClientMock()
	base := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	})

	fixture := &authnCandidateCompiledProviderFixture{}

	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(current *authnCandidateExecution) {
			fixture.execution = current
		},
	}
	fixture.acceptor = newAuthnCandidateTestSupervisor(t, nil)

	installAuthnCandidateServices(t, failingPasswordVerifier{}, testLuaSubject{})
	bindRegisteredAuthnApplicationHostServicesForTest(base)

	catalog := compileAuthnCandidateConfiguredCatalogFor(
		t,
		fixture.acceptor,
		operation.operation,
		policy.StagePreAuth,
	)
	runtime := newAuthnCandidateDecisionServiceFromCatalog(t, cfg, fixture.acceptor, catalog)

	adapter, err := NewAuthnCandidateApplicationService(host, runtime, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	fixture.adapter = adapter

	return fixture
}

// assertAuthnCandidateCompiledPreAuthProviders proves actual work follows the captured provider plan.
func assertAuthnCandidateCompiledPreAuthProviders(
	t *testing.T,
	operation authnApplicationOperationCase,
	wantEnvironment int32,
	wantBruteForce bool,
) {
	t.Helper()

	fixture := newAuthnCandidateCompiledProviderFixture(t, operation)

	result, err := operation.runForDecision(
		context.Background(),
		fixture.adapter,
		authnApplicationTestInput(operation.mode),
	)
	if err != nil {
		t.Fatalf("candidate operation error = %v", err)
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err = fixture.acceptor.WaitIdle(waitCtx); err != nil {
		t.Fatalf("configured pre-auth post-action wait: %v", err)
	}

	assertAuthnCandidateCompiledProviderResult(
		t,
		result,
		fixture.execution,
		wantEnvironment > 0,
		wantBruteForce,
	)
}

// assertAuthnCandidateCompiledProviderResult verifies exact selected host-provider execution.
func assertAuthnCandidateCompiledProviderResult(
	t *testing.T,
	result authnMappedTestResult,
	execution *authnCandidateExecution,
	wantEnvironment bool,
	wantBruteForce bool,
) {
	t.Helper()

	if result.decision != AuthDecisionFail {
		t.Fatalf("candidate decision = %q, want fail", result.decision)
	}

	if execution == nil {
		t.Fatal("candidate provider execution was not captured")
	}

	if execution.bruteForceRun != wantBruteForce || execution.environmentRun != wantEnvironment {
		t.Fatalf(
			"provider execution brute_force=%t environment=%t, want %t/%t",
			execution.bruteForceRun,
			execution.environmentRun,
			wantBruteForce,
			wantEnvironment,
		)
	}
}

// runAuthnCandidateConfiguredCheckpointParity exercises one operation and configured checkpoint.
func runAuthnCandidateConfiguredCheckpointParity(
	t *testing.T,
	operation authnApplicationOperationCase,
	checkpoint policy.Stage,
) {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	db, _ := redismock.NewClientMock()
	base := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	})
	host := newAuthnConfiguredCheckpointHost(base)
	acceptor := effectsupervisor.Acceptor(&authnCandidateAcceptAll{})

	bindRegisteredAuthnApplicationHostServicesForTest(base)

	catalog := compileAuthnCandidateConfiguredCatalogFor(t, acceptor, operation.operation, checkpoint)

	assertAuthnCandidateConfiguredAuthority(t, catalog, operation.operation, checkpoint)

	runtime := newAuthnCandidateDecisionServiceFromCatalog(t, cfg, acceptor, catalog)
	recorder := &authnCandidateCheckpointFactory{delegate: runtime, checkpoints: make(map[string][]string)}

	adapter, err := NewAuthnCandidateApplicationService(host, recorder, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	result, err := operation.runForDecision(
		context.Background(),
		adapter,
		authnApplicationTestInput(operation.mode),
	)
	if err != nil {
		t.Fatalf("candidate operation error = %v", err)
	}

	assertAuthnCandidateConfiguredTraversal(t, result, recorder, host, operation, checkpoint)
}

// newAuthnConfiguredCheckpointHost returns deterministic current-pipeline state for every operation.
func newAuthnConfiguredCheckpointHost(base authnCandidateHost) *authnCandidateInjectedHost {
	return &authnCandidateInjectedHost{
		base: base,
		configure: func(execution *authnCandidateExecution) {
			execution.preAuthReady = true
			execution.finalReady = true
			execution.authResult = definitions.AuthResultOK
			execution.auth.Runtime.Authorized = true
			execution.accounts = AccountList{"alice@example.test"}
		},
	}
}

// assertAuthnCandidateConfiguredTraversal verifies result, checkpoint order, and sole runtime ownership.
func assertAuthnCandidateConfiguredTraversal(
	t *testing.T,
	result authnMappedTestResult,
	recorder *authnCandidateCheckpointFactory,
	host *authnCandidateInjectedHost,
	operation authnApplicationOperationCase,
	checkpoint policy.Stage,
) {
	t.Helper()

	if result.decision != AuthDecisionFail {
		t.Fatalf("configured decision = %q, want fail", result.decision)
	}

	wantCheckpoints := operation.checkpointNames()
	if checkpoint == policy.StagePreAuth {
		wantCheckpoints = []string{string(policy.StagePreAuth)}
	}

	wantTraversal := map[string][]string{
		policy.AuthnNamespace + "/" + string(operation.operation): wantCheckpoints,
	}
	if got := recorder.snapshot(); !reflect.DeepEqual(got, wantTraversal) {
		t.Fatalf("configured traversal = %#v, want %#v", got, wantTraversal)
	}

	if host.calls.Load() != 0 {
		t.Fatalf("legacy aggregate calls = %d, want 0", host.calls.Load())
	}
}

// assertAuthnCandidateConfiguredAuthority verifies configured and standard checkpoint ownership together.
func assertAuthnCandidateConfiguredAuthority(
	t *testing.T,
	catalog *policyruntime.TargetCatalog,
	operation policy.Operation,
	configuredCheckpoint policy.Stage,
) {
	t.Helper()

	target, err := decision.NewTarget(policy.AuthnNamespace, string(operation))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	compiled, exists := catalog.Lookup(target)
	if !exists {
		t.Fatalf("configured target %s is missing", target.String())
	}

	for _, checkpoint := range compiled.DomainPlan().Checkpoints() {
		production := checkpoint.ProductionPolicySetIDs()
		if checkpoint.Name() == string(configuredCheckpoint) {
			if len(production) != 1 || production[0] != "authn/configured_candidate" {
				t.Fatalf("configured checkpoint %s authority = %v", checkpoint.Name(), production)
			}

			continue
		}

		if len(production) != 1 || production[0] != registry.BuiltinStandardAuthPolicySet {
			t.Fatalf("default checkpoint %s authority = %v", checkpoint.Name(), production)
		}
	}
}

// runAuthnCandidateAuthOperation returns the complete public auth outcome for one operation.
func runAuthnCandidateAuthOperation(
	t *testing.T,
	adapter AuthApplicationService,
	operation authnApplicationOperationCase,
) *AuthOutcome {
	t.Helper()

	var (
		outcome *AuthOutcome
		err     error
	)

	input := authnApplicationTestInput(operation.mode)
	ctx, gate := authnCandidateTestContext(context.Background(), input)

	if operation.operation == policy.OperationAuthenticate {
		outcome, err = adapter.Authenticate(ctx, input)
	} else {
		outcome, err = adapter.LookupIdentity(ctx, input)
	}

	gate.Complete()

	if err != nil {
		t.Fatalf("candidate %s error = %v", operation.name, err)
	}

	return outcome
}

// newAuthnCandidateRealCollectorBase isolates account and positive-auth caches for real collector tests.
func newAuthnCandidateRealCollectorBase(
	t *testing.T,
	cfg config.File,
) *registeredAuthApplicationTestHost {
	t.Helper()

	db, _ := redismock.NewClientMock()
	manager := accountcache.NewManager(cfg)
	manager.Set(cfg, "alice@example.test", definitions.ProtoIMAP, "oidc-client", "alice@example.test")

	backendCache := NewPositiveBackendAuthenticationCache(time.Now)
	t.Cleanup(backendCache.Close)

	return newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: manager,
		BackendAuthenticationCache: backendCache,
	})
}

// assertAuthnCandidateConfiguredParity verifies response, FSM, checkpoint, and provider parity.
func assertAuthnCandidateConfiguredParity(
	t *testing.T,
	outcome *AuthOutcome,
	recorder *authnCandidateCheckpointFactory,
	verifierCalls *atomic.Int32,
	subjectCalls *atomic.Int32,
) {
	t.Helper()

	if outcome.Decision != AuthDecisionFail || outcome.TerminalState != string(authFSMStateAuthFail) {
		t.Fatalf("configured result = %q/%q, want fail/auth_fail", outcome.Decision, outcome.TerminalState)
	}

	if outcome.StatusMessage != "configured denial" ||
		outcome.StatusMessageI18NKey != "auth.policy.configured_denial" ||
		outcome.ResponseLanguage != "de" {
		t.Fatalf(
			"configured presentation = %q/%q/%q",
			outcome.StatusMessage, outcome.StatusMessageI18NKey, outcome.ResponseLanguage,
		)
	}

	wantFSM := []string{
		policy.FSMEventMarkerParseOK,
		policy.FSMEventMarkerPreAuthOK,
		policy.FSMEventMarkerAuthEvaluated,
		policy.FSMEventMarkerAuthDeny,
	}
	if !reflect.DeepEqual(outcome.FSMEventPath, wantFSM) {
		t.Fatalf("configured FSM = %v, want %v", outcome.FSMEventPath, wantFSM)
	}

	wantCheckpoints := map[string][]string{
		"authn/authenticate": {string(policy.StagePreAuth), string(policy.StageAuthDecision)},
	}
	if got := recorder.snapshot(); !reflect.DeepEqual(got, wantCheckpoints) {
		t.Fatalf("configured/default checkpoints = %#v, want %#v", got, wantCheckpoints)
	}

	if verifierCalls.Load() != 1 || subjectCalls.Load() != 0 {
		t.Fatalf("configured backend/ambient-subject calls = %d/%d, want 1/0", verifierCalls.Load(), subjectCalls.Load())
	}
}

// authenticateAuthnCandidate runs one candidate authentication and requires a transport result.
func authenticateAuthnCandidate(
	t *testing.T,
	name string,
	adapter AuthApplicationService,
	input AuthInput,
) *AuthOutcome {
	t.Helper()

	ctx, gate := authnCandidateTestContext(context.Background(), input)
	outcome, err := adapter.Authenticate(ctx, input)

	gate.Complete()

	if err != nil {
		t.Fatalf("%s Authenticate() error = %v", name, err)
	}

	return outcome
}

func TestAuthnCandidateOrdinaryPasswordFailurePreservesDelayedResponseEligibility(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	var capturedExecution *authnCandidateExecution

	db, mock := redismock.NewClientMock()

	base := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	})

	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(execution *authnCandidateExecution) {
			capturedExecution = execution
		},
	}

	adapter, err := NewAuthnCandidateApplicationService(
		host,
		newAuthnCandidateDecisionService(t, cfg, &authnCandidateAcceptAll{}),
		mustAuthnCandidateAuthentication(t),
	)
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	installAuthnCandidateServices(t, failingPasswordVerifier{}, testLuaSubject{})
	bindRegisteredAuthnApplicationHostServicesForTest(base)

	outcome := authenticateAuthnCandidate(
		t, "ordinary password failure", adapter, authnApplicationTestInput(AuthModeAuthenticate),
	)

	selected := capturedExecution.selectedDecision(string(policy.StageAuthDecision))
	if outcome.Decision != AuthDecisionFail || selected == nil ||
		selected.OutcomeMarker != policy.OutcomeMarkerAuthFailure ||
		selected.ResponseMarker != policy.ResponseMarkerFail ||
		!configuredPolicyAllowsIDPDelayedResponse(selected) {
		t.Fatalf("ordinary password failure = outcome:%#v selection:%#v, want delayed-response eligible deny", outcome, selected)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected Redis operation: %v", err)
	}
}

func TestAuthnCandidateAllOperationsTraverseSharedRuntimeCheckpoints(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	manager := accountcache.NewManager(cfg)
	manager.Set(cfg, "candidate-auth@example.test", definitions.ProtoIMAP, "", "candidate-auth@example.test")
	manager.Set(cfg, "candidate-lookup@example.test", definitions.ProtoIMAP, "", "candidate-lookup@example.test")

	db, mock := redismock.NewClientMock()
	current := newRegisteredAuthApplicationServiceHost(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: manager,
		BackendAuthenticationCache: NewPositiveBackendAuthenticationCache(time.Now),
	})
	runtime := newAuthnCandidateDecisionService(t, cfg, &authnCandidateAcceptAll{})
	recorder := &authnCandidateCheckpointFactory{delegate: runtime, checkpoints: make(map[string][]string)}

	adapter, err := NewAuthnCandidateApplicationService(current, recorder, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}

	installAuthnCandidateServices(
		t,
		backendAuthenticationContractVerifier{calls: verifierCalls},
		backendAuthenticationContractSubject{calls: subjectCalls},
	)
	bindRegisteredAuthnApplicationHostServicesForTest(current)

	outcomes := runAuthnCandidateOperations(t, adapter)
	assertAuthnCandidateOperationParity(t, outcomes, recorder, verifierCalls, subjectCalls)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected Redis operation: %v", err)
	}
}

type authnCandidateOperationOutcomes struct {
	auth     *AuthOutcome
	lookup   *AuthOutcome
	accounts *ListAccountsOutcome
}

// runAuthnCandidateOperations invokes all public auth operations through the shared candidate.
func runAuthnCandidateOperations(
	t *testing.T,
	adapter AuthApplicationService,
) authnCandidateOperationOutcomes {
	t.Helper()

	authInput := NewAuthInputFromStructuredRequest(
		definitions.ServGRPC,
		AuthModeAuthenticate,
		authdto.Request{
			Username: "candidate-auth@example.test", Password: "candidate-secret",
			Protocol: definitions.ProtoIMAP, ClientIP: "203.0.113.75", Method: "plain",
		},
	)
	authCtx, authGate := authnCandidateTestContext(context.Background(), authInput)
	authOutcome, err := adapter.Authenticate(authCtx, authInput)

	authGate.Complete()

	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	lookupInput := NewAuthInputFromStructuredRequest(
		definitions.ServGRPC,
		AuthModeLookupIdentity,
		authdto.Request{
			Username: "candidate-lookup@example.test", Protocol: definitions.ProtoIMAP,
			ClientIP: "203.0.113.76", Method: "plain",
		},
	)
	lookupCtx, lookupGate := authnCandidateTestContext(context.Background(), lookupInput)
	lookupOutcome, err := adapter.LookupIdentity(lookupCtx, lookupInput)

	lookupGate.Complete()

	if err != nil {
		t.Fatalf("LookupIdentity() error = %v", err)
	}

	listInput := NewAuthInputFromStructuredRequest(
		definitions.ServGRPC,
		AuthModeListAccounts,
		authdto.Request{ClientIP: "203.0.113.77"},
	)
	listCtx, listGate := authnCandidateTestContext(context.Background(), listInput)
	listOutcome, err := adapter.ListAccounts(listCtx, listInput)

	listGate.Complete()

	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}

	return authnCandidateOperationOutcomes{auth: authOutcome, lookup: lookupOutcome, accounts: listOutcome}
}

// assertAuthnCandidateOperationParity verifies decisions, checkpoints, and provider ownership.
func assertAuthnCandidateOperationParity(
	t *testing.T,
	outcomes authnCandidateOperationOutcomes,
	recorder *authnCandidateCheckpointFactory,
	verifierCalls *atomic.Int32,
	subjectCalls *atomic.Int32,
) {
	t.Helper()

	if outcomes.auth.Decision != AuthDecisionOK ||
		outcomes.lookup.Decision != AuthDecisionOK ||
		outcomes.accounts.Decision != AuthDecisionOK {
		t.Fatalf(
			"operation decisions = %q/%q/%q status=%q/%q errors=%q/%q FSM=%v/%v backend=%s/%s calls=%d/%d, want all ok",
			outcomes.auth.Decision, outcomes.lookup.Decision, outcomes.accounts.Decision,
			outcomes.auth.StatusMessage, outcomes.lookup.StatusMessage,
			outcomes.auth.Error, outcomes.lookup.Error,
			outcomes.auth.FSMEventPath, outcomes.lookup.FSMEventPath,
			outcomes.auth.Backend, outcomes.lookup.Backend, verifierCalls.Load(), subjectCalls.Load(),
		)
	}

	want := map[string][]string{
		"authn/authenticate":    {string(policy.StagePreAuth), string(policy.StageAuthDecision)},
		"authn/lookup_identity": {string(policy.StagePreAuth), string(policy.StageAuthDecision)},
		"authn/list_accounts":   {string(policy.StageAuthDecision)},
	}
	if got := recorder.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("shared runtime checkpoints = %#v, want %#v", got, want)
	}

	if verifierCalls.Load() != 2 || subjectCalls.Load() != 0 {
		t.Fatalf("backend/ambient-subject calls = %d/%d, want 2/0", verifierCalls.Load(), subjectCalls.Load())
	}
}

// newAuthnCandidateDecisionService assembles the same generation-owned runtime used by generic evaluation.
func newAuthnCandidateDecisionService(
	t *testing.T,
	cfg config.File,
	acceptor effectsupervisor.Acceptor,
) *decisionservice.DecisionService {
	t.Helper()

	model := authnCandidateModelWithBuiltins(t, &authnCandidatePolicyModel{
		Generation: 701, Mode: "enforce",
	})
	catalog := compileAuthnCandidateCatalogWithModel(t, acceptor, model)

	return newAuthnCandidateDecisionServiceFromCatalogAndModel(t, cfg, acceptor, catalog, model)
}

// newAuthnCandidateDecisionServiceWithModel assembles one exact captured policy model.
func newAuthnCandidateDecisionServiceWithModel(
	t *testing.T,
	cfg config.File,
	acceptor effectsupervisor.Acceptor,
	model *authnCandidatePolicyModel,
) *decisionservice.DecisionService {
	t.Helper()

	model = authnCandidateModelWithBuiltins(t, model)
	catalog := compileAuthnCandidateCatalogWithModel(t, acceptor, model)

	return newAuthnCandidateDecisionServiceFromCatalogAndModel(t, cfg, acceptor, catalog, model)
}

// newAuthnCandidateDecisionServiceFromCatalog assembles one test generation around an exact catalog.
func newAuthnCandidateDecisionServiceFromCatalog(
	t *testing.T,
	cfg config.File,
	acceptor effectsupervisor.Acceptor,
	catalog *policyruntime.TargetCatalog,
) *decisionservice.DecisionService {
	t.Helper()

	return newAuthnCandidateDecisionServiceFromCatalogAndModel(
		t,
		cfg,
		acceptor,
		catalog,
		&authnCandidatePolicyModel{Generation: 701, Mode: "enforce"},
	)
}

// newAuthnCandidateDecisionServiceFromCatalogAndModel assembles one exact captured policy view.
func newAuthnCandidateDecisionServiceFromCatalogAndModel(
	t *testing.T,
	cfg config.File,
	acceptor effectsupervisor.Acceptor,
	catalog *policyruntime.TargetCatalog,
	model *authnCandidatePolicyModel,
) *decisionservice.DecisionService {
	return newAuthnCandidateDecisionServiceWithBindings(t, cfg, acceptor, catalog, model, nil)
}

// authnCandidateModelWithBuiltins gives the fixture the same builtin registry as production compilation.
func authnCandidateModelWithBuiltins(
	t *testing.T,
	model *authnCandidatePolicyModel,
) *authnCandidatePolicyModel {
	t.Helper()

	captured := model.clone()
	if captured == nil {
		captured = &authnCandidatePolicyModel{}
	}

	attributes, err := registry.NewBuiltinAttributeRegistry()
	if err != nil {
		t.Fatalf("NewBuiltinAttributeRegistry() error = %v", err)
	}

	if captured.AttributeRegistry == nil {
		captured.AttributeRegistry = make(map[string]registry.AttributeDefinition)
	}

	for id, definition := range attributes.Snapshot() {
		if _, exists := captured.AttributeRegistry[id]; !exists {
			captured.AttributeRegistry[id] = definition
		}
	}

	return captured
}

// newAuthnCandidateDecisionServiceWithBindings adds exact test-owned effect seams to one captured generation.
func newAuthnCandidateDecisionServiceWithBindings(
	t *testing.T,
	cfg config.File,
	acceptor effectsupervisor.Acceptor,
	catalog *policyruntime.TargetCatalog,
	model *authnCandidatePolicyModel,
	extraSyncEffects map[string]policyruntime.SyncEffectProvider,
) *decisionservice.DecisionService {
	return newAuthnCandidateReloadableDecisionRuntime(
		t,
		cfg,
		acceptor,
		catalog,
		model,
		extraSyncEffects,
	).service
}

type authnCandidateDecisionRuntime struct {
	coordinator *policyruntime.Coordinator
	service     *decisionservice.DecisionService
	store       *policyruntime.GenerationStore
}

// newAuthnCandidateReloadableDecisionRuntime returns one test-owned coordinator, store, and service graph.
func newAuthnCandidateReloadableDecisionRuntime(
	t *testing.T,
	cfg config.File,
	acceptor effectsupervisor.Acceptor,
	catalog *policyruntime.TargetCatalog,
	model *authnCandidatePolicyModel,
	extraSyncEffects map[string]policyruntime.SyncEffectProvider,
) *authnCandidateDecisionRuntime {
	t.Helper()
	model = authnCandidateModelWithBuiltins(t, model)

	syncEffects, postActions := AuthnStandardEffectBindings()
	for providerID, provider := range extraSyncEffects {
		syncEffects[providerID] = provider
	}

	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		SyncEffects: syncEffects, PostActions: postActions, PostActionAcceptance: acceptor,
	})
	if err != nil {
		t.Fatalf("NewBindingSet() error = %v", err)
	}

	store := policyruntime.NewGenerationStore()

	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{
		Store: store,
		Slots: authnCandidatePreparationSlots(t, catalog, bindings, model),
	})
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	if _, err = coordinator.Apply(context.Background(), policyruntime.PrepareInput{Config: cfg, ID: 701}); err != nil {
		t.Fatalf("candidate generation Apply() error = %v", err)
	}

	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		if shutdownErr := store.Shutdown(shutdownCtx); shutdownErr != nil {
			t.Errorf("candidate generation shutdown: %v", shutdownErr)
		}
	})

	source, err := decisionservice.NewStoreGenerationSource(store)
	if err != nil {
		t.Fatalf("NewStoreGenerationSource() error = %v", err)
	}

	service, err := decisionservice.NewDecisionService(source)
	if err != nil {
		t.Fatalf("NewDecisionService() error = %v", err)
	}

	return &authnCandidateDecisionRuntime{coordinator: coordinator, service: service, store: store}
}

// compileAuthnCandidateConfiguredCatalog binds one final deny while leaving pre-auth on standard authority.
func compileAuthnCandidateConfiguredCatalog(
	t *testing.T,
	acceptor effectsupervisor.Acceptor,
) *policyruntime.TargetCatalog {
	return compileAuthnCandidateConfiguredCatalogFor(
		t,
		acceptor,
		policy.OperationAuthenticate,
		policy.StageAuthDecision,
	)
}

// compileAuthnCandidateConfiguredCatalogFor binds one operation/checkpoint rule beside standard authority.
func compileAuthnCandidateConfiguredCatalogFor(
	t *testing.T,
	acceptor effectsupervisor.Acceptor,
	operation policy.Operation,
	checkpoint policy.Stage,
) *policyruntime.TargetCatalog {
	t.Helper()

	return compileAuthnCandidateConfiguredCatalogWithRule(
		t,
		acceptor,
		operation,
		checkpoint,
		newAuthnCandidateConfiguredRuleFor(t, operation, checkpoint),
	)
}

// compileAuthnCandidateConfiguredCatalogWithRule binds one explicit rule beside standard authority.
func compileAuthnCandidateConfiguredCatalogWithRule(
	t *testing.T,
	acceptor effectsupervisor.Acceptor,
	operation policy.Operation,
	checkpoint policy.Stage,
	rule registry.PolicyRule,
) *policyruntime.TargetCatalog {
	t.Helper()

	target, err := decision.NewTarget(policy.AuthnNamespace, string(operation))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	setID, contribution := newAuthnCandidateConfiguredContribution(t, rule)
	activation := newAuthnCandidateConfiguredActivationFor(t, target, setID, checkpoint)

	catalog, err := catalogcompile.NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributor(acceptor),
		authnCandidateStaticContributor{contribution: contribution},
	).Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("configured authn catalog Compile() error = %v", err)
	}

	return catalog
}

// newAuthnCandidateConfiguredRuleFor constructs one localized operation/checkpoint denial.
func newAuthnCandidateConfiguredRuleFor(
	t *testing.T,
	operation policy.Operation,
	checkpoint policy.Stage,
) registry.PolicyRule {
	t.Helper()

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{Kind: registry.ExpressionKindAlways})
	if err != nil {
		t.Fatalf("NewPolicyExpression() error = %v", err)
	}

	return newAuthnCandidateConfiguredDenyRule(t, operation, checkpoint, "deny", expression)
}

// newAuthnCandidateConfiguredNoMatchRule constructs a valid pre-auth rule whose predicate is absent.
func newAuthnCandidateConfiguredNoMatchRule(
	t *testing.T,
	operation policy.Operation,
) registry.PolicyRule {
	t.Helper()

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindAttribute, FactID: policy.AuthnFactRBLThresholdReached,
		FactKind: decision.ValueKindBoolean, Operator: registry.ExpressionOperatorIs,
		Values: []decision.Value{mustAuthnBooleanValue(t, true)},
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression(no-match) error = %v", err)
	}

	return newAuthnCandidateConfiguredDenyRule(t, operation, policy.StagePreAuth, "no_match", expression)
}

// newAuthnCandidateConfiguredDenyRule centralizes localized configured-rule presentation.
func newAuthnCandidateConfiguredDenyRule(
	t *testing.T,
	operation policy.Operation,
	checkpoint policy.Stage,
	nameSuffix string,
	expression registry.PolicyExpression,
) registry.PolicyRule {
	t.Helper()

	message, err := registry.NewPolicyResponseMessage(registry.PolicyResponseMessageInput{
		From: policy.ResponseSourceI18N, I18NKey: "auth.policy.configured_denial", Fallback: "configured denial",
	})
	if err != nil {
		t.Fatalf("NewPolicyResponseMessage() error = %v", err)
	}

	language, err := registry.NewPolicyResponseLanguage(registry.PolicyResponseLanguageInput{
		From: policy.ResponseSourceLiteral, Language: "de",
	})
	if err != nil {
		t.Fatalf("NewPolicyResponseLanguage() error = %v", err)
	}

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name:       "configured_" + string(operation) + "_" + string(checkpoint) + "_" + nameSuffix,
		Checkpoint: string(checkpoint), Actions: []string{string(operation)},
		Expression: expression, Decision: decision.EffectDeny,
		OutcomeMarker:  "auth.outcome.configured_denial",
		FSMEventMarker: configuredAuthnCandidateFSMMarker(checkpoint), ResponseMarker: policy.ResponseMarkerFail,
		ResponseMessage: message, ResponseLanguage: language,
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	return rule
}

// configuredAuthnCandidateFSMMarker selects the exact checkpoint-local denial marker.
func configuredAuthnCandidateFSMMarker(checkpoint policy.Stage) string {
	if checkpoint == policy.StagePreAuth {
		return policy.FSMEventMarkerPreAuthDeny
	}

	return policy.FSMEventMarkerAuthDeny
}

// newAuthnCandidateConfiguredContribution owns the test set and namespace export.
func newAuthnCandidateConfiguredContribution(
	t *testing.T,
	rule registry.PolicyRule,
) (registry.PolicySetID, registry.DefinitionContribution) {
	t.Helper()

	setID, err := registry.ParsePolicySetID("test.authn.configured", "authn/configured_candidate")
	if err != nil {
		t.Fatalf("ParsePolicySetID() error = %v", err)
	}

	set, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{
		ID: setID, Rules: []registry.PolicyRule{rule},
	})
	if err != nil {
		t.Fatalf("NewPolicySetDefinition() error = %v", err)
	}

	ownership, err := registry.NewNamespaceOwnership("test.authn.configured", []string{policy.AuthnNamespace})
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	contribution, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership: ownership, PolicySets: []registry.PolicySetDefinition{set},
	})
	if err != nil {
		t.Fatalf("NewCompleteDefinitionContribution() error = %v", err)
	}

	return setID, contribution
}

// newAuthnCandidateConfiguredActivation imports one configured final rule beside standard pre-auth.
func newAuthnCandidateConfiguredActivation(
	t *testing.T,
	target decision.Target,
	setID registry.PolicySetID,
) registry.TargetActivation {
	return newAuthnCandidateConfiguredActivationFor(t, target, setID, policy.StageAuthDecision)
}

// newAuthnCandidateConfiguredActivationFor imports one exact checkpoint while retaining standard fallback.
func newAuthnCandidateConfiguredActivationFor(
	t *testing.T,
	target decision.Target,
	setID registry.PolicySetID,
	checkpoint policy.Stage,
) registry.TargetActivation {
	t.Helper()

	binding, err := registry.NewPolicySetImport(
		"policy.targets.authn."+target.Action()+"."+string(checkpoint),
		setID.String(),
		target,
		string(checkpoint),
		registry.ExportContract{},
	)
	if err != nil {
		t.Fatalf("NewPolicySetImport() error = %v", err)
	}

	activation, err := registry.NewTargetActivation(
		"policy.targets.authn."+target.Action(),
		policy.AuthnNamespace,
		target.Action(),
		"authn/"+target.Action()+"/v1",
	)
	if err != nil {
		t.Fatalf("NewTargetActivation() error = %v", err)
	}

	activation, err = activation.WithPolicy(registry.BuiltinStandardAuthPolicySet, "")
	if err != nil {
		t.Fatalf("TargetActivation.WithPolicy() error = %v", err)
	}

	activation, err = activation.WithPolicySetBindings([]registry.PolicySetImport{binding})
	if err != nil {
		t.Fatalf("TargetActivation.WithPolicySetBindings() error = %v", err)
	}

	return activation
}

// compileAuthnCandidateCatalogWithModel binds standard rules to one captured attribute registry.
func compileAuthnCandidateCatalogWithModel(
	t *testing.T,
	acceptor effectsupervisor.Acceptor,
	model *authnCandidatePolicyModel,
) *policyruntime.TargetCatalog {
	t.Helper()

	operations := []policy.Operation{
		policy.OperationAuthenticate,
		policy.OperationLookupIdentity,
		policy.OperationListAccounts,
	}

	activations := make([]registry.TargetActivation, 0, len(operations))
	for _, operation := range operations {
		path := "policy.targets.authn." + string(operation)

		activation, err := registry.NewTargetActivation(
			path,
			policy.AuthnNamespace,
			string(operation),
			"authn/"+string(operation)+"/v1",
		)
		if err != nil {
			t.Fatalf("NewTargetActivation(%s) error = %v", operation, err)
		}

		activation, err = activation.WithPolicy(registry.BuiltinStandardAuthPolicySet, "")
		if err != nil {
			t.Fatalf("TargetActivation.WithPolicy(%s) error = %v", operation, err)
		}

		mode := registry.AuthorityMode(model.Mode)
		if !mode.Valid() {
			mode = registry.AuthorityModeEnforce
		}

		activation, err = activation.WithAuthorityMode(mode)
		if err != nil {
			t.Fatalf("TargetActivation.WithAuthorityMode(%s) error = %v", operation, err)
		}

		activations = append(activations, activation)
	}

	catalog, err := catalogcompile.NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributorWithAuthnPolicy(model.AttributeRegistry, acceptor),
	).Compile(context.Background(), activations)
	if err != nil {
		t.Fatalf("authn catalog Compile() error = %v", err)
	}

	return catalog
}

// authnCandidatePreparationSlots returns the complete test-only generation assembly graph.
func authnCandidatePreparationSlots(
	t *testing.T,
	catalog *policyruntime.TargetCatalog,
	bindings *policyruntime.BindingSet,
	model *authnCandidatePolicyModel,
) policyruntime.PreparationSlots {
	t.Helper()

	return policyruntime.PreparationSlots{
		Policy: policyruntime.PolicyPreparationFunc(func(
			_ context.Context,
			input policyruntime.PreparationInput,
		) (policyruntime.PolicyPreparation, error) {
			captured := model.clone()
			if captured == nil {
				captured = &authnCandidatePolicyModel{}
			}

			captured.Generation = input.ID()

			return policyruntime.PolicyPreparation{Policy: captured}, nil
		}),
		Extensions: policyruntime.ExtensionPreparationFunc(func(
			context.Context,
			policyruntime.PreparationInput,
		) (policyruntime.ExtensionPreparation, error) {
			return policyruntime.ExtensionPreparation{Bindings: bindings}, nil
		}),
		Catalog: policyruntime.CatalogPreparationFunc(func(
			context.Context,
			policyruntime.CatalogPreparationInput,
		) (policyruntime.CatalogPreparation, error) {
			return policyruntime.CatalogPreparation{Catalog: catalog}, nil
		}),
		CallerAuthentication: policyruntime.CallerAuthenticationPreparationFunc(func(
			context.Context,
			policyruntime.AuthorityPreparationInput,
		) (policyruntime.CallerAuthenticationPreparation, error) {
			return policyruntime.CallerAuthenticationPreparation{
				Authenticator:         authnCandidateAuthenticator{},
				InternalPresentations: authnCandidateInternalPresentations(t),
			}, nil
		}),
		Admission: policyruntime.AdmissionPreparationFunc(func(
			context.Context,
			policyruntime.AdmissionPreparationInput,
		) (policyruntime.AdmissionPreparation, error) {
			return policyruntime.AdmissionPreparation{Authority: authnCandidateAdmission{}}, nil
		}),
		Settings: policyruntime.SettingsPreparationFunc(func(
			_ context.Context,
			input policyruntime.SettingsPreparationInput,
		) (policyruntime.SettingsPreparation, error) {
			return policyruntime.SettingsPreparation{
				MessageResolver: authnCandidateMessageResolver(input.ID()),
				Settings: policyruntime.GenerationSettings{
					Limits: policyruntime.DecisionLimits{
						EvaluationTimeout: time.Second, PostActionBudget: time.Second, MaxDiagnosticsEntries: 32,
					},
					Reports: policyruntime.DecisionReportSettings{MaxEntries: 32},
				},
			}, nil
		}),
		Application: decisionservice.NewRuntimeApplicationPreparationSlot(),
	}
}

// authnCandidateMessageResolver builds one immutable catalog owned by the fixture generation.
func authnCandidateMessageResolver(generation uint64) localization.MessageResolver {
	return localization.NewResolver(localization.NewMapCatalog(map[string]map[string]string{
		"en": {
			"auth.policy.configured_denial": fmt.Sprintf("generation-%d configured denial", generation),
		},
	}), "en")
}

type authnResolverLeaseApplication struct {
	base     authnCandidateHost
	cfg      config.File
	logger   *slog.Logger
	started  chan struct{}
	release  chan struct{}
	messages []string
	mu       sync.Mutex
	calls    atomic.Int32
}

type authnResolverLeaseResult struct {
	outcome *AuthOutcome
	err     error
}

// newAuthnResolverLeaseApplication blocks only its first authentication inside the captured session.
func newAuthnResolverLeaseApplication(cfg config.File) *authnResolverLeaseApplication {
	db, _ := redismock.NewClientMock()

	return &authnResolverLeaseApplication{
		base: newRegisteredAuthApplicationServiceHost(AuthDeps{
			Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
		}),
		cfg:     cfg,
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

// prepareAuthnCandidateExecution holds the first exact Decision session while a successor publishes.
func (s *authnResolverLeaseApplication) prepareAuthnCandidateExecution(
	ctx context.Context,
	input AuthInput,
	operation policy.Operation,
) (*authnCandidateExecution, context.Context, error) {
	message, err := s.localizedMessage(ctx)
	if err != nil {
		return nil, ctx, err
	}

	s.mu.Lock()
	s.messages = append(s.messages, message)
	s.mu.Unlock()

	if s.calls.Add(1) == 1 {
		close(s.started)

		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx, ctx.Err()
		}
	}

	return s.base.prepareAuthnCandidateExecution(ctx, input, operation)
}

// localizedMessages returns detached request-Lua resolver evidence.
func (s *authnResolverLeaseApplication) localizedMessages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.messages...)
}

// Authenticate keeps the first generation leased until the test publishes its successor.
func (s *authnResolverLeaseApplication) Authenticate(ctx context.Context, _ AuthInput) (*AuthOutcome, error) {
	message, err := s.localizedMessage(ctx)
	if err != nil {
		return nil, err
	}

	return newAuthnResolverLeaseOutcome(message), nil
}

// LookupIdentity returns a fresh outcome for the unused interface operation.
func (s *authnResolverLeaseApplication) LookupIdentity(ctx context.Context, _ AuthInput) (*AuthOutcome, error) {
	message, err := s.localizedMessage(ctx)
	if err != nil {
		return nil, err
	}

	return newAuthnResolverLeaseOutcome(message), nil
}

// ListAccounts returns a fresh list outcome so resolver propagation covers both outcome types.
func (s *authnResolverLeaseApplication) ListAccounts(
	ctx context.Context,
	_ AuthInput,
) (*ListAccountsOutcome, error) {
	message, err := s.localizedMessage(ctx)
	if err != nil {
		return nil, err
	}

	return &ListAccountsOutcome{
		Accounts:             AccountList{"lease@example.test"},
		Decision:             AuthDecisionOK,
		Session:              "resolver-lease-list",
		StatusMessage:        message,
		StatusMessageI18NKey: "auth.policy.configured_denial",
	}, nil
}

// newAuthnResolverLeaseOutcome returns a detached response for generation annotation.
func newAuthnResolverLeaseOutcome(message string) *AuthOutcome {
	return &AuthOutcome{
		Decision:             AuthDecisionOK,
		Session:              "resolver-lease-auth",
		StatusMessage:        message,
		StatusMessageI18NKey: "auth.policy.configured_denial",
	}
}

// localizedMessage executes the request Lua i18n module bound by the production default module manager.
func (s *authnResolverLeaseApplication) localizedMessage(ctx context.Context) (string, error) {
	L := lua.NewState()
	defer L.Close()

	L.SetContext(ctx)
	manager := luamod.NewModuleManager(ctx, s.cfg, s.logger, nil)
	manager.BindAllDefault(ctx, L, lualib.NewContext(), tolerate.GetTolerate())

	if err := L.DoString(`
		local i18n = require("nauthilus_i18n")
		resolver_result = i18n.get_localized({
			i18n_key = "auth.policy.configured_denial",
			fallback = "configured denial",
			language = "en",
		})
	`); err != nil {
		return "", fmt.Errorf("run generation-owned Lua localization: %w", err)
	}

	result, ok := L.GetGlobal("resolver_result").(*lua.LTable)
	if !ok {
		return "", fmt.Errorf("generation-owned Lua localization returned no result table")
	}

	message, ok := L.GetField(result, "message").(lua.LString)
	if !ok || message == "" {
		return "", fmt.Errorf("generation-owned Lua localization returned no message")
	}

	return string(message), nil
}

// assertAuthnCapturedResolverMessage resolves one outcome through its exact generation catalog.
func assertAuthnCapturedResolverMessage(
	t *testing.T,
	resolver localization.MessageResolver,
	want string,
) {
	t.Helper()

	if resolver == nil {
		t.Fatal("captured outcome resolver is nil")
	}

	resolved := resolver.ResolveStatusMessage(
		context.Background(),
		localization.StatusMessage{
			Text:    "configured denial",
			I18NKey: "auth.policy.configured_denial",
		},
		localization.LanguagePreference{Default: "en"},
	)
	if resolved.Text != want {
		t.Fatalf("resolved message = %q, want %q", resolved.Text, want)
	}
}

type authnCandidateAuthenticator struct{}

// authnCandidateInternalPresentations projects the authoritative production
// entry-operation matrix into deterministic test-owned caller evidence.
func authnCandidateInternalPresentations(t *testing.T) map[string]decision.AuthenticationInput {
	t.Helper()

	profileIDs, err := AuthnInternalProfileIDs()
	if err != nil {
		t.Fatalf("AuthnInternalProfileIDs() error = %v", err)
	}

	presentations := make(map[string]decision.AuthenticationInput, len(profileIDs))
	for _, profileID := range profileIDs {
		presentation, presentationErr := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
			Kind:          "internal",
			Credential:    []byte("authn-policy-test:" + profileID.String()),
			TransportKind: "internal",
		})
		if presentationErr != nil {
			t.Fatalf("NewAuthenticationInput(%s) error = %v", profileID, presentationErr)
		}

		presentations[profileID.String()] = presentation
	}

	return presentations
}

type authnCandidateStaticContributor struct {
	contribution registry.DefinitionContribution
}

// Contribute returns one immutable test-only configured authn policy set.
func (c authnCandidateStaticContributor) Contribute(context.Context) (registry.DefinitionContribution, error) {
	return c.contribution, nil
}

// Authenticate returns the explicit builtin internal caller used by the candidate adapter.
func (authnCandidateAuthenticator) Authenticate(
	context.Context,
	decision.AuthenticationInput,
) (decision.CallerContext, error) {
	return decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: "nauthilus-authn-candidate", AuthenticationKind: "internal",
		TransportKind: "internal", Internal: true,
	})
}

type authnCandidateAdmission struct{}

// Admit permits only the test generation's already authenticated internal invocation.
func (authnCandidateAdmission) Admit(
	context.Context,
	decision.CallerContext,
	decision.DecisionRequest,
) (policyruntime.AdmissionPermit, error) {
	facts, err := decision.NewFactSet(nil)
	if err != nil {
		return nil, err
	}

	return authnCandidatePermit{facts: facts}, nil
}

type authnCandidatePermit struct {
	facts decision.FactSet
}

// Facts returns the empty admitted fact set used by this candidate-only test.
func (p authnCandidatePermit) Facts() decision.FactSet {
	return p.facts
}

// Release has no capacity to return for this candidate-only test.
func (authnCandidatePermit) Release() {}

type authnCandidateAcceptAll struct{}

type authnCandidateCountingAcceptor struct {
	delegate effectsupervisor.Acceptor
	calls    atomic.Int32
}

// Accept records one successful result-bearing supervisor handoff.
func (a *authnCandidateCountingAcceptor) Accept(
	ctx context.Context,
	plan effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	a.calls.Add(1)

	if a.delegate != nil {
		return a.delegate.Accept(ctx, plan)
	}

	return effectsupervisor.Receipt{}, nil
}

// Accept confirms ownership for tests whose selected standard result has no post-action.
func (*authnCandidateAcceptAll) Accept(
	context.Context,
	effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

type authnCandidateInjectedHost struct {
	base      authnCandidateHost
	configure func(*authnCandidateExecution)
	calls     atomic.Int32
}

// prepareAuthnCandidateExecution installs deterministic request-local facts and effect owners.
func (h *authnCandidateInjectedHost) prepareAuthnCandidateExecution(
	ctx context.Context,
	input AuthInput,
	operation policy.Operation,
) (*authnCandidateExecution, context.Context, error) {
	execution, evaluationCtx, err := h.base.prepareAuthnCandidateExecution(ctx, input, operation)
	if err == nil && h.configure != nil {
		h.configure(execution)
	}

	return execution, evaluationCtx, err
}

// Authenticate fails if the candidate accidentally invokes the retired aggregate service.
func (h *authnCandidateInjectedHost) Authenticate(context.Context, AuthInput) (*AuthOutcome, error) {
	h.calls.Add(1)

	return nil, errors.New("retired aggregate authenticate was invoked")
}

// LookupIdentity fails if the candidate accidentally invokes the retired aggregate service.
func (h *authnCandidateInjectedHost) LookupIdentity(context.Context, AuthInput) (*AuthOutcome, error) {
	h.calls.Add(1)

	return nil, errors.New("retired aggregate lookup was invoked")
}

// ListAccounts fails if the candidate accidentally invokes the retired aggregate service.
func (h *authnCandidateInjectedHost) ListAccounts(context.Context, AuthInput) (*ListAccountsOutcome, error) {
	h.calls.Add(1)

	return nil, errors.New("retired aggregate account listing was invoked")
}

type authnCandidateEffectLog struct {
	values []string
	mu     sync.Mutex
}

// append records one ordered candidate effect boundary.
func (l *authnCandidateEffectLog) append(value string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.values = append(l.values, value)
}

// entries returns a detached candidate effect order.
func (l *authnCandidateEffectLog) entries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return append([]string(nil), l.values...)
}

type authnCandidateRejectingAcceptor struct {
	log *authnCandidateEffectLog
}

// Accept records and rejects the mandatory supervisor transfer.
func (a *authnCandidateRejectingAcceptor) Accept(
	_ context.Context,
	plan effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	a.log.append(fmt.Sprintf("accept:%s:%d", plan.Provider(), plan.EffectOrdinal()))

	return effectsupervisor.Receipt{}, errors.New("candidate supervisor capacity unavailable")
}

type authnCandidateCheckpointFactory struct {
	delegate    decisionservice.DecisionSessionFactory
	checkpoints map[string][]string
	mu          sync.Mutex
}

// WithSession wraps the real Decision Service session with checkpoint recording.
func (f *authnCandidateCheckpointFactory) WithSession(
	ctx context.Context,
	invocation decision.Invocation,
	use func(decisionservice.DecisionSession) error,
) error {
	target := invocation.Request.Target.String()

	return f.delegate.WithSession(ctx, invocation, f.recordCheckpointSession(target, use))
}

// WithInternalSession records checkpoint traversal for one generation-owned internal profile.
func (f *authnCandidateCheckpointFactory) WithInternalSession(
	ctx context.Context,
	input decisionservice.InternalSessionInput,
	use func(decisionservice.DecisionSession) error,
) error {
	target := input.Request.Target.String()

	return f.delegate.WithInternalSession(ctx, input, f.recordCheckpointSession(target, use))
}

// recordCheckpointSession wraps one admitted session with traversal evidence.
func (f *authnCandidateCheckpointFactory) recordCheckpointSession(
	target string,
	use func(decisionservice.DecisionSession) error,
) func(decisionservice.DecisionSession) error {
	return func(session decisionservice.DecisionSession) error {
		return use(&authnCandidateCheckpointSession{delegate: session, target: target, owner: f})
	}
}

// snapshot returns detached operation/checkpoint traversal evidence.
func (f *authnCandidateCheckpointFactory) snapshot() map[string][]string {
	f.mu.Lock()
	defer f.mu.Unlock()

	result := make(map[string][]string, len(f.checkpoints))
	for target, checkpoints := range f.checkpoints {
		result[target] = append([]string(nil), checkpoints...)
	}

	return result
}

type authnCandidateCheckpointSession struct {
	delegate decisionservice.DecisionSession
	owner    *authnCandidateCheckpointFactory
	target   string
}

// Checkpoints returns the real captured compiled checkpoint order.
func (s *authnCandidateCheckpointSession) Checkpoints() []decisionservice.CheckpointPlan {
	return s.delegate.Checkpoints()
}

// RequestContext preserves the exact captured generation context from the delegate.
func (s *authnCandidateCheckpointSession) RequestContext(ctx context.Context) context.Context {
	return s.delegate.RequestContext(ctx)
}

// AuthnHostProvider preserves generation-owned source lookup through the recording wrapper.
func (s *authnCandidateCheckpointSession) AuthnHostProvider(
	id string,
) (decisionservice.AuthnHostProvider, bool) {
	providerSession, ok := s.delegate.(decisionservice.AuthnHostProviderSession)
	if !ok {
		return nil, false
	}

	return providerSession.AuthnHostProvider(id)
}

// AuthnLuaFacts preserves generation-owned registry declarations through the recording wrapper.
func (s *authnCandidateCheckpointSession) AuthnLuaFacts() []decisionservice.AuthnLuaFactDeclaration {
	factSession, ok := s.delegate.(decisionservice.AuthnLuaFactSession)
	if !ok {
		return nil
	}

	return factSession.AuthnLuaFacts()
}

// NextAuthnHostProvider preserves exact scheduler ownership through the recording wrapper.
func (s *authnCandidateCheckpointSession) NextAuthnHostProvider(
	input decisionservice.AuthnHostScheduleInput,
) (decisionservice.AuthnHostDirective, bool, error) {
	executionSession, ok := s.delegate.(decisionservice.AuthnHostExecutionSession)
	if !ok {
		return decisionservice.AuthnHostDirective{}, false, fmt.Errorf("authn host execution session is unavailable")
	}

	return executionSession.NextAuthnHostProvider(input)
}

// CompleteAuthnHostSchedule forwards terminal exhaustion to the captured scheduler.
func (s *authnCandidateCheckpointSession) CompleteAuthnHostSchedule(checkpoint string) error {
	executionSession, ok := s.delegate.(decisionservice.AuthnHostExecutionSession)
	if !ok {
		return fmt.Errorf("authn host execution session is unavailable")
	}

	return executionSession.CompleteAuthnHostSchedule(checkpoint)
}

// RecordAuthnHostProvider preserves exact receipt ownership through the recording wrapper.
func (s *authnCandidateCheckpointSession) RecordAuthnHostProvider(
	receipt decisionservice.AuthnHostReceipt,
) error {
	executionSession, ok := s.delegate.(decisionservice.AuthnHostExecutionSession)
	if !ok {
		return fmt.Errorf("authn host execution session is unavailable")
	}

	return executionSession.RecordAuthnHostProvider(receipt)
}

// Evaluate records one traversal before delegating to the shared runtime.
func (s *authnCandidateCheckpointSession) Evaluate(
	ctx context.Context,
	checkpoint decision.Checkpoint,
) (decision.DecisionResponse, error) {
	s.owner.mu.Lock()
	s.owner.checkpoints[s.target] = append(s.owner.checkpoints[s.target], checkpoint.Name())
	s.owner.mu.Unlock()

	return s.delegate.Evaluate(ctx, checkpoint)
}

type authnCandidateEffectObserver struct {
	events []effectsupervisor.Event
	mu     sync.Mutex
}

// Observe records redacted supervisor lifecycle evidence.
func (o *authnCandidateEffectObserver) Observe(_ context.Context, event effectsupervisor.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.events = append(o.events, event)
}

// saw reports whether one exact late lifecycle state was recorded.
func (o *authnCandidateEffectObserver) saw(phase effectsupervisor.Phase, state effectsupervisor.State) bool {
	o.mu.Lock()
	defer o.mu.Unlock()

	for _, event := range o.events {
		if event.Phase == phase && event.State == state {
			return true
		}
	}

	return false
}
