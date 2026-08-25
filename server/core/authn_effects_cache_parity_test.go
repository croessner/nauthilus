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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/backend/accountcache"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/model/authdto"
	"github.com/croessner/nauthilus/v3/server/pluginloader"
	"github.com/croessner/nauthilus/v3/server/policy"
	policycollection "github.com/croessner/nauthilus/v3/server/policy/collection"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/evaluation"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	"github.com/croessner/nauthilus/v3/server/policy/report"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
	"github.com/croessner/nauthilus/v3/server/rediscli"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

const (
	authnCandidateLuaAttributeID    = "auth.lua.environment.current_behavior_environment.triggered"
	authnCandidateLuaFactID         = "nauthilus.auth.lua.environment.current_behavior_environment.triggered"
	authnCandidateNativeAttributeID = "auth.plugin.environment.candidate.verdict.triggered"
	authnCandidateNativeFactID      = "nauthilus.auth.plugin.environment.candidate.verdict.triggered"
	authnCandidateNativeCheck       = "plugin_environment_candidate"
	authnCandidateNativeProviderID  = "authn/candidate_native"
	authnCandidateNativeEffectID    = "authn/candidate_native_effect"
)

// installAuthnCandidateServices installs one request-pipeline fixture and restores global seams.
func installAuthnCandidateServices(
	t *testing.T,
	verifier PasswordVerifier,
	subject LuaSubject,
	postAction PostAction,
) {
	t.Helper()

	previousVerifier := getPasswordVerifier()
	previousSubject := getLuaSubject()
	previousPostAction := getPostAction()

	RegisterPasswordVerifier(verifier)
	RegisterLuaSubject(subject)
	RegisterPostAction(postAction)
	t.Cleanup(func() {
		RegisterPasswordVerifier(previousVerifier)
		RegisterLuaSubject(previousSubject)
		RegisterPostAction(previousPostAction)
	})
}

func TestAuthnCandidateBruteForceAcceptanceFailurePreservesSyncEffectsAndMapsTempFail(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation: 702, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet,
	})

	db, _ := redismock.NewClientMock()
	base := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	}).(*authApplicationService)
	log := &authnCandidateEffectLog{}
	work := &authnCandidateEffectWork{}
	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(execution *authnCandidateExecution) {
			snapshot := policyruntime.PolicySnapshotFromContext(execution.ginCtx.Request.Context())
			if snapshot == nil || snapshot.Generation != 701 || snapshot.Mode != "enforce" {
				t.Fatalf("captured policy snapshot = %#v, want generation 701 enforce", snapshot)
			}

			execution.preAuthReady = true
			execution.auth.Security.BruteForceName = "candidate_block"
			execution.auth.Runtime.EnvironmentName = definitions.ControlBruteForce
			execution.auth.recordPolicyBruteForce(execution.ginCtx, true)
			execution.executeEffect = func(effect report.EffectRequest) effectsupervisor.Result {
				log.append("sync:" + effect.ID)

				return effectsupervisor.Succeeded()
			}
			execution.preparePost = func(effect report.EffectRequest, ordinal uint32) (effectsupervisor.ExecutableWork, error) {
				log.append(fmt.Sprintf("prepare:%s:%d", effect.ID, ordinal))

				return work, nil
			}
		},
	}
	rejector := &authnCandidateRejectingAcceptor{log: log}
	runtime := newAuthnCandidateDecisionService(t, cfg, rejector)

	adapter, err := NewAuthnCandidateApplicationService(host, runtime, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	outcome := authenticateAuthnCandidate(
		t, "brute-force acceptance rejection", adapter, authnApplicationTestInput(AuthModeAuthenticate),
	)

	assertAuthnCandidateRejectedPlan(t, outcome, log, host, work)
}

func TestAuthnCandidateSynchronousFailureClearsStaleLocalization(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	db, _ := redismock.NewClientMock()
	base := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	}).(*authApplicationService)
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
			execution.preparePost = func(
				report.EffectRequest,
				uint32,
			) (effectsupervisor.ExecutableWork, error) {
				return &authnCandidateEffectWork{}, nil
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

// assertAuthnCandidateRejectedPlan verifies ordered partial effects and the final tempfail surface.
func assertAuthnCandidateRejectedPlan(
	t *testing.T,
	outcome *AuthOutcome,
	log *authnCandidateEffectLog,
	host *authnCandidateInjectedHost,
	work *authnCandidateEffectWork,
) {
	t.Helper()

	wantOrder := []string{
		"sync:" + policy.ObligationBruteForceUpdate,
		"sync:" + policy.ObligationLuaActionDispatch,
		"prepare:" + policy.ObligationLuaPostActionEnqueue + ":3",
		"accept:authn/post_action:3",
	}
	if got := log.entries(); !reflect.DeepEqual(got, wantOrder) {
		t.Fatalf("candidate effect order = %v, want %v", got, wantOrder)
	}

	if outcome.Decision != AuthDecisionTempFail || outcome.TerminalState != string(authFSMStateAuthTempFail) {
		t.Fatalf("candidate result = %q/%q, want tempfail/auth_tempfail", outcome.Decision, outcome.TerminalState)
	}

	if outcome.StatusMessage != definitions.TempFailDefault || outcome.HTTPStatus != 500 {
		t.Fatalf("candidate tempfail presentation = %q/%d", outcome.StatusMessage, outcome.HTTPStatus)
	}

	wantFSM := []string{policy.FSMEventMarkerParseOK, policy.FSMEventMarkerPreAuthTempFail}
	if !reflect.DeepEqual(outcome.FSMEventPath, wantFSM) {
		t.Fatalf("candidate tempfail FSM = %v, want %v", outcome.FSMEventPath, wantFSM)
	}

	if host.calls.Load() != 0 || work.cleanupCalls.Load() != 1 || work.executeCalls.Load() != 0 {
		t.Fatalf(
			"current/cleanup/worker calls = %d/%d/%d, want 0/1/0",
			host.calls.Load(), work.cleanupCalls.Load(), work.executeCalls.Load(),
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
	base := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	}).(*authApplicationService)
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

func TestAuthnCandidateRejectedExistingPostActionAcceptanceMapsPermitToTempFail(t *testing.T) {
	outcome, execution, postAction := runAuthnCandidateExistingPostActionFailure(
		t,
		"rejected existing post-action",
		"candidate-post-reject@example.test",
		PostActionAcceptanceRejected(),
	)

	assertAuthnCandidateRejectedExistingPostAction(t, outcome, postAction)

	if execution == nil || !authnCandidatePostActionAcceptanceFailed(execution.ginCtx) {
		t.Fatal("explicit supervisor rejection did not retain the acceptance marker")
	}
}

func TestAuthnCandidateCanceledExistingPostActionMapsTempFailWithoutAcceptanceMarker(t *testing.T) {
	outcome, execution, postAction := runAuthnCandidateExistingPostActionFailure(
		t,
		"canceled existing post-action",
		"candidate-post-canceled@example.test",
		PostActionCanceled(),
	)

	assertAuthnCandidateRejectedExistingPostAction(t, outcome, postAction)

	if execution == nil {
		t.Fatal("candidate execution was not captured")
	}

	if authnCandidatePostActionAcceptanceFailed(execution.ginCtx) {
		t.Fatal("post-action cancellation was mislabeled as acceptance rejection")
	}
}

// runAuthnCandidateExistingPostActionFailure executes one cause-bearing existing seam failure.
func runAuthnCandidateExistingPostActionFailure(
	t *testing.T,
	name string,
	username string,
	postActionResult PostActionResult,
) (*AuthOutcome, *authnCandidateExecution, *authnCandidateClassifiedPostAction) {
	t.Helper()

	fixture := newAuthnCandidateExistingPostActionFixture(t, username, postActionResult)
	input := NewAuthInputFromStructuredRequest(
		definitions.ServGRPC,
		AuthModeAuthenticate,
		authdto.Request{
			Username: username, Password: "candidate-secret", Protocol: definitions.ProtoIMAP,
			ClientIP: "203.0.113.79", Method: "plain",
		},
	)
	outcome := authenticateAuthnCandidate(t, name, fixture.adapter, input)

	if fixture.verifierCalls.Load() != 1 || fixture.subjectCalls.Load() != 1 {
		t.Fatalf(
			"backend/subject calls = %d/%d, want 1/1",
			fixture.verifierCalls.Load(),
			fixture.subjectCalls.Load(),
		)
	}

	return outcome, fixture.execution, fixture.postAction
}

type authnCandidateExistingPostActionFixture struct {
	adapter       AuthApplicationService
	execution     *authnCandidateExecution
	postAction    *authnCandidateClassifiedPostAction
	verifierCalls *atomic.Int32
	subjectCalls  *atomic.Int32
}

// newAuthnCandidateExistingPostActionFixture assembles one classified existing post-action request.
func newAuthnCandidateExistingPostActionFixture(
	t *testing.T,
	username string,
	postActionResult PostActionResult,
) *authnCandidateExistingPostActionFixture {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation: 708, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet,
	})

	manager := accountcache.NewManager(cfg)
	manager.Set(cfg, username, definitions.ProtoIMAP, "", username)

	db, mock := redismock.NewClientMock()
	current := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: manager,
		BackendAuthenticationCache: NewPositiveBackendAuthenticationCache(time.Now),
	}).(*authApplicationService)
	fixture := &authnCandidateExistingPostActionFixture{
		postAction:    &authnCandidateClassifiedPostAction{result: postActionResult},
		verifierCalls: &atomic.Int32{}, subjectCalls: &atomic.Int32{},
	}
	host := &authnCandidateInjectedHost{
		base: current,
		configure: func(execution *authnCandidateExecution) {
			fixture.execution = execution
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

	fixture.adapter = adapter
	installAuthnCandidateServices(
		t,
		backendAuthenticationContractVerifier{calls: fixture.verifierCalls},
		backendAuthenticationContractSubject{calls: fixture.subjectCalls},
		fixture.postAction,
	)
	t.Cleanup(func() {
		if expectationErr := mock.ExpectationsWereMet(); expectationErr != nil {
			t.Errorf("unexpected Redis operation: %v", expectationErr)
		}
	})

	return fixture
}

// assertAuthnCandidateRejectedExistingPostAction verifies complete host execution before rejection.
func assertAuthnCandidateRejectedExistingPostAction(
	t *testing.T,
	outcome *AuthOutcome,
	postAction *authnCandidateClassifiedPostAction,
) {
	t.Helper()

	if outcome.Decision != AuthDecisionTempFail || outcome.TerminalState != string(authFSMStateAuthTempFail) ||
		outcome.StatusMessage != definitions.TempFailDefault {
		t.Fatalf("rejected existing post-action result = %#v, want complete tempfail", outcome)
	}

	if postAction.calls.Load() != 1 {
		t.Fatalf("post-action calls = %d, want 1", postAction.calls.Load())
	}
}

func TestAuthnPolicyEffectRequestRestoresExactLegacySelectionAndParameters(t *testing.T) {
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

	action := policy.LuaActionDispatchBruteForce
	environment := "candidate_environment"
	wait := false
	actionValue := mustAuthnStringValue(t, action)
	environmentValue := mustAuthnStringValue(t, environment)

	waitValue, err := decision.NewValue(decision.ValueInput{Boolean: &wait})
	if err != nil {
		t.Fatalf("NewValue(wait) error = %v", err)
	}

	for ordinal, binding := range registry.BuiltinAuthEffectBindings() {
		parameters := map[string]decision.Value{policy.ObligationArgEnvironment: environmentValue}
		wantArgs := map[string]any{policy.ObligationArgEnvironment: environment}

		if binding.Selection != policy.ObligationBruteForceUpdate {
			parameters[policy.ObligationArgAction] = actionValue
			parameters[policy.ObligationArgWait] = waitValue
			wantArgs[policy.ObligationArgAction] = action
			wantArgs[policy.ObligationArgWait] = wait
		}

		valueMap, mapErr := decision.NewValueMap(parameters)
		if mapErr != nil {
			t.Fatalf("NewValueMap(%q) error = %v", binding.Selection, mapErr)
		}

		execution, executionErr := policyruntime.NewEffectExecution(policyruntime.EffectExecutionInput{
			Facts: facts, Caller: caller,
			Parameters: valueMap, Target: target, EffectID: binding.EffectID,
			DecisionID: "decision-authn-effect", Provider: binding.Provider,
			Generation: 1, Ordinal: uint32(ordinal + 1),
		})
		if executionErr != nil {
			t.Fatalf("NewEffectExecution(%q) error = %v", binding.Selection, executionErr)
		}

		request, requestErr := authnPolicyEffectRequest(execution)
		if requestErr != nil {
			t.Fatalf("authnPolicyEffectRequest(%q) error = %v", binding.Selection, requestErr)
		}

		if request.ID != binding.Selection || !reflect.DeepEqual(request.Args, wantArgs) {
			t.Fatalf("restored effect = %#v, want %q/%#v", request, binding.Selection, wantArgs)
		}
	}
}

func TestAuthnCandidateAcceptedPostActionWaitsForFinalizationAndLateFailureCannotMutateResult(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation: 703, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet,
	})

	observer := &authnCandidateEffectObserver{}
	supervisor := newAuthnCandidateTestSupervisor(t, observer)

	db, _ := redismock.NewClientMock()
	base := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	}).(*authApplicationService)
	work := &authnCandidateEffectWork{
		started: make(chan struct{}),
		result:  effectsupervisor.Failed("late_provider_failure"),
	}
	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(execution *authnCandidateExecution) {
			execution.preAuthReady = true
			execution.auth.Security.BruteForceName = "candidate_block"
			execution.auth.Runtime.EnvironmentName = definitions.ControlBruteForce
			execution.auth.recordPolicyBruteForce(execution.ginCtx, true)
			execution.executeEffect = func(report.EffectRequest) effectsupervisor.Result {
				return effectsupervisor.Succeeded()
			}
			execution.preparePost = func(report.EffectRequest, uint32) (effectsupervisor.ExecutableWork, error) {
				return work, nil
			}
		},
	}
	decisionRuntime := newAuthnCandidateDecisionService(t, cfg, supervisor)
	factory := &authnCandidateFinalizationFactory{delegate: decisionRuntime, work: work}

	adapter, err := NewAuthnCandidateApplicationService(host, factory, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	input := authnApplicationTestInput(AuthModeAuthenticate)
	ctx, gate := authnCandidateTestContext(context.Background(), input)

	outcome, err := adapter.Authenticate(ctx, input)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	select {
	case <-work.started:
		t.Fatal("accepted post-action started before the gRPC unary boundary")
	default:
	}

	gate.Complete()

	assertAuthnCandidateLatePostActionFailure(t, supervisor, work, observer, outcome)
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

// assertAuthnCandidateLatePostActionFailure verifies finalization order and immutable response state.
func assertAuthnCandidateLatePostActionFailure(
	t *testing.T,
	supervisor *effectsupervisor.Supervisor,
	work *authnCandidateEffectWork,
	observer *authnCandidateEffectObserver,
	outcome *AuthOutcome,
) {
	t.Helper()

	select {
	case <-work.started:
	case <-time.After(time.Second):
		t.Fatal("accepted post-action did not execute after finalization")
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := supervisor.WaitIdle(waitCtx); err != nil {
		t.Fatalf("WaitIdle() error = %v", err)
	}

	if work.startedBeforeFinalization.Load() {
		t.Fatal("accepted post-action executed before the candidate finalization boundary")
	}

	if outcome.Decision != AuthDecisionFail || outcome.TerminalState != string(authFSMStateAuthFail) {
		t.Fatalf("returned result after late failure = %q/%q, want fail/auth_fail", outcome.Decision, outcome.TerminalState)
	}

	if work.executeCalls.Load() != 1 || work.cleanupCalls.Load() != 1 {
		t.Fatalf("worker execute/cleanup calls = %d/%d, want 1/1", work.executeCalls.Load(), work.cleanupCalls.Load())
	}

	if !observer.saw(effectsupervisor.PhaseExecution, effectsupervisor.StateFailed) {
		t.Fatal("late provider failure was not observable as a failed execution event")
	}
}

func TestAuthnCandidateObserveSuppressesStandardEffectsWithoutChangingDeny(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation: 704, Mode: "observe", DefaultPolicy: policy.BuiltinDefaultSet,
	})

	db, _ := redismock.NewClientMock()
	base := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	}).(*authApplicationService)
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
			execution.preparePost = func(report.EffectRequest, uint32) (effectsupervisor.ExecutableWork, error) {
				effectCalls.Add(1)

				return &authnCandidateEffectWork{}, nil
			}
		},
	}
	runtime := newAuthnCandidateDecisionServiceWithSnapshot(
		t,
		cfg,
		&authnCandidateAcceptAll{},
		&policyruntime.Snapshot{Generation: 704, Mode: "observe", DefaultPolicy: policy.BuiltinDefaultSet},
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

func TestAuthnCandidateCapturedGenerationIgnoresAmbientObserveSnapshot(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation: 999, Mode: "observe", DefaultPolicy: policy.BuiltinDefaultSet,
	})

	db, _ := redismock.NewClientMock()
	base := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	}).(*authApplicationService)
	effectCalls := &atomic.Int32{}
	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(execution *authnCandidateExecution) {
			snapshot := policyruntime.PolicySnapshotFromContext(execution.ginCtx.Request.Context())
			if snapshot == nil || snapshot.Generation != 701 || snapshot.Mode != "enforce" {
				t.Fatalf("captured policy snapshot = %#v, want generation 701 enforce", snapshot)
			}

			execution.preAuthReady = true
			execution.auth.Security.BruteForceName = "captured_generation_block"
			execution.auth.Runtime.EnvironmentName = definitions.ControlBruteForce
			execution.auth.recordPolicyBruteForce(execution.ginCtx, true)
			execution.executeEffect = func(report.EffectRequest) effectsupervisor.Result {
				effectCalls.Add(1)

				return effectsupervisor.Succeeded()
			}
			execution.preparePost = func(report.EffectRequest, uint32) (effectsupervisor.ExecutableWork, error) {
				effectCalls.Add(1)

				return &authnCandidateEffectWork{}, nil
			}
		},
	}
	captured := &policyruntime.Snapshot{
		Generation: 701, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet,
	}
	rejector := &authnCandidateRejectingAcceptor{log: &authnCandidateEffectLog{}}
	runtime := newAuthnCandidateDecisionServiceWithSnapshot(t, cfg, rejector, captured)

	adapter, err := NewAuthnCandidateApplicationService(host, runtime, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	outcome := authenticateAuthnCandidate(
		t, "captured generation", adapter, authnApplicationTestInput(AuthModeAuthenticate),
	)

	if effectCalls.Load() != 3 {
		t.Fatalf("captured-generation effect calls = %d, want three enforce-mode owners", effectCalls.Load())
	}

	if outcome.Decision != AuthDecisionTempFail {
		t.Fatalf("captured-generation decision = %q, want acceptance-failure tempfail", outcome.Decision)
	}
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

	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation: 707, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet,
	})

	username := "candidate-configured@example.test"
	manager := accountcache.NewManager(cfg)
	manager.Set(cfg, username, definitions.ProtoIMAP, "", username)

	db, mock := redismock.NewClientMock()
	current := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: manager,
		BackendAuthenticationCache: NewPositiveBackendAuthenticationCache(time.Now),
	}).(*authApplicationService)
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
		recordingPlanPostAction{},
	)

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
	base := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	}).(*authApplicationService)

	var (
		execution        *authnCandidateExecution
		syncCalls        atomic.Int32
		postPreparations atomic.Int32
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
			current.preparePost = func(
				report.EffectRequest,
				uint32,
			) (effectsupervisor.ExecutableWork, error) {
				postPreparations.Add(1)

				return &authnCandidateEffectWork{}, nil
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

	assertAuthnCandidateDefaultBruteForceResult(
		t, adapter, acceptor, recorder, &execution, &syncCalls, &postPreparations,
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
	postPreparations *atomic.Int32,
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

	if current.finalReady || syncCalls.Load() != 2 || postPreparations.Load() != 1 {
		t.Fatalf(
			"backend/sync/post execution = %t/%d/%d, want false/2/1",
			current.finalReady, syncCalls.Load(), postPreparations.Load(),
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
	base := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	}).(*authApplicationService)

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

type authnCandidateCompiledProviderFixture struct {
	adapter   AuthApplicationService
	acceptor  *effectsupervisor.Supervisor
	bridge    *recordingAuthnCandidateEnvironmentBridge
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
	base := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	}).(*authApplicationService)

	fixture := &authnCandidateCompiledProviderFixture{
		bridge: &recordingAuthnCandidateEnvironmentBridge{},
	}
	previousBridge := getPluginEnvironmentSourceBridge()

	RegisterPluginEnvironmentSourceBridge(fixture.bridge)
	t.Cleanup(func() {
		RegisterPluginEnvironmentSourceBridge(previousBridge)
	})

	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(current *authnCandidateExecution) {
			fixture.execution = current
		},
	}
	fixture.acceptor = newAuthnCandidateTestSupervisor(t, nil)

	installAuthnCandidateServices(t, failingPasswordVerifier{}, testLuaSubject{}, recordingPlanPostAction{})

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
		fixture.bridge,
		fixture.execution,
		wantEnvironment,
		wantBruteForce,
	)
}

// assertAuthnCandidateCompiledProviderResult verifies exact selected host-provider execution.
func assertAuthnCandidateCompiledProviderResult(
	t *testing.T,
	result authnMappedTestResult,
	bridge *recordingAuthnCandidateEnvironmentBridge,
	execution *authnCandidateExecution,
	wantEnvironment int32,
	wantBruteForce bool,
) {
	t.Helper()

	if result.decision != AuthDecisionFail {
		t.Fatalf("candidate decision = %q, want fail", result.decision)
	}

	if got := bridge.calls.Load(); got != wantEnvironment {
		t.Fatalf("environment provider calls = %d, want %d", got, wantEnvironment)
	}

	if execution == nil {
		t.Fatal("candidate provider execution was not captured")
	}

	if execution.bruteForceRun != wantBruteForce || execution.environmentRun != (wantEnvironment > 0) {
		t.Fatalf(
			"provider execution brute_force=%t environment=%t, want %t/%t",
			execution.bruteForceRun,
			execution.environmentRun,
			wantBruteForce,
			wantEnvironment > 0,
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
	base := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	}).(*authApplicationService)
	host := newAuthnConfiguredCheckpointHost(base)
	acceptor, supervisor, postAction, acceptance := authnCandidateConfiguredCheckpointAcceptor(
		t,
		operation.operation,
		checkpoint,
	)

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

	if supervisor != nil {
		waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		if err = supervisor.WaitIdle(waitCtx); err != nil {
			t.Fatalf("configured checkpoint post-action wait: %v", err)
		}

		if postAction.preparations.Load() != 1 || acceptance.calls.Load() != 1 {
			t.Fatalf(
				"configured pre-auth post prepare/accept = %d/%d, want 1/1",
				postAction.preparations.Load(),
				acceptance.calls.Load(),
			)
		}
	}

	assertAuthnCandidateConfiguredTraversal(t, result, recorder, host, operation, checkpoint)
}

// authnCandidateConfiguredCheckpointAcceptor instruments terminal configured pre-auth post-actions.
func authnCandidateConfiguredCheckpointAcceptor(
	t *testing.T,
	operation policy.Operation,
	checkpoint policy.Stage,
) (effectsupervisor.Acceptor, *effectsupervisor.Supervisor, *authnCandidateCountingPlanPostAction, *authnCandidateCountingAcceptor) {
	t.Helper()

	if checkpoint != policy.StagePreAuth || operation == policy.OperationListAccounts {
		return &authnCandidateAcceptAll{}, nil, nil, nil
	}

	supervisor := newAuthnCandidateTestSupervisor(t, nil)
	acceptance := &authnCandidateCountingAcceptor{delegate: supervisor}
	postAction := &authnCandidateCountingPlanPostAction{}
	installAuthnCandidateServices(t, failingPasswordVerifier{}, testLuaSubject{}, postAction)

	return acceptance, supervisor, postAction, acceptance
}

// newAuthnConfiguredCheckpointHost returns deterministic current-pipeline state for every operation.
func newAuthnConfiguredCheckpointHost(base *authApplicationService) *authnCandidateInjectedHost {
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

func TestAuthnCandidateLuaNativeFactAndEffectParity(t *testing.T) {
	fixture := newAuthnCandidateLuaNativeFixture(t)
	outcome := authenticateAuthnCandidate(
		t,
		"Lua/native authority and effect order",
		fixture.adapter,
		authnApplicationTestInput(AuthModeAuthenticate),
	)

	if outcome.Decision != AuthDecisionOK {
		t.Fatalf("candidate decision = %q, want ok", outcome.Decision)
	}

	wantOrder := []string{
		"lua:" + policy.ObligationLuaActionDispatch,
		"native:" + authnCandidateNativeEffectID,
	}
	if got := fixture.log.entries(); !reflect.DeepEqual(got, wantOrder) {
		t.Fatalf("Lua/native effect order = %v, want %v", got, wantOrder)
	}

	if err := fixture.bridge.validationError(); err != nil {
		t.Fatalf("Lua/native fact authority: %v", err)
	}

	if fixture.environment.calls.Load() != 1 {
		t.Fatalf("native environment collector calls = %d, want 1", fixture.environment.calls.Load())
	}

	if fixture.host.calls.Load() != 0 {
		t.Fatalf("legacy aggregate calls = %d, want 0", fixture.host.calls.Load())
	}
}

func TestAuthnCandidateNativeTerminalPreAuthParity(t *testing.T) {
	operations := authnApplicationOperationCases()[:2]
	outcomes := []authnCandidateNativeTerminalCase{
		{
			name: "trigger", triggered: true, wantDecision: AuthDecisionFail,
			wantRuleSuffix: "trigger", wantFSM: policy.FSMEventMarkerPreAuthDeny,
			wantPostActions: 1, wantStatus: "native environment denied",
		},
		{
			name: "error", err: errors.New("native environment unavailable"),
			wantDecision: AuthDecisionTempFail, wantRuleSuffix: "error",
			wantFSM: policy.FSMEventMarkerPreAuthTempFail, wantStatus: definitions.TempFailDefault,
		},
	}

	for _, operation := range operations {
		for _, outcome := range outcomes {
			t.Run(operation.name+"/"+outcome.name, func(t *testing.T) {
				assertAuthnCandidateNativeTerminalResult(t, operation, outcome)
			})
		}
	}
}

type authnCandidateNativeTerminalCase struct {
	name            string
	triggered       bool
	err             error
	wantDecision    AuthDecision
	wantRuleSuffix  string
	wantFSM         string
	wantPostActions int32
	wantStatus      string
}

// assertAuthnCandidateNativeTerminalResult verifies one operation and native terminal cause.
func assertAuthnCandidateNativeTerminalResult(
	t *testing.T,
	operation authnApplicationOperationCase,
	outcome authnCandidateNativeTerminalCase,
) {
	t.Helper()

	fixture := newAuthnCandidateNativeTerminalFixture(t, operation, outcome.triggered, outcome.err)
	result := runAuthnCandidateAuthOperation(t, fixture.adapter, operation)

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := fixture.supervisor.WaitIdle(waitCtx); err != nil {
		t.Fatalf("native terminal post-action wait: %v", err)
	}

	assertAuthnCandidateNativeTerminalPresentation(t, result, outcome)
	assertAuthnCandidateNativeTerminalAuthority(t, fixture, operation, outcome)
}

// assertAuthnCandidateNativeTerminalPresentation verifies the public result and FSM markers.
func assertAuthnCandidateNativeTerminalPresentation(
	t *testing.T,
	result *AuthOutcome,
	outcome authnCandidateNativeTerminalCase,
) {
	t.Helper()

	if result.Decision != outcome.wantDecision || result.StatusMessage != outcome.wantStatus {
		t.Fatalf(
			"native terminal result = %q/%q, want %q/%q",
			result.Decision, result.StatusMessage, outcome.wantDecision, outcome.wantStatus,
		)
	}

	wantFSM := []string{policy.FSMEventMarkerParseOK, outcome.wantFSM}
	if !reflect.DeepEqual(result.FSMEventPath, wantFSM) {
		t.Fatalf("native terminal FSM = %v, want %v", result.FSMEventPath, wantFSM)
	}
}

// assertAuthnCandidateNativeTerminalAuthority verifies selected rule and host effect ownership.
func assertAuthnCandidateNativeTerminalAuthority(
	t *testing.T,
	fixture *authnCandidateNativeTerminalFixture,
	operation authnApplicationOperationCase,
	outcome authnCandidateNativeTerminalCase,
) {
	t.Helper()

	checkpoint := string(policy.StagePreAuth)
	if operation.operation == policy.OperationAuthenticate {
		checkpoint = string(policy.StageAuthDecision)
	}

	selected := fixture.execution.selectedDecision(checkpoint)

	wantRule := "standard_plugin_environment_candidate_verdict_" + outcome.wantRuleSuffix
	if selected == nil || selected.PolicyName != wantRule || selected.Stage != policy.StagePreAuth {
		t.Fatalf("native terminal selection = %#v, want %s at pre-auth", selected, wantRule)
	}

	if fixture.postAction.preparations.Load() != outcome.wantPostActions ||
		fixture.acceptor.calls.Load() != outcome.wantPostActions {
		t.Fatalf(
			"native terminal post prepare/accept = %d/%d, want %d/%d",
			fixture.postAction.preparations.Load(), fixture.acceptor.calls.Load(),
			outcome.wantPostActions, outcome.wantPostActions,
		)
	}

	if fixture.verifierCalls.Load() != 0 || fixture.host.calls.Load() != 0 {
		t.Fatalf(
			"native terminal backend/legacy calls = %d/%d, want 0/0",
			fixture.verifierCalls.Load(), fixture.host.calls.Load(),
		)
	}
}

func TestAuthnCandidateNativeEnvironmentPreservesDependencyOrderAndFinalStatus(t *testing.T) {
	operation := authnApplicationOperationCases()[0]
	bridge := &authnCandidateNativeEnvironmentBridge{sources: []authnCandidateNativeEnvironmentOutcome{
		{name: "alpha", triggered: true, status: "alpha denied"},
		{name: "zeta", triggered: true, status: "zeta denied"},
	}}
	fixture := newAuthnCandidateNativeFixture(
		t,
		operation,
		bridge,
		authnCandidateCompilerEnvironmentSource{name: "zeta", after: []string{"alpha"}},
		authnCandidateCompilerEnvironmentSource{name: "alpha"},
	)
	result := runAuthnCandidateAuthOperation(t, fixture.adapter, operation)

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := fixture.supervisor.WaitIdle(waitCtx); err != nil {
		t.Fatalf("native ordered post-action wait: %v", err)
	}

	if result.Decision != AuthDecisionFail || result.StatusMessage != "zeta denied" {
		t.Fatalf(
			"native ordered result = %q/%q, want fail/zeta denied",
			result.Decision,
			result.StatusMessage,
		)
	}

	selected := fixture.execution.selectedDecision(string(policy.StageAuthDecision))
	if selected == nil || selected.PolicyName != "standard_plugin_environment_candidate_zeta_trigger" {
		t.Fatalf("native ordered selection = %#v, want final dependency source", selected)
	}

	if fixture.postAction.preparations.Load() != 1 || fixture.acceptor.calls.Load() != 1 {
		t.Fatalf(
			"native ordered post prepare/accept = %d/%d, want 1/1",
			fixture.postAction.preparations.Load(),
			fixture.acceptor.calls.Load(),
		)
	}
}

func TestAuthnCandidateNativeSubjectPreservesDependencyOrderAndFinalStatus(t *testing.T) {
	bridge := &authnCandidateNativeSubjectBridge{sources: []authnCandidateNativeSubjectOutcome{
		{name: "alpha", rejected: true, status: "alpha subject denied"},
		{name: "zeta", rejected: true, status: "zeta subject denied"},
	}}
	fixture := newAuthnCandidateNativeSubjectFixture(
		t,
		bridge,
		authnCandidateCompilerSubjectSource{name: "zeta", after: []string{"alpha"}},
		authnCandidateCompilerSubjectSource{name: "alpha"},
	)
	operation := authnApplicationOperationCases()[0]
	result := runAuthnCandidateAuthOperation(t, fixture.adapter, operation)

	if result.Decision != AuthDecisionFail || result.StatusMessage != "zeta subject denied" {
		t.Fatalf(
			"native ordered subject result = %q/%q, want fail/zeta subject denied",
			result.Decision,
			result.StatusMessage,
		)
	}

	selected := fixture.execution.selectedDecision(string(policy.StageAuthDecision))
	if selected == nil || selected.PolicyName != "standard_plugin_subject_candidate_zeta_reject" {
		t.Fatalf("native ordered subject selection = %#v, want final dependency source", selected)
	}

	if fixture.verifierCalls.Load() != 1 || fixture.host.calls.Load() != 0 {
		t.Fatalf(
			"native ordered subject backend/legacy calls = %d/%d, want 1/0",
			fixture.verifierCalls.Load(),
			fixture.host.calls.Load(),
		)
	}
}

func TestAuthnCandidateLuaAbortContinuesToBackendResult(t *testing.T) {
	for _, test := range []authnCandidateLuaAbortCase{
		{
			name: "success", verifier: currentBehaviorPasswordVerifier{},
			subject:      testLuaSubject{},
			wantDecision: AuthDecisionOK, wantPolicy: "standard_auth_success",
			wantFSM: policy.FSMEventMarkerAuthPermit,
		},
		{
			name: "failure", verifier: failingPasswordVerifier{}, subject: testLuaSubject{},
			wantDecision: AuthDecisionFail, wantPolicy: "standard_auth_failure",
			wantFSM: policy.FSMEventMarkerAuthDeny,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertAuthnCandidateLuaAbortResult(t, test)
		})
	}
}

type authnCandidateLuaAbortCase struct {
	verifier     PasswordVerifier
	subject      LuaSubject
	name         string
	wantDecision AuthDecision
	wantPolicy   string
	wantFSM      string
}

// assertAuthnCandidateLuaAbortResult verifies nonterminal control and the later backend selection.
func assertAuthnCandidateLuaAbortResult(t *testing.T, test authnCandidateLuaAbortCase) {
	t.Helper()

	fixture := newAuthnCandidateRealLuaFixture(t, `
function nauthilus_call_environment(request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_YES, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`, test.verifier, test.subject)
	outcome := authenticateAuthnCandidate(
		t,
		"Lua abort "+test.name,
		fixture.adapter,
		authnApplicationTestInput(AuthModeAuthenticate),
	)
	fixture.waitPostActions(t)

	if outcome.Decision != test.wantDecision {
		t.Fatalf(
			"Lua abort outcome = %#v, selected = %#v, report = %#v, want decision %q",
			outcome,
			fixture.execution.selectedDecision(string(policy.StageAuthDecision)),
			fixture.execution.auth.policyReport(fixture.execution.ginCtx),
			test.wantDecision,
		)
	}

	selected := fixture.execution.selectedDecision(string(policy.StageAuthDecision))
	if selected == nil || selected.PolicyName != test.wantPolicy {
		t.Fatalf("Lua abort final selection = %#v, want %s", selected, test.wantPolicy)
	}

	assertAuthnCandidateFinalAndPoliciesParity(t, fixture.execution)

	wantFSM := []string{
		policy.FSMEventMarkerParseOK,
		policy.FSMEventMarkerPreAuthOK,
		policy.FSMEventMarkerAuthEvaluated,
		test.wantFSM,
	}
	if !reflect.DeepEqual(outcome.FSMEventPath, wantFSM) {
		t.Fatalf("Lua abort FSM = %v, want %v", outcome.FSMEventPath, wantFSM)
	}

	attribute := fixture.execution.auth.policyReport(fixture.execution.ginCtx).
		Attributes["auth.lua.environment.current_behavior_environment.abort"]
	if attribute.Value != true {
		t.Fatalf("Lua abort fact = %#v, want true", attribute.Value)
	}
}

func TestAuthnCandidateLuaResponseIsSanitizedBeforeSchemaValidation(t *testing.T) {
	fixture := newAuthnCandidateRealLuaFixture(t, `
function nauthilus_call_environment(request)
    nauthilus_builtin.status_message_set("denied\n" .. string.rep("x", 300))
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`, failingPasswordVerifier{}, testLuaSubject{})

	outcome := authenticateAuthnCandidate(
		t,
		"sanitized Lua response",
		fixture.adapter,
		authnApplicationTestInput(AuthModeAuthenticate),
	)
	fixture.waitPostActions(t)

	wantMessage := "denied" + strings.Repeat("x", 250)
	if outcome.Decision != AuthDecisionFail || outcome.StatusMessage != wantMessage {
		t.Fatalf("sanitized Lua result = %q/%q, want fail/%q", outcome.Decision, outcome.StatusMessage, wantMessage)
	}

	if strings.ContainsAny(outcome.StatusMessage, "\r\n\x00") {
		t.Fatalf("sanitized Lua response retains a forbidden control: %q", outcome.StatusMessage)
	}

	selected := fixture.execution.selectedDecision(string(policy.StageAuthDecision))
	if selected == nil || selected.ResponseMessage == nil {
		t.Fatalf("Lua response selection = %#v, want selected response", selected)
	}

	assertAuthnCandidateLuaResponseReportParity(t, fixture.execution)
}

func TestAuthnCandidateLuaControlOnlyResponsePreservesRawSelection(t *testing.T) {
	fixture := newAuthnCandidateRealLuaFixture(t, `
function nauthilus_call_environment(request)
    nauthilus_builtin.status_message_set(string.char(1))
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`, failingPasswordVerifier{}, testLuaSubject{})

	outcome := authenticateAuthnCandidate(
		t,
		"control-only Lua response",
		fixture.adapter,
		authnApplicationTestInput(AuthModeAuthenticate),
	)
	fixture.waitPostActions(t)

	if outcome.Decision != AuthDecisionFail {
		t.Fatalf("control-only Lua decision = %q, want fail", outcome.Decision)
	}

	selected := fixture.execution.selectedDecision(string(policy.StageAuthDecision))
	if selected == nil || selected.ResponseMessage == nil || selected.ResponseMessage.Message != "" ||
		selected.ResponseMessage.FallbackUsed {
		t.Fatalf("control-only Lua response selection = %#v, want selected empty non-fallback", selected)
	}

	assertAuthnCandidateLuaResponseReportParity(t, fixture.execution)
}

// assertAuthnCandidateLuaResponseReportParity compares candidate metadata with the frozen legacy oracle.
func assertAuthnCandidateLuaResponseReportParity(
	t *testing.T,
	execution *authnCandidateExecution,
) {
	t.Helper()

	candidateReport, legacyReport := assertAuthnCandidateFinalAndPoliciesParity(t, execution)

	attributeID := "auth.lua.environment.current_behavior_environment.triggered"
	if !reflect.DeepEqual(candidateReport.Attributes[attributeID], legacyReport.Attributes[attributeID]) {
		t.Fatalf(
			"Lua response attribute report = %#v, want legacy %#v",
			candidateReport.Attributes[attributeID],
			legacyReport.Attributes[attributeID],
		)
	}
}

// assertAuthnCandidateFinalAndPoliciesParity compares catalog report projection with the test-only oracle.
func assertAuthnCandidateFinalAndPoliciesParity(
	t *testing.T,
	execution *authnCandidateExecution,
) (*report.DecisionReport, *report.DecisionReport) {
	t.Helper()

	candidateReport := execution.auth.policyReport(execution.ginCtx)
	legacyReport := cloneAuthnCandidatePolicyInputs(candidateReport)
	legacyFinal := evaluation.EvaluateStandardAuth(legacyReport).Final

	selected := execution.selectedDecision(string(policy.StageAuthDecision))
	if !reflect.DeepEqual(selected, legacyFinal) {
		t.Fatalf("authn final report = %#v, want legacy %#v", selected, legacyFinal)
	}

	if !reflect.DeepEqual(candidateReport.Policies, legacyReport.Policies) {
		t.Fatalf("authn policy reports = %#v, want legacy %#v", candidateReport.Policies, legacyReport.Policies)
	}

	return candidateReport, legacyReport
}

// cloneAuthnCandidatePolicyInputs detaches collected facts for the frozen legacy report oracle.
func cloneAuthnCandidatePolicyInputs(source *report.DecisionReport) *report.DecisionReport {
	cloned := report.NewDecisionReport()
	if source == nil {
		return cloned
	}

	cloned.SessionID = source.SessionID
	cloned.Operation = source.Operation
	cloned.Stage = source.Stage

	for id, attribute := range source.Attributes {
		attribute.Details = cloneAuthnCandidateDetails(attribute.Details)
		cloned.Attributes[id] = attribute
	}

	for id, check := range source.Checks {
		check.Attributes = append([]string(nil), check.Attributes...)
		cloned.Checks[id] = check
	}

	for id, reason := range source.MissingChecks {
		cloned.MissingChecks[id] = reason
	}

	for id, unavailable := range source.Unavailable {
		cloned.Unavailable[id] = unavailable
	}

	return cloned
}

// cloneAuthnCandidateDetails detaches mutable response-detail selection metadata.
func cloneAuthnCandidateDetails(source map[string]report.DetailValue) map[string]report.DetailValue {
	if source == nil {
		return nil
	}

	cloned := make(map[string]report.DetailValue, len(source))
	for id, detail := range source {
		detail.Selected = false
		cloned[id] = detail
	}

	return cloned
}

type authnCandidateRealLuaFixture struct {
	adapter    AuthApplicationService
	execution  *authnCandidateExecution
	supervisor *effectsupervisor.Supervisor
}

// waitPostActions waits until accepted Lua post-actions release their generation lease.
func (f *authnCandidateRealLuaFixture) waitPostActions(t *testing.T) {
	t.Helper()

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := f.supervisor.WaitIdle(waitCtx); err != nil {
		t.Fatalf("Lua post-action wait: %v", err)
	}
}

// newAuthnCandidateRealLuaFixture runs the actual environment collector under catalog authority.
func newAuthnCandidateRealLuaFixture(
	t *testing.T,
	script string,
	verifier PasswordVerifier,
	subject LuaSubject,
) *authnCandidateRealLuaFixture {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t, definitions.ControlLua)
	cfg.Server.Redis.AccountLocalCache.Enabled = true
	cfg.Server.Backends = []*config.Backend{mustPolicyBackendForTest(t, definitions.BackendTest)}
	scriptPath := withCurrentBehaviorLuaEnvironment(t, script)
	cfg.Lua = &config.LuaSection{EnvironmentSources: []config.LuaEnvironmentSource{{
		Name: "current_behavior_environment", ScriptPath: scriptPath,
	}}}
	snapshot := compileAuthnCandidateLegacySnapshot(t, cfg)
	supervisor := newAuthnCandidateTestSupervisor(t, nil)
	catalog := compileAuthnCandidateCatalogWithSnapshot(t, supervisor, snapshot)
	runtime := newAuthnCandidateDecisionServiceFromCatalogAndSnapshot(t, cfg, supervisor, catalog, snapshot)

	base := newAuthnCandidateRealCollectorBase(t, cfg)

	fixture := &authnCandidateRealLuaFixture{supervisor: supervisor}
	host := &authnCandidateInjectedHost{
		base: base,
		configure: func(current *authnCandidateExecution) {
			fixture.execution = current
			current.executeEffect = func(report.EffectRequest) effectsupervisor.Result {
				return effectsupervisor.Succeeded()
			}
		},
	}

	installAuthnCandidateServices(t, verifier, subject, recordingPlanPostAction{})

	adapter, err := NewAuthnCandidateApplicationService(host, runtime, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	fixture.adapter = adapter

	return fixture
}

type authnCandidateLuaNativeFixture struct {
	adapter     AuthApplicationService
	host        *authnCandidateInjectedHost
	bridge      *authnCandidateFactAwarePluginBridge
	environment *authnCandidateNativeEnvironmentBridge
	log         *authnCandidateEffectLog
}

type authnCandidateNativeTerminalFixture struct {
	adapter       AuthApplicationService
	host          *authnCandidateInjectedHost
	execution     *authnCandidateExecution
	acceptor      *authnCandidateCountingAcceptor
	postAction    *authnCandidateCountingPlanPostAction
	supervisor    *effectsupervisor.Supervisor
	verifierCalls *atomic.Int32
}

// newAuthnCandidateNativeTerminalFixture runs the real native collector under builtin catalog authority.
func newAuthnCandidateNativeTerminalFixture(
	t *testing.T,
	operation authnApplicationOperationCase,
	triggered bool,
	nativeErr error,
) *authnCandidateNativeTerminalFixture {
	t.Helper()

	bridge := &authnCandidateNativeEnvironmentBridge{
		triggered: triggered,
		err:       nativeErr,
		status:    "native environment denied",
	}

	return newAuthnCandidateNativeFixture(
		t,
		operation,
		bridge,
		authnCandidateCompilerEnvironmentSource{name: "verdict"},
	)
}

// newAuthnCandidateNativeFixture installs captured native sources and their request-local bridge.
func newAuthnCandidateNativeFixture(
	t *testing.T,
	operation authnApplicationOperationCase,
	bridge PluginEnvironmentSourceBridge,
	sources ...pluginapi.EnvironmentSource,
) *authnCandidateNativeTerminalFixture {
	t.Helper()

	cfg := newAuthnCandidateNativeConfig(t)
	publishAuthnCandidateNativeCompilerState(t, sources...)

	snapshot := compileAuthnCandidateLegacySnapshot(t, cfg)
	fixture := newAuthnCandidateNativeCapturedFixture(t, cfg, snapshot)
	previousBridge := getPluginEnvironmentSourceBridge()

	RegisterPluginEnvironmentSourceBridge(bridge)
	t.Cleanup(func() {
		RegisterPluginEnvironmentSourceBridge(previousBridge)
	})

	if operation.operation == policy.OperationListAccounts {
		t.Fatal("native terminal fixture does not support list accounts")
	}

	return fixture
}

// newAuthnCandidateNativeSubjectFixture installs captured native subject sources and their bridge.
func newAuthnCandidateNativeSubjectFixture(
	t *testing.T,
	bridge PluginSubjectSourceBridge,
	sources ...pluginapi.SubjectSource,
) *authnCandidateNativeTerminalFixture {
	t.Helper()

	cfg := newAuthnCandidateNativeConfig(t)
	publishAuthnCandidateSubjectCompilerState(t, sources...)
	snapshot := compileAuthnCandidateLegacySnapshot(t, cfg)
	fixture := newAuthnCandidateNativeCapturedFixture(t, cfg, snapshot)
	previousBridge := getPluginSubjectSourceBridge()

	RegisterPluginSubjectSourceBridge(bridge)
	t.Cleanup(func() {
		RegisterPluginSubjectSourceBridge(previousBridge)
	})

	return fixture
}

// newAuthnCandidateNativeConfig returns one neutral Lua environment around native source tests.
func newAuthnCandidateNativeConfig(t *testing.T) *config.FileSettings {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t, definitions.ControlLua)
	cfg.Server.Redis.AccountLocalCache.Enabled = true
	cfg.Server.Backends = []*config.Backend{mustPolicyBackendForTest(t, definitions.BackendTest)}
	scriptPath := withCurrentBehaviorLuaEnvironment(t, `
function nauthilus_call_environment(request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)
	cfg.Lua = &config.LuaSection{EnvironmentSources: []config.LuaEnvironmentSource{{
		Name: "current_behavior_environment", ScriptPath: scriptPath,
	}}}

	return cfg
}

// newAuthnCandidateNativeCapturedFixture binds one compiler snapshot to the public auth adapter.
func newAuthnCandidateNativeCapturedFixture(
	t *testing.T,
	cfg config.File,
	snapshot *policyruntime.Snapshot,
) *authnCandidateNativeTerminalFixture {
	t.Helper()

	supervisor := newAuthnCandidateTestSupervisor(t, nil)
	acceptor := &authnCandidateCountingAcceptor{delegate: supervisor}
	catalog := compileAuthnCandidateCatalogWithSnapshot(t, acceptor, snapshot)
	runtime := newAuthnCandidateDecisionServiceFromCatalogAndSnapshot(t, cfg, acceptor, catalog, snapshot)
	fixture := &authnCandidateNativeTerminalFixture{
		acceptor: acceptor, postAction: &authnCandidateCountingPlanPostAction{},
		supervisor: supervisor, verifierCalls: &atomic.Int32{},
	}
	fixture.host = &authnCandidateInjectedHost{
		base: newAuthnCandidateRealCollectorBase(t, cfg),
		configure: func(execution *authnCandidateExecution) {
			fixture.execution = execution
		},
	}

	adapter, err := NewAuthnCandidateApplicationService(
		fixture.host,
		runtime,
		mustAuthnCandidateAuthentication(t),
	)
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	fixture.adapter = adapter

	installAuthnCandidateServices(
		t,
		backendAuthenticationContractVerifier{calls: fixture.verifierCalls},
		backendAuthenticationContractSubject{calls: &atomic.Int32{}},
		fixture.postAction,
	)

	return fixture
}

// compileAuthnCandidateLegacySnapshot captures the real legacy compiler view used by the catalog.
func compileAuthnCandidateLegacySnapshot(t *testing.T, cfg config.File) *policyruntime.Snapshot {
	t.Helper()

	snapshot, err := compiler.NewCompiler().Compile(context.Background(), compiler.Input{
		Config: cfg, Generation: 701,
	})
	if err != nil {
		t.Fatalf("legacy policy snapshot Compile() error = %v", err)
	}

	return snapshot
}

// publishAuthnCandidateNativeCompilerState exposes the registered source to snapshot compilation.
func publishAuthnCandidateNativeCompilerState(t *testing.T, sources ...pluginapi.EnvironmentSource) {
	t.Helper()
	publishAuthnCandidateCompilerState(t, sources, nil)
}

// publishAuthnCandidateSubjectCompilerState exposes registered subject sources to snapshot compilation.
func publishAuthnCandidateSubjectCompilerState(t *testing.T, sources ...pluginapi.SubjectSource) {
	t.Helper()
	publishAuthnCandidateCompilerState(t, nil, sources)
}

// publishAuthnCandidateCompilerState owns the shared plugin registration and restoration lifecycle.
func publishAuthnCandidateCompilerState(
	t *testing.T,
	environmentSources []pluginapi.EnvironmentSource,
	subjectSources []pluginapi.SubjectSource,
) {
	t.Helper()

	state, err := pluginloader.NewLoader().Load(nil)
	if err != nil {
		t.Fatalf("empty plugin state Load() error = %v", err)
	}

	registrar := state.Registry().NewRegistrar(config.PluginModule{
		Name: "candidate", Type: config.PluginModuleTypeGo,
	})
	for _, source := range environmentSources {
		if err = registrar.RegisterEnvironmentSource(source); err != nil {
			t.Fatalf("RegisterEnvironmentSource() error = %v", err)
		}
	}

	for _, source := range subjectSources {
		if err = registrar.RegisterSubjectSource(source); err != nil {
			t.Fatalf("RegisterSubjectSource() error = %v", err)
		}
	}

	if err = registrar.Commit(); err != nil {
		t.Fatalf("plugin registrar Commit() error = %v", err)
	}

	previous, hadPrevious := pluginloader.DefaultState()

	pluginloader.SetDefaultState(state)
	t.Cleanup(func() {
		if hadPrevious {
			pluginloader.SetDefaultState(previous)

			return
		}

		pluginloader.SetDefaultState((*pluginloader.State)(nil))
	})
}

type authnCandidateCompilerEnvironmentSource struct {
	name  string
	after []string
}

type authnCandidateCompilerSubjectSource struct {
	name  string
	after []string
}

// Descriptor identifies the source compiled into the captured default snapshot.
func (s authnCandidateCompilerEnvironmentSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{Name: s.name, After: append([]string(nil), s.after...)}
}

// Evaluate is not called because the core collector bridge owns this public-flow fixture.
func (authnCandidateCompilerEnvironmentSource) Evaluate(
	context.Context,
	pluginapi.EnvironmentRequest,
) (pluginapi.EnvironmentResult, error) {
	return pluginapi.EnvironmentResult{}, nil
}

// Descriptor identifies one subject source compiled into the captured default snapshot.
func (s authnCandidateCompilerSubjectSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{Name: s.name, After: append([]string(nil), s.after...)}
}

// Evaluate is not called because the core collector bridge owns this public-flow fixture.
func (authnCandidateCompilerSubjectSource) Evaluate(
	context.Context,
	pluginapi.SubjectRequest,
) (pluginapi.SubjectResult, error) {
	return pluginapi.SubjectResult{}, nil
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

// newAuthnCandidateLuaNativeFixture assembles actual candidate Lua and native seams.
func newAuthnCandidateLuaNativeFixture(t *testing.T) authnCandidateLuaNativeFixture {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t, definitions.ControlLua)
	cfg.Server.Redis.AccountLocalCache.Enabled = true
	cfg.Server.Backends = []*config.Backend{mustPolicyBackendForTest(t, definitions.BackendTest)}
	cfg.Lua = &config.LuaSection{Actions: []config.LuaAction{{
		ActionType: policy.LuaActionDispatchTLS,
		ScriptName: "candidate_tls_action",
		ScriptPath: "/tmp/candidate-tls-action.lua",
	}}}
	snapshot := newAuthnCandidateLuaNativeSnapshot(t)
	log := &authnCandidateEffectLog{}
	dispatcher := &authnCandidateOrderedActionDispatcher{log: log}
	bridge := &authnCandidateFactAwarePluginBridge{log: log}
	environmentBridge := &authnCandidateNativeEnvironmentBridge{}

	withCurrentBehaviorLuaEnvironment(t, `
function nauthilus_call_environment(request)
    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
`)

	installAuthnCandidateLuaNativeSeams(t, dispatcher, bridge, environmentBridge)

	host := newAuthnCandidateLuaNativeHost(t, cfg)
	acceptor := &authnCandidateAcceptAll{}
	catalog := compileAuthnCandidateLuaNativeCatalog(t, acceptor, snapshot)
	runtime := newAuthnCandidateDecisionServiceWithBindings(
		t,
		cfg,
		acceptor,
		catalog,
		snapshot,
		map[string]policyruntime.SyncEffectProvider{
			authnCandidateNativeProviderID: authnCandidateNativeSyncEffectProvider{},
		},
	)

	adapter, err := NewAuthnCandidateApplicationService(host, runtime, mustAuthnCandidateAuthentication(t))
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	verifierCalls := &atomic.Int32{}
	subjectCalls := &atomic.Int32{}
	installAuthnCandidateServices(
		t,
		backendAuthenticationContractVerifier{calls: verifierCalls},
		backendAuthenticationContractSubject{calls: subjectCalls},
		recordingPlanPostAction{},
	)

	return authnCandidateLuaNativeFixture{
		adapter: adapter, host: host, bridge: bridge, environment: environmentBridge, log: log,
	}
}

// installAuthnCandidateLuaNativeSeams restores global extension seams after the fixture.
func installAuthnCandidateLuaNativeSeams(
	t *testing.T,
	dispatcher ActionDispatcher,
	bridge PluginEffectBridge,
	environmentBridge PluginEnvironmentSourceBridge,
) {
	t.Helper()

	previousDispatcher := getActionDispatcher()
	previousBridge := getPluginEffectBridge()
	previousEnvironmentBridge := getPluginEnvironmentSourceBridge()

	RegisterActionDispatcher(dispatcher)
	RegisterPluginEffectBridge(bridge)
	RegisterPluginEnvironmentSourceBridge(environmentBridge)
	t.Cleanup(func() {
		RegisterActionDispatcher(previousDispatcher)
		RegisterPluginEffectBridge(previousBridge)
		RegisterPluginEnvironmentSourceBridge(previousEnvironmentBridge)
	})
}

// newAuthnCandidateLuaNativeHost leaves fact collection to the real environment provider seams.
func newAuthnCandidateLuaNativeHost(
	t *testing.T,
	cfg config.File,
) *authnCandidateInjectedHost {
	t.Helper()

	return &authnCandidateInjectedHost{base: newAuthnCandidateRealCollectorBase(t, cfg)}
}

// newAuthnCandidateRealCollectorBase isolates account and positive-auth caches for real collector tests.
func newAuthnCandidateRealCollectorBase(
	t *testing.T,
	cfg config.File,
) *authApplicationService {
	t.Helper()

	db, _ := redismock.NewClientMock()
	manager := accountcache.NewManager(cfg)
	manager.Set(cfg, "alice@example.test", definitions.ProtoIMAP, "oidc-client", "alice@example.test")

	backendCache := NewPositiveBackendAuthenticationCache(time.Now)
	t.Cleanup(backendCache.Close)

	return NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: manager,
		BackendAuthenticationCache: backendCache,
	}).(*authApplicationService)
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

	if verifierCalls.Load() != 1 || subjectCalls.Load() != 1 {
		t.Fatalf("configured backend/subject calls = %d/%d, want 1/1", verifierCalls.Load(), subjectCalls.Load())
	}
}

func TestAuthnCandidateCacheColdWarmParityKeepsRequestLocalStandardAuthority(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	cfg.Server.Redis.AccountLocalCache.Enabled = true

	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation: 701, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet,
	})

	username := "candidate-cache@example.test"
	fixture := newAuthnCandidateCacheFixture(t, cfg, username)

	input := NewAuthInputFromStructuredRequest(definitions.ServGRPC, AuthModeAuthenticate, authdto.Request{
		Username: username, Password: "candidate-secret", ClientIP: "203.0.113.71",
		Protocol: definitions.ProtoIMAP, Method: "plain",
	})
	cold := authenticateAuthnCandidate(t, "cold", fixture.adapter, input)

	fixture.subject.rejected.Store(true)

	warm := authenticateAuthnCandidate(t, "warm", fixture.adapter, input)

	assertAuthnCandidateCacheExecutionParity(t, fixture, cold, warm)
	assertAuthnCandidateColdCacheOutcome(t, cold)
	assertAuthnCandidateWarmCacheOutcome(t, warm, fixture.execution)

	if err := fixture.mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unexpected Redis cache ownership call: %v", err)
	}
}

type authnCandidateCacheFixture struct {
	adapter       AuthApplicationService
	mock          redismock.ClientMock
	verifierCalls *atomic.Int32
	subject       *authnCandidateCacheSubject
	execution     *authnCandidateExecution
}

// newAuthnCandidateCacheFixture assembles auth-specific cache owners without a decision cache.
func newAuthnCandidateCacheFixture(
	t *testing.T,
	cfg config.File,
	username string,
) *authnCandidateCacheFixture {
	t.Helper()

	manager := accountcache.NewManager(cfg)
	manager.Set(cfg, username, definitions.ProtoIMAP, "", username)

	db, mock := redismock.NewClientMock()
	current := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: manager,
		BackendAuthenticationCache: NewPositiveBackendAuthenticationCache(time.Now),
	}).(*authApplicationService)
	fixture := &authnCandidateCacheFixture{
		mock: mock, verifierCalls: &atomic.Int32{}, subject: &authnCandidateCacheSubject{},
	}

	host := &authnCandidateInjectedHost{
		base: current,
		configure: func(execution *authnCandidateExecution) {
			fixture.execution = execution
		},
	}
	acceptor := &authnCandidateAcceptAll{}
	snapshot := newAuthnCandidateScriptSnapshot(t, policycollection.ScriptKindSubject, "candidate_cache")
	catalog := compileAuthnCandidateCatalogWithSnapshot(t, acceptor, snapshot)
	decisionRuntime := newAuthnCandidateDecisionServiceFromCatalogAndSnapshot(
		t,
		cfg,
		acceptor,
		catalog,
		snapshot,
	)

	adapter, err := NewAuthnCandidateApplicationService(
		host,
		decisionRuntime,
		mustAuthnCandidateAuthentication(t),
	)
	if err != nil {
		t.Fatalf("NewAuthnCandidateApplicationService() error = %v", err)
	}

	fixture.adapter = adapter
	installAuthnCandidateServices(
		t,
		backendAuthenticationContractVerifier{calls: fixture.verifierCalls},
		fixture.subject,
		recordingPlanPostAction{},
	)

	return fixture
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

// assertAuthnCandidateCacheExecutionParity verifies backend ownership across cold and warm requests.
func assertAuthnCandidateCacheExecutionParity(
	t *testing.T,
	fixture *authnCandidateCacheFixture,
	cold *AuthOutcome,
	warm *AuthOutcome,
) {
	t.Helper()

	if fixture.verifierCalls.Load() != 1 || fixture.subject.calls.Load() != 2 {
		t.Fatalf(
			"backend/subject calls = %d/%d, want 1/2",
			fixture.verifierCalls.Load(), fixture.subject.calls.Load(),
		)
	}

	if cold.Backend != definitions.BackendLDAP || warm.Backend != definitions.BackendLDAP ||
		cold.AccountField != "uid" || warm.AccountField != "uid" {
		t.Fatalf(
			"cold/warm backend affinity = %s/%s fields=%q/%q, want LDAP/LDAP uid/uid",
			cold.Backend, warm.Backend, cold.AccountField, warm.AccountField,
		)
	}
}

// assertAuthnCandidateColdCacheOutcome verifies successful cold-path response and localization.
func assertAuthnCandidateColdCacheOutcome(t *testing.T, cold *AuthOutcome) {
	t.Helper()

	if cold.Decision != AuthDecisionOK || cold.TerminalState != string(authFSMStateAuthOK) {
		t.Fatalf("cold decision/state = %q/%q, want ok/auth_ok", cold.Decision, cold.TerminalState)
	}

	if cold.StatusMessageI18NKey != "auth.success" || cold.ResponseLanguage != "de" {
		t.Fatalf("cold localization = %q/%q, want auth.success/de", cold.StatusMessageI18NKey, cold.ResponseLanguage)
	}
}

// assertAuthnCandidateWarmCacheOutcome verifies request-local denial and delayed-response markers.
func assertAuthnCandidateWarmCacheOutcome(
	t *testing.T,
	warm *AuthOutcome,
	execution *authnCandidateExecution,
) {
	t.Helper()

	if warm.Decision != AuthDecisionFail || warm.TerminalState != string(authFSMStateAuthFail) {
		t.Fatalf("warm decision/state = %q/%q, want fail/auth_fail", warm.Decision, warm.TerminalState)
	}

	if warm.StatusMessage != "warm subject rejected" {
		t.Fatalf("warm localized status = %q, want request-local subject rejection", warm.StatusMessage)
	}

	wantFSM := []string{
		policy.FSMEventMarkerParseOK,
		policy.FSMEventMarkerPreAuthOK,
		policy.FSMEventMarkerAuthEvaluated,
		policy.FSMEventMarkerAuthDeny,
	}
	if !reflect.DeepEqual(warm.FSMEventPath, wantFSM) {
		t.Fatalf("warm FSM path = %v, want %v", warm.FSMEventPath, wantFSM)
	}

	selected := execution.selectedDecision(string(policy.StageAuthDecision))
	if selected == nil || selected.OutcomeMarker == policy.OutcomeMarkerAuthFailure ||
		configuredPolicyAllowsIDPDelayedResponse(selected) {
		t.Fatalf("warm delayed-response selection = %#v, want subject-specific failure to remain ineligible", selected)
	}
}

func TestAuthnCandidateOrdinaryPasswordFailurePreservesDelayedResponseEligibility(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation: 706, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet,
	})

	var capturedExecution *authnCandidateExecution

	db, mock := redismock.NewClientMock()

	base := NewAuthApplicationService(AuthDeps{
		Cfg: cfg, Env: config.NewTestEnvironmentConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Redis:  rediscli.NewTestClient(db), AccountCache: accountcache.NewManager(cfg),
	}).(*authApplicationService)

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

	installAuthnCandidateServices(t, failingPasswordVerifier{}, testLuaSubject{}, recordingPlanPostAction{})

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

	activatePolicySnapshotForTest(t, &policyruntime.Snapshot{
		Generation: 705, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet,
	})

	manager := accountcache.NewManager(cfg)
	manager.Set(cfg, "candidate-auth@example.test", definitions.ProtoIMAP, "", "candidate-auth@example.test")
	manager.Set(cfg, "candidate-lookup@example.test", definitions.ProtoIMAP, "", "candidate-lookup@example.test")

	db, mock := redismock.NewClientMock()
	current := NewAuthApplicationService(AuthDeps{
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
		recordingPlanPostAction{},
	)

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

	if verifierCalls.Load() != 2 || subjectCalls.Load() != 2 {
		t.Fatalf("backend/subject calls = %d/%d, want 2/2", verifierCalls.Load(), subjectCalls.Load())
	}
}

// newAuthnCandidateDecisionService assembles the same generation-owned runtime used by generic evaluation.
func newAuthnCandidateDecisionService(
	t *testing.T,
	cfg config.File,
	acceptor effectsupervisor.Acceptor,
) *decisionservice.DecisionService {
	t.Helper()

	snapshot := authnCandidateSnapshotWithBuiltins(t, &policyruntime.Snapshot{
		Generation: 701, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet,
	})
	catalog := compileAuthnCandidateCatalogWithSnapshot(t, acceptor, snapshot)

	return newAuthnCandidateDecisionServiceFromCatalogAndSnapshot(t, cfg, acceptor, catalog, snapshot)
}

// newAuthnCandidateDecisionServiceWithSnapshot assembles one exact captured legacy-view projection.
func newAuthnCandidateDecisionServiceWithSnapshot(
	t *testing.T,
	cfg config.File,
	acceptor effectsupervisor.Acceptor,
	snapshot *policyruntime.Snapshot,
) *decisionservice.DecisionService {
	t.Helper()

	snapshot = authnCandidateSnapshotWithBuiltins(t, snapshot)
	catalog := compileAuthnCandidateCatalogWithSnapshot(t, acceptor, snapshot)

	return newAuthnCandidateDecisionServiceFromCatalogAndSnapshot(t, cfg, acceptor, catalog, snapshot)
}

// newAuthnCandidateDecisionServiceFromCatalog assembles one test generation around an exact catalog.
func newAuthnCandidateDecisionServiceFromCatalog(
	t *testing.T,
	cfg config.File,
	acceptor effectsupervisor.Acceptor,
	catalog *policyruntime.TargetCatalog,
) *decisionservice.DecisionService {
	t.Helper()

	return newAuthnCandidateDecisionServiceFromCatalogAndSnapshot(
		t,
		cfg,
		acceptor,
		catalog,
		&policyruntime.Snapshot{Generation: 701, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet},
	)
}

// newAuthnCandidateDecisionServiceFromCatalogAndSnapshot assembles one exact captured policy view.
func newAuthnCandidateDecisionServiceFromCatalogAndSnapshot(
	t *testing.T,
	cfg config.File,
	acceptor effectsupervisor.Acceptor,
	catalog *policyruntime.TargetCatalog,
	snapshot *policyruntime.Snapshot,
) *decisionservice.DecisionService {
	return newAuthnCandidateDecisionServiceWithBindings(t, cfg, acceptor, catalog, snapshot, nil)
}

// authnCandidateSnapshotWithBuiltins gives the fixture the same captured registry as production compilation.
func authnCandidateSnapshotWithBuiltins(
	t *testing.T,
	snapshot *policyruntime.Snapshot,
) *policyruntime.Snapshot {
	t.Helper()

	captured := snapshot.Clone()
	if captured == nil {
		captured = &policyruntime.Snapshot{}
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

// newAuthnCandidateScriptSnapshot registers one real script collector in the captured generation.
func newAuthnCandidateScriptSnapshot(
	t *testing.T,
	kind policycollection.ScriptKind,
	name string,
) *policyruntime.Snapshot {
	t.Helper()

	snapshot := authnCandidateSnapshotWithBuiltins(t, &policyruntime.Snapshot{
		Generation: 701, Mode: "enforce", DefaultPolicy: policy.BuiltinDefaultSet,
	})
	check := "lua_" + string(kind) + "_" + name
	stage := policy.StagePreAuth
	category := registry.AttributeCategoryEnvironment
	suffixes := []string{"triggered", "abort", "error"}

	if kind == policycollection.ScriptKindSubject {
		stage = policy.StageSubjectAnalysis
		category = registry.AttributeCategorySubject
		suffixes = []string{"rejected", "error"}
	}

	for _, suffix := range suffixes {
		definition := registry.AttributeDefinition{
			ID:    "auth.lua." + string(kind) + "." + name + "." + suffix,
			Stage: stage, Operations: []policy.Operation{policy.OperationAuthenticate},
			ProducerCheck: check, Category: category, Type: registry.AttributeTypeBool,
			Source: registry.SourceBuiltin,
		}
		if suffix == "triggered" || suffix == "rejected" {
			definition.Details = map[string]registry.DetailDefinition{
				"status_message": {
					Type: registry.AttributeTypeString, Sensitivity: registry.DetailSensitivityPublic,
					Purpose: registry.DetailPurposeResponseMessage, MaxLength: 256,
				},
			}
		}

		snapshot.AttributeRegistry[definition.ID] = definition
	}

	return snapshot
}

// newAuthnCandidateDecisionServiceWithBindings adds exact test-owned effect seams to one captured generation.
func newAuthnCandidateDecisionServiceWithBindings(
	t *testing.T,
	cfg config.File,
	acceptor effectsupervisor.Acceptor,
	catalog *policyruntime.TargetCatalog,
	snapshot *policyruntime.Snapshot,
	extraSyncEffects map[string]policyruntime.SyncEffectProvider,
) *decisionservice.DecisionService {
	t.Helper()
	snapshot = authnCandidateSnapshotWithBuiltins(t, snapshot)

	syncEffects, postActions := authnStandardEffectBindingMaps()
	for providerID, provider := range extraSyncEffects {
		syncEffects[providerID] = provider
	}

	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		FactProviders: authnCandidateFactBindings(catalog),
		SyncEffects:   syncEffects, PostActions: postActions, PostActionAcceptance: acceptor,
	})
	if err != nil {
		t.Fatalf("NewBindingSet() error = %v", err)
	}

	store := policyruntime.NewGenerationStore()

	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{
		Store: store,
		Slots: authnCandidatePreparationSlots(t, catalog, bindings, snapshot),
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

	return service
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

	catalog, err := compiler.NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributor(acceptor),
		authnCandidateStaticContributor{contribution: contribution},
	).Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("configured authn catalog Compile() error = %v", err)
	}

	return catalog
}

// compileAuthnCandidateLuaNativeCatalog selects actual Lua and native host seams in one configured rule.
func compileAuthnCandidateLuaNativeCatalog(
	t *testing.T,
	acceptor effectsupervisor.Acceptor,
	snapshot *policyruntime.Snapshot,
) *policyruntime.TargetCatalog {
	t.Helper()

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	rule := newAuthnCandidateLuaNativeRule(t)
	setID, baseContribution := newAuthnCandidateConfiguredContribution(t, rule)
	provider, effect := newAuthnCandidateNativeEffectDefinitions(t, target)
	contribution := extendAuthnCandidateContribution(t, baseContribution, provider, effect)
	activation := newAuthnCandidateConfiguredActivation(t, target, setID)

	catalog, err := compiler.NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributorWithAuthnPolicy(snapshot.AttributeRegistry, acceptor),
		authnCandidateStaticContributor{contribution: contribution},
	).Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("Lua/native authn catalog Compile() error = %v", err)
	}

	return catalog
}

// newAuthnCandidateLuaNativeRule selects neutral collector facts and orders both effect seams.
func newAuthnCandidateLuaNativeRule(t *testing.T) registry.PolicyRule {
	t.Helper()

	luaUse, err := registry.NewEffectUse("authn/lua_action_dispatch", map[string]decision.Value{
		policy.ObligationArgAction:  mustAuthnStringValue(t, policy.LuaActionDispatchTLS),
		policy.ObligationArgFeature: mustAuthnStringValue(t, policy.LuaActionDispatchTLS),
	})
	if err != nil {
		t.Fatalf("NewEffectUse(lua) error = %v", err)
	}

	nativeUse, err := registry.NewEffectUse(authnCandidateNativeEffectID, nil)
	if err != nil {
		t.Fatalf("NewEffectUse(native) error = %v", err)
	}

	luaNeutral, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindAttribute, FactID: authnCandidateLuaFactID,
		FactKind: decision.ValueKindBoolean, Operator: registry.ExpressionOperatorIs,
		Values: []decision.Value{mustAuthnBooleanValue(t, false)},
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression(lua fact) error = %v", err)
	}

	nativeNeutral, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindAttribute, FactID: authnCandidateNativeFactID,
		FactKind: decision.ValueKindBoolean, Operator: registry.ExpressionOperatorIs,
		Values: []decision.Value{mustAuthnBooleanValue(t, false)},
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression(native fact) error = %v", err)
	}

	expression, err := registry.NewPolicyExpression(registry.PolicyExpressionInput{
		Kind: registry.ExpressionKindAll, Children: []registry.PolicyExpression{luaNeutral, nativeNeutral},
	})
	if err != nil {
		t.Fatalf("NewPolicyExpression(combined facts) error = %v", err)
	}

	rule, err := registry.NewPolicyRule(registry.PolicyRuleInput{
		Name: "configured_lua_native_permit", Checkpoint: string(policy.StageAuthDecision),
		Expression: expression, Decision: decision.EffectPermit,
		OutcomeMarker:  "auth.outcome.configured_lua_native_permit",
		FSMEventMarker: policy.FSMEventMarkerAuthPermit, ResponseMarker: policy.ResponseMarkerOK,
		Effects: []registry.EffectUse{luaUse, nativeUse},
	})
	if err != nil {
		t.Fatalf("NewPolicyRule() error = %v", err)
	}

	return rule
}

// newAuthnCandidateNativeEffectDefinitions declares one configured synchronous plugin seam.
func newAuthnCandidateNativeEffectDefinitions(
	t *testing.T,
	target decision.Target,
) (registry.ProviderDefinition, registry.EffectDefinition) {
	t.Helper()

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID: authnCandidateNativeProviderID, Targets: []decision.Target{target},
		Executions: []registry.ExecutionClass{registry.ExecutionHostSync},
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition(native) error = %v", err)
	}

	effect, err := registry.NewEffectDefinition(registry.EffectDefinitionInput{
		ID: authnCandidateNativeEffectID, Provider: provider.ID(), Targets: []decision.Target{target},
		Kind: registry.EffectKindObligation, Execution: registry.ExecutionHostSync,
	})
	if err != nil {
		t.Fatalf("NewEffectDefinition(native) error = %v", err)
	}

	return provider, effect
}

// extendAuthnCandidateContribution retains one set while adding its native effect owner.
func extendAuthnCandidateContribution(
	t *testing.T,
	base registry.DefinitionContribution,
	provider registry.ProviderDefinition,
	effect registry.EffectDefinition,
) registry.DefinitionContribution {
	t.Helper()

	contribution, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership: base.Ownership(), PolicySets: base.PolicySets(),
		Providers: []registry.ProviderDefinition{provider}, Effects: []registry.EffectDefinition{effect},
	})
	if err != nil {
		t.Fatalf("NewCompleteDefinitionContribution(lua/native) error = %v", err)
	}

	return contribution
}

// newAuthnCandidateLuaNativeSnapshot registers real Lua and native collector facts in the captured generation.
func newAuthnCandidateLuaNativeSnapshot(t *testing.T) *policyruntime.Snapshot {
	t.Helper()

	snapshot := newAuthnCandidateScriptSnapshot(
		t,
		policycollection.ScriptKindEnvironment,
		"current_behavior_environment",
	)

	for _, suffix := range []string{"triggered", "abort", "error"} {
		attributeID := "auth.plugin.environment.candidate.verdict." + suffix

		definition := registry.AttributeDefinition{
			ID: attributeID, Stage: policy.StagePreAuth,
			Operations: []policy.Operation{
				policy.OperationAuthenticate,
				policy.OperationLookupIdentity,
			},
			ProducerCheck: authnCandidateNativeCheck,
			Category:      registry.AttributeCategoryEnvironment,
			Type:          registry.AttributeTypeBool,
			Source:        registry.SourceBuiltin,
		}
		if suffix == "triggered" {
			definition.Details = map[string]registry.DetailDefinition{
				"status_message": {
					Type: registry.AttributeTypeString, Sensitivity: registry.DetailSensitivityPublic,
					Purpose: registry.DetailPurposeResponseMessage, MaxLength: 256,
				},
			}
		}

		snapshot.AttributeRegistry[attributeID] = definition
	}

	return snapshot
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

// authnCandidateFactBindings lets the request-local legacy collector retain builtin fact ownership.
func authnCandidateFactBindings(catalog *policyruntime.TargetCatalog) map[string]policyruntime.FactProviderBinding {
	bindings := make(map[string]policyruntime.FactProviderBinding)

	for _, target := range catalog.Targets() {
		for _, checkpoint := range target.DomainPlan().Checkpoints() {
			for _, providerID := range checkpoint.ProviderIDs() {
				bindings[providerID] = policyruntime.FactProviderBinding{
					Provider: authnCandidateNoopFactProvider{}, Source: decision.FactSourceNauthilus,
					Authority: "nauthilus", Component: providerID,
				}
			}
		}
	}

	return bindings
}

// compileAuthnCandidateCatalogWithSnapshot binds standard rules to one captured attribute registry.
func compileAuthnCandidateCatalogWithSnapshot(
	t *testing.T,
	acceptor effectsupervisor.Acceptor,
	snapshot *policyruntime.Snapshot,
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

		activations = append(activations, activation)
	}

	catalog, err := compiler.NewTargetCatalogCompiler(
		registry.NewBuiltinTargetContributorWithAuthnPolicy(snapshot.AttributeRegistry, acceptor),
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
	snapshot *policyruntime.Snapshot,
) policyruntime.PreparationSlots {
	t.Helper()

	return policyruntime.PreparationSlots{
		Policy: policyruntime.PolicyPreparationFunc(func(
			_ context.Context,
			input policyruntime.PreparationInput,
		) (policyruntime.PolicyPreparation, error) {
			captured := snapshot.Clone()
			if captured == nil {
				captured = &policyruntime.Snapshot{}
			}

			captured.Generation = input.ID()

			return policyruntime.PolicyPreparation{Snapshot: captured}, nil
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
			return policyruntime.CallerAuthenticationPreparation{Authenticator: authnCandidateAuthenticator{}}, nil
		}),
		Admission: policyruntime.AdmissionPreparationFunc(func(
			context.Context,
			policyruntime.AdmissionPreparationInput,
		) (policyruntime.AdmissionPreparation, error) {
			return policyruntime.AdmissionPreparation{Authority: authnCandidateAdmission{}}, nil
		}),
		Settings: policyruntime.SettingsPreparationFunc(func(
			context.Context,
			policyruntime.SettingsPreparationInput,
		) (policyruntime.SettingsPreparation, error) {
			return policyruntime.SettingsPreparation{Settings: policyruntime.GenerationSettings{
				Limits: policyruntime.DecisionLimits{
					EvaluationTimeout: time.Second, PostActionBudget: time.Second, MaxDiagnosticsEntries: 32,
				},
				Reports: policyruntime.DecisionReportSettings{MaxEntries: 32},
			}}, nil
		}),
		Application: decisionservice.NewRuntimeApplicationPreparationSlot(),
	}
}

type authnCandidateAuthenticator struct{}

type authnCandidateStaticContributor struct {
	contribution registry.DefinitionContribution
}

// Contribute returns one immutable test-only configured authn policy set.
func (c authnCandidateStaticContributor) Contribute(context.Context) (registry.DefinitionContribution, error) {
	return c.contribution, nil
}

type authnCandidateCacheSubject struct {
	calls    atomic.Int32
	rejected atomic.Bool
}

type authnCandidateClassifiedPostAction struct {
	result PostActionResult
	calls  atomic.Int32
}

type authnCandidateCountingPlanPostAction struct {
	preparations atomic.Int32
}

// Run preserves the synchronous compatibility seam when no plan owner is selected.
func (*authnCandidateCountingPlanPostAction) Run(PostActionInput) PostActionResult {
	return PostActionSucceeded()
}

// PreparePlanStep records immutable capture through the actual post-action adapter.
func (a *authnCandidateCountingPlanPostAction) PreparePlanStep(PostActionInput) PostActionPlanRunner {
	a.preparations.Add(1)

	return recordingPlanPostAction{}
}

// Run records one preselected synchronous post-action cause.
func (a *authnCandidateClassifiedPostAction) Run(PostActionInput) PostActionResult {
	a.calls.Add(1)

	return a.result
}

// Analyze records request-local subject authority on both cold and warm cache paths.
func (s *authnCandidateCacheSubject) Analyze(
	ctx *gin.Context,
	view *StateView,
	_ *PassDBResult,
) definitions.AuthResult {
	s.calls.Add(1)

	auth := view.Auth()
	rejected := s.rejected.Load()
	auth.Runtime.Authorized = !rejected
	auth.Runtime.StatusMessage = "authentication accepted"
	auth.Runtime.StatusMessageI18NKey = "auth.success"
	auth.Runtime.ResponseLanguage = "de"

	if recorder := auth.PolicyScriptRecorder(ctx); recorder != nil {
		recorder.RecordScriptResult(ctx.Request.Context(), policycollection.ScriptResult{
			Kind: policycollection.ScriptKindSubject, Name: "candidate_cache",
			Action: rejected, StatusMessage: "warm subject rejected",
		})
	}

	if rejected {
		return definitions.AuthResultFail
	}

	return definitions.AuthResultOK
}

type authnCandidateNoopFactProvider struct{}

type authnCandidateNativeSyncEffectProvider struct{}

type authnCandidateOrderedActionDispatcher struct {
	log *authnCandidateEffectLog
}

type authnCandidateFactAwarePluginBridge struct {
	log           *authnCandidateEffectLog
	validationErr error
	mu            sync.Mutex
}

// Collect leaves existing request-local auth facts under their established collectors.
func (authnCandidateNoopFactProvider) Collect(
	context.Context,
	policyruntime.FactProviderInput,
) ([]policyruntime.ProvidedFact, error) {
	return nil, nil
}

// Execute routes one configured native selection through the actual core plugin bridge seam.
func (authnCandidateNativeSyncEffectProvider) Execute(
	ctx context.Context,
	execution policyruntime.EffectExecution,
) effectsupervisor.Result {
	owner := authnPolicyEffectOwnerFromContext(ctx)
	if owner == nil || execution.EffectID() != authnCandidateNativeEffectID {
		return effectsupervisor.Failed("authn_native_effect_owner_unavailable")
	}

	return owner.executeAuthnPolicyEffect(report.EffectRequest{ID: execution.EffectID()})
}

// Dispatch records the actual Lua action seam in selected effect order.
func (d *authnCandidateOrderedActionDispatcher) Dispatch(
	_ *StateView,
	_ string,
	_ definitions.LuaAction,
) {
	d.log.append("lua:" + policy.ObligationLuaActionDispatch)
}

// IsPostActionEffect keeps the configured native fixture synchronous.
func (*authnCandidateFactAwarePluginBridge) IsPostActionEffect(report.EffectRequest) bool {
	return false
}

// EnqueuePostActionPlan rejects unexpected post-action use in the synchronous fixture.
func (*authnCandidateFactAwarePluginBridge) EnqueuePostActionPlan(
	*gin.Context,
	*StateView,
	[]PostActionPlanStep,
) (bool, bool) {
	return false, false
}

// ExecutePolicyEffect verifies captured Lua/native provenance at the actual native effect seam.
func (b *authnCandidateFactAwarePluginBridge) ExecutePolicyEffect(
	ctx *gin.Context,
	view *StateView,
	effect report.EffectRequest,
) (bool, bool) {
	b.log.append("native:" + effect.ID)

	var validationErr error
	if effect.ID != authnCandidateNativeEffectID || view == nil || view.Auth() == nil {
		validationErr = fmt.Errorf("native effect request or state view is incomplete")
	} else {
		validationErr = validateAuthnCandidateExtensionFacts(ctx, view.Auth())
	}

	b.mu.Lock()
	b.validationErr = validationErr
	b.mu.Unlock()

	return true, validationErr == nil
}

// validationError returns the fact-authority result recorded by the native seam.
func (b *authnCandidateFactAwarePluginBridge) validationError() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.validationErr
}

// validateAuthnCandidateExtensionFacts checks exact Lua/plugin owners and retained values.
func validateAuthnCandidateExtensionFacts(ctx *gin.Context, auth *AuthState) error {
	policyCtx := auth.requestPolicyContext(ctx)
	if policyCtx == nil || policyCtx.Report() == nil {
		return fmt.Errorf("request-local policy facts are unavailable")
	}

	wantSources := map[string]registry.AttributeSource{
		authnCandidateLuaAttributeID:    registry.SourceBuiltin,
		authnCandidateNativeAttributeID: registry.SourceBuiltin,
	}
	for factID, wantSource := range wantSources {
		definition, exists := policyCtx.AttributeDefinition(factID)
		if !exists || definition.Source != wantSource {
			return fmt.Errorf("fact %s source = %q, want %q", factID, definition.Source, wantSource)
		}

		attribute, exists := policyCtx.Report().Attributes[factID]
		if !exists || attribute.Value != false {
			return fmt.Errorf("fact %s value = %#v, want false", factID, attribute.Value)
		}
	}

	return nil
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
	base      *authApplicationService
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

// Authenticate fails if the staged candidate accidentally invokes the legacy aggregate service.
func (h *authnCandidateInjectedHost) Authenticate(context.Context, AuthInput) (*AuthOutcome, error) {
	h.calls.Add(1)

	return nil, errors.New("legacy aggregate authenticate was invoked")
}

// LookupIdentity fails if the staged candidate accidentally invokes the legacy aggregate service.
func (h *authnCandidateInjectedHost) LookupIdentity(context.Context, AuthInput) (*AuthOutcome, error) {
	h.calls.Add(1)

	return nil, errors.New("legacy aggregate lookup was invoked")
}

// ListAccounts fails if the staged candidate accidentally invokes the legacy aggregate service.
func (h *authnCandidateInjectedHost) ListAccounts(context.Context, AuthInput) (*ListAccountsOutcome, error) {
	h.calls.Add(1)

	return nil, errors.New("legacy aggregate account listing was invoked")
}

type authnCandidateEffectLog struct {
	values []string
	mu     sync.Mutex
}

type recordingAuthnCandidateEnvironmentBridge struct {
	calls atomic.Int32
}

type authnCandidateNativeEnvironmentBridge struct {
	sources   []authnCandidateNativeEnvironmentOutcome
	err       error
	status    string
	calls     atomic.Int32
	triggered bool
	abort     bool
}

type authnCandidateNativeEnvironmentOutcome struct {
	err       error
	name      string
	status    string
	triggered bool
	abort     bool
}

type authnCandidateNativeSubjectBridge struct {
	sources []authnCandidateNativeSubjectOutcome
}

type authnCandidateNativeSubjectOutcome struct {
	err      error
	name     string
	status   string
	rejected bool
}

// Evaluate records actual native environment collection without changing its outcome.
func (b *recordingAuthnCandidateEnvironmentBridge) Evaluate(
	*gin.Context,
	*StateView,
) (bool, bool, bool, error) {
	b.calls.Add(1)

	return false, false, true, nil
}

// Evaluate records native terminal facts through the same collector boundary as pluginruntime.
func (b *authnCandidateNativeEnvironmentBridge) Evaluate(
	ctx *gin.Context,
	view *StateView,
) (bool, bool, bool, error) {
	b.calls.Add(1)

	if view == nil || view.Auth() == nil {
		return false, false, true, errors.New("native environment auth state is unavailable")
	}

	policyCtx := view.Auth().PolicyDecisionContext(ctx)
	if policyCtx == nil {
		return false, false, true, errors.New("native environment policy context is unavailable")
	}

	sources := b.sources
	if len(sources) == 0 {
		sources = []authnCandidateNativeEnvironmentOutcome{{
			name: "verdict", status: b.status, triggered: b.triggered, abort: b.abort, err: b.err,
		}}
	}

	var (
		triggered bool
		abort     bool
	)

	for _, source := range sources {
		recordAuthnCandidateNativeEnvironmentOutcome(ctx, view.Auth(), policyCtx, source)

		if source.err != nil {
			return false, false, true, source.err
		}

		if source.status != "" {
			view.Auth().Runtime.StatusMessage = source.status
		}

		triggered = triggered || source.triggered
		abort = abort || source.abort
	}

	return triggered, abort, true, nil
}

// recordAuthnCandidateNativeEnvironmentOutcome mirrors the native collector's report boundary.
func recordAuthnCandidateNativeEnvironmentOutcome(
	ctx *gin.Context,
	auth *AuthState,
	policyCtx *policycollection.DecisionContext,
	source authnCandidateNativeEnvironmentOutcome,
) {
	check := policyCtx.BeginCheck(ctx.Request.Context(), policycollection.CheckSelector{
		CheckType: policy.CheckTypePluginEnvironment,
		Stage:     policy.StagePreAuth,
		Name:      authnCandidateNativeCheck,
		ConfigRef: "plugins.modules.candidate.environment",
	})

	details := map[string]policycollection.DetailValue(nil)
	if source.status != "" {
		details = map[string]policycollection.DetailValue{
			"status_message": {
				Value: source.status, Sensitivity: report.SensitivityPublic,
				Purpose: report.PurposeResponseMessage,
			},
		}
	}

	operation := auth.policyOperation()
	attributePrefix := "auth.plugin.environment.candidate." + source.name
	check.Finish(policycollection.CheckResult{
		Err: source.err, Status: policy.CheckStatusOK, Matched: source.triggered,
		DecisionHint: policyDecision(source.triggered, policy.DecisionDeny),
		Attributes: []policycollection.AttributeValue{
			policycollection.BoolAttribute(
				attributePrefix+".triggered",
				policy.StagePreAuth,
				operation,
				source.triggered,
				details,
			),
			policycollection.BoolAttribute(
				attributePrefix+".abort",
				policy.StagePreAuth,
				operation,
				source.abort,
				nil,
			),
			policycollection.BoolAttribute(
				attributePrefix+".error",
				policy.StagePreAuth,
				operation,
				source.err != nil,
				nil,
			),
		},
	})
}

// Analyze records ordered native subject facts through the same collector boundary as pluginruntime.
func (b *authnCandidateNativeSubjectBridge) Analyze(
	ctx *gin.Context,
	view *StateView,
	_ *PassDBResult,
	current definitions.AuthResult,
) (definitions.AuthResult, bool) {
	if view == nil || view.Auth() == nil {
		return definitions.AuthResultTempFail, true
	}

	policyCtx := view.Auth().PolicyDecisionContext(ctx)
	if policyCtx == nil {
		return definitions.AuthResultTempFail, true
	}

	var rejected bool

	for _, source := range b.sources {
		recordAuthnCandidateNativeSubjectOutcome(ctx, view.Auth(), policyCtx, source)

		if source.err != nil {
			view.Auth().Runtime.Authorized = false

			return definitions.AuthResultTempFail, true
		}

		if source.status != "" {
			view.Auth().Runtime.StatusMessage = source.status
		}

		rejected = rejected || source.rejected
	}

	if rejected {
		view.Auth().Runtime.Authorized = false

		return definitions.AuthResultFail, true
	}

	return current, true
}

// recordAuthnCandidateNativeSubjectOutcome mirrors the native subject collector report boundary.
func recordAuthnCandidateNativeSubjectOutcome(
	ctx *gin.Context,
	auth *AuthState,
	policyCtx *policycollection.DecisionContext,
	source authnCandidateNativeSubjectOutcome,
) {
	details := map[string]policycollection.DetailValue(nil)
	if source.status != "" {
		details = map[string]policycollection.DetailValue{
			"status_message": {
				Value: source.status, Sensitivity: report.SensitivityPublic,
				Purpose: report.PurposeResponseMessage,
			},
		}
	}

	attributePrefix := "auth.plugin.subject.candidate." + source.name
	check := policyCtx.BeginCheck(ctx.Request.Context(), policycollection.CheckSelector{
		CheckType: policy.CheckTypePluginSubjectSource,
		Stage:     policy.StageSubjectAnalysis,
		Name:      policy.PluginSubjectCheckName("candidate", source.name),
		ConfigRef: "plugins.modules.candidate.subject",
	})
	check.Finish(policycollection.CheckResult{
		Err: source.err, Status: policy.CheckStatusOK, Matched: source.rejected,
		DecisionHint: policyDecision(source.rejected, policy.DecisionDeny),
		Attributes: []policycollection.AttributeValue{
			policycollection.BoolAttribute(
				attributePrefix+".rejected",
				policy.StageSubjectAnalysis,
				auth.policyOperation(),
				source.rejected,
				details,
			),
			policycollection.BoolAttribute(
				attributePrefix+".error",
				policy.StageSubjectAnalysis,
				auth.policyOperation(),
				source.err != nil,
				nil,
			),
		},
	})
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

type authnCandidateEffectWork struct {
	finalization              decision.EvaluationFinalization
	started                   chan struct{}
	result                    effectsupervisor.Result
	executeCalls              atomic.Int32
	cleanupCalls              atomic.Int32
	startedBeforeFinalization atomic.Bool
}

// Validate accepts the immutable test work.
func (*authnCandidateEffectWork) Validate() error { return nil }

// Execute records an unexpected worker start after rejected acceptance.
func (w *authnCandidateEffectWork) Execute(context.Context) effectsupervisor.Result {
	w.executeCalls.Add(1)

	if w.finalization.Valid() {
		select {
		case <-w.finalization.Done():
		default:
			w.startedBeforeFinalization.Store(true)
		}
	}

	if w.started != nil {
		close(w.started)
	}

	if w.result.State() != "" {
		return w.result
	}

	return effectsupervisor.Succeeded()
}

// Cleanup records release of rejected prepared work.
func (w *authnCandidateEffectWork) Cleanup() {
	w.cleanupCalls.Add(1)
}

type authnCandidateFinalizationFactory struct {
	delegate decisionservice.DecisionSessionFactory
	work     *authnCandidateEffectWork
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

	return f.delegate.WithSession(ctx, invocation, func(session decisionservice.DecisionSession) error {
		return use(&authnCandidateCheckpointSession{delegate: session, target: target, owner: f})
	})
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

// WithSession records the exact gate later inspected by accepted work.
func (f *authnCandidateFinalizationFactory) WithSession(
	ctx context.Context,
	invocation decision.Invocation,
	use func(decisionservice.DecisionSession) error,
) error {
	f.work.finalization = invocation.Finalization

	return f.delegate.WithSession(ctx, invocation, use)
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
