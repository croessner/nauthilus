// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyfx

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/pluginapi/v1/exchange"
	"github.com/croessner/nauthilus/v4/server/app/configfx"
	"github.com/croessner/nauthilus/v4/server/backend/accountcache"
	"github.com/croessner/nauthilus/v4/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const (
	terminalCompletionUsername   = "completion@example.test"
	terminalCompletionClientIP   = "192.0.2.35"
	terminalCompletionBucket     = "completion_block"
	terminalCompletionRedisRoot  = "completion:"
	terminalCompletionTargetLine = "      default_policy: authn/standard_auth\n"
	terminalCompletionOptIn      = terminalCompletionTargetLine +
		"      terminal_post_actions: [{id: authn/plugin.example.post_action}]\n"
)

// nativeTerminalCompletionFixture mirrors the shadow pre-auth layout: the brute-force provider runs before an
// environment provider (standing in for GeoIP), and the configured brute-force rule requires both. A ban hit therefore
// closes the environment provider and the builtin standard_auth rule answers without any configured obligation.
const nativeTerminalCompletionFixture = `policy:
  namespaces:
    authn:
      providers:
        plugin.example.environment:
          kind: plugin
          module: example
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          checkpoints:
            pre_auth:
              providers:
                - {name: brute_force, use: authn/builtin/brute_force, actions: [authenticate]}
                - {name: native_environment, use: authn/plugin.example.environment, actions: [authenticate]}
            auth_backend:
              providers:
                - {name: ldap_backend, use: authn/builtin/ldap_backend}
            auth_decision: {providers: []}
      policy_sets:
        configured:
          rules:
            - name: standard_brute_force_deny
              checkpoint: pre_auth
              actions: [authenticate]
              require_providers: [brute_force, native_environment]
              if:
                all:
                  - {attribute: nauthilus.auth.brute_force.triggered, is: true}
                  - not: {attribute: plugin.environment.example.score, gte: 0.5}
              then:
                decision: deny
                outcome_marker: auth.outcome.brute_force_reject
                fsm_event_marker: auth.fsm.event.pre_auth_deny
                response_marker: auth.response.fail
                obligations: [{id: authn/brute_force_update}, {id: authn/plugin.example.post_action}]
            - name: environment_observed
              checkpoint: pre_auth
              actions: [authenticate]
              require_providers: [native_environment]
              if: {attribute: plugin.environment.example.score, gte: 0.5}
              then:
                decision: neutral
                outcome_marker: auth.outcome.environment_observed
                fsm_event_marker: auth.fsm.event.pre_auth_ok
                obligations: [{id: authn/plugin.example.post_action}]
            - name: standard_auth_failure
              checkpoint: auth_decision
              actions: [authenticate]
              if: {attribute: backend.authenticated, is: false}
              then:
                decision: deny
                outcome_marker: auth.outcome.auth_failure
                fsm_event_marker: auth.fsm.event.auth_deny
                response_marker: auth.response.fail
                obligations: [{id: authn/plugin.example.post_action}]
            - name: standard_auth_success
              checkpoint: auth_decision
              actions: [authenticate]
              if: {attribute: backend.authenticated, is: true}
              then:
                decision: permit
                outcome_marker: auth.outcome.auth_success
                fsm_event_marker: auth.fsm.event.auth_permit
                response_marker: auth.response.ok
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

// terminalCompletionCase describes one request and the single login completion it must produce.
type terminalCompletionCase struct {
	wantSources   []string
	name          string
	wantRule      string
	wantStage     string
	wantMarker    string
	wantDecision  core.AuthDecision
	wantCompleted int32
	verifier      nativeAuthOutcomeVerifier
	// repeats answers this many identical requests first, so the checked request repeats the same password.
	repeats       int
	banned        bool
	knownAccount  bool
	optIn         bool
	observe       bool
	httpTransport bool
	wantVerified  bool
	wantRWP       bool
}

// TestTerminalPostActionsCompleteEveryAuthenticateOnce reproduces the overnight shadow finding: a ban hit was answered
// by the builtin brute-force rule, so no login completion reached the analytics post-action. With the target-level
// terminal post-action declared, every answered authenticate request must produce exactly one completion carrying the
// enforced outcome, and selecting the same post-action in a rule must not add a second one.
func TestTerminalPostActionsCompleteEveryAuthenticateOnce(t *testing.T) {
	core.InitPassDBResultPool()
	core.SetDefaultLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))

	for _, testCase := range []terminalCompletionCase{
		{name: "ban hit answered by builtin rule", banned: true, optIn: true, wantCompleted: 1,
			wantDecision: core.AuthDecisionFail, wantStage: "pre_auth", wantRule: "standard_brute_force_deny",
			wantMarker: "auth.outcome.brute_force_reject", wantSources: []string{exchange.FeatureBruteForce}},
		{name: "ban hit with repeating wrong password", banned: true, knownAccount: true, optIn: true,
			repeats: 1, wantCompleted: 1, wantRWP: true, wantDecision: core.AuthDecisionFail, wantStage: "pre_auth",
			wantRule: "standard_brute_force_deny", wantMarker: "auth.outcome.brute_force_reject",
			wantSources: []string{exchange.FeatureBruteForce}},
		{name: "ban hit over HTTP", banned: true, optIn: true, httpTransport: true, wantCompleted: 1,
			wantDecision: core.AuthDecisionFail, wantStage: "pre_auth", wantRule: "standard_brute_force_deny",
			wantMarker: "auth.outcome.brute_force_reject", wantSources: []string{exchange.FeatureBruteForce}},
		{name: "credential failure after neutral pre-auth rule", optIn: true, wantCompleted: 1, wantVerified: true,
			wantDecision: core.AuthDecisionFail, wantStage: "auth_decision", wantRule: "standard_auth_failure",
			wantMarker: "auth.outcome.auth_failure"},
		{name: "success after neutral pre-auth rule", optIn: true, wantCompleted: 1, wantVerified: true,
			verifier: nativeAuthOutcomeVerifier{authenticated: true}, wantDecision: core.AuthDecisionOK,
			wantStage: "auth_decision", wantRule: "standard_auth_success", wantMarker: "auth.outcome.auth_success"},
		{name: "ban hit without opt-in keeps the builtin rule effect-free", banned: true,
			wantDecision: core.AuthDecisionFail},
		{name: "observe mode withholds the completion", banned: true, optIn: true, observe: true,
			wantDecision: core.AuthDecisionFail},
		{name: "rule-selected post-actions without opt-in run per checkpoint", wantCompleted: 2, wantVerified: true,
			wantDecision: core.AuthDecisionFail, wantStage: "auth_decision", wantRule: "standard_auth_failure",
			wantMarker: "auth.outcome.auth_failure"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			runTerminalCompletionCase(t, testCase)
		})
	}
}

// runTerminalCompletionCase answers one request and checks the decision, the host work, and the completions.
func runTerminalCompletionCase(t *testing.T, testCase terminalCompletionCase) {
	t.Helper()

	probe := &nativeAuthExecutionProbe{postActionRequests: make(chan pluginapi.PostActionRequest, 4)}
	verifier := &countingAuthVerifier{delegate: testCase.verifier}
	answer := newTerminalCompletionRequester(t, testCase, probe, verifier)

	for range testCase.repeats {
		answer()
		drainTerminalCompletions(probe, testCase.wantCompleted)
	}

	verifier.calls.Store(0)
	probe.postActionCalls.Store(0)
	probe.environmentCalls.Store(0)

	outcome := answer()

	if outcome.Decision != testCase.wantDecision {
		t.Fatalf("answered decision = %q, want %q", outcome.Decision, testCase.wantDecision)
	}

	if verified := verifier.calls.Load() > 0; verified != testCase.wantVerified {
		t.Fatalf("password verification ran = %t, want %t", verified, testCase.wantVerified)
	}

	if testCase.banned && probe.environmentCalls.Load() != 0 {
		t.Fatalf("environment provider ran %d times after a ban hit, want 0", probe.environmentCalls.Load())
	}

	requests := drainTerminalCompletions(probe, testCase.wantCompleted)
	if int32(len(requests)) != testCase.wantCompleted || probe.postActionCalls.Load() != testCase.wantCompleted {
		t.Fatalf("login completions = %d (calls %d), want exactly %d",
			len(requests), probe.postActionCalls.Load(), testCase.wantCompleted)
	}

	for _, request := range requests {
		assertTerminalCompletionOutcome(t, testCase, request.Outcome)
		assertTerminalCompletionSnapshot(t, testCase, request)
	}
}

// assertTerminalCompletionSnapshot checks the analytics view of a completion: decision sources and the RWP marker.
func assertTerminalCompletionSnapshot(t *testing.T, testCase terminalCompletionCase, request pluginapi.PostActionRequest) {
	t.Helper()

	sources := exchange.NewSnapshot(request.Runtime, request.Facts).DecisionSources()
	if !slices.Equal(sources, testCase.wantSources) {
		t.Fatalf("completion decision sources = %v, want %v", sources, testCase.wantSources)
	}

	if request.Snapshot.Runtime.RWP != testCase.wantRWP {
		t.Fatalf("completion RWP marker = %t, want %t", request.Snapshot.Runtime.RWP, testCase.wantRWP)
	}
}

// assertTerminalCompletionOutcome compares the sealed outcome a completion carries with the enforced answer.
func assertTerminalCompletionOutcome(t *testing.T, testCase terminalCompletionCase, outcome pluginapi.AuthOutcome) {
	t.Helper()

	if !outcome.Known || string(outcome.Decision) != string(testCase.wantDecision) || outcome.Stage != testCase.wantStage ||
		outcome.PolicyRule != testCase.wantRule || outcome.OutcomeMarker != testCase.wantMarker {
		t.Fatalf("completion outcome = %+v, want decision %q stage %q rule %q marker %q", outcome,
			testCase.wantDecision, testCase.wantStage, testCase.wantRule, testCase.wantMarker)
	}
}

// newTerminalCompletionRequester builds the generation and host for one case and returns a function that answers
// one identical request against the same Redis state per call.
func newTerminalCompletionRequester(
	t *testing.T,
	testCase terminalCompletionCase,
	probe *nativeAuthExecutionProbe,
	verifier core.PasswordVerifier,
) func() *core.AuthOutcome {
	t.Helper()

	fixture := terminalCompletionFixture(testCase.optIn, testCase.observe)

	configured, state := nativeAuthGenerationCandidateFromFixture(t, fixture, probe)
	enableTerminalCompletionBruteForce(t, configured)

	runtime := newNativeAuthGenerationRuntime(t, configured, state)
	redisClient := newTerminalCompletionRedis(t, configured, testCase)
	application := newNativeAuthApplicationWithDeps(t, configured, runtime.service, verifier,
		slog.New(slog.NewTextHandler(io.Discard, nil)), func(deps *core.AuthDeps) {
			deps.Redis = redisClient
			deps.Tolerate = tolerate.NewTolerateWithDeps(configured, deps.Logger, redisClient, 0)
		})

	return func() *core.AuthOutcome {
		return answerTerminalCompletion(t, testCase, application)
	}
}

// answerTerminalCompletion answers one request over the case's transport and completes its finalization gate.
func answerTerminalCompletion(
	t *testing.T,
	testCase terminalCompletionCase,
	application core.AuthApplicationService,
) *core.AuthOutcome {
	t.Helper()

	newGate := core.ContextWithPostActionExecutionGate
	service := definitions.ServGRPC

	if testCase.httpTransport {
		newGate = core.ContextWithHTTPPostActionExecutionGate
		service = definitions.ServBasic
	}

	requestContext, finalization := newGate(t.Context())

	outcome, err := application.Authenticate(requestContext, core.AuthInput{
		Credentials: core.NewCredentials(
			core.WithUsername(terminalCompletionUsername),
			core.WithPassword(secret.FromBytes([]byte("terminal-completion-password"))),
		),
		Context: core.NewAuthContext(
			core.WithProtocol(definitions.ProtoIMAP), core.WithClientIP(terminalCompletionClientIP),
		),
		CorrelationID: "terminal-completion-" + strings.ReplaceAll(testCase.name, " ", "-"),
		EntryPoint:    core.AuthnEntryBackchannel,
		Service:       service,
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}

	finalization.Complete()

	return outcome
}

// terminalCompletionFixture returns the shared fixture with the optional terminal opt-in and observe authority.
func terminalCompletionFixture(optIn bool, observe bool) string {
	targetLines := terminalCompletionTargetLine
	if optIn {
		targetLines = terminalCompletionOptIn
	}

	if observe {
		targetLines += "      mode: observe\n"
	}

	return strings.Replace(nativeTerminalCompletionFixture, terminalCompletionTargetLine, targetLines, 1)
}

// TestTerminalPostActionsRejectDecisionEffects proves that only detached post-actions can be declared terminal, so a
// counting or decision-relevant effect never runs for every request, and that the rejected reload keeps G1.
func TestTerminalPostActionsRejectDecisionEffects(t *testing.T) {
	core.InitPassDBResultPool()

	configured, state := nativeAuthGenerationCandidateFromFixture(t, terminalCompletionFixture(true, false), nil)
	enableTerminalCompletionBruteForce(t, configured)

	runtime := newNativeAuthGenerationRuntime(t, configured, state)
	active := runtime.store.Active()

	invalid, _ := nativeAuthGenerationCandidateFromFixture(t, strings.Replace(
		terminalCompletionFixture(true, false), "terminal_post_actions: [{id: authn/plugin.example.post_action}]",
		"terminal_post_actions: [{id: authn/brute_force_update}]", 1,
	), nil)
	invalid.Plugins = configured.Plugins
	enableTerminalCompletionBruteForce(t, invalid)

	err := runtime.coordinator.Apply(t.Context(), configfx.Snapshot{File: invalid, Version: 2})
	if err == nil || !strings.Contains(err.Error(), "terminal_post_actions") {
		t.Fatalf("Apply(terminal brute_force_update) error = %v, want terminal_post_actions rejection", err)
	}

	if runtime.store.Active() != active {
		t.Fatal("rejected terminal post-action candidate replaced the active generation")
	}
}

// enableTerminalCompletionBruteForce configures one IPv4 bucket that the seeded ban key belongs to.
func enableTerminalCompletionBruteForce(t *testing.T, configured *config.FileSettings) {
	t.Helper()

	var runtimeModule config.RuntimeModule
	if err := runtimeModule.Set(definitions.ControlBruteForce); err != nil {
		t.Fatalf("set brute-force control: %v", err)
	}

	configured.Server.RuntimeModules = []*config.RuntimeModule{&runtimeModule}
	configured.Server.Redis.Prefix = terminalCompletionRedisRoot
	configured.Server.MaxLoginAttempts = 5
	configured.Server.BruteForceProtocols = []*config.Protocol{config.NewProtocol(definitions.ProtoIMAP)}
	configured.BruteForce = &config.BruteForceSection{
		AllowedUniqueWrongPWHashes: 1,
		RWPWindow:                  time.Minute,
		Buckets: []config.BruteForceRule{{
			Name: terminalCompletionBucket, Period: time.Hour, CIDR: 32, IPv4: true, FailedRequests: 5,
		}},
	}
}

// newTerminalCompletionRedis starts miniredis with the brute-force scripts and optionally an active ban.
func newTerminalCompletionRedis(
	t *testing.T,
	configured *config.FileSettings,
	testCase terminalCompletionCase,
) rediscli.Client {
	t.Helper()

	// Script upload reads the process-wide configuration.
	config.SetTestFile(configured)

	storage := miniredis.RunT(t)
	database := redis.NewClient(&redis.Options{Addr: storage.Addr()})

	t.Cleanup(func() { _ = database.Close() })

	client := rediscli.NewTestClient(database)

	rediscli.ClearScriptCache()

	if err := rediscli.UploadAllScripts(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), client); err != nil {
		t.Fatalf("upload scripts: %v", err)
	}

	if testCase.banned {
		key := rediscli.GetBruteForceBanKey(terminalCompletionRedisRoot, terminalCompletionClientIP+"/32")
		if err := storage.Set(key, terminalCompletionBucket); err != nil {
			t.Fatalf("seed ban key: %v", err)
		}
	}

	// A known account mapping makes the request an RWP candidate, as for the shadow ban hits.
	if testCase.knownAccount {
		field := accountcache.GetAccountMappingField(terminalCompletionUsername, definitions.ProtoIMAP, "")
		storage.HSet(rediscli.GetUserHashKey(terminalCompletionRedisRoot, terminalCompletionUsername), field,
			terminalCompletionUsername)
	}

	return client
}

// drainTerminalCompletions collects executed completions until the expected count arrives and a quiet period
// passes, so a duplicate completion is observed instead of racing the detached supervisor.
func drainTerminalCompletions(probe *nativeAuthExecutionProbe, want int32) []pluginapi.PostActionRequest {
	requests := make([]pluginapi.PostActionRequest, 0, want)
	deadline := time.After(5 * time.Second)

	for int32(len(requests)) < want {
		select {
		case request := <-probe.postActionRequests:
			requests = append(requests, request)
		case <-deadline:
			return requests
		}
	}

	quiet, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	for {
		select {
		case request := <-probe.postActionRequests:
			requests = append(requests, request)
		case <-quiet.Done():
			return requests
		}
	}
}

// countingAuthVerifier counts password verifications so tests can prove a rejected request never verified one.
type countingAuthVerifier struct {
	delegate nativeAuthOutcomeVerifier
	calls    atomic.Int32
}

// Verify counts the call and delegates to the configured deterministic verifier.
func (v *countingAuthVerifier) Verify(
	ctx *gin.Context,
	auth *core.AuthState,
	passDBs []*core.PassDBMap,
) (*core.PassDBResult, error) {
	v.calls.Add(1)

	return v.delegate.Verify(ctx, auth, passDBs)
}
