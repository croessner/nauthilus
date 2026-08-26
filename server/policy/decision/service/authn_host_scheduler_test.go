// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
)

const authnHostSchedulerFixture = `policy:
  namespaces:
    authn:
      providers:
        lua_environment_risk:
          kind: lua_environment
          script_path: risk.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          scheduler_guards:
            trusted_client:
              if: {attribute: caller.client_id, is: trusted-client}
              on_missing_attribute: run
          checkpoints:
            pre_auth:
              providers:
                - name: guarded
                  use: authn/lua_environment_risk
                  actions: [authenticate]
                  run_if: {auth_state: unauthenticated}
                  skip_if: [trusted_client]
                  observe_safe: true
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
      mode: observe
`

const authnHostDependencyOrderFixture = `policy:
  namespaces:
    authn:
      providers:
        lua_environment_primary:
          kind: lua_environment
          script_path: primary.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
        lua_environment_dependent:
          kind: lua_environment
          script_path: dependent.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          checkpoints:
            pre_auth:
              providers:
                - name: dependent
                  use: authn/lua_environment_dependent
                  after: [primary]
                - name: primary
                  use: authn/lua_environment_primary
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
`

const authnHostGenericDependencyFixture = `policy:
  namespaces:
    authn:
      providers:
        generic:
          kind: native
          module: test
          targets: [{action: authenticate}]
          executions: [host_sync]
        lua_environment_dependent:
          kind: lua_environment
          script_path: dependent.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          checkpoints:
            pre_auth:
              providers:
                - name: dependent
                  use: authn/lua_environment_dependent
                  after: [generic]
                - name: generic
                  use: authn/generic
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
`

const authnProtocolSchedulerFixture = `policy:
  namespaces:
    authn:
      condition_sets:
        strings:
          privileged_services: [imap]
      providers:
        lua_environment_service:
          kind: lua_environment
          script_path: service.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          scheduler_guards:
            service_allowed:
              if:
                attribute: request.protocol
                in: "@string.privileged_services"
              on_missing_attribute: run
          checkpoints:
            pre_auth:
              providers:
                - name: service
                  use: authn/lua_environment_service
                  skip_if: [service_allowed]
            auth_decision: {providers: []}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
`

// TestCheckpointRuntimeSchedulesExactHostInstanceWithGuards proves one scheduler authority owns host disposition.
func TestCheckpointRuntimeSchedulesExactHostInstanceWithGuards(t *testing.T) {
	runtime, target := authnHostSchedulerRuntime(t)
	facts := authnHostSchedulerFacts(t, true)

	directive, next, found, err := runtime.nextAuthnHostProvider(hostScheduleInput{
		target: target, checkpoint: string(policy.StagePreAuth), facts: facts, authenticated: false,
	})
	if err != nil {
		t.Fatalf("nextAuthnHostProvider() error = %v", err)
	}

	if !found || next != 1 || directive.instance.Name() != "guarded" ||
		directive.disposition != AuthnHostDispositionSkipped ||
		directive.reason != AuthnHostReasonSchedulerGuardPrefix+"trusted_client" {
		t.Fatalf("directive = %#v, next = %d, found = %t", directive, next, found)
	}
}

// TestAuthnHostSchedulerUsesCanonicalProtocolFact proves the frozen request.protocol mapping remains effective.
func TestAuthnHostSchedulerUsesCanonicalProtocolFact(t *testing.T) {
	runtime, target := compileAuthnHostSchedulerRuntime(t, authnProtocolSchedulerFixture)

	tests := []struct {
		name       string
		protocol   string
		wantReason string
		want       AuthnHostDisposition
	}{
		{name: "matching IMAP", protocol: "imap", want: AuthnHostDispositionSkipped, wantReason: AuthnHostReasonSchedulerGuardPrefix + "service_allowed"},
		{name: "nonmatching POP3", protocol: "pop3", want: AuthnHostDispositionRun, wantReason: AuthnHostReasonScheduled},
		{name: "missing protocol", want: AuthnHostDispositionRun, wantReason: AuthnHostReasonScheduled},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := authnProtocolFactsOrEmpty(t, test.protocol)

			directive, _, found, err := runtime.nextAuthnHostProvider(hostScheduleInput{
				target: target, checkpoint: string(policy.StagePreAuth), facts: facts,
			})
			if err != nil {
				t.Fatalf("nextAuthnHostProvider() error = %v", err)
			}

			if !found || directive.Disposition() != test.want || directive.Reason() != test.wantReason {
				t.Fatalf("directive = %#v, want %q/%q", directive, test.want, test.wantReason)
			}
		})
	}
}

// TestCheckpointRuntimeSchedulesHostInstancesInDependencyLevelOrder protects forward dependencies.
func TestCheckpointRuntimeSchedulesHostInstancesInDependencyLevelOrder(t *testing.T) {
	runtime, target := compileAuthnHostSchedulerRuntime(t, authnHostDependencyOrderFixture)

	first, cursor, found, err := runtime.nextAuthnHostProvider(hostScheduleInput{
		target: target, checkpoint: string(policy.StagePreAuth), states: make(map[string]providerState),
	})
	if err != nil {
		t.Fatalf("nextAuthnHostProvider() error = %v", err)
	}

	if !found || first.Instance().Name() != "primary" {
		t.Fatalf("first directive = %#v, found:%t, want primary", first, found)
	}

	second, _, found, err := runtime.nextAuthnHostProvider(hostScheduleInput{
		target: target, checkpoint: string(policy.StagePreAuth), cursor: cursor,
		states: map[string]providerState{"primary": providerStateCompleted},
	})
	if err != nil {
		t.Fatalf("second nextAuthnHostProvider() error = %v", err)
	}

	if !found || second.Instance().Name() != "dependent" {
		t.Fatalf("second directive = %#v, found:%t, want dependent", second, found)
	}
}

// TestCheckpointRuntimeRejectsHostDependencyOnEvaluatorProvider protects the pre-evaluation boundary.
func TestCheckpointRuntimeRejectsHostDependencyOnEvaluatorProvider(t *testing.T) {
	document, err := policyconfig.Decode("yaml", strings.NewReader(authnHostGenericDependencyFixture))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	input, err := configinput.Normalize(t.Context(), document)
	if err != nil {
		t.Fatalf("configinput.Normalize() error = %v", err)
	}

	catalog, err := input.Compile(t.Context(), &recordingEffectAcceptor{})
	if err != nil {
		t.Fatalf("UnifiedPolicyInput.Compile() error = %v", err)
	}

	_, err = newCheckpointRuntime(checkpointRuntimeConfig{catalog: catalog})
	if !errors.Is(err, ErrDecisionServiceDependencyMissing) {
		t.Fatalf("newCheckpointRuntime() error = %v, want ErrDecisionServiceDependencyMissing", err)
	}
}

// TestDecisionSessionRequiresExactHostScheduleExhaustion rejects partial or omitted host traversal.
func TestDecisionSessionRequiresExactHostScheduleExhaustion(t *testing.T) {
	runtime, _ := authnHostSchedulerRuntime(t)
	runAuthnHostSessionTest(t, 41, runtime, exerciseExactHostScheduleExhaustion)
}

// TestDecisionSessionRejectsInvalidAndMissingHostReceipts protects exact receipt correlation.
func TestDecisionSessionRejectsInvalidAndMissingHostReceipts(t *testing.T) {
	runtime, _ := authnHostSchedulerRuntime(t)
	runAuthnHostSessionTest(t, 44, runtime, exerciseInvalidAndMissingHostReceipts)
}

// TestDecisionSessionTerminalCompletionClosesRemainingExactHostInstances protects early host decisions.
func TestDecisionSessionTerminalCompletionClosesRemainingExactHostInstances(t *testing.T) {
	runtime, _ := compileAuthnHostSchedulerRuntime(t, authnHostDependencyOrderFixture)
	runAuthnHostSessionTest(t, 43, runtime, exerciseTerminalHostScheduleCompletion)
}

// runAuthnHostSessionTest owns the shared generation and session harness for scheduler assertions.
func runAuthnHostSessionTest(
	t *testing.T,
	generationID uint64,
	runtime *checkpointRuntime,
	exercise func(*testing.T, DecisionSession),
) {
	t.Helper()

	generation := mustRuntimeGeneration(
		t,
		generationID,
		&recordingCallerAuthenticator{caller: mustAuthorityCaller(t, true)},
		&recordingAdmissionAuthority{},
		runtime,
	)
	service := mustDecisionService(t, &replaceableGenerationSource{generation: generation})

	err := service.WithSession(
		t.Context(),
		mustAuthorityTargetInvocation(t, policy.AuthnNamespace, string(policy.OperationAuthenticate)),
		func(session DecisionSession) error {
			exercise(t, session)

			return nil
		},
	)
	if err != nil {
		t.Fatalf("DecisionService.WithSession() error = %v", err)
	}
}

// authnProtocolFactsOrEmpty constructs the canonical protocol facts or an empty set.
func authnProtocolFactsOrEmpty(t *testing.T, protocol string) decision.FactSet {
	t.Helper()

	if protocol == "" {
		return mustAuthorityEmptyFacts(t)
	}

	return authnProtocolSchedulerFacts(t, protocol)
}

// exerciseExactHostScheduleExhaustion verifies evaluation remains closed until exact traversal completes.
func exerciseExactHostScheduleExhaustion(t *testing.T, session DecisionSession) {
	t.Helper()

	checkpointName := string(policy.StagePreAuth)
	scheduler := mustAuthnHostExecutionSession(t, session)
	facts := authnHostSchedulerFacts(t, false)
	checkpoint := mustAuthnHostCheckpoint(t, checkpointName, facts)

	_, evaluationErr := session.Evaluate(t.Context(), checkpoint)
	requireDecisionEvaluationError(t, "Evaluate() before schedule", evaluationErr)

	directive := mustNextAuthnHostDirective(t, scheduler, AuthnHostScheduleInput{
		Facts: facts, Checkpoint: checkpointName,
	}, "", AuthnHostDispositionRun)
	mustRecordAuthnHostReceipt(t, scheduler, AuthnHostReceipt{
		Checkpoint: checkpointName, Instance: directive.Instance().Name(), State: AuthnHostReceiptCompleted,
	})

	requireDecisionEvaluationError(
		t,
		"nonterminal completion",
		scheduler.CompleteAuthnHostSchedule(checkpointName),
	)

	_, evaluationErr = session.Evaluate(t.Context(), checkpoint)
	requireDecisionEvaluationError(t, "Evaluate() before exhaustion", evaluationErr)
	requireAuthnHostScheduleExhausted(t, scheduler, AuthnHostScheduleInput{
		Facts: facts, Checkpoint: checkpointName, Authenticated: true,
	})
	mustEvaluateAuthnHostCheckpoint(t, session, checkpoint)
}

// exerciseInvalidAndMissingHostReceipts verifies strict callback correlation and single receipt use.
func exerciseInvalidAndMissingHostReceipts(t *testing.T, session DecisionSession) {
	t.Helper()

	checkpointName := string(policy.StagePreAuth)
	scheduler := mustAuthnHostExecutionSession(t, session)
	facts := authnHostSchedulerFacts(t, false)
	directive := mustNextAuthnHostDirective(t, scheduler, AuthnHostScheduleInput{
		Facts: facts, Checkpoint: checkpointName,
	}, "", AuthnHostDispositionRun)

	requireInvalidAuthnHostReceipts(t, scheduler, checkpointName, directive.Instance().Name())

	_, _, scheduleErr := scheduler.NextAuthnHostProvider(AuthnHostScheduleInput{
		Facts: facts, Checkpoint: checkpointName,
	})
	requireDecisionEvaluationError(t, "NextAuthnHostProvider() without receipt", scheduleErr)

	checkpoint := mustAuthnHostCheckpoint(t, checkpointName, facts)
	_, evaluationErr := session.Evaluate(t.Context(), checkpoint)
	requireDecisionEvaluationError(t, "Evaluate() without receipt", evaluationErr)

	receipt := AuthnHostReceipt{
		Checkpoint: checkpointName, Instance: directive.Instance().Name(), State: AuthnHostReceiptCompleted,
	}
	mustRecordAuthnHostReceipt(t, scheduler, receipt)
	requireDecisionEvaluationError(t, "duplicate RecordAuthnHostProvider()", scheduler.RecordAuthnHostProvider(receipt))
	requireAuthnHostScheduleExhausted(t, scheduler, AuthnHostScheduleInput{
		Facts: facts, Checkpoint: checkpointName,
	})
	mustEvaluateAuthnHostCheckpoint(t, session, checkpoint)
}

// exerciseTerminalHostScheduleCompletion verifies terminal closure records every remaining instance.
func exerciseTerminalHostScheduleCompletion(t *testing.T, session DecisionSession) {
	t.Helper()

	checkpointName := string(policy.StagePreAuth)
	scheduler := mustAuthnHostExecutionSession(t, session)
	directive := mustNextAuthnHostDirective(t, scheduler, AuthnHostScheduleInput{
		Checkpoint: checkpointName,
	}, "primary", AuthnHostDispositionRun)
	mustRecordAuthnHostReceipt(t, scheduler, AuthnHostReceipt{
		Checkpoint: checkpointName, Instance: directive.Instance().Name(), State: AuthnHostReceiptCompleted,
		Authenticated: true, Terminal: true,
	})

	if err := scheduler.CompleteAuthnHostSchedule(checkpointName); err != nil {
		t.Fatalf("CompleteAuthnHostSchedule() error = %v", err)
	}

	requireTerminalHostScheduleState(t, session)
	mustEvaluateAuthnHostCheckpoint(t, session, mustAuthnHostCheckpoint(t, checkpointName, mustAuthorityEmptyFacts(t)))
}

// mustAuthnHostExecutionSession resolves the exact scheduler boundary exposed by a decision session.
func mustAuthnHostExecutionSession(t *testing.T, session DecisionSession) AuthnHostExecutionSession {
	t.Helper()

	scheduler, ok := session.(AuthnHostExecutionSession)
	if !ok {
		t.Fatal("captured authn session has no exact host scheduler")
	}

	return scheduler
}

// mustAuthnHostCheckpoint constructs one checkpoint for scheduler session assertions.
func mustAuthnHostCheckpoint(t *testing.T, name string, facts decision.FactSet) decision.Checkpoint {
	t.Helper()

	checkpoint, err := decision.NewCheckpoint(name, facts)
	if err != nil {
		t.Fatalf("NewCheckpoint(%q) error = %v", name, err)
	}

	return checkpoint
}

// mustNextAuthnHostDirective returns one exact runnable directive or fails the current test.
func mustNextAuthnHostDirective(
	t *testing.T,
	scheduler AuthnHostExecutionSession,
	input AuthnHostScheduleInput,
	wantName string,
	wantDisposition AuthnHostDisposition,
) AuthnHostDirective {
	t.Helper()

	directive, found, err := scheduler.NextAuthnHostProvider(input)
	if err != nil || !found {
		t.Fatalf("NextAuthnHostProvider() = %#v, %t, %v", directive, found, err)
	}

	if directive.Disposition() != wantDisposition {
		t.Fatalf("directive disposition = %q, want %q", directive.Disposition(), wantDisposition)
	}

	if wantName != "" && directive.Instance().Name() != wantName {
		t.Fatalf("directive instance = %q, want %q", directive.Instance().Name(), wantName)
	}

	return directive
}

// mustRecordAuthnHostReceipt records one exact successful callback receipt.
func mustRecordAuthnHostReceipt(t *testing.T, scheduler AuthnHostExecutionSession, receipt AuthnHostReceipt) {
	t.Helper()

	if err := scheduler.RecordAuthnHostProvider(receipt); err != nil {
		t.Fatalf("RecordAuthnHostProvider() error = %v", err)
	}
}

// requireInvalidAuthnHostReceipts verifies each malformed receipt is rejected without consuming the callback.
func requireInvalidAuthnHostReceipts(
	t *testing.T,
	scheduler AuthnHostExecutionSession,
	checkpointName string,
	instanceName string,
) {
	t.Helper()

	receipts := []struct {
		name    string
		receipt AuthnHostReceipt
	}{
		{
			name: "wrong checkpoint",
			receipt: AuthnHostReceipt{
				Checkpoint: string(policy.StageAuthDecision), Instance: instanceName,
				State: AuthnHostReceiptCompleted,
			},
		},
		{
			name: "wrong instance",
			receipt: AuthnHostReceipt{
				Checkpoint: checkpointName, Instance: "other", State: AuthnHostReceiptCompleted,
			},
		},
		{
			name: "invalid state",
			receipt: AuthnHostReceipt{
				Checkpoint: checkpointName, Instance: instanceName, State: "invalid",
			},
		},
		{
			name: "terminal failure",
			receipt: AuthnHostReceipt{
				Checkpoint: checkpointName, Instance: instanceName,
				State: AuthnHostReceiptFailed, Terminal: true,
			},
		},
	}

	for _, test := range receipts {
		t.Run(test.name, func(t *testing.T) {
			requireDecisionEvaluationError(t, "RecordAuthnHostProvider()", scheduler.RecordAuthnHostProvider(test.receipt))
		})
	}
}

// requireAuthnHostScheduleExhausted verifies that no further host directive remains.
func requireAuthnHostScheduleExhausted(
	t *testing.T,
	scheduler AuthnHostExecutionSession,
	input AuthnHostScheduleInput,
) {
	t.Helper()

	_, found, err := scheduler.NextAuthnHostProvider(input)
	if err != nil || found {
		t.Fatalf("schedule exhaustion = found:%t err:%v", found, err)
	}
}

// requireDecisionEvaluationError verifies the closed scheduler error identity.
func requireDecisionEvaluationError(t *testing.T, operation string, err error) {
	t.Helper()

	if !errors.Is(err, ErrDecisionEvaluation) {
		t.Fatalf("%s error = %v, want ErrDecisionEvaluation", operation, err)
	}
}

// requireTerminalHostScheduleState verifies terminal completion closes the dependent instance.
func requireTerminalHostScheduleState(t *testing.T, session DecisionSession) {
	t.Helper()

	concrete, ok := session.(*decisionSession)
	if !ok {
		t.Fatal("captured authn session has no concrete scheduler state")
	}

	if concrete.hostStates["dependent"] != providerStateSkipped ||
		concrete.hostReasons["dependent"] != AuthnHostReasonTerminal || !concrete.hostAuthn {
		t.Fatalf(
			"terminal dependent receipt = %q/%q, want skipped/terminal",
			concrete.hostStates["dependent"],
			concrete.hostReasons["dependent"],
		)
	}
}

// mustEvaluateAuthnHostCheckpoint requires the post-scheduler checkpoint to evaluate successfully.
func mustEvaluateAuthnHostCheckpoint(t *testing.T, session DecisionSession, checkpoint decision.Checkpoint) {
	t.Helper()

	if _, err := session.Evaluate(t.Context(), checkpoint); err != nil {
		t.Fatalf("Evaluate() after exhaustion error = %v", err)
	}
}

func TestCheckpointRuntimeReconcilesExactHostReceiptWithoutGuardReplay(t *testing.T) {
	runtime, target := authnHostSchedulerRuntime(t)

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion,
		Target:  target,
	}, mustAuthorityCaller(t, true))
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	facts := authnHostSchedulerFacts(t, false)

	checkpoint, err := decision.NewCheckpoint(string(policy.StagePreAuth), facts)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}

	outcome, err := runtime.Evaluate(t.Context(), checkpointEvaluation{
		request:       request,
		checkpoint:    checkpoint,
		hostStates:    map[string]providerState{"guarded": providerStateCompleted},
		hostReasons:   map[string]string{"guarded": AuthnHostReasonScheduled},
		supervisor:    &recordingEffectAcceptor{},
		generation:    42,
		authenticated: true,
		finalization:  decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	})
	if err != nil {
		t.Fatalf("checkpointRuntime.Evaluate() error = %v", err)
	}

	want := providerRecord{
		id: "guarded", use: "authn/lua_environment_risk", reason: AuthnHostReasonScheduled,
		state: providerStateCompleted,
	}
	if len(outcome.report.runtime.providers) != 1 || outcome.report.runtime.providers[0] != want {
		t.Fatalf("provider report = %#v, want %#v", outcome.report.runtime.providers, want)
	}
}

// authnHostSchedulerRuntime compiles one exact observe-safe host schedule.
func authnHostSchedulerRuntime(t *testing.T) (*checkpointRuntime, decision.Target) {
	t.Helper()

	return compileAuthnHostSchedulerRuntime(t, authnHostSchedulerFixture)
}

// compileAuthnHostSchedulerRuntime compiles one exact configured host schedule.
func compileAuthnHostSchedulerRuntime(
	t *testing.T,
	fixture string,
) (*checkpointRuntime, decision.Target) {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	input, err := configinput.Normalize(t.Context(), document)
	if err != nil {
		t.Fatalf("configinput.Normalize() error = %v", err)
	}

	catalog, err := input.Compile(t.Context(), &recordingEffectAcceptor{})
	if err != nil {
		t.Fatalf("UnifiedPolicyInput.Compile() error = %v", err)
	}

	conditionSets, timeWindows, err := configinput.PrepareConditionMaterial(input.Policy)
	if err != nil {
		t.Fatalf("PrepareConditionMaterial() error = %v", err)
	}

	runtime, err := newCheckpointRuntime(checkpointRuntimeConfig{
		catalog: catalog, conditionSets: conditionSets, timeWindows: timeWindows,
	})
	if err != nil {
		t.Fatalf("newCheckpointRuntime() error = %v", err)
	}

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return runtime, target
}

// authnProtocolSchedulerFacts constructs the canonical protocol fact admitted by the authn schema.
func authnProtocolSchedulerFacts(t *testing.T, protocol string) decision.FactSet {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &protocol})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "caller", "protocol")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	fact, err := decision.NewFact(
		policy.AuthnFactProtocol,
		decision.FactCategoryEnvironment,
		value,
		provenance,
	)
	if err != nil {
		t.Fatalf("NewFact() error = %v", err)
	}

	facts, err := decision.NewFactSet([]decision.Fact{fact})
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return facts
}

// authnHostSchedulerFacts constructs one exact authenticator-owned guard input fact.
func authnHostSchedulerFacts(t *testing.T, trusted bool) decision.FactSet {
	t.Helper()

	clientID := "untrusted-client"
	if trusted {
		clientID = "trusted-client"
	}

	value, err := decision.NewValue(decision.ValueInput{String: &clientID})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	provenance, err := decision.NewProvenance(decision.FactSourceNauthilus, "test-authority", "authenticator")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	fact, err := decision.NewFact(decision.FactCallerClientID, decision.FactCategoryEnvironment, value, provenance)
	if err != nil {
		t.Fatalf("NewFact() error = %v", err)
	}

	facts, err := decision.NewFactSet([]decision.Fact{fact})
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	return facts
}
