// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const providerInstanceExecutionFixture = `policy:
  namespaces:
    mail:
      schema_contributions:
        static:
          submit:
            versions:
              v1: {facts: []}
      providers:
        shared:
          kind: native
          targets: [{action: submit}]
          executions: [host_sync]
          failure: indeterminate
          timeout: 1s
      domain_plans:
        default:
          checkpoints:
            final_decision:
              providers:
                - name: primary
                  use: mail/shared
                - name: dependent
                  use: mail/shared
                  after: [primary]
      policy_sets:
        default:
          rules:
            - name: instance_state_authority
              checkpoint: final_decision
              require_providers: [dependent]
              if: {always: true}
              then: {decision: permit}
  targets:
    - namespace: mail
      action: submit
      schema: mail/submit/v1
      domain_plan: mail/default
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 1s}
      plans:
        final_decision:
          policy_sets: [mail/default]
`

const providerInstanceOutputFact = "plugin.instance.output"

func TestPolicyCompiledPlanExecutesProviderInstancesAfterDependencies(t *testing.T) {
	harness := newProviderInstanceExecutionHarness(t)
	outcome := harness.evaluate(t)

	assertProviderInstanceOutcome(t, outcome, harness.provider)
}

type providerInstanceExecutionHarness struct {
	evaluator *checkpointRuntime
	provider  *sequencedInstanceProvider
	target    decision.Target
}

type providerInstanceEvaluationResult struct {
	outcome runtimeEvaluation
	err     error
}

// newProviderInstanceExecutionHarness owns the compiled schedule and shared host binding.
func newProviderInstanceExecutionHarness(t *testing.T) providerInstanceExecutionHarness {
	t.Helper()

	catalog, target := compileProviderInstanceExecutionCatalog(t)

	checkpoint, ok := catalogCheckpoint(catalog, target, decision.CheckpointFinalDecision)
	if !ok {
		t.Fatal("compiled final_decision checkpoint is missing")
	}

	assertProviderInstanceLevels(t, checkpoint)

	provider := newSequencedInstanceProvider()
	t.Cleanup(provider.releasePrimary)

	evaluator, err := newCheckpointRuntime(checkpointRuntimeConfig{
		catalog: catalog,
		factProviders: map[string]factProviderBinding{
			"mail/shared": {
				provider: provider, source: decision.FactSourcePlugin, authority: "shared", component: "mail/shared",
			},
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newCheckpointRuntime() error = %v", err)
	}

	return providerInstanceExecutionHarness{evaluator: evaluator, provider: provider, target: target}
}

// evaluate proves the dependent instance remains blocked until its predecessor completes.
func (h providerInstanceExecutionHarness) evaluate(t *testing.T) runtimeEvaluation {
	t.Helper()

	evaluation := providerInstanceEvaluation(t, h.target)
	results := make(chan providerInstanceEvaluationResult, 1)

	go func() {
		outcome, err := h.evaluator.Evaluate(context.Background(), evaluation)

		results <- providerInstanceEvaluationResult{outcome: outcome, err: err}
	}()

	waitForInstanceSignal(t, h.provider.primaryStarted, "primary provider instance start")

	select {
	case <-h.provider.dependentStarted:
		h.provider.releasePrimary()
		t.Fatal("dependent provider instance started before primary completed")
	case <-time.After(100 * time.Millisecond):
	}

	h.provider.releasePrimary()
	waitForInstanceSignal(t, h.provider.dependentStarted, "dependent provider instance start")

	result := <-results
	if result.err != nil {
		t.Fatalf("checkpointRuntime.Evaluate() error = %v", result.err)
	}

	return result.outcome
}

// assertProviderInstanceLevels verifies the compiled local-name dependency topology.
func assertProviderInstanceLevels(t *testing.T, checkpoint policyruntime.CompiledCheckpoint) {
	t.Helper()

	want := [][]string{{"primary"}, {"dependent"}}
	if got := checkpoint.ProviderLevels(); !slices.EqualFunc(got, want, func(left, right []string) bool {
		return slices.Equal(left, right)
	}) {
		t.Fatalf("provider levels = %v, want %v", got, want)
	}
}

// assertProviderInstanceOutcome verifies instance-keyed state and shared-use invocation evidence.
func assertProviderInstanceOutcome(
	t *testing.T,
	outcome runtimeEvaluation,
	provider *sequencedInstanceProvider,
) {
	t.Helper()

	if outcome.response.Effect() != decision.EffectPermit {
		t.Fatalf("effect = %q, want permit from dependent instance requirement", outcome.response.Effect())
	}

	want := []providerRecord{
		{id: "primary", state: providerStateCompleted},
		{id: "dependent", state: providerStateCompleted},
	}
	if !slices.Equal(outcome.report.runtime.providers, want) {
		t.Fatalf("provider report = %#v, want instance identities %#v", outcome.report.runtime.providers, want)
	}

	if provider.callCount() != 2 {
		t.Fatalf("shared host-provider calls = %d, want one per provider instance", provider.callCount())
	}
}

func TestPolicyCompiledPlanAdmissionRecognizesInstanceOutput(t *testing.T) {
	catalog, target := providerInstanceOutputCatalog(t)

	compiled, ok := catalog.Lookup(target)

	if !ok {
		t.Fatal("compiled output target is missing")
	}

	checkpoint, ok := compiled.DomainPlan().Checkpoint(decision.CheckpointFinalDecision)

	if !ok {
		t.Fatal("compiled output checkpoint is missing")
	}

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	if err = validateAdmittedFacts(facts, compiled, checkpoint); err != nil {
		t.Fatalf("validateAdmittedFacts() rejected instance-declared output: %v", err)
	}
}

func TestPolicyCompiledPlanExecutesInstanceDeclaredOutput(t *testing.T) {
	catalog, target := providerInstanceOutputCatalog(t)
	provider := &recordingFactProvider{facts: []providedFact{{
		id: providerInstanceOutputFact, category: decision.FactCategoryEnvironment,
		value: runtimeStringValue(t, "accepted"),
	}}}

	evaluator, err := newCheckpointRuntime(checkpointRuntimeConfig{
		catalog: catalog,
		factProviders: map[string]factProviderBinding{
			"mail/output": {
				provider: provider, source: decision.FactSourcePlugin,
				authority: "instance", component: "mail/output",
			},
		},
		ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("newCheckpointRuntime() error = %v", err)
	}

	outcome, err := evaluator.Evaluate(context.Background(), providerInstanceEvaluation(t, target))
	if err != nil {
		t.Fatalf("checkpointRuntime.Evaluate() error = %v", err)
	}

	wantProviders := []providerRecord{{id: "output", state: providerStateCompleted}}
	if !slices.Equal(outcome.report.runtime.providers, wantProviders) {
		t.Fatalf(
			"provider report = %#v, want %#v; effect = %q",
			outcome.report.runtime.providers,
			wantProviders,
			outcome.response.Effect(),
		)
	}

	fact, ok := outcome.report.runtime.facts.Get(providerInstanceOutputFact)
	if !ok {
		t.Fatalf("runtime facts do not contain instance-declared output %q", providerInstanceOutputFact)
	}

	if got, ok := fact.Value().StringValue(); !ok || got != "accepted" {
		t.Fatalf("instance-declared output value = %q, %t, want accepted, true", got, ok)
	}

	if got := outcome.response.Effect(); got != decision.EffectDeny {
		t.Fatalf("effect = %q, want normal no-match deny after accepting instance-declared output", got)
	}
}

// compileProviderInstanceExecutionCatalog builds the standalone configuration path under test.
func compileProviderInstanceExecutionCatalog(t *testing.T) (*policyruntime.TargetCatalog, decision.Target) {
	t.Helper()

	document, err := policyconfig.Decode("yaml", strings.NewReader(providerInstanceExecutionFixture))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	input, err := configinput.Normalize(context.Background(), document)
	if err != nil {
		t.Fatalf("configinput.Normalize() error = %v", err)
	}

	catalog, err := input.Compile(context.Background(), &recordingEffectAcceptor{})
	if err != nil {
		t.Fatalf("UnifiedPolicyInput.Compile() error = %v", err)
	}

	target, err := decision.NewTarget("mail", "submit")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return catalog, target
}

// catalogCheckpoint resolves one exact compiled checkpoint for scheduling assertions.
func catalogCheckpoint(
	catalog *policyruntime.TargetCatalog,
	target decision.Target,
	checkpoint string,
) (policyruntime.CompiledCheckpoint, bool) {
	compiled, ok := catalog.Lookup(target)
	if !ok {
		return policyruntime.CompiledCheckpoint{}, false
	}

	return compiled.DomainPlan().Checkpoint(checkpoint)
}

// providerInstanceOutputCatalog constructs a required fact produced only through instance metadata.
func providerInstanceOutputCatalog(t *testing.T) (*policyruntime.TargetCatalog, decision.Target) {
	t.Helper()

	target, schema, provider, instance := providerInstanceOutputDefinitions(t)

	checkpoint, err := registry.NewCheckpointDefinitionWithProviderInstances(
		decision.CheckpointFinalDecision,
		nil,
		[]registry.ProviderInstanceDefinition{instance},
	)
	if err != nil {
		t.Fatalf("NewCheckpointDefinitionWithProviderInstances() error = %v", err)
	}

	plan, err := registry.NewDomainPlanDefinition(target, []registry.CheckpointDefinition{checkpoint})
	if err != nil {
		t.Fatalf("NewDomainPlanDefinition() error = %v", err)
	}

	catalog, err := policyruntime.NewTargetCatalog([]policyruntime.TargetCatalogRecord{{
		Target: target, Schema: schema, SourcePlan: plan, Providers: []registry.ProviderDefinition{provider},
		Checkpoints: []policyruntime.CheckpointRecord{{
			Name: decision.CheckpointFinalDecision, ProviderIDs: []string{provider.ID()},
			ProviderInstances: []registry.ProviderInstanceDefinition{instance},
		}},
		NoMatch: registry.NoMatchDeny, AuthorityMode: registry.AuthorityModeEnforce,
	}})
	if err != nil {
		t.Fatalf("NewTargetCatalog() error = %v", err)
	}

	return catalog, target
}

// providerInstanceOutputDefinitions constructs the schema, provider, and instance metadata under test.
func providerInstanceOutputDefinitions(
	t *testing.T,
) (decision.Target, registry.SchemaDefinition, registry.ProviderDefinition, registry.ProviderInstanceDefinition) {
	t.Helper()

	target, err := decision.NewTarget("mail", "submit")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	identity, err := registry.NewSchemaIdentity("mail", "submit", "v1")
	if err != nil {
		t.Fatalf("NewSchemaIdentity() error = %v", err)
	}

	schema, err := registry.NewSchemaDefinition(identity, []registry.FactSchema{
		decisionRuntimeFactSchema(t, providerInstanceOutputFact, decision.FactSourcePlugin, true),
	})
	if err != nil {
		t.Fatalf("NewSchemaDefinition() error = %v", err)
	}

	provider, err := registry.NewProviderDefinition(registry.ProviderDefinitionInput{
		ID: "mail/output", Targets: []decision.Target{target}, Executions: []registry.ExecutionClass{registry.ExecutionHostSync},
		Failure: registry.ProviderFailureIndeterminate, Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewProviderDefinition() error = %v", err)
	}

	instance, err := registry.NewProviderInstanceDefinition(registry.ProviderInstanceDefinitionInput{
		Path: "mail/default/final_decision/output", Name: "output", Use: provider.ID(), Output: providerInstanceOutputFact,
	})
	if err != nil {
		t.Fatalf("NewProviderInstanceDefinition() error = %v", err)
	}

	return target, schema, provider, instance
}

// providerInstanceEvaluation constructs one exact generic checkpoint invocation.
func providerInstanceEvaluation(t *testing.T, target decision.Target) checkpointEvaluation {
	t.Helper()

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version: decision.ContractVersion, RequestID: "provider-instance-execution", Target: target,
	}, mustAuthorityCaller(t, false))
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	facts, err := decision.NewFactSet(nil)
	if err != nil {
		t.Fatalf("NewFactSet() error = %v", err)
	}

	checkpoint, err := decision.NewCheckpoint(decision.CheckpointFinalDecision, facts)
	if err != nil {
		t.Fatalf("NewCheckpoint() error = %v", err)
	}

	return checkpointEvaluation{
		request: request, checkpoint: checkpoint, supervisor: &recordingEffectAcceptor{}, generation: 1,
		finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	}
}

type sequencedInstanceProvider struct {
	primaryStarted   chan struct{}
	release          chan struct{}
	dependentStarted chan struct{}
	releaseOnce      sync.Once
	mu               sync.Mutex
	calls            int
}

// newSequencedInstanceProvider constructs a shared host implementation with observable call order.
func newSequencedInstanceProvider() *sequencedInstanceProvider {
	return &sequencedInstanceProvider{
		primaryStarted: make(chan struct{}), release: make(chan struct{}), dependentStarted: make(chan struct{}),
	}
}

// Collect blocks the first instance until the test explicitly completes its dependency level.
func (p *sequencedInstanceProvider) Collect(ctx context.Context, _ factProviderInput) ([]providedFact, error) {
	p.mu.Lock()
	p.calls++
	call := p.calls
	p.mu.Unlock()

	if call == 1 {
		close(p.primaryStarted)

		select {
		case <-p.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if call == 2 {
		close(p.dependentStarted)
	}

	return nil, nil
}

// releasePrimary completes the first instance exactly once.
func (p *sequencedInstanceProvider) releasePrimary() {
	p.releaseOnce.Do(func() { close(p.release) })
}

// callCount returns the synchronized shared binding invocation count.
func (p *sequencedInstanceProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.calls
}

// waitForInstanceSignal fails one bounded scheduling handshake deterministically.
func waitForInstanceSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()

	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}
