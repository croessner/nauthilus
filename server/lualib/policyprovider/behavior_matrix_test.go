// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package policyprovider_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/lualib/policyprovider"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	behaviorMatrixAuthority = "matrix"
	behaviorMatrixFactID    = "lua.matrix.risk.label"
)

func TestLuaFactCollectorClosedResultBehaviorMatrix(t *testing.T) {
	script := mustCompileFixture(t, "behavior_matrix_facts.lua")
	collector := mustBehaviorMatrixFactCollector(t, script, "fact-provider")

	tests := []struct {
		name       string
		mode       string
		wantResult bool
	}{
		{name: "declared fact", mode: "success", wantResult: true},
		{name: "wrong type", mode: "wrong_type"},
		{name: "undeclared fact", mode: "undeclared"},
		{name: "local authority prefix", mode: "local_authority_prefix"},
		{name: "foreign authority", mode: "foreign_authority"},
		{name: "forbidden source", mode: "forbidden_source"},
		{name: "forbidden namespace", mode: "forbidden_namespace"},
		{name: "duplicate fact", mode: "duplicate"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := collector.Collect(t.Context(), behaviorMatrixFactRequest(t, test.mode))
			if test.wantResult {
				assertBehaviorMatrixFactSuccess(t, result, err)

				return
			}

			assertBehaviorMatrixInvalidResult(t, result, err)
		})
	}
}

func TestLuaFactCollectorRejectsWrongTargetBeforeCallback(t *testing.T) {
	collector := mustBehaviorMatrixFactCollector(
		t,
		mustCompileFixture(t, "behavior_matrix_facts.lua"),
		"target-provider",
	)
	request := behaviorMatrixFactRequest(t, "lua_error")
	request.Target.Action = "deliver"

	result, err := collector.Collect(t.Context(), request)
	if !errors.Is(err, policyprovider.ErrCallbackInput) || errors.Is(err, policyprovider.ErrCallbackExecution) {
		t.Fatalf("Collect(wrong target) error = %v, want pre-callback input rejection", err)
	}

	if result.ErrorClass != policyprovider.ErrorClassInvalidInput {
		t.Fatalf("Collect(wrong target) error class = %q, want invalid_input", result.ErrorClass)
	}

	if strings.Contains(err.Error(), "behavior-matrix-fact-secret") {
		t.Fatalf("wrong-target rejection exposed callback text: %v", err)
	}
}

func TestLuaFactCollectorContainsRegistrationAndExecutionErrors(t *testing.T) {
	t.Run("missing exact callback", func(t *testing.T) {
		script := mustCompileFixture(t, "behavior_matrix_missing_fact_callback.lua")

		_, err := policyprovider.NewLuaFactCollector(
			t.Context(),
			script,
			behaviorMatrixFactDescriptor("missing-provider"),
		)
		if !errors.Is(err, policyprovider.ErrCallbackRegistration) {
			t.Fatalf("NewLuaFactCollector() error = %v, want callback registration", err)
		}

		if strings.Contains(err.Error(), "behavior_matrix_missing_fact_callback") {
			t.Fatalf("registration error exposed configured path: %v", err)
		}
	})

	t.Run("protected Lua error", func(t *testing.T) {
		collector := mustBehaviorMatrixFactCollector(
			t,
			mustCompileFixture(t, "behavior_matrix_facts.lua"),
			"error-provider",
		)

		result, err := collector.Collect(t.Context(), behaviorMatrixFactRequest(t, "lua_error"))
		if !errors.Is(err, policyprovider.ErrCallbackExecution) || errors.Is(err, policyprovider.ErrInvalidResult) {
			t.Fatalf("Collect(Lua error) error = %v, want callback execution only", err)
		}

		if result.ErrorClass != policyprovider.ErrorClassInternal {
			t.Fatalf("Collect(Lua error) class = %q, want internal", result.ErrorClass)
		}

		if strings.Contains(err.Error(), "behavior-matrix-fact-secret") {
			t.Fatalf("callback error exposed Lua text: %v", err)
		}
	})
}

func TestLuaGenerationContainsCollectorPanic(t *testing.T) {
	collector := &behaviorMatrixPanickingCollector{
		descriptor: behaviorMatrixFactDescriptor("panic-provider"),
	}
	prepared := mustBehaviorMatrixGeneration(t, []policyprovider.FactProviderRegistration{{
		Collector: collector,
		Failure:   registry.ProviderFailureContinue,
	}}, nil)

	preparation, err := prepared.ExtensionPreparation(nil)
	if err != nil {
		t.Fatalf("ExtensionPreparation() error = %v", err)
	}

	binding := preparation.Bindings.FactProviders()["mail/lua.matrix.panic-provider"]

	_, err = binding.Provider.Collect(t.Context(), mustGenerationFactInput(t))
	if !errors.Is(err, policyruntime.ErrProviderContractViolation) {
		t.Fatalf("Collect(panic) error = %v, want provider contract violation", err)
	}

	if strings.Contains(err.Error(), "behavior-matrix-panic-secret") {
		t.Fatalf("panic containment exposed panic value: %v", err)
	}
}

func TestLuaEffectExecutorRejectsUnselectedAndPreservesOutcomeUnknown(t *testing.T) {
	script := mustCompileFixture(t, "behavior_matrix_effects.lua")
	descriptor := behaviorMatrixEffectDescriptor(
		"effect-provider",
		"matrix-effect",
		policyprovider.EffectExecutionHostSync,
	)
	executor := mustBehaviorMatrixEffectExecutor(t, script, descriptor)

	unselected := behaviorMatrixEffectRequest(t, "mail/unselected", "called")

	result, err := executor.Execute(t.Context(), unselected)
	if !errors.Is(err, policyprovider.ErrCallbackInput) || errors.Is(err, policyprovider.ErrCallbackExecution) {
		t.Fatalf("Execute(unselected) error = %v, want pre-callback input rejection", err)
	}

	if result.State != policyprovider.EffectStateFailed || result.ErrorClass != policyprovider.ErrorClassInvalidInput {
		t.Fatalf("Execute(unselected) result = %#v", result)
	}

	if strings.Contains(err.Error(), "behavior-matrix-effect-secret") {
		t.Fatalf("unselected rejection exposed callback text: %v", err)
	}

	result, err = executor.Execute(t.Context(), behaviorMatrixEffectRequest(t, "mail/matrix-effect", "unknown"))
	if err != nil {
		t.Fatalf("Execute(outcome_unknown) error = %v", err)
	}

	if result.State != policyprovider.EffectStateOutcomeUnknown || result.ErrorClass != policyprovider.ErrorClassUnavailable {
		t.Fatalf("Execute(outcome_unknown) result = %#v", result)
	}
}

func TestLuaPostActionRunsOnlyThroughExecutableWorkAndCleansUp(t *testing.T) {
	descriptor := behaviorMatrixEffectDescriptor(
		"post-provider",
		"matrix-post",
		policyprovider.EffectExecutionHostPostAction,
	)
	realExecutor := mustBehaviorMatrixEffectExecutor(
		t,
		mustCompileFixture(t, "behavior_matrix_effects.lua"),
		descriptor,
	)
	executor := &behaviorMatrixCountingExecutor{delegate: realExecutor}
	prepared := mustBehaviorMatrixGeneration(t, nil, []policyprovider.EffectProviderRegistration{{
		Executor: executor,
	}})

	preparation, err := prepared.ExtensionPreparation(nil)
	if err != nil {
		t.Fatalf("ExtensionPreparation() error = %v", err)
	}

	provider := preparation.Bindings.PostActions()["mail/lua.matrix.post-provider"]

	work, err := provider.Prepare(t.Context(), behaviorMatrixEffectExecution(t))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	if calls := executor.calls.Load(); calls != 0 {
		t.Fatalf("callback calls after Prepare() = %d, want 0", calls)
	}

	executable, ok := work.(effectsupervisor.ExecutableWork)
	if !ok {
		t.Fatalf("prepared work type = %T, want ExecutableWork", work)
	}

	if result := executable.Execute(t.Context()); result.State() != effectsupervisor.StateSucceeded {
		t.Fatalf("Execute() state = %q, want succeeded", result.State())
	}

	if calls := executor.calls.Load(); calls != 1 {
		t.Fatalf("callback calls after Execute() = %d, want 1", calls)
	}

	executable.Cleanup()
	executable.Cleanup()

	if err = executable.Validate(); !errors.Is(err, effectsupervisor.ErrInvalidWork) {
		t.Fatalf("Validate(after cleanup) error = %v, want invalid work", err)
	}

	if result := executable.Execute(t.Context()); result.State() != effectsupervisor.StateFailed {
		t.Fatalf("Execute(after cleanup) state = %q, want failed", result.State())
	}

	if calls := executor.calls.Load(); calls != 1 {
		t.Fatalf("callback calls after cleanup = %d, want 1", calls)
	}
}

func TestLuaCatalogRejectsTwoProvidersClaimingOneQualifiedFact(t *testing.T) {
	script := mustCompileFixture(t, "behavior_matrix_facts.lua")
	first := mustBehaviorMatrixFactCollector(t, script, "first-provider")
	second := mustBehaviorMatrixFactCollector(t, script, "second-provider")
	prepared := mustBehaviorMatrixGeneration(t, []policyprovider.FactProviderRegistration{
		{Collector: first, Failure: registry.ProviderFailureIndeterminate},
		{Collector: second, Failure: registry.ProviderFailureIndeterminate},
	}, nil)

	preparation, err := prepared.ExtensionPreparation(nil)
	if err != nil {
		t.Fatalf("ExtensionPreparation() error = %v", err)
	}

	base := behaviorMatrixCatalogContribution(t, []string{
		"mail/lua.matrix.first-provider",
		"mail/lua.matrix.second-provider",
	})
	activation := mustBehaviorMatrixActivation(t)
	catalogCompiler := compiler.NewTargetCatalogCompiler(
		behaviorMatrixContributor{contribution: base},
		behaviorMatrixContributor{contribution: preparation.Definitions[0]},
	)

	_, err = catalogCompiler.Compile(t.Context(), []registry.TargetActivation{activation})
	if !errors.Is(err, policyruntime.ErrInvalidCompiledTarget) {
		t.Fatalf("Compile() error = %v, want invalid compiled target", err)
	}

	if !strings.Contains(err.Error(), "both produce fact "+behaviorMatrixFactID) {
		t.Fatalf("Compile() error = %v, want exact fact collision", err)
	}
}

// behaviorMatrixFactDescriptor declares one local output for exact-target matrix cases.
func behaviorMatrixFactDescriptor(name string) policyprovider.FactProviderDescriptor {
	return policyprovider.FactProviderDescriptor{
		Namespace: "mail",
		Name:      name,
		Targets: []policyprovider.TargetSelector{{
			Namespace: "mail",
			Action:    "filter",
		}},
		Outputs: []policyprovider.FactOutputDescriptor{{
			Name:      "risk.label",
			Category:  decision.FactCategoryEnvironment,
			Kind:      decision.ValueKindString,
			MaxLength: 32,
		}},
		Timeout: 100 * time.Millisecond,
	}
}

// mustBehaviorMatrixFactCollector constructs one real restricted collector.
func mustBehaviorMatrixFactCollector(
	t *testing.T,
	script *policyprovider.Script,
	name string,
) *policyprovider.LuaFactCollector {
	t.Helper()

	collector, err := policyprovider.NewLuaFactCollector(t.Context(), script, behaviorMatrixFactDescriptor(name))
	if err != nil {
		t.Fatalf("NewLuaFactCollector() error = %v", err)
	}

	return collector
}

// behaviorMatrixFactRequest selects one fixture path through redacted caller metadata.
func behaviorMatrixFactRequest(t *testing.T, mode string) policyprovider.FactRequest {
	t.Helper()

	request := validFactRequest(t)
	request.Target = policyprovider.TargetSelector{Namespace: "mail", Action: "filter"}
	request.Caller.ClientID = mode

	return request
}

// assertBehaviorMatrixFactSuccess verifies the sole declared success output.
func assertBehaviorMatrixFactSuccess(t *testing.T, result policyprovider.FactResult, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("Collect(success) error = %v", err)
	}

	if len(result.Facts) != 1 || result.Facts[0].Name != "risk.label" {
		t.Fatalf("Collect(success) facts = %#v", result.Facts)
	}

	value, ok := result.Facts[0].Value.StringValue()
	if !ok || value != "accepted" {
		t.Fatalf("Collect(success) value = %q, valid = %t", value, ok)
	}
}

// assertBehaviorMatrixInvalidResult verifies one closed typed-result rejection.
func assertBehaviorMatrixInvalidResult(t *testing.T, result policyprovider.FactResult, err error) {
	t.Helper()

	if !errors.Is(err, policyprovider.ErrCallbackExecution) || !errors.Is(err, policyprovider.ErrInvalidResult) {
		t.Fatalf("Collect(invalid result) error = %v, want execution and invalid-result classes", err)
	}

	if result.ErrorClass != policyprovider.ErrorClassInternal {
		t.Fatalf("Collect(invalid result) class = %q, want internal", result.ErrorClass)
	}

	if strings.Contains(err.Error(), "accepted") || strings.Contains(err.Error(), "risk.label") {
		t.Fatalf("invalid-result error exposed callback output: %v", err)
	}
}

// behaviorMatrixEffectDescriptor declares one selected host effect and bounded mode parameter.
func behaviorMatrixEffectDescriptor(
	name string,
	effectName string,
	execution policyprovider.EffectExecution,
) policyprovider.EffectProviderDescriptor {
	return policyprovider.EffectProviderDescriptor{
		Namespace: "mail",
		Name:      name,
		Effects: []policyprovider.EffectDescriptor{{
			Name:      effectName,
			Targets:   []policyprovider.TargetSelector{{Namespace: "mail", Action: "filter"}},
			Execution: execution,
			Parameters: []policyprovider.ParameterDescriptor{{
				Name:           "message",
				Kind:           decision.ValueKindString,
				MaxLength:      16,
				AllowedStrings: []string{"called", "post", "unknown"},
				NonEmpty:       true,
				Required:       true,
			}},
		}},
	}
}

// mustBehaviorMatrixEffectExecutor constructs one real restricted effect executor.
func mustBehaviorMatrixEffectExecutor(
	t *testing.T,
	script *policyprovider.Script,
	descriptor policyprovider.EffectProviderDescriptor,
) *policyprovider.LuaEffectExecutor {
	t.Helper()

	executor, err := policyprovider.NewLuaEffectExecutor(t.Context(), script, descriptor)
	if err != nil {
		t.Fatalf("NewLuaEffectExecutor() error = %v", err)
	}

	return executor
}

// behaviorMatrixEffectRequest constructs one exact selected-effect callback request.
func behaviorMatrixEffectRequest(t *testing.T, effectID string, mode string) policyprovider.EffectRequest {
	t.Helper()

	request := validEffectRequest(t)
	request.Target = policyprovider.TargetSelector{Namespace: "mail", Action: "filter"}
	request.Effect = effectID
	request.Parameters[0].Value = mustExecutorStringValue(t, mode)

	return request
}

// behaviorMatrixEffectExecution constructs one immutable post-action selection.
func behaviorMatrixEffectExecution(t *testing.T) policyruntime.EffectExecution {
	t.Helper()

	parameters, err := decision.NewValueMap(map[string]decision.Value{
		"message": mustExecutorStringValue(t, "post"),
	})
	if err != nil {
		t.Fatalf("NewValueMap() error = %v", err)
	}

	execution, err := policyruntime.NewEffectExecution(policyruntime.EffectExecutionInput{
		Facts:      mustGenerationFacts(t),
		Caller:     mustGenerationCaller(t),
		Parameters: parameters,
		Target:     mustPolicyTarget(t, "mail", "filter"),
		EffectID:   "mail/matrix-post",
		DecisionID: "behavior-matrix",
		Provider:   "mail/lua.matrix.post-provider",
		Generation: 1,
		Ordinal:    1,
	})
	if err != nil {
		t.Fatalf("NewEffectExecution() error = %v", err)
	}

	return execution
}

// mustBehaviorMatrixGeneration prepares one immutable public Lua generation adapter.
func mustBehaviorMatrixGeneration(
	t *testing.T,
	facts []policyprovider.FactProviderRegistration,
	effects []policyprovider.EffectProviderRegistration,
) policyprovider.PreparedGeneration {
	t.Helper()

	prepared, err := policyprovider.PrepareGeneration(t.Context(), policyprovider.GenerationInput{
		PostActionAcceptance: &generationTestAcceptor{},
		Ownership:            mustNamespaceOwnership(t, "lua.matrix", []string{"mail"}),
		FactProviders:        facts,
		EffectProviders:      effects,
		Authority:            behaviorMatrixAuthority,
	})
	if err != nil {
		t.Fatalf("PrepareGeneration() error = %v", err)
	}

	return prepared
}

// behaviorMatrixCatalogContribution builds the minimum target plan that schedules both providers.
func behaviorMatrixCatalogContribution(t *testing.T, providerIDs []string) registry.DefinitionContribution {
	t.Helper()

	target := mustPolicyTarget(t, "mail", "filter")
	schema := mustBehaviorMatrixSchema(t)

	targetDefinition, err := registry.NewTargetDefinition(target, []registry.SchemaIdentity{schema.Identity()})
	if err != nil {
		t.Fatalf("NewTargetDefinition() error = %v", err)
	}

	policySet, checkpoint := mustBehaviorMatrixPlanEntries(t, target, providerIDs)

	plan, err := registry.NewDomainPlanDefinition(target, []registry.CheckpointDefinition{checkpoint})
	if err != nil {
		t.Fatalf("NewDomainPlanDefinition() error = %v", err)
	}

	contribution, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership:  mustNamespaceOwnership(t, "matrix.catalog", []string{"mail"}),
		Targets:    []registry.TargetDefinition{targetDefinition},
		Schemas:    []registry.SchemaDefinition{schema},
		PolicySets: []registry.PolicySetDefinition{policySet},
		Plans:      []registry.DomainPlanDefinition{plan},
	})
	if err != nil {
		t.Fatalf("NewCompleteDefinitionContribution() error = %v", err)
	}

	return contribution
}

// mustBehaviorMatrixSchema declares the exact Lua output in the active target schema.
func mustBehaviorMatrixSchema(t *testing.T) registry.SchemaDefinition {
	t.Helper()

	fact, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID:             behaviorMatrixFactID,
		AllowedSources: []decision.FactSource{decision.FactSourceLua},
		Category:       decision.FactCategoryEnvironment,
		Kind:           decision.ValueKindString,
		MaxLength:      32,
	})
	if err != nil {
		t.Fatalf("NewFactSchema() error = %v", err)
	}

	identity, err := registry.NewSchemaIdentity("mail", "filter", "v1")
	if err != nil {
		t.Fatalf("NewSchemaIdentity() error = %v", err)
	}

	schema, err := registry.NewSchemaDefinition(identity, []registry.FactSchema{fact})
	if err != nil {
		t.Fatalf("NewSchemaDefinition() error = %v", err)
	}

	return schema
}

// mustBehaviorMatrixPlanEntries constructs the empty policy set and provider checkpoint.
func mustBehaviorMatrixPlanEntries(
	t *testing.T,
	target decision.Target,
	providerIDs []string,
) (registry.PolicySetDefinition, registry.CheckpointDefinition) {
	t.Helper()

	setID, err := registry.NewPolicySetID("mail", "root")
	if err != nil {
		t.Fatalf("NewPolicySetID() error = %v", err)
	}

	policySet, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{ID: setID})
	if err != nil {
		t.Fatalf("NewPolicySetDefinition() error = %v", err)
	}

	setImport, err := registry.NewPolicySetImport(
		"matrix.plan",
		setID.String(),
		target,
		decision.CheckpointFinalDecision,
		registry.ExportContract{},
	)
	if err != nil {
		t.Fatalf("NewPolicySetImport() error = %v", err)
	}

	instances := mustBehaviorMatrixProviderInstances(t, providerIDs)

	checkpoint, err := registry.NewCheckpointDefinitionWithProviderInstances(
		decision.CheckpointFinalDecision,
		[]registry.PolicySetImport{setImport},
		instances,
	)
	if err != nil {
		t.Fatalf("NewCheckpointDefinitionWithProviderInstances() error = %v", err)
	}

	return policySet, checkpoint
}

// mustBehaviorMatrixProviderInstances constructs distinct scheduler names for the colliding providers.
func mustBehaviorMatrixProviderInstances(
	t *testing.T,
	providerIDs []string,
) []registry.ProviderInstanceDefinition {
	t.Helper()

	instances := make([]registry.ProviderInstanceDefinition, 0, len(providerIDs))
	for index, providerID := range providerIDs {
		name := []string{"first", "second"}[index]

		instance, err := registry.NewProviderInstanceDefinition(registry.ProviderInstanceDefinitionInput{
			Path: "matrix.plan.providers." + name,
			Name: name,
			Use:  providerID,
		})
		if err != nil {
			t.Fatalf("NewProviderInstanceDefinition(%q) error = %v", name, err)
		}

		instances = append(instances, instance)
	}

	return instances
}

// mustBehaviorMatrixActivation selects the exact matrix target and schema.
func mustBehaviorMatrixActivation(t *testing.T) registry.TargetActivation {
	t.Helper()

	activation, err := registry.NewTargetActivation(
		"policy.targets[0]",
		"mail",
		"filter",
		"mail/filter/v1",
	)
	if err != nil {
		t.Fatalf("NewTargetActivation() error = %v", err)
	}

	activation, err = activation.WithPolicy("mail/root", "deny")
	if err != nil {
		t.Fatalf("TargetActivation.WithPolicy() error = %v", err)
	}

	return activation
}

type behaviorMatrixCountingExecutor struct {
	delegate policyprovider.EffectExecutor
	calls    atomic.Int64
}

// Descriptor forwards the immutable real Lua effect capability.
func (e *behaviorMatrixCountingExecutor) Descriptor() policyprovider.EffectProviderDescriptor {
	return e.delegate.Descriptor()
}

// Execute records host invocation timing before delegating to the real Lua executor.
func (e *behaviorMatrixCountingExecutor) Execute(
	ctx context.Context,
	request policyprovider.EffectRequest,
) (policyprovider.EffectResult, error) {
	e.calls.Add(1)

	return e.delegate.Execute(ctx, request)
}

type behaviorMatrixPanickingCollector struct {
	descriptor policyprovider.FactProviderDescriptor
}

// Descriptor returns one valid capability before the runtime panic reproducer.
func (c *behaviorMatrixPanickingCollector) Descriptor() policyprovider.FactProviderDescriptor {
	return c.descriptor
}

// Collect reproduces a provider panic whose value must never cross the adapter boundary.
func (*behaviorMatrixPanickingCollector) Collect(
	context.Context,
	policyprovider.FactRequest,
) (policyprovider.FactResult, error) {
	panic("behavior-matrix-panic-secret")
}

type behaviorMatrixContributor struct {
	contribution registry.DefinitionContribution
}

// Contribute returns one immutable matrix definition batch to the candidate compiler.
func (c behaviorMatrixContributor) Contribute(
	context.Context,
) (registry.DefinitionContribution, error) {
	return c.contribution, nil
}
