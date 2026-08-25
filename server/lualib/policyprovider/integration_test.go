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
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/lualib/policyprovider"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

func TestLuaGenerationPreparationOwnsDefinitionsAndRuntimeBindings(t *testing.T) {
	factDescriptor := validFactProviderDescriptor()
	factDescriptor.Targets = []policyprovider.TargetSelector{{Namespace: "mail", Action: "filter"}}
	collector := &generationFactCollector{
		descriptor: factDescriptor,
		result: policyprovider.FactResult{Facts: []policyprovider.FactValue{{
			Name: "risk.score", Value: mustStringValue(t, "trusted"),
		}}},
	}
	effectDescriptor := validEffectProviderDescriptor()
	effectDescriptor.Name = "reputation"
	effectDescriptor.Effects = append(effectDescriptor.Effects, policyprovider.EffectDescriptor{
		Name: "record-sync", Targets: effectDescriptor.Effects[0].Targets,
		Execution:  policyprovider.EffectExecutionHostSync,
		Parameters: effectDescriptor.Effects[0].Parameters,
	})
	executor := &generationEffectExecutor{descriptor: effectDescriptor}
	acceptor := &generationTestAcceptor{}
	ownership := mustNamespaceOwnership(t, "lua.risk", []string{"mail"})

	prepared, err := policyprovider.PrepareGeneration(context.Background(), policyprovider.GenerationInput{
		Ownership: ownership, Authority: "risk", PostActionAcceptance: acceptor,
		FactProviders: []policyprovider.FactProviderRegistration{{
			Collector: collector, Failure: registry.ProviderFailureContinue,
			Requires: []string{"mail/base"}, DiagnosticID: "risk-provider",
		}},
		EffectProviders: []policyprovider.EffectProviderRegistration{{
			Executor: executor, DiagnosticID: "audit-provider",
		}},
	})
	if err != nil {
		t.Fatalf("PrepareGeneration() error = %v", err)
	}

	preparation, err := prepared.ExtensionPreparation(nil)
	if err != nil {
		t.Fatalf("ExtensionPreparation() error = %v", err)
	}

	assertPreparedLuaDefinitions(t, preparation)
	assertPreparedLuaFactBinding(t, preparation, collector)
	assertPreparedLuaEffectBindings(t, preparation, executor)
}

func TestLuaGenerationFactContractViolationIsFailClosed(t *testing.T) {
	descriptor := validFactProviderDescriptor()
	descriptor.Targets = []policyprovider.TargetSelector{{Namespace: "mail", Action: "filter"}}
	collector := &generationFactCollector{
		descriptor: descriptor,
		result: policyprovider.FactResult{Facts: []policyprovider.FactValue{{
			Name: "undeclared", Value: mustStringValue(t, "secret-value"),
		}}},
	}
	prepared := mustPreparedLuaGeneration(t, collector, nil)

	preparation, err := prepared.ExtensionPreparation(nil)
	if err != nil {
		t.Fatalf("ExtensionPreparation() error = %v", err)
	}

	binding := preparation.Bindings.FactProviders()["mail/lua.risk.reputation"]

	_, err = binding.Provider.Collect(context.Background(), mustGenerationFactInput(t))
	if !errors.Is(err, policyruntime.ErrProviderContractViolation) {
		t.Fatalf("Collect() error = %v, want provider contract violation", err)
	}

	if err != nil && (strings.Contains(err.Error(), "secret-value") || strings.Contains(err.Error(), "undeclared")) {
		t.Fatalf("contract error exposed callback output: %v", err)
	}
}

func TestLuaGenerationExecutorContractErrorOverridesConfiguredContinuation(t *testing.T) {
	descriptor := validFactProviderDescriptor()
	descriptor.Targets = []policyprovider.TargetSelector{{Namespace: "mail", Action: "filter"}}
	collector := &generationFactCollector{
		descriptor: descriptor,
		err:        fmt.Errorf("%w: callback-secret", policyprovider.ErrInvalidResult),
	}
	prepared := mustPreparedLuaGeneration(t, collector, nil)

	preparation, err := prepared.ExtensionPreparation(nil)
	if err != nil {
		t.Fatalf("ExtensionPreparation() error = %v", err)
	}

	binding := preparation.Bindings.FactProviders()["mail/lua.risk.reputation"]

	_, err = binding.Provider.Collect(context.Background(), mustGenerationFactInput(t))
	if !errors.Is(err, policyruntime.ErrProviderContractViolation) {
		t.Fatalf("Collect() error = %v, want provider contract violation", err)
	}

	if strings.Contains(err.Error(), "callback-secret") {
		t.Fatalf("contract error exposed callback error text: %v", err)
	}
}

func TestLuaGenerationPreservesCallbackDeadlineIdentity(t *testing.T) {
	descriptor := validFactProviderDescriptor()
	descriptor.Targets = []policyprovider.TargetSelector{{Namespace: "mail", Action: "filter"}}
	collector := &generationFactCollector{
		descriptor: descriptor,
		err:        fmt.Errorf("%w: %w", policyprovider.ErrCallbackExecution, context.DeadlineExceeded),
	}
	prepared := mustPreparedLuaGeneration(t, collector, nil)

	preparation, err := prepared.ExtensionPreparation(nil)
	if err != nil {
		t.Fatalf("ExtensionPreparation() error = %v", err)
	}

	binding := preparation.Bindings.FactProviders()["mail/lua.risk.reputation"]

	_, err = binding.Provider.Collect(context.Background(), mustGenerationFactInput(t))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Collect() error = %v, want callback deadline identity", err)
	}
}

// assertPreparedLuaDefinitions verifies configured schedule overlays the adapted contribution once.
func assertPreparedLuaDefinitions(t *testing.T, preparation policyruntime.ExtensionPreparation) {
	t.Helper()

	if len(preparation.Definitions) != 1 {
		t.Fatalf("definitions = %d, want 1", len(preparation.Definitions))
	}

	providers := preparation.Definitions[0].Providers()
	if len(providers) != 1 {
		t.Fatalf("providers = %d, want one merged fact/effect provider", len(providers))
	}

	factProvider := providers[0]
	if factProvider.ID() != "mail/lua.risk.reputation" ||
		factProvider.Failure() != registry.ProviderFailureContinue ||
		len(factProvider.Requires()) != 1 || factProvider.Requires()[0] != "mail/base" ||
		factProvider.DiagnosticID() != "risk-provider" {
		t.Fatalf("fact provider = %#v", factProvider)
	}
}

// assertPreparedLuaFactBinding verifies local Lua output receives exact host authority.
func assertPreparedLuaFactBinding(
	t *testing.T,
	preparation policyruntime.ExtensionPreparation,
	collector *generationFactCollector,
) {
	t.Helper()

	binding, exists := preparation.Bindings.FactProviders()["mail/lua.risk.reputation"]
	if !exists || binding.Source != decision.FactSourceLua || binding.Authority != "risk" {
		t.Fatalf("fact binding = %#v", binding)
	}

	provided, err := binding.Provider.Collect(context.Background(), mustGenerationFactInput(t))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if len(provided) != 1 || provided[0].ID() != "lua.risk.risk.score" ||
		provided[0].Category() != decision.FactCategoryEnvironment {
		t.Fatalf("provided facts = %#v", provided)
	}

	if collector.request.Caller.Principal != "policy-client" || collector.request.Target.Namespace != "mail" {
		t.Fatalf("collector request = %#v", collector.request)
	}
}

// assertPreparedLuaEffectBindings proves sync execution and post work share one selected owner.
func assertPreparedLuaEffectBindings(
	t *testing.T,
	preparation policyruntime.ExtensionPreparation,
	executor *generationEffectExecutor,
) {
	t.Helper()

	providerID := "mail/lua.risk.reputation"
	syncProvider, syncExists := preparation.Bindings.SyncEffects()[providerID]

	postProvider, postExists := preparation.Bindings.PostActions()[providerID]
	if !syncExists || !postExists {
		t.Fatalf("effect bindings sync/post = %t/%t", syncExists, postExists)
	}

	syncExecution := mustGenerationEffectExecution(t, "mail/record-sync", providerID, 1)
	if result := syncProvider.Execute(context.Background(), syncExecution); result.State() != effectsupervisor.StateSucceeded {
		t.Fatalf("sync result = %q", result.State())
	}

	postExecution := mustGenerationEffectExecution(t, "mail/record-audit", providerID, 2)

	work, err := postProvider.Prepare(context.Background(), postExecution)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	if executor.callCount != 1 {
		t.Fatalf("effect calls before supervised work = %d, want 1 sync call", executor.callCount)
	}

	executable := work.(effectsupervisor.ExecutableWork)
	if result := executable.Execute(context.Background()); result.State() != effectsupervisor.StateSucceeded {
		t.Fatalf("post result = %q", result.State())
	}

	executable.Cleanup()

	if executor.callCount != 2 || executor.requests[0].Effect != "mail/record-sync" ||
		executor.requests[1].Effect != "mail/record-audit" {
		t.Fatalf("effect requests = %#v", executor.requests)
	}
}

// mustPreparedLuaGeneration prepares one focused fact or effect registration fixture.
func mustPreparedLuaGeneration(
	t *testing.T,
	collector policyprovider.FactCollector,
	executor policyprovider.EffectExecutor,
) policyprovider.PreparedGeneration {
	t.Helper()

	input := policyprovider.GenerationInput{
		Ownership: mustNamespaceOwnership(t, "lua.risk", []string{"mail"}),
		Authority: "risk", PostActionAcceptance: &generationTestAcceptor{},
	}
	if collector != nil {
		input.FactProviders = []policyprovider.FactProviderRegistration{{
			Collector: collector, Failure: registry.ProviderFailureContinue,
		}}
	}

	if executor != nil {
		input.EffectProviders = []policyprovider.EffectProviderRegistration{{Executor: executor}}
	}

	prepared, err := policyprovider.PrepareGeneration(context.Background(), input)
	if err != nil {
		t.Fatalf("PrepareGeneration() error = %v", err)
	}

	return prepared
}

// mustGenerationFactInput constructs one bounded caller/fact provider request.
func mustGenerationFactInput(t *testing.T) policyruntime.FactProviderInput {
	t.Helper()

	input, err := policyruntime.NewFactProviderInput(
		mustGenerationFacts(t),
		mustPolicyTarget(t, "mail", "filter"),
		mustGenerationCaller(t),
		policyprovider.PolicyFactsCollectCallback,
	)
	if err != nil {
		t.Fatalf("NewFactProviderInput() error = %v", err)
	}

	return input
}

// mustGenerationEffectExecution constructs one selected immutable effect invocation.
func mustGenerationEffectExecution(
	t *testing.T,
	effectID string,
	providerID string,
	ordinal uint32,
) policyruntime.EffectExecution {
	t.Helper()

	parameters, err := decision.NewValueMap(map[string]decision.Value{
		"message": mustStringValue(t, "accepted"),
	})
	if err != nil {
		t.Fatalf("NewValueMap() error = %v", err)
	}

	execution, err := policyruntime.NewEffectExecution(policyruntime.EffectExecutionInput{
		Facts: mustGenerationFacts(t), Caller: mustGenerationCaller(t), Parameters: parameters,
		Target: mustPolicyTarget(t, "authn", "authenticate"), EffectID: effectID,
		DecisionID: "decision-lua", Provider: providerID, Generation: 1, Ordinal: ordinal,
	})
	if err != nil {
		t.Fatalf("NewEffectExecution() error = %v", err)
	}

	return execution
}

// mustGenerationCaller constructs one redacted caller view.
func mustGenerationCaller(t *testing.T) decision.CallerContext {
	t.Helper()

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: "policy-client", ClientID: "client-1", Scopes: []string{"policy.evaluate"},
		AuthenticationKind: "basic", TransportKind: "http",
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	return caller
}

// mustGenerationFacts constructs one detached caller fact.
func mustGenerationFacts(t *testing.T) decision.FactSet {
	t.Helper()

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "policy-client", "request")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	fact, err := decision.NewFact(
		"resource.message_id",
		decision.FactCategoryResource,
		mustStringValue(t, "message-1"),
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

type generationFactCollector struct {
	descriptor policyprovider.FactProviderDescriptor
	result     policyprovider.FactResult
	request    policyprovider.FactRequest
	err        error
}

// Descriptor returns the immutable test capability.
func (c *generationFactCollector) Descriptor() policyprovider.FactProviderDescriptor {
	return c.descriptor
}

// Collect records the bounded request and returns one configured fixture result.
func (c *generationFactCollector) Collect(
	_ context.Context,
	request policyprovider.FactRequest,
) (policyprovider.FactResult, error) {
	c.request = request

	return c.result, c.err
}

type generationEffectExecutor struct {
	descriptor policyprovider.EffectProviderDescriptor
	requests   []policyprovider.EffectRequest
	callCount  int
}

// Descriptor returns the immutable test effect capability.
func (e *generationEffectExecutor) Descriptor() policyprovider.EffectProviderDescriptor {
	return e.descriptor
}

// Execute records exactly one policy-selected typed effect.
func (e *generationEffectExecutor) Execute(
	_ context.Context,
	request policyprovider.EffectRequest,
) (policyprovider.EffectResult, error) {
	e.callCount++
	e.requests = append(e.requests, request)

	return policyprovider.EffectResult{State: policyprovider.EffectStateSucceeded}, nil
}

type generationTestAcceptor struct{}

// Accept returns one deterministic receipt without executing post work.
func (*generationTestAcceptor) Accept(
	context.Context,
	effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}
