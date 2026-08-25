// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package runtime

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

func TestGenericProviderBindingInputsOwnCallerAndFactViews(t *testing.T) {
	caller := mustBindingCaller(t)
	facts := mustBindingFacts(t)
	target := mustBindingTarget(t)

	providerInput, err := NewFactProviderInput(facts, target, caller, "policy.facts.collect")
	if err != nil {
		t.Fatalf("NewFactProviderInput() error = %v", err)
	}

	effectInput, err := NewEffectExecution(EffectExecutionInput{
		Facts: facts, Caller: caller, Parameters: mustBindingValueMap(t), Target: target,
		EffectID: "mail/audit", DecisionID: "decision-1", Provider: "mail/lua.risk.audit",
		Generation: 1, Ordinal: 1,
	})
	if err != nil {
		t.Fatalf("NewEffectExecution() error = %v", err)
	}

	if providerInput.Caller().Principal() != "policy-client" || effectInput.Caller().ClientID() != "client-1" {
		t.Fatal("captured caller view was not preserved")
	}

	if _, ok := providerInput.Facts().Get("resource.id"); !ok {
		t.Fatal("provider input lost captured facts")
	}

	if _, ok := effectInput.Facts().Get("resource.id"); !ok {
		t.Fatal("effect input lost captured facts")
	}

	returnedScopes := providerInput.Caller().Scopes()
	returnedScopes[0] = "mutated"

	if providerInput.Caller().Scopes()[0] != "policy.evaluate" {
		t.Fatal("provider input returned mutable caller scopes")
	}
}

// mustBindingCaller constructs trusted caller evidence for binding ownership tests.
func mustBindingCaller(t *testing.T) decision.CallerContext {
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

// mustBindingFacts constructs one immutable fact set for binding ownership tests.
func mustBindingFacts(t *testing.T) decision.FactSet {
	t.Helper()

	value := mustBindingStringValue(t, "message-1")

	provenance, err := decision.NewProvenance(decision.FactSourceCaller, "client", "resource")
	if err != nil {
		t.Fatalf("NewProvenance() error = %v", err)
	}

	fact, err := decision.NewFact(
		"resource.id",
		decision.FactCategoryResource,
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

// mustBindingValueMap constructs one strict selected-effect parameter map.
func mustBindingValueMap(t *testing.T) decision.ValueMap {
	t.Helper()

	values, err := decision.NewValueMap(map[string]decision.Value{
		"level": mustBindingStringValue(t, "accepted"),
	})
	if err != nil {
		t.Fatalf("NewValueMap() error = %v", err)
	}

	return values
}

// mustBindingStringValue constructs one strict string value.
func mustBindingStringValue(t *testing.T, input string) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err != nil {
		t.Fatalf("NewValue() error = %v", err)
	}

	return value
}

// mustBindingTarget constructs one exact generic target.
func mustBindingTarget(t *testing.T) decision.Target {
	t.Helper()

	target, err := decision.NewTarget("mail", "filter")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return target
}
