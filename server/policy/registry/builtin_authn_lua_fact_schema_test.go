// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package registry

import (
	"testing"

	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

// TestExtendBuiltinAuthnSchemasWithLuaFactsAddsExactActionFact proves registry-script composition.
func TestExtendBuiltinAuthnSchemasWithLuaFactsAddsExactActionFact(t *testing.T) {
	builtin := mustBuiltinAuthnContribution(t)

	declaration, err := NewAuthnLuaFactDeclaration(AuthnLuaFactDeclarationInput{
		ID:       "lua.contract.registry_flag",
		Stage:    string(policy.StagePreAuth),
		Actions:  []string{string(policy.OperationAuthenticate)},
		Category: decision.FactCategoryEnvironment,
		Kind:     decision.ValueKindBoolean,
	})
	if err != nil {
		t.Fatalf("NewAuthnLuaFactDeclaration() error = %v", err)
	}

	extended, err := ExtendBuiltinAuthnSchemasWithLuaFacts(builtin, []AuthnLuaFactDeclaration{declaration})
	if err != nil {
		t.Fatalf("ExtendBuiltinAuthnSchemasWithLuaFacts() error = %v", err)
	}

	schema := findBuiltinAuthnSchema(t, extended, string(policy.OperationAuthenticate))

	fact, found := findFactSchema(schema.Facts(), "lua.contract.registry_flag")
	if !found || fact.Kind() != decision.ValueKindBoolean ||
		fact.Category() != decision.FactCategoryEnvironment ||
		!containsFactSource(fact.AllowedSources(), decision.FactSourceLua) {
		t.Fatalf("registry-script fact = %#v", fact)
	}

	lookup := findBuiltinAuthnSchema(t, extended, string(policy.OperationLookupIdentity))
	if _, found = findFactSchema(lookup.Facts(), "lua.contract.registry_flag"); found {
		t.Fatal("registry-script fact leaked into an unselected action")
	}
}

// findBuiltinAuthnSchema returns one exact action schema from a builtin contribution.
func findBuiltinAuthnSchema(t *testing.T, contribution DefinitionContribution, action string) SchemaDefinition {
	t.Helper()

	for _, schema := range contribution.Schemas() {
		if schema.Identity().Name() == action {
			return schema
		}
	}

	t.Fatalf("builtin authn schema %s is unavailable", action)

	return SchemaDefinition{}
}

// findFactSchema resolves one exact fact from a detached schema list.
func findFactSchema(facts []FactSchema, id string) (FactSchema, bool) {
	for _, fact := range facts {
		if fact.ID() == id {
			return fact, true
		}
	}

	return FactSchema{}, false
}

// containsFactSource reports exact source membership.
func containsFactSource(sources []decision.FactSource, expected decision.FactSource) bool {
	for _, source := range sources {
		if source == expected {
			return true
		}
	}

	return false
}
