// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package collection

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyregistry "github.com/croessner/nauthilus/v4/server/policy/registry"
)

func TestDecisionContextAddsCapturedAuthnLuaFactDeclarations(t *testing.T) {
	declaration, err := policyregistry.NewAuthnLuaFactDeclaration(policyregistry.AuthnLuaFactDeclarationInput{
		ID:           "lua.contract.captured_risk",
		Description:  "captured generation risk fact",
		Stage:        string(policy.StagePreAuth),
		Actions:      []string{string(policy.OperationAuthenticate)},
		Category:     decision.FactCategoryEnvironment,
		Kind:         decision.ValueKindBoolean,
		DeclaredType: policyregistry.AttributeTypeBool,
		Details: map[string]policyregistry.DetailDefinition{
			"status_message": {
				Type:        policyregistry.AttributeTypeString,
				Sensitivity: policyregistry.DetailSensitivityPublic,
				Purpose:     policyregistry.DetailPurposeResponseMessage,
				MaxLength:   128,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAuthnLuaFactDeclaration() error = %v", err)
	}

	ctx := NewDecisionContext(policy.OperationAuthenticate, nil, 701)
	if err = ctx.AddAuthnLuaFactDeclarations([]policyregistry.AuthnLuaFactDeclaration{declaration}); err != nil {
		t.Fatalf("AddAuthnLuaFactDeclarations() error = %v", err)
	}

	definition, found := ctx.AttributeDefinition(declaration.ID())
	if !found {
		t.Fatal("captured Lua fact declaration was not installed")
	}

	assertCapturedAuthnLuaFactDefinition(t, declaration, definition)

	if err = ctx.AddAuthnLuaFactDeclarations([]policyregistry.AuthnLuaFactDeclaration{declaration}); err == nil {
		t.Fatal("duplicate captured Lua fact declaration was accepted")
	}
}

// assertCapturedAuthnLuaFactDefinition checks the exact installed fact and detail projections.
func assertCapturedAuthnLuaFactDefinition(
	t *testing.T,
	declaration policyregistry.AuthnLuaFactDeclaration,
	definition policyregistry.AttributeDefinition,
) {
	t.Helper()

	if definition.ID != declaration.ID() || definition.Source != policyregistry.SourceLua ||
		definition.Stage != policy.StagePreAuth || definition.Type != policyregistry.AttributeTypeBool ||
		definition.Category != policyregistry.AttributeCategoryEnvironment {
		t.Fatalf("captured Lua fact definition = %#v", definition)
	}

	if len(definition.Operations) != 1 || definition.Operations[0] != policy.OperationAuthenticate {
		t.Fatalf("captured Lua fact operations = %#v", definition.Operations)
	}

	detail := definition.Details["status_message"]
	if detail.MaxLength != 128 || detail.Sensitivity != policyregistry.DetailSensitivityPublic ||
		detail.Purpose != policyregistry.DetailPurposeResponseMessage {
		t.Fatalf("captured Lua fact detail = %#v", detail)
	}
}
