// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// TestPrepareConfiguredAuthnLuaFactsExecutesRegistryScriptsOffSide proves exact candidate materialization.
func TestPrepareConfiguredAuthnLuaFactsExecutesRegistryScriptsOffSide(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "registry.lua")
	if err := os.WriteFile(scriptPath, []byte(`
nauthilus_policy.register_attribute({
    id = "lua.contract.registry_flag",
    stage = "pre_auth",
    operations = {"authenticate"},
    category = "environment",
    type = "bool",
    description = "Candidate-owned contract fact",
    details = {
        status_message = {
            type = "string",
            sensitivity = "public",
            purpose = "response_message",
            max_length = 128,
        },
    },
})
`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	configured := policyconfig.PolicyConfig{
		Namespaces: map[string]policyconfig.NamespaceConfig{
			policy.AuthnNamespace: {
				SchemaContributions: policyconfig.SchemaContributionsConfig{
					Lua: policyconfig.LuaSchemaContributionsConfig{RegistryScripts: []string{scriptPath}},
				},
			},
		},
	}

	artifacts := capturePolicyLuaTestArtifacts(t, configured)
	if err := os.WriteFile(scriptPath, []byte("function broken("), 0o600); err != nil {
		t.Fatalf("mutate registry script: %v", err)
	}

	declarations, err := PrepareConfiguredAuthnLuaFacts(t.Context(), configured, artifacts)
	if err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaFacts() error = %v", err)
	}

	if len(declarations) != 1 {
		t.Fatalf("declarations = %d, want 1", len(declarations))
	}

	declaration := declarations[0]
	assertPreparedAuthnLuaFactDeclaration(t, declaration)
	assertCompiledAuthnLuaFact(t, configured, declarations, declaration.ID())
}

// assertPreparedAuthnLuaFactDeclaration checks the exact detached registry-script projection.
func assertPreparedAuthnLuaFactDeclaration(t *testing.T, declaration registry.AuthnLuaFactDeclaration) {
	t.Helper()

	if declaration.ID() != "lua.contract.registry_flag" || declaration.Stage() != policy.StagePreAuth ||
		declaration.Category() != decision.FactCategoryEnvironment || declaration.Kind() != decision.ValueKindBoolean ||
		declaration.DeclaredType() != registry.AttributeTypeBool {
		t.Fatalf("declaration = %#v", declaration)
	}

	details := declaration.Details()

	detail := details["status_message"]
	if detail.Type != registry.AttributeTypeString || detail.Sensitivity != registry.DetailSensitivityPublic ||
		detail.Purpose != registry.DetailPurposeResponseMessage || detail.MaxLength != 128 {
		t.Fatalf("detail = %#v", detail)
	}
}

// assertCompiledAuthnLuaFact checks that candidate compilation retains one prepared declaration.
func assertCompiledAuthnLuaFact(
	t *testing.T,
	configured policyconfig.PolicyConfig,
	declarations []registry.AuthnLuaFactDeclaration,
	declarationID string,
) {
	t.Helper()

	prepared, err := PreparePolicy(t.Context(), 1, configured)
	if err != nil {
		t.Fatalf("PreparePolicy() error = %v", err)
	}

	catalog, _, err := prepared.CompileCandidate(
		t.Context(),
		&nativeGenerationAcceptor{},
		nil,
		declarations,
	)
	if err != nil {
		t.Fatalf("CompileCandidate() error = %v", err)
	}

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	compiled, found := catalog.Lookup(target)
	if !found {
		t.Fatal("compiled authn target is unavailable")
	}

	if _, found = findCompiledFactSchema(compiled.Schema().Facts(), declarationID); !found {
		t.Fatalf("compiled schema lost registry fact %q", declarationID)
	}
}

// TestPrepareConfiguredAuthnLuaFactsUsesRestrictedRegistryVM proves ambient host modules and I/O are absent.
func TestPrepareConfiguredAuthnLuaFactsUsesRestrictedRegistryVM(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "restricted.lua")
	if err := os.WriteFile(scriptPath, []byte(`
local stringlib = require("string")
assert(stringlib.lower("SAFE") == "safe")
assert(os == nil and io == nil and package == nil and debug == nil)
assert(load == nil and loadfile == nil and dofile == nil and loadstring == nil)
local loaded_host = pcall(require, "nauthilus_context")
assert(not loaded_host)
nauthilus_policy.register_attribute({
    id = "lua.contract.restricted",
    stage = "pre_auth",
    category = "environment",
    type = "bool",
})
`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	configured := policyconfig.PolicyConfig{Namespaces: map[string]policyconfig.NamespaceConfig{
		policy.AuthnNamespace: {SchemaContributions: policyconfig.SchemaContributionsConfig{
			Lua: policyconfig.LuaSchemaContributionsConfig{RegistryScripts: []string{scriptPath}},
		}},
	}}

	declarations, err := PrepareConfiguredAuthnLuaFacts(
		t.Context(),
		configured,
		capturePolicyLuaTestArtifacts(t, configured),
	)
	if err != nil {
		t.Fatalf("PrepareConfiguredAuthnLuaFacts() error = %v", err)
	}

	if len(declarations) != 1 || declarations[0].ID() != "lua.contract.restricted" {
		t.Fatalf("declarations = %#v", declarations)
	}
}

// findCompiledFactSchema resolves one fact from a compiled target schema.
func findCompiledFactSchema(facts []registry.FactSchema, id string) (registry.FactSchema, bool) {
	for _, fact := range facts {
		if fact.ID() == id {
			return fact, true
		}
	}

	return registry.FactSchema{}, false
}
