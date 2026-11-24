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
	"strings"
	"testing"

	policy "github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const authnLuaResponseDetailRegistryScript = `
nauthilus_policy.register_attribute({
    id = "lua.plugin.contract.rejected",
    stage = "pre_auth",
    operations = {"authenticate"},
    category = "environment",
    type = "bool",
    description = "Contract rejection flag",
    details = {
        status_message = {
            type = "string",
            sensitivity = "public",
            purpose = "response_message",
            max_length = 128,
        },
        reason = {
            type = "string",
            sensitivity = "public",
            purpose = "response_message",
        },
    },
})
`

const authnLuaResponseDetailPolicyFixture = `policy:
  namespaces:
    authn:
      schema_contributions:
        lua:
          registry_scripts: [REGISTRY_SCRIPT]
      domain_plans:
        configured:
          checkpoints:
            pre_auth: {providers: []}
      policy_sets:
        configured:
          visibility: private
          rules:
            - name: deny_contract_rejection
              checkpoint: pre_auth
              actions: [authenticate]
              if: {attribute: lua.plugin.contract.rejected, is: true}
              then:
                decision: deny
                response_message:
                  from: attribute_detail
                  attribute: lua.plugin.contract.rejected
                  detail: status_message
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      domain_plan: authn/configured
      default_policy: authn/standard_auth
      plans:
        pre_auth:
          policy_sets: [authn/configured]
`

// TestConfiguredAuthnRuleSelectsRegisteredLuaAttributeDetail reproduces a configured rule whose attribute_detail
// response message referenced the detail of a Lua registry attribute and failed with a rule fact mismatch, because
// the Lua schema declared the attribute but none of its public response details.
func TestConfiguredAuthnRuleSelectsRegisteredLuaAttributeDetail(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "registry.lua")
	if err := os.WriteFile(scriptPath, []byte(authnLuaResponseDetailRegistryScript), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	configured := decodePolicy(t, strings.ReplaceAll(authnLuaResponseDetailPolicyFixture, "REGISTRY_SCRIPT", scriptPath)).Policy
	artifacts := capturePolicyLuaTestArtifacts(t, configured)

	declarations, err := PrepareConfiguredAuthnLuaFacts(t.Context(), configured, artifacts)
	requireNoError(t, err)

	prepared, err := PreparePolicy(t.Context(), 1, configured)
	requireNoError(t, err)

	catalog, _, err := prepared.CompileCandidate(t.Context(), &nativeGenerationAcceptor{}, nil, declarations)
	requireNoError(t, err)

	target := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, string(policy.OperationAuthenticate))

	for _, detail := range []string{"status_message", "reason"} {
		detailFactID := policy.AuthnResponseDetailFactID("lua.plugin.contract.rejected", detail)
		wantKinds := map[string]decision.ValueKind{
			detailFactID: decision.ValueKindString,
			policy.AuthnResponseDetailTruncatedFactID("lua.plugin.contract.rejected", detail): decision.ValueKindBoolean,
			policy.AuthnResponseDetailSelectedFactID("lua.plugin.contract.rejected", detail):  decision.ValueKindBoolean,
		}

		for id, kind := range wantKinds {
			fact, found := findCompiledFactSchema(target.Schema().Facts(), id)
			if !found || fact.Kind() != kind {
				t.Fatalf("compiled schema fact %q = %#v (found %t), want kind %q", id, fact, found, kind)
			}
		}
	}

	assertAuthnLuaResponseDetailFactsAdmitted(t, target)
}

// assertAuthnLuaResponseDetailFactsAdmitted reproduces the checkpoint admission of an emitted attribute with a
// response detail. Before the schema declared detail facts, this admission failed and the request answered with a
// generic temporary failure instead of the rule decision.
func assertAuthnLuaResponseDetailFactsAdmitted(t *testing.T, target policyruntime.CompiledTarget) {
	t.Helper()

	const attributeID = "lua.plugin.contract.rejected"

	provenance, err := decision.NewProvenance(decision.FactSourceLua, "plugin", "auth-policy")
	requireNoError(t, err)

	text := "Maintenance in progress"
	flag := true
	inputs := map[string]decision.ValueInput{
		attributeID: {Boolean: &flag},
		policy.AuthnResponseDetailFactID(attributeID, "status_message"):          {String: &text},
		policy.AuthnResponseDetailTruncatedFactID(attributeID, "status_message"): {Boolean: new(bool)},
		policy.AuthnResponseDetailSelectedFactID(attributeID, "status_message"):  {Boolean: &flag},
	}

	facts := make([]decision.Fact, 0, len(inputs))
	for id, input := range inputs {
		value, valueErr := decision.NewValue(input)
		requireNoError(t, valueErr)

		fact, factErr := decision.NewFact(id, decision.FactCategoryEnvironment, value, provenance)
		requireNoError(t, factErr)

		facts = append(facts, fact)
	}

	set, err := decision.NewFactSet(facts)
	requireNoError(t, err)

	normalized, err := target.Schema().NormalizeFacts(set)
	requireNoError(t, err)
	requireNoError(t, target.Schema().ValidatePresentFacts(normalized))
}
