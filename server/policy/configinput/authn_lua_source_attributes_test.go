// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

// configuredAuthnLuaSourceRulesFixture schedules one Lua environment and one Lua subject source and lets a
// configured rule reference the generated environment fact.
const configuredAuthnLuaSourceRulesFixture = `policy:
  namespaces:
    authn:
      providers:
        lua_environment_risk:
          kind: lua_environment
          script_path: environment.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
        lua_subject_risk:
          kind: lua_subject
          script_path: subject.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          checkpoints:
            pre_auth:
              providers:
                - {name: environment_risk, use: authn/lua_environment_risk, actions: [authenticate]}
            subject_analysis:
              providers:
                - {name: subject_risk, use: authn/lua_subject_risk}
            auth_decision: {providers: []}
      policy_sets:
        configured:
          visibility: private
          rules:
            - name: environment_risk_seen
              checkpoint: auth_decision
              actions: [authenticate]
              if: {attribute: nauthilus.auth.lua.environment.risk.triggered, is: true}
              then: {decision: deny}
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      default_policy: authn/standard_auth
      domain_plan: authn/configured
      plans:
        auth_decision:
          policy_sets: [authn/configured]
`

// TestConfiguredAuthnLuaSourcesGenerateStandardAuthRules proves that a scheduled Lua environment source gets the
// standard deny, tempfail, and abort rules, that a scheduled Lua subject source gets its error and reject rules, and
// that configured rules may reference the generated facts.
func TestConfiguredAuthnLuaSourcesGenerateStandardAuthRules(t *testing.T) {
	input, err := Normalize(context.Background(), decodePolicy(t, configuredAuthnLuaSourceRulesFixture))
	requireNoError(t, err)

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	target := lookupCompiledTarget(t, catalog, policy.AuthnNamespace, string(policy.OperationAuthenticate))

	standard, ok := target.LookupPolicySet(mustPolicySetID(t, policy.AuthnNamespace, "standard_auth"))
	if !ok {
		t.Fatal("standard_auth policy set is missing")
	}

	decisions := make(map[string]decision.Effect)
	for _, rule := range standard.Rules() {
		decisions[rule.Name()] = rule.Decision()
	}

	want := map[string]decision.Effect{
		"standard_lua_environment_risk_error":   decision.EffectIndeterminate,
		"standard_lua_environment_risk_trigger": decision.EffectDeny,
		"standard_lua_environment_risk_abort":   decision.EffectNotApplicable,
		"standard_lua_subject_risk_error":       decision.EffectIndeterminate,
		"standard_lua_subject_risk_reject":      decision.EffectDeny,
	}

	for name, effect := range want {
		got, exists := decisions[name]
		if !exists {
			t.Errorf("standard_auth rule %s is missing", name)

			continue
		}

		if got != effect {
			t.Errorf("standard_auth rule %s decision = %q, want %q", name, got, effect)
		}
	}
}

// TestConfiguredAuthnLuaSourceAttributesFollowActivatedActions proves the generated vocabulary is limited to
// scheduled sources and the actions their plan activates.
func TestConfiguredAuthnLuaSourceAttributesFollowActivatedActions(t *testing.T) {
	document := decodePolicy(t, configuredAuthnLuaSourceRulesFixture)
	attributes := ConfiguredAuthnLuaSourceAttributes(document.Policy)

	want := map[string]registry.AttributeCategory{
		"auth.lua.environment.risk.triggered": registry.AttributeCategoryEnvironment,
		"auth.lua.environment.risk.abort":     registry.AttributeCategoryEnvironment,
		"auth.lua.environment.risk.error":     registry.AttributeCategoryEnvironment,
		"auth.lua.subject.risk.rejected":      registry.AttributeCategorySubject,
		"auth.lua.subject.risk.error":         registry.AttributeCategorySubject,
	}

	if len(attributes) != len(want) {
		t.Fatalf("generated Lua source attributes = %d, want %d: %v", len(attributes), len(want), attributes)
	}

	for id, category := range want {
		assertConfiguredAuthnLuaSourceAttribute(t, attributes, id, category)
	}

	for _, id := range []string{"auth.lua.environment.risk.triggered", "auth.lua.subject.risk.rejected"} {
		if _, exists := attributes[id].Details[registry.DetailStatusMessage]; !exists {
			t.Fatalf("generated Lua source attribute %s lost its public status message detail", id)
		}
	}
}

// assertConfiguredAuthnLuaSourceAttribute checks one generated host-owned boolean result fact.
func assertConfiguredAuthnLuaSourceAttribute(
	t *testing.T,
	attributes map[string]registry.AttributeDefinition,
	id string,
	category registry.AttributeCategory,
) {
	t.Helper()

	definition, exists := attributes[id]
	if !exists {
		t.Fatalf("generated Lua source attribute %s is missing", id)
	}

	if definition.ID != id || definition.Category != category || definition.Type != registry.AttributeTypeBool ||
		definition.Source != registry.SourceBuiltin || definition.ProducerCheck == "" {
		t.Fatalf("generated Lua source attribute %s = %+v", id, definition)
	}

	if len(definition.Operations) != 1 || definition.Operations[0] != policy.OperationAuthenticate {
		t.Fatalf("generated Lua source attribute %s operations = %v, want [authenticate]", id, definition.Operations)
	}
}
