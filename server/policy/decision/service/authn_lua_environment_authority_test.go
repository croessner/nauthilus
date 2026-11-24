// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"strings"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/policy"
	"github.com/croessner/nauthilus/v4/server/policy/configinput"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
)

// authnLuaEnvironmentAuthorityFixture schedules one configured Lua environment source. The operator rules
// placeholder is replaced per test case, so the same policy runs with and without an operator decision.
const authnLuaEnvironmentAuthorityFixture = `policy:
  namespaces:
    authn:
      providers:
        lua_environment_risk:
          kind: lua_environment
          script_path: environment.lua
          targets: [{action: authenticate}]
          executions: [host_sync]
      domain_plans:
        configured:
          checkpoints:
            pre_auth:
              providers:
                - {name: environment_risk, use: authn/lua_environment_risk}
            auth_decision: {providers: []}
      policy_sets:
        operator:
          visibility: private
          rules:
OPERATOR_RULES
  targets:
    - namespace: authn
      action: authenticate
      schema: authn/authenticate/v1
      default_policy: authn/standard_auth
      domain_plan: authn/configured
      plans:
        auth_decision:
          policy_sets: [authn/operator]
`

// authnLuaEnvironmentUnrelatedRule never matches the trigger, so the standard rules decide.
const authnLuaEnvironmentUnrelatedRule = `            - name: never
              checkpoint: auth_decision
              actions: [authenticate]
              if: {attribute: nauthilus.auth.backend.tempfail, is: true}
              then: {decision: tempfail}`

// authnLuaEnvironmentTempFailRule lets the operator answer a triggered source with a temporary failure.
const authnLuaEnvironmentTempFailRule = `            - name: environment_risk_tempfail
              checkpoint: auth_decision
              actions: [authenticate]
              if: {attribute: nauthilus.auth.lua.environment.risk.triggered, is: true}
              then: {decision: tempfail}`

// authnLuaEnvironmentPermitRule lets the operator ignore the trigger for an authenticated request.
const authnLuaEnvironmentPermitRule = `            - name: environment_risk_ignored
              checkpoint: auth_decision
              actions: [authenticate]
              if:
                all:
                  - {attribute: nauthilus.auth.lua.environment.risk.triggered, is: true}
                  - {attribute: backend.authenticated, is: true}
              then: {decision: permit}`

// TestConfiguredLuaEnvironmentTriggerIsDecidedByPolicy proves that a Lua environment trigger is only a fact: the
// generated standard rule denies it when no operator rule decides first, and configured operator rules, which run
// before the authn/standard_auth fallback, may answer it differently or ignore it.
func TestConfiguredLuaEnvironmentTriggerIsDecidedByPolicy(t *testing.T) {
	tests := []struct {
		name       string
		rules      string
		wantRule   string
		wantEffect decision.Effect
	}{
		{
			name: "standard fallback denies", rules: authnLuaEnvironmentUnrelatedRule,
			wantRule: "standard_lua_environment_risk_trigger", wantEffect: decision.EffectDeny,
		},
		{
			name: "operator answers with tempfail", rules: authnLuaEnvironmentTempFailRule,
			wantRule: "environment_risk_tempfail", wantEffect: decision.EffectIndeterminate,
		},
		{
			name: "operator ignores the trigger", rules: authnLuaEnvironmentPermitRule,
			wantRule: "environment_risk_ignored", wantEffect: decision.EffectPermit,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluator, target := mustConfiguredLuaEnvironmentRuntime(t, test.rules)
			source := newSuppliedAuthnDecisionSource(t, []authnCatalogBooleanFact{
				authnNauthilusBooleanFact(
					policy.AuthnLuaEnvironmentFactID("risk", policy.SourceResultTriggered),
					decision.FactCategoryEnvironment,
					true,
				),
				authnBackendBooleanFact(policy.AuthnFactAuthenticated, true),
			}, false)

			outcome := evaluateAuthnSourceNamedCheckpoint(
				t, evaluator, target, source, &recordingEffectAcceptor{}, string(policy.StageAuthDecision),
			)

			if outcome.response.Effect() != test.wantEffect {
				t.Fatalf("effect = %q, want %q", outcome.response.Effect(), test.wantEffect)
			}

			if selected := source.capturedDecision(); selected == nil || selected.PolicyName != test.wantRule {
				t.Fatalf("selected decision = %#v, want rule %s", selected, test.wantRule)
			}
		})
	}
}

// mustConfiguredLuaEnvironmentRuntime compiles the fixture with the given operator rules through the configured
// policy path, so the Lua source facts come from configuration and not from hand-written definitions.
func mustConfiguredLuaEnvironmentRuntime(t *testing.T, rules string) (checkpointEvaluator, decision.Target) {
	t.Helper()

	source := strings.Replace(authnLuaEnvironmentAuthorityFixture, "OPERATOR_RULES", rules, 1)

	document, err := policyconfig.Decode("yaml", strings.NewReader(source))
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

	target, err := decision.NewTarget(policy.AuthnNamespace, string(policy.OperationAuthenticate))
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	log := &authnEffectOrderLog{}
	evaluator := mustCheckpointRuntime(t, checkpointRuntimeConfig{
		catalog: catalog, ids: &sequenceIDGenerator{}, evaluationTimeout: time.Second,
		syncEffects: map[string]syncEffectBinding{
			policy.AuthnProviderBruteForce: {provider: &orderedAuthnSyncEffectProvider{log: log}},
			"authn/lua_action":             {provider: &orderedAuthnSyncEffectProvider{log: log}},
		},
		postActions: map[string]postActionBinding{
			"authn/post_action": {provider: &orderedAuthnPostActionProvider{log: log}},
		},
	})

	return evaluator, target
}
