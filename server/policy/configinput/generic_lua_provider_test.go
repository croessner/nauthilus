// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/policy/decision"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
)

const genericLuaProviderFixture = `policy:
  namespaces:
    dkim2:
      schema_contributions:
        static:
          sign-message-instance:
            versions:
              v1:
                facts:
                  - attribute: lua.reputation.base_score
                    category: environment
                    type: integer
                    allowed_sources: [lua]
                  - attribute: lua.reputation.risk_score
                    category: environment
                    type: integer
                    allowed_sources: [lua]
      providers:
        base:
          kind: lua
          module: reputation
          script_path: /etc/nauthilus/lua/reputation.lua
          produced_facts: [lua.reputation.base_score]
          failure: continue
          timeout: 100ms
        risk:
          kind: lua
          module: reputation
          script_path: /etc/nauthilus/lua/reputation.lua
          requires: [base]
          produced_facts: [lua.reputation.risk_score]
          executions: [host_sync]
          failure: indeterminate
          timeout: 100ms
      effects:
        audit:
          kind: obligation
          provider: dkim2/risk
          targets: [{action: sign-message-instance}]
          execution: host_sync
      domain_plans:
        default:
          checkpoints:
            final_decision:
              providers:
                - name: base
                  use: dkim2/base
                - name: risk
                  use: dkim2/risk
                  after: [base]
      policy_sets:
        default:
          rules: []
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      domain_plan: dkim2/default
      default_policy: dkim2/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision:
          policy_sets: [dkim2/default]
`

const genericLuaInconsistentSchemaFixture = `policy:
  namespaces:
    mail:
      schema_contributions:
        static:
          submit:
            versions:
              v1:
                facts:
                  - attribute: lua.reputation.score
                    category: environment
                    type: integer
                    allowed_sources: [lua]
          verify:
            versions:
              v1:
                facts:
                  - attribute: lua.reputation.score
                    category: environment
                    type: string
                    allowed_sources: [lua]
      providers:
        risk:
          kind: lua
          module: reputation
          script_path: /etc/nauthilus/lua/reputation.lua
          targets: [{action: submit}, {action: verify}]
          produced_facts: [lua.reputation.score]
          failure: indeterminate
          timeout: 100ms
      policy_sets:
        default: {rules: []}
  targets:
    - namespace: mail
      action: submit
      schema: mail/submit/v1
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision: {policy_sets: [mail/default]}
    - namespace: mail
      action: verify
      schema: mail/verify/v1
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision: {policy_sets: [mail/default]}
`

func TestGenericLuaProviderReferencesResolveToAuthorityOwnedIdentities(t *testing.T) {
	document := decodePolicy(t, genericLuaProviderFixture)

	input, err := Normalize(context.Background(), document)
	requireNoError(t, err)

	base, _ := findProviderAndEffectOptional(input, "dkim2/lua.reputation.base", "")
	risk, effect := findProviderAndEffect(t, input, "dkim2/lua.reputation.risk", "dkim2/audit")

	if got := risk.Requires(); !slices.Equal(got, []string{base.ID()}) {
		t.Fatalf("risk requires = %v, want [%s]", got, base.ID())
	}

	if effect.Provider() != risk.ID() {
		t.Fatalf("effect provider = %q, want %q", effect.Provider(), risk.ID())
	}

	assertGenericLuaProviderShape(t, base)
	assertGenericLuaProviderShape(t, risk)

	if len(base.Executions()) != 0 {
		t.Fatalf("fact-only base executions = %v, want none", base.Executions())
	}

	projected, err := LuaProviderOutputs(input.Policy, "dkim2", "risk")
	requireNoError(t, err)

	if len(projected) != 1 || projected[0].ID != "lua.reputation.risk_score" {
		t.Fatalf("LuaProviderOutputs() = %#v, want typed risk output", projected)
	}

	catalog, err := input.Compile(context.Background(), testAcceptanceCapability{})
	requireNoError(t, err)

	target := lookupCompiledTarget(t, catalog, "dkim2", "sign-message-instance")

	checkpoint, ok := target.DomainPlan().Checkpoint("final_decision")
	if !ok {
		t.Fatal("final_decision checkpoint is missing")
	}

	if got := checkpoint.ProviderIDs(); !slices.Equal(got, []string{base.ID(), risk.ID()}) {
		t.Fatalf("compiled provider IDs = %v, want [%s %s]", got, base.ID(), risk.ID())
	}
}

func TestGenericLuaProviderOutputProjectionRequiresLuaCompatibleExactSchemas(t *testing.T) {
	tests := []struct {
		name        string
		replacement string
		want        string
	}{
		{
			name:        "missing declared fact",
			replacement: "lua.reputation.unknown_score",
			want:        "produced_facts[0]",
		},
		{
			name:        "source not allowed",
			replacement: "allowed_sources: [caller]",
			want:        "allowed_sources",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oldValue := "produced_facts: [lua.reputation.base_score]"

			newValue := "produced_facts: [" + test.replacement + "]"
			if test.name == "source not allowed" {
				oldValue = "allowed_sources: [lua]"
				newValue = test.replacement
			}

			source := strings.Replace(genericLuaProviderFixture, oldValue, newValue, 1)

			_, err := Normalize(context.Background(), decodePolicy(t, source))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Normalize() error = %v, want path containing %q", err, test.want)
			}
		})
	}
}

// assertGenericLuaProviderShape proves exact target derivation and typed output retention.
func assertGenericLuaProviderShape(t *testing.T, provider registry.ProviderDefinition) {
	t.Helper()

	if got := targetStrings(provider.Targets()); !slices.Equal(got, []string{"dkim2/sign-message-instance"}) {
		t.Fatalf("%s targets = %v, want derived exact target", provider.ID(), got)
	}

	outputs := provider.Outputs()
	if len(outputs) != 1 || outputs[0].Category() != decision.FactCategoryEnvironment ||
		outputs[0].Kind() != decision.ValueKindInteger {
		t.Fatalf("%s outputs = %#v, want one typed environment integer", provider.ID(), outputs)
	}
}

func TestGenericLuaProviderOutputProjectionRejectsTargetSchemaDrift(t *testing.T) {
	_, err := Normalize(context.Background(), decodePolicy(t, genericLuaInconsistentSchemaFixture))
	if err == nil || !strings.Contains(err.Error(), "identical category, kind, and bounds") {
		t.Fatalf("Normalize() error = %v, want exact target schema consistency failure", err)
	}
}

// targetStrings renders exact target identities for stable assertions.
func targetStrings(targets []decision.Target) []string {
	result := make([]string, 0, len(targets))
	for _, target := range targets {
		result = append(result, target.String())
	}

	return result
}
