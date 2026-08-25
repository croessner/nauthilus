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

	"github.com/croessner/nauthilus/v3/server/policy/decision"
)

const genericNativeProviderFixture = `policy:
  namespaces:
    dkim2:
      schema_contributions:
        static:
          sign-message-instance:
            versions:
              v1:
                facts:
                  - attribute: plugin.reputation.risk_score
                    category: environment
                    type: integer
                    allowed_sources: [plugin]
      providers:
        risk:
          kind: native
          module: reputation
          targets: [{action: sign-message-instance}]
          produced_facts: [plugin.reputation.risk_score]
          failure: continue
          timeout: 100ms
      domain_plans:
        default:
          checkpoints:
            final_decision:
              providers:
                - name: risk
                  use: dkim2/risk
      policy_sets:
        default: {rules: []}
  targets:
    - namespace: dkim2
      action: sign-message-instance
      schema: dkim2/sign-message-instance/v1
      domain_plan: dkim2/default
      default_policy: dkim2/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision: {policy_sets: [dkim2/default]}
`

func TestGenericNativeProviderProjectsPluginFactsWithoutImplicitEffectExecution(t *testing.T) {
	input, err := Normalize(context.Background(), decodePolicy(t, genericNativeProviderFixture))
	requireNoError(t, err)

	provider, _ := findProviderAndEffectOptional(input, "dkim2/plugin.reputation.risk", "")
	if got := provider.Executions(); len(got) != 0 {
		t.Fatalf("fact-only native provider executions = %v, want none", got)
	}

	if got := targetStrings(provider.Targets()); !slices.Equal(got, []string{"dkim2/sign-message-instance"}) {
		t.Fatalf("native provider targets = %v, want configured target", got)
	}

	outputs := provider.Outputs()
	if len(outputs) != 1 || outputs[0].ID() != "plugin.reputation.risk_score" ||
		outputs[0].Category() != decision.FactCategoryEnvironment ||
		outputs[0].Kind() != decision.ValueKindInteger {
		t.Fatalf("native provider outputs = %#v, want one typed plugin fact", outputs)
	}
}

func TestGenericNativeProviderOutputProjectionRequiresPluginSource(t *testing.T) {
	source := strings.Replace(genericNativeProviderFixture, "allowed_sources: [plugin]", "allowed_sources: [lua]", 1)

	_, err := Normalize(context.Background(), decodePolicy(t, source))
	if err == nil || !strings.Contains(err.Error(), "allowed_sources") {
		t.Fatalf("Normalize() error = %v, want plugin source path", err)
	}
}
