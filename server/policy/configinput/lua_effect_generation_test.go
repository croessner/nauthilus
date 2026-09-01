// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package configinput

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const configuredLuaEffectOnlyFixture = `policy:
  namespaces:
    mail:
      schema_contributions:
        static:
          filter:
            versions:
              v1: {facts: []}
      providers:
        notifier:
          kind: lua
          module: audit
          script_path: %q
          targets: [{action: filter}]
          executions: [host_sync]
          failure: indeterminate
          timeout: 50ms
      effects:
        notify:
          kind: obligation
          provider: mail/notifier
          targets: [{action: filter}]
          execution: host_sync
      policy_sets:
        default: {rules: []}
  targets:
    - namespace: mail
      action: filter
      schema: mail/filter/v1
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision: {policy_sets: [mail/default]}
`

const configuredNativeFactsWithoutLuaFixture = `policy:
  namespaces:
    mail:
      schema_contributions:
        static:
          filter:
            versions:
              v1: {facts: []}
      providers:
        risk:
          kind: native
          module: reputation
          targets: [{action: filter}]
          produced_facts: [plugin.reputation.risk_score]
          failure: indeterminate
          timeout: 50ms
      domain_plans:
        default:
          checkpoints:
            final_decision:
              providers:
                - name: risk
                  use: mail/plugin.reputation.risk
      policy_sets:
        default:
          rules:
            - name: native_risk
              if: {attribute: plugin.reputation.risk_score, gte: 10}
              then: {decision: deny}
  targets:
    - namespace: mail
      action: filter
      schema: mail/filter/v1
      domain_plan: mail/default
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision: {policy_sets: [mail/default]}
`

func TestConfiguredLuaEffectProviderContributionDoesNotGainFactSchedule(t *testing.T) {
	script := filepath.Join(t.TempDir(), "effect.lua")
	if err := os.WriteFile(script, []byte(`
_G["policy.effects.execute"] = function(request)
    return { state = "succeeded" }
end
`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	configured := decodePolicy(t, fmt.Sprintf(configuredLuaEffectOnlyFixture, script)).Policy
	preparation, err := PrepareConfiguredLuaGeneration(t.Context(), ConfiguredLuaGenerationInput{
		Artifacts:            capturePolicyLuaTestArtifacts(t, configured),
		Policy:               configured,
		PostActionAcceptance: &nativeGenerationAcceptor{},
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredLuaGeneration() error = %v", err)
	}

	providers := preparation.Definitions[0].Providers()
	if len(providers) != 1 || providers[0].Scheduled() || providers[0].Timeout() != 0 ||
		providers[0].Failure() != "" {
		t.Fatalf("Lua effect-only provider retained fact schedule metadata: %#v", providers)
	}
}

// TestConfiguredLuaGenerationSkipsUnownedNativeFacts proves empty Lua preparation does not validate native owners.
func TestConfiguredLuaGenerationSkipsUnownedNativeFacts(t *testing.T) {
	configured := decodePolicy(t, configuredNativeFactsWithoutLuaFixture).Policy

	preparation, err := PrepareConfiguredLuaGeneration(t.Context(), ConfiguredLuaGenerationInput{
		Policy:               configured,
		PostActionAcceptance: &nativeGenerationAcceptor{},
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredLuaGeneration() error = %v", err)
	}

	if len(preparation.Definitions) != 0 || len(preparation.Resources) != 0 {
		t.Fatalf("Lua preparation = %#v, want no unowned native material", preparation)
	}
}
