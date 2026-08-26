// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package runtime_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config/policyconfig"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/policy/configinput"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const conditionMaterialBindingFixture = `policy:
  namespaces:
    mail:
      condition_sets:
        strings:
          allowed_protocols: [smtp]
        networks:
          trusted_networks: [10.0.0.0/8]
        time_windows:
          business_hours:
            timezone: UTC
            days: [mon]
            intervals: [{start: "08:00", end: "18:00"}]
      schema_contributions:
        static:
          submit:
            versions:
              v1:
                facts:
                  - {attribute: input.protocol, category: environment, type: string, allowed_sources: [caller]}
                  - {attribute: input.address, category: environment, type: string, allowed_sources: [caller]}
                  - {attribute: input.instant, category: environment, type: timestamp, allowed_sources: [caller]}
      domain_plans:
        default:
          checkpoints:
            final_decision: {providers: []}
      policy_sets:
        default:
          rules:
            - name: string_reference
              checkpoint: final_decision
              if: {attribute: input.protocol, in: "@string.allowed_protocols"}
              then: {decision: permit}
            - name: network_reference
              checkpoint: final_decision
              if: {attribute: input.address, cidr_contains: "@network.trusted_networks"}
              then: {decision: permit}
            - name: time_reference
              checkpoint: final_decision
              if: {attribute: input.instant, within_time_window: "@time_window.business_hours"}
              then: {decision: permit}
  targets:
    - namespace: mail
      action: submit
      schema: mail/submit/v1
      domain_plan: mail/default
      default_policy: mail/default
      no_match: deny
      timeouts: {evaluation: 2s, provider_default: 500ms}
      plans:
        final_decision: {policy_sets: [mail/default]}
`

type conditionMaterialAcceptor struct{}

// Accept returns one inert receipt because this fixture declares no host effects.
func (*conditionMaterialAcceptor) Accept(
	context.Context,
	effectsupervisor.Plan,
) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

// TestBindingSetRejectsMissingReferencedConditionMaterial closes candidate activation under negation.
func TestBindingSetRejectsMissingReferencedConditionMaterial(t *testing.T) {
	document, err := policyconfig.Decode("yaml", strings.NewReader(conditionMaterialBindingFixture))
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	input, err := configinput.Normalize(t.Context(), document)
	if err != nil {
		t.Fatalf("configinput.Normalize() error = %v", err)
	}

	catalog, err := input.Compile(t.Context(), &conditionMaterialAcceptor{})
	if err != nil {
		t.Fatalf("UnifiedPolicyInput.Compile() error = %v", err)
	}

	sets, windows, err := configinput.PrepareConditionMaterial(input.Policy)
	if err != nil {
		t.Fatalf("PrepareConditionMaterial() error = %v", err)
	}

	complete := newConditionMaterialBindingSet(t, sets, windows)
	if err = complete.ValidateCatalog(catalog); err != nil {
		t.Fatalf("complete BindingSet.ValidateCatalog() error = %v", err)
	}

	tests := []struct {
		name      string
		reference string
		window    bool
	}{
		{name: "string", reference: "@string.allowed_protocols"},
		{name: "network", reference: "@network.trusted_networks"},
		{name: "time window", reference: "@time_window.business_hours", window: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateSets := cloneConditionSets(sets)
			candidateWindows := cloneTimeWindows(windows)

			key := policyruntime.ConditionMaterialKey("mail", test.reference)
			if test.window {
				delete(candidateWindows, key)
			} else {
				delete(candidateSets, key)
			}

			candidate := newConditionMaterialBindingSet(t, candidateSets, candidateWindows)
			if err := candidate.ValidateCatalog(catalog); !errors.Is(err, policyruntime.ErrInvalidGenerationBinding) {
				t.Fatalf("BindingSet.ValidateCatalog() error = %v, want ErrInvalidGenerationBinding", err)
			}
		})
	}
}

// newConditionMaterialBindingSet constructs one candidate with no unrelated runtime owners.
func newConditionMaterialBindingSet(
	t *testing.T,
	sets map[string][]decision.Value,
	windows map[string]policyruntime.CompiledTimeWindow,
) *policyruntime.BindingSet {
	t.Helper()

	syncEffects, postActions := core.AuthnStandardEffectBindings()

	bindings, err := policyruntime.NewBindingSet(policyruntime.BindingSetInput{
		ConditionSets: sets, TimeWindows: windows, PostActionAcceptance: &conditionMaterialAcceptor{},
		SyncEffects: syncEffects, PostActions: postActions,
	})
	if err != nil {
		t.Fatalf("NewBindingSet() error = %v", err)
	}

	return bindings
}

// cloneConditionSets detaches strict operand collections for destructive test mutation.
func cloneConditionSets(input map[string][]decision.Value) map[string][]decision.Value {
	result := make(map[string][]decision.Value, len(input))
	for key, values := range input {
		result[key] = append([]decision.Value(nil), values...)
	}

	return result
}

// cloneTimeWindows detaches recurring schedules for destructive test mutation.
func cloneTimeWindows(
	input map[string]policyruntime.CompiledTimeWindow,
) map[string]policyruntime.CompiledTimeWindow {
	result := make(map[string]policyruntime.CompiledTimeWindow, len(input))
	for key, window := range input {
		result[key] = window.Clone()
	}

	return result
}
